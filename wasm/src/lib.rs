#![allow(clippy::new_without_default)]
mod utils;

use midnight_base_crypto::{
    curve::Fr,
    fab::AlignedValue,
    hash::{transient_commit, transient_hash},
    proofs::{IrSource, KeyLocation, ParamsProver, ProofPreimage, ProverKey, VerifierKey},
    serialize::{deserialize, serialize, NetworkId},
};
use midnight_impact_rps_example::{
    add_commitment_encode_params,
    common::{gen_proof_and_check, ProofParams},
    dummy_contract_address, initial_state, make_add_commitments_circuit, make_openings_circuit,
    open_commitments_encode_params, run_open_commitments_program, INDEX_PLAYER1_PK,
    INDEX_PLAYER1_VICTORIES, INDEX_PLAYER2_PK, INDEX_TIES,
};
use midnight_impact_rps_example::{run_add_commitment, INDEX_PLAYER2_VICTORIES};
use midnight_ledger::{
    construct::ContractCallPrototype,
    structure::{ContractCalls, Transaction},
    zswap::Offer,
};
use midnight_onchain_runtime::{
    state::{self, ContractOperation, StateValue},
    transcript::Transcript,
};
use rand::{rngs::OsRng, Rng as _, SeedableRng as _};
use rand_chacha::ChaCha20Rng;
use std::{borrow::Cow, convert::TryInto as _, io::Cursor};
use utils::set_panic_hook;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::js_sys::Uint8Array;

pub use wasm_bindgen_rayon::init_thread_pool;

const KZG: &[u8] = include_bytes!(concat!(env!("MIDNIGHT_LEDGER_STATIC_DIR"), "/kzg"));

const PK_ADD_COMMITMENTS: &[u8] = include_bytes!("../pk_add_commitments");
const VK_ADD_COMMITMENTS: &[u8] = include_bytes!("../vk_add_commitments");

const PK_OPEN_COMMITMENTS: &[u8] = include_bytes!("../pk_open_commitments");
const VK_OPEN_COMMITMENTS: &[u8] = include_bytes!("../vk_open_commitments");

const OUTPUT_VK_RAW: &[u8] = include_bytes!(concat!(
    env!("MIDNIGHT_LEDGER_STATIC_DIR"),
    "/zswap/keys/output.verifier"
));

const OUTPUT_PK_RAW: &[u8] = include_bytes!(concat!(
    env!("MIDNIGHT_LEDGER_STATIC_DIR"),
    "/zswap/keys/output.prover"
));

const OUTPUT_IR_RAW: &[u8] = include_bytes!(concat!(
    env!("MIDNIGHT_LEDGER_STATIC_DIR"),
    "/zswap/zkir/output.zkir"
));

const SPEND_VK_RAW: &[u8] = include_bytes!(concat!(
    env!("MIDNIGHT_LEDGER_STATIC_DIR"),
    "/zswap/keys/spend.verifier"
));

const SPEND_PK_RAW: &[u8] = include_bytes!(concat!(
    env!("MIDNIGHT_LEDGER_STATIC_DIR"),
    "/zswap/keys/spend.prover"
));

const SPEND_IR_RAW: &[u8] = include_bytes!(concat!(
    env!("MIDNIGHT_LEDGER_STATIC_DIR"),
    "/zswap/zkir/spend.zkir"
));

const SIGN_VK_RAW: &[u8] = include_bytes!(concat!(
    env!("MIDNIGHT_LEDGER_STATIC_DIR"),
    "/zswap/keys/sign.verifier"
));

const SIGN_PK_RAW: &[u8] = include_bytes!(concat!(
    env!("MIDNIGHT_LEDGER_STATIC_DIR"),
    "/zswap/keys/sign.prover"
));

const SIGN_IR_RAW: &[u8] = include_bytes!(concat!(
    env!("MIDNIGHT_LEDGER_STATIC_DIR"),
    "/zswap/zkir/sign.zkir"
));

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);

    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

pub fn decode_zswap_proof_params(
    pk: &[u8],
    vk: &[u8],
    ir: &[u8],
) -> (ProverKey, VerifierKey, IrSource) {
    let pk = deserialize::<ProverKey, _>(Cursor::new(pk), NetworkId::Undeployed).unwrap();
    let vk = deserialize::<VerifierKey, _>(Cursor::new(vk), NetworkId::Undeployed).unwrap();
    let ir = IrSource::load(Cursor::new(ir)).unwrap();

    (pk, vk, ir)
}

pub fn decode_proof_params(pk: &[u8], vk: &[u8]) -> ProofParams {
    let mut pp = ParamsProver::read(Cursor::new(KZG)).unwrap();

    let k = 9;
    pp = pp.downsize(k);

    let pk = deserialize::<ProverKey, _>(Cursor::new(pk), NetworkId::Undeployed).unwrap();
    let vk = deserialize::<VerifierKey, _>(Cursor::new(vk), NetworkId::Undeployed).unwrap();

    ProofParams { pp, pk, vk }
}

// Called when the Wasm module is instantiated
#[wasm_bindgen(start)]
fn main() -> Result<(), JsValue> {
    set_panic_hook();
    Ok(())
}

#[wasm_bindgen]
#[repr(u64)]
pub enum RpsInput {
    Rock = 0,
    Paper = 1,
    Scissors = 2,
}

#[wasm_bindgen]
#[derive(Copy, Clone)]
pub enum Player {
    P1,
    P2,
}

#[wasm_bindgen]
#[derive(Copy, Clone)]
pub enum Winner {
    P1,
    P2,
    Tie,
}

#[wasm_bindgen]
pub struct Rng(ChaCha20Rng);

#[wasm_bindgen]
impl Rng {
    pub fn new() -> Self {
        Rng(ChaCha20Rng::from_rng(rand::thread_rng()).unwrap())
    }

    pub fn random_fr(&mut self) -> FrValue {
        FrValue(self.0.gen())
    }
}

#[wasm_bindgen]
pub struct FrValue(Fr);

// proof tx type
type TransactionProvePayload = (
    Transaction<ProofPreimage>,
    // Hack to allow the payload to be the concatenation of two 'serialize' forms.
    u8,
    std::collections::HashMap<String, (ProverKey, VerifierKey, IrSource)>,
);

#[wasm_bindgen]
pub struct Context {
    current_state: StateValue,
    commit_ir: (IrSource, ProofParams),
    open_ir: (IrSource, ProofParams),
    spend: (ProverKey, VerifierKey, IrSource),
    output: (ProverKey, VerifierKey, IrSource),
    sign: (ProverKey, VerifierKey, IrSource),
}

#[wasm_bindgen]
pub struct PlayerSk([u8; 32]);

#[wasm_bindgen]
impl PlayerSk {
    pub fn to_public(&self) -> PlayerPk {
        let hashed = {
            let mut address_repr = vec![];
            AlignedValue::from(self.0).value_only_field_repr(&mut address_repr);
            transient_hash(&address_repr)
        };

        PlayerPk(hashed)
    }
}

#[wasm_bindgen]
pub struct PlayerPk(Fr);

#[wasm_bindgen]
impl Context {
    pub fn new(pk1: &PlayerPk, pk2: &PlayerPk) -> Self {
        let commit_ir = make_add_commitments_circuit();

        let commit_proof_params = decode_proof_params(PK_ADD_COMMITMENTS, VK_ADD_COMMITMENTS);

        let open_ir = make_openings_circuit();
        let open_proof_params = decode_proof_params(PK_OPEN_COMMITMENTS, VK_OPEN_COMMITMENTS);

        let state = initial_state(pk1.0, pk2.0).context.state;

        let spend = decode_zswap_proof_params(SPEND_PK_RAW, SPEND_VK_RAW, SPEND_IR_RAW);
        let output = decode_zswap_proof_params(OUTPUT_PK_RAW, OUTPUT_VK_RAW, OUTPUT_IR_RAW);
        let sign = decode_zswap_proof_params(SIGN_PK_RAW, SIGN_VK_RAW, SIGN_IR_RAW);

        Context {
            current_state: state,
            commit_ir: (commit_ir, commit_proof_params),
            open_ir: (open_ir, open_proof_params),
            spend,
            output,
            sign,
        }
    }

    pub async fn commit_to_value(
        &mut self,
        player: Player,
        sk: &PlayerSk,
        value: RpsInput,
        opening: &FrValue,
        generate_proof: bool,
    ) -> Result<Uint8Array, JsError> {
        let index = match player {
            Player::P1 => INDEX_PLAYER1_PK,
            Player::P2 => INDEX_PLAYER2_PK,
        };

        let value_fr = Fr::from(value as u64);
        let commitment: AlignedValue = transient_commit(&value_fr, opening.0).into();
        let (transcript, query_result) =
            run_add_commitment(index, self.current_state.clone(), commitment.clone());

        let (inputs, _public_transcript_inputs, _public_transcript_outputs, private_transcript) =
            add_commitment_encode_params(
                sk.0,
                transcript.clone(),
                index,
                commitment,
                (value_fr, opening.0),
            );

        self.current_state = query_result.context.state;

        let guaranted_coins = Offer {
            inputs: vec![],
            outputs: vec![],
            transient: vec![],
            deltas: vec![],
        };
        let fallible_coins = None;

        let cc = ContractCalls::new(&mut OsRng);

        let inputs_aligned = inputs
            .iter()
            .map(|fr| AlignedValue::from(*fr))
            .collect::<Vec<_>>();
        let input = AlignedValue::concat(&inputs_aligned);

        let cc = cc.add_call(ContractCallPrototype {
            address: dummy_contract_address(),
            entry_point: state::EntryPointBuf("commit_to_value".to_string().into_bytes()),
            op: ContractOperation::new(None),
            guaranteed_public_transcript: Some(Transcript {
                gas: query_result.gas_cost,
                effects: query_result.context.effects,
                program: transcript,
            }),
            fallible_public_transcript: None,
            private_transcript_outputs: private_transcript
                .iter()
                .map(|fr| AlignedValue::from(*fr))
                .collect(),
            input,
            output: AlignedValue::from(vec![]),
            communication_commitment_rand: OsRng.gen(),
            key_location: KeyLocation(Cow::Borrowed("commit_to_value")),
        });

        let unproven_tx: Transaction<ProofPreimage> =
            Transaction::new(guaranted_coins, fallible_coins, Some(cc));

        let call_resolver = (
            self.commit_ir.1.pk.clone(),
            self.commit_ir.1.vk.clone(),
            self.commit_ir.0.clone(),
        );

        if !generate_proof {
            let mut res = Vec::new();

            let resolvers = vec![("commit_to_value".to_string(), call_resolver.clone())]
                .into_iter()
                .collect::<std::collections::HashMap<_, _>>();

            let tx_proof_payload: TransactionProvePayload = (unproven_tx, 1u8, resolvers);

            serialize(&tx_proof_payload, &mut res, NetworkId::Undeployed)?;

            return Ok(Uint8Array::from(&res[..]));
        }

        let unbalanced_tx = unproven_tx
            .prove(OsRng, &self.commit_ir.1.pp, |loc| match &*loc.0 {
                "midnight/zswap/spend" => Some(self.spend.clone()),
                "midnight/zswap/output" => Some(self.output.clone()),
                "midnight/zswap/sign" => Some(self.sign.clone()),
                _ => Some(call_resolver.clone()),
            })
            .await;

        let unbalanced_tx = match unbalanced_tx {
            Ok(unbalanced_tx) => unbalanced_tx,
            Err(error) => {
                log(&format!("{:?}", &error));
                return Err(error.into());
            }
        };

        let mut res = Vec::new();
        serialize(&unbalanced_tx, &mut res, NetworkId::Undeployed)?;
        Ok(Uint8Array::from(&res[..]))
    }

    pub async fn open(
        &mut self,
        winner: Winner,
        opening1_value: RpsInput,
        opening1_random: &FrValue,
        opening2_value: RpsInput,
        opening2_random: &FrValue,
    ) -> Vec<u8> {
        let winner = match winner {
            Winner::P1 => Fr::from(INDEX_PLAYER1_VICTORIES),
            Winner::P2 => Fr::from(INDEX_PLAYER2_VICTORIES),
            Winner::Tie => Fr::from(INDEX_TIES),
        };

        let opening1_value = Fr::from(opening1_value as u64);
        let opening2_value = Fr::from(opening2_value as u64);

        let (transcript, query_result) =
            run_open_commitments_program(self.current_state.clone(), winner);

        let (inputs, public_transcript_inputs, public_transcript_outputs, private_transcript) =
            open_commitments_encode_params(
                transcript,
                (opening1_value, opening1_random.0),
                (opening2_value, opening2_random.0),
                winner,
            );

        let proof = gen_proof_and_check(
            self.open_ir.0.clone(),
            inputs,
            private_transcript,
            public_transcript_inputs,
            public_transcript_outputs,
            self.open_ir.1.clone(),
        )
        .await;

        self.current_state = query_result.context.state;

        let mut buf = vec![];
        serialize(&proof, &mut buf, NetworkId::Undeployed).unwrap();
        buf
    }

    pub fn get_state(&self) -> Vec<u64> {
        let mut values = vec![];
        for i in [INDEX_PLAYER1_VICTORIES, INDEX_PLAYER2_VICTORIES, INDEX_TIES] {
            match &self.current_state {
                StateValue::Array(array) => match &array[i as usize] {
                    StateValue::Cell(val) => {
                        let mut writer = vec![];
                        val.value_only_field_repr(&mut writer);

                        let n: u64 = writer[0].try_into().unwrap();

                        values.push(n);
                    }
                    _ => unreachable!(),
                },
                _ => unreachable!(),
            }
        }

        values
    }
}
