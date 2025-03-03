#![allow(clippy::new_without_default)]
mod utils;

use midnight_base_crypto::fab::{AlignmentSegment, ValueAtom};
use midnight_impact_rps_example::{common::gen_transcript_constraints, dummy_contract_address};
use midnight_ledger::{
    construct::ContractCallPrototype,
    structure::{ContractCalls, ContractDeploy, Transaction},
    transient_crypto::{
        curve::Fr,
        proofs::{ProofPreimage, ProverKey, VerifierKey},
    },
    zswap::Offer,
};
use midnight_onchain_runtime::{
    cost_model::DUMMY_COST_MODEL,
    ops::Op,
    result_mode::ResultModeVerify,
    state::{ContractOperation, ContractState},
};
use midnight_transient_crypto::fab::AlignedValueExt as _;
use midnight_transient_crypto::proofs::{
    ir::{Index, Instruction},
    KeyLocation,
};
use rand::{rngs::StdRng, Rng as _, SeedableRng as _};
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    io::Cursor,
    ops::Deref as _,
    sync::Arc,
};
use utils::set_panic_hook;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::js_sys::Uint8Array;
pub use wasm_bindgen_rayon::init_thread_pool;

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

// Called when the Wasm module is instantiated
#[wasm_bindgen(start)]
fn main() -> Result<(), JsValue> {
    set_panic_hook();
    Ok(())
}

#[wasm_bindgen]
pub struct WasmProver {
    proof_params: Arc<ParamsProver>,
}

#[wasm_bindgen]
pub struct ZkConfig(ZkConfigEnum);

enum ZkConfigEnum {
    Circuit {
        pk: ProverKey,
        vk: VerifierKey,
        ir: midnight_transient_crypto::proofs::IrSource,
        circuit_id: String,
    },
    Empty,
}

#[wasm_bindgen]
impl ZkConfig {
    pub fn empty() -> Self {
        Self(ZkConfigEnum::Empty)
    }

    pub fn new(
        circuit_id: String,
        pk: &Uint8Array,
        vk: &Uint8Array,
        ir: &Uint8Array,
    ) -> Result<Self, JsError> {
        let pk: ProverKey = midnight_ledger::serialize::deserialize(
            &pk.to_vec()[..],
            midnight_ledger::serialize::NetworkId::Undeployed,
        )
        .map_err(|e| JsError::new(e.to_string().as_str()))?;

        let vk: VerifierKey = midnight_ledger::serialize::deserialize(
            &vk.to_vec()[..],
            midnight_ledger::serialize::NetworkId::Undeployed,
        )
        .map_err(|e| JsError::new(e.to_string().as_str()))?;

        let ir: midnight_transient_crypto::proofs::IrSource =
            midnight_ledger::serialize::deserialize(
                &ir.to_vec()[..],
                midnight_ledger::serialize::NetworkId::Undeployed,
            )
            .map_err(|e| JsError::new(e.to_string().as_str()))?;

        Ok(ZkConfig(ZkConfigEnum::Circuit {
            pk,
            vk,
            ir,
            circuit_id,
        }))
    }
}

#[wasm_bindgen]
impl WasmProver {
    pub fn new(pp: &ParamsProver) -> WasmProver {
        WasmProver {
            proof_params: Arc::new(pp.clone()),
        }
    }

    pub async fn prove_tx(
        &self,
        rng: &Rng,
        unproven_tx: &Uint8Array,
        network_id: NetworkId,
        zk_config: &ZkConfig,
    ) -> Result<Uint8Array, JsError> {
        let tx: Transaction<ProofPreimage> =
            midnight_ledger::serialize::deserialize(&unproven_tx.to_vec()[..], network_id.0)
                .map_err(|e| JsError::new(e.to_string().as_ref()))?;

        let call_resolver = match &zk_config.0 {
            ZkConfigEnum::Circuit {
                pk,
                vk,
                ir,
                circuit_id: _,
            } => Some((pk.clone(), vk.clone(), ir.clone())),
            ZkConfigEnum::Empty => None,
        };

        let (oneshot_tx, oneshot_rx) = futures::channel::oneshot::channel();

        {
            let proof_params = Arc::clone(&self.proof_params);
            let rng = rng.0.clone();
            rayon::spawn(move || {
                let unbalanced_tx =
                    futures::executor::block_on(
                        tx.prove(rng, &proof_params.0, |_loc| call_resolver.clone()),
                    );

                oneshot_tx.send(unbalanced_tx).unwrap();
            });
        }

        let unbalanced_tx = oneshot_rx
            .await
            .unwrap()
            .map_err(|e| JsError::new(&e.to_string()))?;

        let mut res = Vec::new();
        midnight_ledger::serialize::serialize(&unbalanced_tx, &mut res, network_id.0)?;
        Ok(Uint8Array::from(&res[..]))
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct ParamsProver(midnight_transient_crypto::proofs::ParamsProver);

#[wasm_bindgen]
impl ParamsProver {
    pub fn generate(rng: &mut Rng, k: u8) -> Self {
        let pp = midnight_transient_crypto::proofs::ParamsProver::gen(&mut rng.0, k);

        Self(pp)
    }

    pub fn read(bytes: Vec<u8>) -> Result<Self, JsError> {
        Ok(Self(
            midnight_transient_crypto::proofs::ParamsProver::read(Cursor::new(bytes))
                .map_err(|e| JsError::new(e.to_string().as_str()))?,
        ))
    }

    pub fn downsize(&mut self, k: u8) {
        // TODO: not super optimal to clone this, as it is a big structure.
        self.0 = self.0.clone().downsize(k);
    }

    // this moves the object, but has better performance.
    pub fn downsize_moved(self, k: u8) -> Self {
        Self(self.0.downsize(k))
    }
}

#[wasm_bindgen]
pub struct Rng(StdRng);

#[wasm_bindgen]
impl Rng {
    pub fn new() -> Self {
        Rng(StdRng::from_rng(rand::thread_rng()).unwrap())
    }

    pub fn random_fr(&mut self) -> FrValue {
        FrValue(self.0.gen())
    }

    pub fn random_32_bytes(&mut self) -> Uint8Array {
        let res: [u8; 32] = self.0.gen();
        Uint8Array::from(&res[..])
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Copy)]
pub struct FrValue(Fr);

#[wasm_bindgen]
impl FrValue {
    pub fn to_aligned_value(&self) -> AlignedValue {
        AlignedValue(self.0.into())
    }

    pub fn from_u64(n: u64) -> FrValue {
        FrValue(Fr::from(n))
    }

    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        format!("{}", self.0)
    }
}

#[wasm_bindgen]
pub struct Ops(Vec<IrSource>);

#[wasm_bindgen]
impl Ops {
    pub fn empty() -> Self {
        Ops(vec![])
    }

    pub fn add(&mut self, ir: &IrSource) {
        self.0.push(ir.clone());
    }
}

#[wasm_bindgen]
pub struct Context {
    current_state: StateValue,
    contract_address: Option<Address>,
    network_id: NetworkId,
}

#[wasm_bindgen]
impl Context {
    pub fn new(state: StateValue, network_id: NetworkId) -> Self {
        Context {
            current_state: state,
            contract_address: None,
            network_id,
        }
    }

    pub fn contract_address(&self) -> Option<Address> {
        self.contract_address.clone()
    }

    pub async fn unbalanced_deploy_tx(
        &mut self,
        rng: &mut Rng,
        ops: &mut Ops,
        pp: &ParamsProver,
    ) -> Result<Uint8Array, JsError> {
        let guaranted_coins = Offer {
            inputs: vec![],
            outputs: vec![],
            transient: vec![],
            deltas: vec![],
        };

        let fallible_coins = None;

        let cc = ContractCalls::new(&mut rng.0);

        let mut contract_state = ContractState {
            data: self.current_state.clone().0,
            ..Default::default()
        };

        for op in &mut ops.0 {
            let pp = op.proof_params(pp).await;

            contract_state.operations = contract_state.operations.insert(
                midnight_onchain_runtime::state::EntryPointBuf(op.entry_point.clone().into_bytes()),
                ContractOperation::new(Some(pp.vk.clone())),
            );
        }

        let deploy = ContractDeploy::new(&mut rng.0, contract_state);

        let contract_address = deploy.address();

        self.contract_address.replace(Address(contract_address));

        let cc = cc.add_deploy(deploy);

        let unproven_tx = Transaction::new(guaranted_coins, fallible_coins, Some(cc));

        let unbalanced_tx = unproven_tx
            // TODO: is cloning here fine?
            .prove(rng.0.clone(), &pp.0, |_loc| {
                unreachable!("there is nothing to prove in a deploy transaction")
            })
            .await
            .map_err(|e| JsError::new(e.to_string().as_str()))?;

        let mut res = Vec::new();
        midnight_ledger::serialize::serialize(&unbalanced_tx, &mut res, self.network_id.0)?;
        Ok(Uint8Array::from(&res[..]))
    }

    pub fn get_state(&self) -> StateValue {
        self.current_state.clone()
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct StateValue(midnight_onchain_runtime::state::StateValue);

#[wasm_bindgen]
impl StateValue {
    pub fn deserialize(bytes: Uint8Array, network_id: NetworkId) -> Result<Self, JsError> {
        let state_value =
            midnight_ledger::serialize::deserialize(&bytes.to_vec()[..], network_id.0)
                .map_err(|e| JsError::new(e.to_string().as_ref()))?;

        Ok(Self(state_value))
    }

    pub fn from_number(n: u64) -> Self {
        StateValue(midnight_onchain_runtime::state::StateValue::Cell(Arc::new(
            Fr::from(n).into(),
        )))
    }

    pub fn cell(fr: &AlignedValue) -> Self {
        StateValue(midnight_onchain_runtime::state::StateValue::Cell(Arc::new(
            fr.0.clone(),
        )))
    }

    pub fn null() -> Self {
        StateValue(midnight_onchain_runtime::state::StateValue::Null)
    }

    pub fn debug_repr(&self) -> String {
        format!("{:?}", self.0)
    }

    pub fn index_cell(&self, index: usize) -> Option<AlignedValue> {
        match &self.0 {
            midnight_onchain_runtime::state::StateValue::Array(array) => match &array[index] {
                midnight_onchain_runtime::state::StateValue::Cell(arc) => {
                    Some(AlignedValue(arc.deref().clone()))
                }
                _ => None,
            },
            _ => todo!(),
        }
    }
}

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct AlignedValue(midnight_base_crypto::fab::AlignedValue);

#[wasm_bindgen]
impl AlignedValue {
    pub fn from_fr(fr: &FrValue) -> AlignedValue {
        AlignedValue(midnight_base_crypto::fab::AlignedValue::from(fr.0))
    }

    pub fn from_bytes_32(bytes: &[u8]) -> AlignedValue {
        AlignedValue(midnight_base_crypto::fab::AlignedValue::from(
            <[u8; 32]>::try_from(bytes).unwrap(),
        ))
    }

    pub fn value_only_field_repr(&self) -> FrValue {
        let mut frs = vec![];

        self.0.value_only_field_repr(&mut frs);

        FrValue(frs[0])
    }
}

#[wasm_bindgen]
pub struct Key(midnight_onchain_runtime::ops::Key);

#[wasm_bindgen]
impl Key {
    pub fn stack() -> Self {
        Self(midnight_onchain_runtime::ops::Key::Stack)
    }

    pub fn value(val: AlignedValue) -> Self {
        Self(midnight_onchain_runtime::ops::Key::Value(val.0))
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct IrSource {
    /// The number of inputs, the initial elements in the memory
    pub num_inputs: u32,
    /// Whether or not this IR should compile a communications commitment
    pub do_communications_commitment: bool,
    /// The sequence of instructions to run in-circuit
    instructions: Vec<Instruction>,

    dedup: HashMap<Fr, u32>,
    next_input_id: u32,
    output_indexes: Vec<u32>,
    private_inputs: Vec<u32>,

    entry_point: String,
    proof_params: Option<ProofParams>,
}

impl std::fmt::Debug for IrSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrSource")
            .field("num_inputs", &self.num_inputs)
            .field(
                "do_communications_commitment",
                &self.do_communications_commitment,
            )
            .field("instructions", &self.instructions)
            .field("dedup", &self.dedup)
            .field("next_input_id", &self.next_input_id)
            .field("output_indexes", &self.output_indexes)
            .field("private_inputs", &self.private_inputs)
            .field("entry_point", &self.entry_point)
            .finish()
    }
}

#[wasm_bindgen]
impl IrSource {
    pub async fn proof_params(&mut self, pp: &ParamsProver) -> ProofParams {
        if let Some(pp) = &self.proof_params {
            return pp.clone();
        }

        let inner = midnight_transient_crypto::proofs::IrSource {
            num_inputs: self.num_inputs,
            do_communications_commitment: self.do_communications_commitment,
            instructions: Arc::new(self.instructions.clone()),
        };

        let (pk, vk) = inner.keygen(&pp.0).await.unwrap();

        let pp = ProofParams { pk, vk };

        self.proof_params.replace(pp.clone());

        pp
    }

    pub fn num_inputs(&self) -> u32 {
        self.num_inputs
    }

    fn inner(&self) -> midnight_transient_crypto::proofs::IrSource {
        midnight_transient_crypto::proofs::IrSource {
            num_inputs: self.num_inputs,
            do_communications_commitment: self.do_communications_commitment,
            instructions: Arc::new(self.instructions.clone()),
        }
    }

    pub fn assert(&mut self, cond: Index) {
        self.instructions.push(Instruction::Assert { cond });
    }

    pub fn cond_select(&mut self, bit: Index, a: Index, b: Index) -> Index {
        self.instructions
            .push(Instruction::CondSelect { bit, a, b });

        let index = self.next_input_id;
        self.next_input_id += 1;
        index
    }

    pub fn constrain_bits(&mut self, var: Index, bits: u32) {
        self.instructions
            .push(Instruction::ConstrainBits { var, bits });
    }

    pub fn constrain_eq(&mut self, a: Index, b: Index) {
        self.instructions.push(Instruction::ConstrainEq { a, b });
    }

    pub fn constrain_to_boolean(&mut self, var: Index) {
        self.instructions
            .push(Instruction::ConstrainToBoolean { var });
    }

    pub fn copy(&mut self, var: Index) -> Index {
        self.instructions.push(Instruction::Copy { var });

        let index = self.next_input_id;
        self.next_input_id += 1;
        index
    }

    pub fn declare_pub_input(&mut self, var: Index) {
        self.instructions.push(Instruction::DeclarePubInput { var });
    }

    pub fn pi_skip(&mut self, guard: Option<Index>, count: u32) {
        self.instructions.push(Instruction::PiSkip { guard, count });
    }

    pub fn ec_add(&mut self, a_x: Index, a_y: Index, b_x: Index, b_y: Index) {
        self.instructions
            .push(Instruction::EcAdd { a_x, a_y, b_x, b_y });
    }

    pub fn ec_mul(&mut self, a_x: Index, a_y: Index, scalar: Index) {
        self.instructions
            .push(Instruction::EcMul { a_x, a_y, scalar });
    }

    pub fn ec_mul_generator(&mut self, scalar: Index) {
        self.instructions
            .push(Instruction::EcMulGenerator { scalar });
    }

    pub fn hash_to_curve(&mut self, inputs: Vec<Index>) {
        self.instructions.push(Instruction::HashToCurve { inputs });
    }

    pub fn load_imm(&mut self, imm: &FrValue) -> Index {
        self.instructions.push(Instruction::LoadImm { imm: imm.0 });

        let index = self.next_input_id;
        self.next_input_id += 1;
        index
    }

    pub fn div_mod_power_of_two(&mut self, var: Index, bits: u32) {
        self.instructions
            .push(Instruction::DivModPowerOfTwo { var, bits });
    }

    pub fn reconstitute_field(&mut self, divisor: Index, modulus: Index, bits: u32) {
        self.instructions.push(Instruction::ReconstituteField {
            divisor,
            modulus,
            bits,
        });
    }

    pub fn output(&mut self, var: Index) {
        self.instructions.push(Instruction::Output { var });
    }

    pub fn transient_hash(&mut self, inputs: Vec<Index>) -> Index {
        self.instructions
            .push(Instruction::TransientHash { inputs });

        let index = self.next_input_id;
        self.next_input_id += 1;
        index
    }

    pub fn persistent_hash(&mut self, alignment: Alignment, inputs: Vec<Index>) -> Index {
        self.instructions.push(Instruction::PersistentHash {
            alignment: alignment.0,
            inputs,
        });

        let index = self.next_input_id;
        self.next_input_id += 1;
        index
    }

    pub fn test_eq(&mut self, a: Index, b: Index) -> Index {
        self.instructions.push(Instruction::TestEq { a, b });

        let index = self.next_input_id;
        self.next_input_id += 1;
        index
    }

    pub fn add(&mut self, a: Index, b: Index) -> Index {
        self.instructions.push(Instruction::Add { a, b });

        let index = self.next_input_id;
        self.next_input_id += 1;
        index
    }

    pub fn mul(&mut self, a: Index, b: Index) -> Index {
        self.instructions.push(Instruction::Mul { a, b });

        let index = self.next_input_id;
        self.next_input_id += 1;
        index
    }

    pub fn neg(&mut self, a: Index) -> Index {
        self.instructions.push(Instruction::Neg { a });

        let index = self.next_input_id;
        self.next_input_id += 1;
        index
    }

    pub fn not(&mut self, a: Index) -> Index {
        self.instructions.push(Instruction::Not { a });

        let index = self.next_input_id;
        self.next_input_id += 1;
        index
    }

    pub fn less_than(&mut self, a: Index, b: Index, bits: u32) -> Index {
        self.instructions.push(Instruction::LessThan { a, b, bits });

        let index = self.next_input_id;
        self.next_input_id += 1;
        index
    }

    pub fn public_input(&mut self, guard: Option<Index>) -> Index {
        self.instructions.push(Instruction::PublicInput { guard });

        let index = self.next_input_id;

        self.next_input_id += 1;

        index
    }

    pub fn private_input(&mut self, guard: Option<Index>) -> Index {
        self.instructions.push(Instruction::PrivateInput { guard });

        let index = self.next_input_id;
        self.next_input_id += 1;
        index
    }

    pub fn get_or_insert_constant(&mut self, fr: &FrValue) -> Index {
        if let Some(var) = self.dedup.get(&fr.0).copied() {
            var
        } else {
            let index = self.load_imm(fr);
            self.dedup.insert(fr.0, index);
            index
        }
    }

    pub fn private_inputs(&self) -> Vec<u32> {
        self.private_inputs.clone()
    }

    pub fn output_indexes(&self) -> Vec<u32> {
        self.output_indexes.clone()
    }

    pub fn debug_repr(&self) -> String {
        format!("{:?}", self)
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct ProofParams {
    pk: ProverKey,
    vk: VerifierKey,
}

#[wasm_bindgen]
impl ProofParams {
    pub fn vk(&self) -> Uint8Array {
        let mut res = Vec::new();
        midnight_ledger::serialize::serialize(
            &self.vk,
            &mut res,
            midnight_ledger::serialize::NetworkId::Undeployed,
        )
        .unwrap();

        Uint8Array::from(&res[..])
    }
}

#[wasm_bindgen]
pub struct Alignment(midnight_base_crypto::fab::Alignment);

#[wasm_bindgen]
impl Alignment {
    pub fn single_field() -> Self {
        Self(midnight_base_crypto::fab::Alignment(vec![
            AlignmentSegment::Atom(midnight_base_crypto::fab::AlignmentAtom::Field),
        ]))
    }

    pub fn bytes(length: u32) -> Self {
        Self(midnight_base_crypto::fab::Alignment(vec![
            AlignmentSegment::Atom(midnight_base_crypto::fab::AlignmentAtom::Bytes { length }),
        ]))
    }
}

#[wasm_bindgen]
pub struct ImpactProgram {
    program: Vec<Op<ResultModeVerify>>,
    pushed_inputs: HashSet<usize>,
    entry_point: String,
}

#[wasm_bindgen]
impl ImpactProgram {
    pub fn empty(entry_point: String) -> ImpactProgram {
        ImpactProgram {
            program: vec![],
            pushed_inputs: HashSet::new(),
            entry_point,
        }
    }

    pub fn noop(&mut self, n: u32) {
        self.program.push(Op::Noop { n });
    }

    pub fn lt(&mut self) {
        self.program.push(Op::Lt);
    }

    pub fn eq(&mut self) {
        self.program.push(Op::Eq);
    }

    pub fn r#type(&mut self) {
        self.program.push(Op::Type);
    }

    pub fn size(&mut self) {
        self.program.push(Op::Size);
    }

    #[allow(clippy::new_ret_no_self)]
    pub fn new(&mut self) {
        self.program.push(Op::New);
    }

    pub fn and(&mut self) {
        self.program.push(Op::And);
    }

    pub fn or(&mut self) {
        self.program.push(Op::Or);
    }

    pub fn neg(&mut self) {
        self.program.push(Op::Neg);
    }

    pub fn log(&mut self) {
        self.program.push(Op::Log);
    }

    pub fn root(&mut self) {
        self.program.push(Op::Root);
    }

    pub fn pop(&mut self) {
        self.program.push(Op::Pop);
    }

    pub fn popeq(&mut self, cached: bool, alignment: &Alignment) {
        // we may need to now the length of the value?
        let val = midnight_base_crypto::fab::AlignedValue {
            value: midnight_base_crypto::fab::Value(vec![ValueAtom(vec![])]),
            alignment: alignment.0.clone(),
        };

        self.program.push(Op::Popeq {
            cached,
            result: val,
        });
    }

    pub fn addi(&mut self, immediate: u32) {
        self.program.push(Op::Addi { immediate });
    }

    pub fn subi(&mut self, immediate: u32) {
        self.program.push(Op::Subi { immediate });
    }

    pub fn push_constant(&mut self, storage: bool, value: StateValue) {
        self.program.push(Op::Push {
            storage,
            value: value.0,
        });
    }

    pub fn push_input(&mut self, storage: bool, alignment: &Alignment) {
        self.pushed_inputs.insert(self.program.len());

        // we may need to now the length of the value?
        let val = midnight_base_crypto::fab::AlignedValue {
            value: midnight_base_crypto::fab::Value(vec![ValueAtom(vec![])]),
            alignment: alignment.0.clone(),
        };

        self.program.push(Op::Push {
            storage,
            value: midnight_onchain_runtime::state::StateValue::Cell(Arc::new(val)),
        });
    }

    pub fn branch(&mut self, skip: u32) {
        self.program.push(Op::Branch { skip });
    }

    pub fn jmp(&mut self, skip: u32) {
        self.program.push(Op::Jmp { skip });
    }

    pub fn add(&mut self) {
        self.program.push(Op::Add);
    }

    pub fn sub(&mut self) {
        self.program.push(Op::Sub);
    }

    pub fn concat(&mut self, cached: bool, n: u32) {
        self.program.push(Op::Concat { cached, n });
    }

    pub fn member(&mut self) {
        self.program.push(Op::Member);
    }

    pub fn rem(&mut self, cached: bool) {
        self.program.push(Op::Rem { cached });
    }

    pub fn dup(&mut self, n: u8) {
        self.program.push(Op::Dup { n });
    }

    pub fn swap(&mut self, n: u8) {
        self.program.push(Op::Swap { n });
    }

    pub fn idx(&mut self, cached: bool, push_path: bool, path: Vec<Key>) {
        self.program.push(Op::Idx {
            cached,
            push_path,
            path: path.into_iter().map(|k| k.0).collect(),
        });
    }

    pub fn ins(&mut self, cached: bool, n: u8) {
        self.program.push(Op::Ins { cached, n });
    }

    pub fn ckpt(&mut self) {
        self.program.push(Op::Ckpt);
    }

    pub fn build_base_zkir(&self, num_private_inputs: usize) -> IrSource {
        let num_inputs = self.pushed_inputs.len() as u32;

        dbg!(&self.pushed_inputs);

        let (pis, mut i, dedup, output_indexes) =
            gen_transcript_constraints(self.program.clone(), self.pushed_inputs.clone());

        let mut instructions = pis;

        let mut private_inputs = vec![];

        for _ in 0..num_private_inputs {
            instructions.push(Instruction::PrivateInput { guard: None });
            private_inputs.push(i);
            i += 1;
        }

        IrSource {
            dedup,
            next_input_id: i,
            output_indexes,
            do_communications_commitment: true,
            instructions,
            num_inputs,
            private_inputs,
            entry_point: self.entry_point.clone(),
            proof_params: None,
        }
    }

    pub fn run(&self, context: &mut Context, mut inputs: Vec<StateValue>) -> QueryResults {
        let query_context = midnight_onchain_runtime::context::QueryContext::new(
            context.current_state.0.clone(),
            context
                .contract_address
                .clone()
                .expect("need to make the deploy first")
                .0,
        );

        inputs.reverse();

        let (transcript, query_results) = midnight_impact_rps_example::common::get_transcript(
            query_context,
            self.program
                .clone()
                .into_iter()
                .enumerate()
                .map(|(idx, op)| match op.translate(|_| ()) {
                    Op::Push {
                        storage,
                        // TODO: check alignment
                        value: _dummy_value,
                    } if self.pushed_inputs.contains(&idx) => {
                        let value = inputs.pop().unwrap();

                        Op::Push {
                            storage,
                            value: value.0,
                        }
                    }
                    op => op,
                })
                .collect(),
        );

        // TODO: make immutable?
        context.current_state = StateValue(query_results.context.state.clone());

        QueryResults {
            transcript: Transcript(transcript),
            results: query_results,
        }
    }

    pub fn debug_repr(&self) -> String {
        format!("{:?}", self.program)
    }

    pub fn entry_point(&self) -> String {
        self.entry_point.clone()
    }
}

#[wasm_bindgen]
pub struct QueryResults {
    transcript: Transcript,
    results: midnight_onchain_runtime::context::QueryResults<
        midnight_onchain_runtime::result_mode::ResultModeGather,
    >,
}

#[wasm_bindgen]
pub struct Transcript(Vec<Op<ResultModeVerify>>);

#[wasm_bindgen]
pub fn transient_commit(value: &FrValue, opening: &FrValue) -> FrValue {
    FrValue(midnight_transient_crypto::hash::transient_commit(
        &value.0, opening.0,
    ))
}

#[wasm_bindgen]
pub fn transient_hash(value: &FrValue) -> FrValue {
    FrValue(midnight_transient_crypto::hash::transient_hash(&[value.0]))
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct Address(midnight_ledger::coin_structure::contract::Address);

#[wasm_bindgen]
impl Address {
    pub fn debug_repr(&self) -> String {
        format!("{:?}", self.0)
    }
}

#[wasm_bindgen]
pub struct NetworkId(midnight_base_crypto::serialize::NetworkId);

#[wasm_bindgen]
impl NetworkId {
    pub fn undeployed() -> Self {
        Self(midnight_base_crypto::serialize::NetworkId::Undeployed)
    }

    pub fn testnet() -> Self {
        Self(midnight_base_crypto::serialize::NetworkId::TestNet)
    }
}

#[wasm_bindgen]
pub struct FrValues(Vec<FrValue>);

#[wasm_bindgen]
impl FrValues {
    pub fn empty() -> FrValues {
        FrValues(vec![])
    }

    pub fn push(&mut self, fr: &FrValue) {
        self.0.push(*fr);
    }
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct AlignedValues(Vec<AlignedValue>);

#[wasm_bindgen]
impl AlignedValues {
    pub fn empty() -> AlignedValues {
        AlignedValues(vec![])
    }

    pub fn push(&mut self, av: &AlignedValue) {
        self.0.push(av.clone());
    }

    pub fn from_array(arr: Vec<AlignedValue>) -> AlignedValues {
        AlignedValues(arr)
    }
}

async fn make_unbalanced_transaction_inner(
    entry_point: String,
    query_results: &QueryResults,
    inputs: &AlignedValues,
    private_transcript_outputs: &AlignedValues,
    ir: &mut IrSource,
    rng: &mut Rng,
    context: &Context,
    pp: &ParamsProver,
) -> Vec<u8> {
    let guaranted_coins = Offer {
        inputs: vec![],
        outputs: vec![],
        transient: vec![],
        deltas: vec![],
    };
    let fallible_coins = None;

    let cc = ContractCalls::new(&mut rng.0);

    let inputs_aligned = inputs.0.iter().map(|av| av.0.clone()).collect::<Vec<_>>();
    let input = midnight_base_crypto::fab::AlignedValue::concat(&inputs_aligned);

    let cc = cc.add_call(ContractCallPrototype {
        address: context.contract_address.clone().unwrap().0,
        entry_point: midnight_onchain_runtime::state::EntryPointBuf(
            entry_point.clone().into_bytes(),
        ),
        op: ContractOperation::new(None),
        guaranteed_public_transcript: Some(midnight_onchain_runtime::transcript::Transcript {
            gas: query_results.results.gas_cost,
            effects: query_results.results.context.effects.clone(),
            program: query_results.transcript.0.clone(),
        }),
        fallible_public_transcript: None,
        private_transcript_outputs: private_transcript_outputs
            .0
            .iter()
            .map(|av| av.0.clone())
            .collect(),
        input,
        output: midnight_base_crypto::fab::AlignedValue::concat([]),
        communication_commitment_rand: rng.0.gen(),
        key_location: KeyLocation(Cow::Owned(entry_point)),
    });

    let unproven_tx: Transaction<ProofPreimage> =
        Transaction::new(guaranted_coins, fallible_coins, Some(cc));

    match &unproven_tx {
        Transaction::Standard(standard_transaction) => {
            match standard_transaction
                .contract_calls
                .as_ref()
                .unwrap()
                .calls
                .first()
                .unwrap()
            {
                midnight_ledger::structure::ContractAction::Call(contract_call) => {
                    log(&format!("{:?}", contract_call.proof));
                }
                midnight_ledger::structure::ContractAction::Deploy(_) => (),
                midnight_ledger::structure::ContractAction::Maintain(_) => (),
            }
        }
        Transaction::ClaimMint(_) => (),
    }

    let proof_params = ir.proof_params(pp).await;

    let call_resolver = (
        proof_params.pk.clone(),
        proof_params.vk.clone(),
        ir.inner().clone(),
    );

    let unbalanced_tx = unproven_tx
        .prove(rng.0.clone(), &pp.0, |loc| match &*loc.0 {
            "midnight/zswap/spend" => unreachable!(),
            "midnight/zswap/output" => unreachable!(),
            "midnight/zswap/sign" => unreachable!(),
            _ => Some(call_resolver.clone()),
        })
        .await;

    let unbalanced_tx = match unbalanced_tx {
        Ok(unbalanced_tx) => unbalanced_tx,
        Err(error) => {
            panic!("{:?}", error);
        }
    };

    let mut res = Vec::new();
    midnight_ledger::serialize::serialize(&unbalanced_tx, &mut res, context.network_id.0).unwrap();
    res
}

#[wasm_bindgen]
pub async fn make_unbalanced_transaction(
    entry_point: String,
    query_results: &QueryResults,
    inputs: &AlignedValues,
    private_transcript_outputs: &AlignedValues,
    ir: &mut IrSource,
    rng: &mut Rng,
    context: &Context,
    pp: &ParamsProver,
) -> Result<Uint8Array, JsValue> {
    let res = make_unbalanced_transaction_inner(
        entry_point,
        query_results,
        inputs,
        private_transcript_outputs,
        ir,
        rng,
        context,
        pp,
    )
    .await;

    Ok(Uint8Array::from(&res[..]))
}

#[wasm_bindgen]
pub struct ContractStateBuilder {
    query_context: midnight_onchain_runtime::context::QueryContext,
    num_entries: u32,
}

#[wasm_bindgen]
impl ContractStateBuilder {
    pub fn initial_query_context(operations: Vec<String>, num_entries: u32) -> Self {
        let mut contract_state = ContractState::default();

        for operation in operations {
            contract_state.operations.insert(
                midnight_onchain_runtime::state::EntryPointBuf(operation.into_bytes()),
                ContractOperation::new(None),
            );
        }

        // Equivalent to the way the state is laid out in compact, each entry takes
        // one position in the state array
        //
        // It should be noted however that it doesn't seem like the state has to
        // actually be an array (at least I couldn't find such a restriction in
        // the ledger).
        //
        // The contract deploy payload just takes an initial object of StateValue
        // type.
        //
        // NOTE: this object has to be initialized with Null entries since arrays
        // seem to have only a fixed size.
        let state_value = midnight_ledger::storage::storage::Array::from(
            std::iter::repeat(midnight_onchain_runtime::state::StateValue::Null)
                .take((num_entries) as usize)
                .collect::<Vec<_>>(),
        );

        contract_state.data = midnight_onchain_runtime::state::StateValue::Array(state_value);

        let qc = midnight_onchain_runtime::context::QueryContext {
            state: contract_state.data,
            effects: midnight_onchain_runtime::context::Effects::default(),
            // the actual contract address is the hash of the contract deploy part of the tx
            address: midnight_impact_rps_example::dummy_contract_address(),
            com_indicies: midnight_ledger::storage::storage::Map::from_iter(std::iter::empty()),
            block: midnight_onchain_runtime::context::BlockContext::default(),
        };

        Self {
            query_context: qc,
            num_entries,
        }
    }

    pub fn insert_to_state_array(&mut self, position: u64, value: StateValue) {
        // TODO: transform into an error
        assert!(position < self.num_entries as u64);

        let program = vec![
            Op::Push {
                storage: false,
                value: midnight_onchain_runtime::state::StateValue::Cell(Arc::new(
                    Fr::from(position).into(),
                )),
            },
            Op::Push {
                storage: true,
                value: value.0,
            },
            // NOTE: Ins doesn't remove the array (or merkle tree/map) from the stack.
            Op::Ins {
                cached: false,
                n: 1,
            },
        ];

        let results = self
            .query_context
            .query::<midnight_onchain_runtime::result_mode::ResultModeGather>(
                &program,
                None,
                &DUMMY_COST_MODEL,
            )
            .unwrap();

        self.query_context = results.context;
    }

    pub fn get_state(&self) -> StateValue {
        StateValue(self.query_context.state.clone())
    }
}

#[wasm_bindgen]
pub fn dummy_contract_addr() -> Address {
    Address(dummy_contract_address())
}

// #[cfg(test)]
// mod tests {
//     use std::{io::Cursor, sync::LazyLock};

//     use crate::{
//         make_unbalanced_transaction_inner, transient_commit, transient_hash, AlignedValue,
//         AlignedValues, Alignment, Context, ContractStateBuilder, FrValue, ImpactProgram, Key,
//         ParamsProver, Rng, StateValue,
//     };
//     use midnight_impact_rps_example::{
//         COMMIT_ENTRY_POINT, INDEX_PLAYER1_COMMITMENT, INDEX_PLAYER1_PK, INDEX_PLAYER1_VICTORIES,
//         INDEX_PLAYER2_COMMITMENT, INDEX_PLAYER2_PK, INDEX_PLAYER2_VICTORIES, INDEX_TIES,
//     };
//     use midnight_transient_crypto::curve::Fr;

//     const KZG: &[u8] = include_bytes!(concat!(env!("MIDNIGHT_LEDGER_STATIC_DIR"), "/kzg"));

//     static PP: LazyLock<ParamsProver> = LazyLock::new(|| {
//         let mut pp =
//             midnight_transient_crypto::proofs::ParamsProver::read(Cursor::new(KZG)).unwrap();

//         pp.downsize(12);

//         ParamsProver(pp)
//     });

//     #[tokio::test]
//     pub async fn basic() {
//         let mut builder = ImpactProgram::empty("commit".to_string());

//         builder.dup(0);
//         builder.push_input(false, &Alignment::single_field());
//         builder.idx(false, false, vec![Key::stack()]);
//         builder.popeq(false, &Alignment::single_field());
//         builder.push_input(false, &Alignment::single_field());
//         builder.dup(1);
//         builder.dup(1);
//         builder.idx(false, false, vec![Key::stack()]);
//         builder.r#type();
//         builder.popeq(false, &Alignment::bytes(1));
//         builder.push_input(true, &Alignment::single_field());
//         builder.ins(false, 1);

//         let num_private_inputs = 3;

//         let mut ir = builder.build_base_zkir(num_private_inputs);

//         let private_inputs = ir.private_inputs.clone();
//         let public_key_hash = ir.transient_hash(vec![private_inputs[0]]);
//         ir.constrain_eq(public_key_hash, ir.output_indexes[0]);
//         ir.constrain_eq(
//             *ir.dedup.get(&Fr::from(0x01)).unwrap(),
//             ir.output_indexes[1],
//         );
//         let commitment = ir.transient_hash(vec![private_inputs[2], private_inputs[1]]);
//         ir.constrain_eq(commitment, 2);
//         let zconst = ir.load_imm(&FrValue(Fr::from(0x0)));
//         let tconst = ir.load_imm(&FrValue(Fr::from(0x2)));
//         let teq1 = ir.test_eq(private_inputs[1], *ir.dedup.get(&Fr::from(0x01)).unwrap());
//         let teq2 = ir.test_eq(private_inputs[1], zconst);
//         let teq3 = ir.test_eq(private_inputs[1], tconst);
//         let fa = ir.add(teq1, teq2);
//         let cond = ir.add(teq3, fa);
//         ir.assert(cond);

//         // let query_context = init_state();

//         let mut csb = ContractStateBuilder::initial_query_context(vec!["commit".to_string()], 7);

//         csb.insert_to_state_array(
//             INDEX_PLAYER1_VICTORIES,
//             StateValue::cell(&FrValue::from_u64(0u64).to_aligned_value()),
//         );
//         csb.insert_to_state_array(
//             INDEX_PLAYER2_VICTORIES,
//             StateValue::cell(&FrValue::from_u64(0u64).to_aligned_value()),
//         );
//         csb.insert_to_state_array(
//             INDEX_TIES,
//             StateValue::cell(&FrValue::from_u64(0u64).to_aligned_value()),
//         );

//         let player1_pk = {
//             let address_repr = AlignedValue::from_bytes_32(&PLAYER1_SK).value_only_field_repr();
//             transient_hash(&address_repr)
//         };

//         let player2_pk = {
//             let address_repr = AlignedValue::from_bytes_32(&PLAYER2_SK).value_only_field_repr();
//             transient_hash(&address_repr)
//         };

//         csb.insert_to_state_array(
//             INDEX_PLAYER1_PK,
//             StateValue::cell(&player1_pk.to_aligned_value()),
//         );
//         csb.insert_to_state_array(
//             INDEX_PLAYER2_PK,
//             StateValue::cell(&player2_pk.to_aligned_value()),
//         );
//         csb.insert_to_state_array(INDEX_PLAYER1_COMMITMENT, StateValue::null());
//         csb.insert_to_state_array(INDEX_PLAYER2_COMMITMENT, StateValue::null());

//         let mut context = Context::new(
//             StateValue(csb.query_context.state),
//             crate::NetworkId::undeployed(),
//         );
//         // let mut context = Context::new(StateValue(query_context.context.state));

//         let mut rng = Rng::new();
//         let opening1 = rng.random_fr();

//         // scissors
//         let value1 = FrValue(midnight_transient_crypto::curve::Fr::from(1));

//         let commitment = transient_commit(&value1, &opening1);

//         let public_inputs = vec![
//             StateValue::from_number(3),
//             StateValue::from_number(5),
//             StateValue::cell(&commitment.to_aligned_value()),
//         ];

//         let query_results = builder.run(&mut context, public_inputs);

//         dbg!(&query_results.transcript.0);

//         let mut private_transcript_outputs: Vec<AlignedValue> = vec![];

//         {
//             let player1_sk = AlignedValue::from_bytes_32(&PLAYER1_SK);
//             private_transcript_outputs.push(player1_sk.value_only_field_repr().to_aligned_value());
//             private_transcript_outputs.push(value1.to_aligned_value());
//             private_transcript_outputs.push(opening1.to_aligned_value());
//         }

//         let mut inputs = vec![];

//         {
//             inputs.push(
//                 FrValue(Fr::from(midnight_impact_rps_example::INDEX_PLAYER1_PK)).to_aligned_value(),
//             );
//             inputs.push(
//                 FrValue(Fr::from(
//                     midnight_impact_rps_example::INDEX_PLAYER1_PK
//                         + midnight_impact_rps_example::INDEX_PLAYER1_COMMITMENT
//                         - midnight_impact_rps_example::INDEX_PLAYER1_PK,
//                 ))
//                 .to_aligned_value(),
//             );
//             inputs.push(commitment.to_aligned_value());
//         }

//         dbg!(&private_transcript_outputs);
//         dbg!(&inputs);

//         let tx = make_unbalanced_transaction_inner(
//             COMMIT_ENTRY_POINT.to_string(),
//             &query_results,
//             &AlignedValues(inputs),
//             &AlignedValues(private_transcript_outputs),
//             &mut ir,
//             &mut rng,
//             &context,
//             pp,
//         )
//         .await;

//         dbg!(&tx);
//     }

//     // the secrets for authentication
//     // this means the players are fixed for this particular example.
//     pub const PLAYER1_SK: [u8; 32] = [2u8; 32];
//     pub const PLAYER2_SK: [u8; 32] = [3u8; 32];
// }
