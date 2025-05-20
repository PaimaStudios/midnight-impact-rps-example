use coin_structure::{
    storage::db::InMemoryDB,
    transient_crypto::{
        curve::Fr,
        proofs::{
            ir::Instruction, IrSource, KeyLocation, Proof, ProofPreimage, ProverKey, Resolver,
            VerifierKey,
        },
        repr::FieldRepr as _,
    },
};
use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};
use midnight_onchain_runtime::{
    context::{QueryContext, QueryResults},
    cost_model::DUMMY_COST_MODEL,
    ops::Op,
    result_mode::{GatherEvent, ResultModeGather, ResultModeVerify},
};
use rand::SeedableRng as _;
use rand_chacha::ChaCha20Rng;
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
};

// run the program in ResultModeGather (popeq just reads values)
pub fn get_transcript(
    query_context: QueryContext<InMemoryDB>,
    program: Vec<Op<ResultModeGather, InMemoryDB>>,
) -> (
    Vec<Op<ResultModeVerify, InMemoryDB>>,
    QueryResults<ResultModeGather, InMemoryDB>,
) {
    let new_context = query_context
        .query::<ResultModeGather>(&program, None, &DUMMY_COST_MODEL)
        .unwrap();

    let mut reads = vec![];
    for event in new_context.events.iter().rev() {
        if let GatherEvent::Read(event) = event {
            reads.push(event);
        }
    }

    (
        program
            .into_iter()
            .map(|op| op.translate(|_| reads.pop().unwrap().clone()))
            .collect(),
        new_context,
    )
}

// this part constraints the transcript, so it's independent of any of the business logic.
// this means this function should work regardless of the impact code.
pub fn gen_transcript_constraints(
    program: Vec<Op<ResultModeVerify, InMemoryDB>>,
    pushed_inputs: HashSet<usize>,
) -> (Vec<Instruction>, u32, HashMap<Fr, u32>, Vec<u32>) {
    let mut pis = vec![];
    let mut i = pushed_inputs.len() as u32;

    let mut consumed_inputs = 0;

    // avoid adding constants twice (opcodes and such)
    let mut dedup: HashMap<Fr, u32> = HashMap::new();

    let mut output_indexes: Vec<u32> = vec![];

    for (op_i, op) in program.iter().enumerate() {
        let mut repr = vec![];
        op.field_repr(&mut repr);

        // pop and push can have have non constant values, so we need to make
        // sure to mark those as inputs when needed otherwise the proof would
        // only be possible for a fixed set of inputs/outputs.
        let upto = match op {
            Op::Push { .. } => {
                if pushed_inputs.contains(&op_i) {
                    4
                } else {
                    repr.len()
                }
            }
            Op::Popeq { .. } => 3,
            _ => repr.len(),
        };

        for fr in &repr[0..upto] {
            if let Some(var) = dedup.get(fr).copied() {
                pis.push(Instruction::DeclarePubInput { var });
            } else {
                pis.extend_from_slice(&[
                    Instruction::LoadImm { imm: *fr },
                    Instruction::DeclarePubInput { var: i },
                ]);

                dedup.insert(*fr, i);

                i += 1;
            }
        }
        match op {
            Op::Push { .. } => {
                for _ in &repr[upto..] {
                    pis.extend_from_slice(&[Instruction::DeclarePubInput {
                        var: consumed_inputs,
                    }]);
                    consumed_inputs += 1;
                }
            }
            Op::Popeq { .. } => {
                for _ in &repr[upto..] {
                    pis.extend_from_slice(&[
                        Instruction::PublicInput { guard: None },
                        Instruction::DeclarePubInput { var: i },
                    ]);

                    output_indexes.push(i);

                    i += 1;
                }
            }
            _ => {}
        };

        pis.push(Instruction::PiSkip {
            guard: None,
            count: op.field_size().try_into().unwrap(),
        });
    }

    (pis, i, dedup, output_indexes)
}

#[derive(Clone)]
pub struct ProofParams {
    // pub pp: ParamsProver,
    // pub vp: ParamsVerifier,
    pub pk: ProverKey,
    pub vk: VerifierKey,
}

#[derive(Clone)]
pub struct SimpleResolver {
    pub pk: ProverKey,
    pub vk: VerifierKey,
    pub ir: IrSource,
}

impl Resolver for SimpleResolver {
    async fn resolve_key(
        &self,
        _key: KeyLocation,
    ) -> std::io::Result<Option<(ProverKey, VerifierKey, IrSource)>> {
        Ok(Some((self.pk.clone(), self.vk.clone(), self.ir.clone())))
    }
}

pub async fn gen_proof_and_check(
    ir: IrSource,
    inputs: Vec<Fr>,
    private_transcript: Vec<Fr>,
    public_transcript_inputs: Vec<Fr>,
    public_transcript_outputs: Vec<Fr>,
    proof_params: ProofParams,
) -> Proof {
    let ProofParams { pk, vk } = proof_params;

    // This is a hash of:
    //  - The contract address
    //  - The contract entry point
    //  - Both transcript parts's declared gas costs, and effects
    //  - The count of instructions in the guaranteed transcript
    //  - The parent ContractCalls's `binding_commitment.commitment`.
    // But we don't really care about this to simulate execution/proving
    let binding_input = 42.into();
    let preimage = ProofPreimage {
        binding_input,
        communications_commitment: None,
        inputs,
        private_transcript,
        public_transcript_inputs: public_transcript_inputs.clone(),
        public_transcript_outputs: public_transcript_outputs.clone(),
        key_location: KeyLocation(Cow::Borrowed("builtin")),
    };

    let (proof, _) = preimage
        .prove(
            &mut ChaCha20Rng::from_seed([42; 32]),
            // &SimpleParamsProverProvider { pp },
            &MidnightDataProvider::new(
                FetchMode::OnDemand,
                OutputMode::Log,
                EXPECTED_DATA.to_vec(),
            ),
            &SimpleResolver { pk, vk, ir },
        )
        .await
        .unwrap();

    // // I think this is already done inside of prove anyway, but whatever
    // vk.verify(
    //     &vp,
    //     &proof,
    //     [binding_input].into_iter().chain(public_transcript_inputs),
    // )
    // .unwrap();

    proof
}

pub async fn keygen(ir: &IrSource) -> ProofParams {
    // let pp = read_kzg_params();

    // let pp = pp.downsize();
    //
    // let pp = todo!();

    let data_provider =
        MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, EXPECTED_DATA.to_vec());

    // let pp = data_provider.get_params(ir.model(None).k()).await.unwrap();

    let (pk, vk) = ir.keygen(&data_provider).await.unwrap();

    ProofParams { pk, vk }
}

// pub fn read_kzg_params() -> ParamsProver {
//     let pp = concat!(env!("MIDNIGHT_LEDGER_STATIC_DIR"), "/kzg");

//     ParamsProver::read(BufReader::new(File::open(pp).expect(
//         "kzg params not found, run: cargo run --bin make_params to generate new ones",
//     )))
//     .unwrap()
// }

pub const EXPECTED_DATA: &[(&str, [u8; 32], &str)] = &[
    (
        "bls_filecoin_2p10",
        hexhash(b"d1a3403c1f8669e82ed28d9391e13011aea76801b28fe14b42bf76d141b4efa2"),
        "public parameters for k=10",
    ),
    (
        "bls_filecoin_2p11",
        hexhash(b"b5047f05800dbd84fd1ea43b96a8850e128b7a595ed132cd72588cc2cb146b29"),
        "public parameters for k=11",
    ),
    (
        "bls_filecoin_2p12",
        hexhash(b"b32791775af5fff1ae5ead682c3d8832917ebb0652b43cf810a1e3956eb27a71"),
        "public parameters for k=12",
    ),
    (
        "bls_filecoin_2p13",
        hexhash(b"b9af43892c3cb90321fa00a36e5e59051f356df145d7f58368531f28d212937b"),
        "public parameters for k=13",
    ),
    (
        "bls_filecoin_2p14",
        hexhash(b"4923e5a7fbb715d81cdb5c03b9c0e211768d35ccc52d82f49c3d93bcf8d36a56"),
        "public parameters for k=14",
    ),
    (
        "bls_filecoin_2p15",
        hexhash(b"162fac0cf70b9b02e02195ec37013c04997b39dc1831a97d5a83f47a9ce39c97"),
        "public parameters for k=15",
    ),
    (
        "bls_filecoin_2p16",
        hexhash(b"4ebc0d077fe6645e9b7ca6563217be2176f00dfe39cc97b3f60ecbad3573f973"),
        "public parameters for k=16",
    ),
    (
        "bls_filecoin_2p17",
        hexhash(b"7228c4519e96ece2c54bf2f537d9f26b0ed042819733726623fab5e17eac4360"),
        "public parameters for k=17",
    ),
    (
        "bls_filecoin_2p18",
        hexhash(b"4f023825c14cc0a88070c70588a932519186d646094eddbff93c87a46060fd28"),
        "public parameters for k=18",
    ),
    (
        "bls_filecoin_2p19",
        hexhash(b"0574a536c128142e89c0f28198d048145e2bb2bf645c8b81c8697cba445a1fb1"),
        "public parameters for k=19",
    ),
    (
        "bls_filecoin_2p20",
        hexhash(b"75a1774fdf0848f4ff82790202e5c1401598bafea27321b77180d96c56e62228"),
        "public parameters for k=20",
    ),
    (
        "bls_filecoin_2p21",
        hexhash(b"e05fcbe4f7692800431cfc32e972be629c641fca891017be09a8384d0b5f8d3c"),
        "public parameters for k=21",
    ),
    (
        "bls_filecoin_2p22",
        hexhash(b"277d9c8140c02a1d4472d5da65a823fc883bc4596e69734fb16ca463d193186b"),
        "public parameters for k=22",
    ),
    (
        "bls_filecoin_2p23",
        hexhash(b"7b8dc4b2e809ef24ed459cabaf9286774cf63f2e6e2086f0d9fb014814bdfc97"),
        "public parameters for k=23",
    ),
    (
        "bls_filecoin_2p24",
        hexhash(b"e6b02dccf381a5fc7a79ba4d87612015eba904241f81521e2dea39a60ab6b812"),
        "public parameters for k=24",
    ),
];

/// Parse a 256-bit hex hash at const time.
pub const fn hexhash(hex: &[u8]) -> [u8; 32] {
    match const_hex::const_decode_to_array(hex) {
        Ok(hash) => hash,
        Err(_) => panic!("hash should be correct format"),
    }
}
