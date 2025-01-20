use coin_structure::transient_crypto::{
    curve::Fr,
    proofs::{
        ir::Instruction, IrSource, KeyLocation, ParamsProver, Proof, ProofPreimage, ProverKey,
        VerifierKey,
    },
    repr::FieldRepr as _,
};
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
    fs::File,
    io::BufReader,
};

// run the program in ResultModeGather (popeq just reads values)
pub fn get_transcript(
    query_context: QueryContext,
    program: Vec<Op<ResultModeGather>>,
) -> (Vec<Op<ResultModeVerify>>, QueryResults<ResultModeGather>) {
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
    program: Vec<Op<ResultModeVerify>>,
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
    pub pp: ParamsProver,
    // pub vp: ParamsVerifier,
    pub pk: ProverKey,
    pub vk: VerifierKey,
}

pub async fn gen_proof_and_check(
    ir: IrSource,
    inputs: Vec<Fr>,
    private_transcript: Vec<Fr>,
    public_transcript_inputs: Vec<Fr>,
    public_transcript_outputs: Vec<Fr>,
    proof_params: ProofParams,
) -> Proof {
    let ProofParams { pp, pk, vk } = proof_params;

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
        .prove(&mut ChaCha20Rng::from_seed([42; 32]), &pp, |_| {
            Some((pk.clone(), vk.clone(), ir.clone()))
        })
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
    let pp = read_kzg_params();

    let pp = pp.downsize(ir.model(None).k());

    let (pk, vk) = ir.keygen(&pp).await.unwrap();

    ProofParams { pp, pk, vk }
}

pub fn read_kzg_params() -> ParamsProver {
    let pp = concat!(env!("MIDNIGHT_LEDGER_STATIC_DIR"), "/kzg");

    ParamsProver::read(BufReader::new(File::open(pp).expect(
        "kzg params not found, run: cargo run --bin make_params to generate new ones",
    )))
    .unwrap()
}
