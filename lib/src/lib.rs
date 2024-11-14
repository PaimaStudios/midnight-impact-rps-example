pub mod common;

use common::{gen_transcript_constraints, get_transcript};
use midnight_base_crypto::{
    curve::Fr,
    fab::AlignedValue,
    hash::persistent_hash,
    proofs::{ir::Instruction, IrSource},
    repr::FieldRepr,
};
use midnight_onchain_runtime::{
    coin_structure::contract::Address,
    context::{BlockContext, Effects, QueryContext, QueryResults},
    cost_model::DUMMY_COST_MODEL,
    ops::{Key, Op},
    result_mode::{ResultModeGather, ResultModeVerify},
    state::{
        self, ContractOperation, ContractState,
        StateValue::{self},
    },
    storage::storage::{Array, Map},
};
use std::{collections::HashSet, sync::Arc};

/*
This file implements an example of how to write Impact code by hand, and how to
build the associated circuits and proofs.

The code that follows is an implementation of rock papers scissors for 2 fixed
players. The game works in two stages. In compact this would be equivalent to
having two exported circuits.

The first contract call/circuit allows any of the two players to commit to a
value, by setting it on the corresponding slot in the state array. The zk proof
for this call guarantees that the commited value is one of:

- 0 (rocks)
- 1 (papers)
- 2 (scissors)

And also that the user knows the private key for that player.

The second operation is to open the commitments, and to increase the counter
which keeps track of wins by each player (or ties). Both are opened at once,
mostly to avoid having an extra stage and simplify the code. This also means
there is technically nothing private for this part, and it could be even
submitted by a third party (but needs to know the openings of the commitments,
of course).

The rules of rock papers scissors is only encoded in the circuit.
*/

pub const INDEX_PLAYER1_VICTORIES: u64 = 0;
pub const INDEX_PLAYER2_VICTORIES: u64 = 1;
pub const INDEX_TIES: u64 = 2;

// the public keys are in the state, initialized at the beginning.
pub const INDEX_PLAYER1_PK: u64 = 3;
pub const INDEX_PLAYER2_PK: u64 = 4;

pub const INDEX_PLAYER1_COMMITMENT: u64 = 5;
pub const INDEX_PLAYER2_COMMITMENT: u64 = 6;

// not needed for local evaluation
pub fn dummy_contract_address() -> Address {
    Address(persistent_hash(&[1, 2, 3]))
}

pub fn dummy_fee_payer_address() -> Address {
    Address(persistent_hash(&[1, 2, 3, 4]))
}

pub fn initial_query_context() -> QueryContext {
    let mut contract_state = ContractState::default();

    // not used for anything in this example, but would need to be set to build a tx
    // technically we would need two of these, one for each circuit
    contract_state.operations.insert(
        state::EntryPointBuf("circuit1".to_string().into_bytes()),
        ContractOperation::new(None),
    );

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
    let state_value = Array::from(
        std::iter::repeat(StateValue::Null)
            .take((INDEX_PLAYER2_COMMITMENT + 1) as usize)
            .collect::<Vec<_>>(),
    );

    contract_state.data = StateValue::Array(state_value);

    QueryContext {
        state: contract_state.data,
        effects: Effects::default(),
        // the actual contract address is the hash of the contract deploy part of the tx
        address: dummy_contract_address(),
        com_indicies: Map::from_iter(std::iter::empty()),
        block: BlockContext::default(),
    }
}

pub fn initial_state(
    pk1: Fr,
    pk2: Fr,
) -> midnight_onchain_runtime::context::QueryResults<ResultModeGather> {
    let query_context = initial_query_context();

    // let player1 = {
    //     let mut address_repr = vec![];
    //     AlignedValue::from(PLAYER1_SK).value_only_field_repr(&mut address_repr);
    //     AlignedValue::from(transient_hash(&address_repr))
    // };

    let player1 = AlignedValue::from(pk1);
    let player2 = AlignedValue::from(pk2);

    // let player2 = {
    //     let mut address_repr = vec![];
    //     AlignedValue::from(PLAYER2_SK).value_only_field_repr(&mut address_repr);
    //     AlignedValue::from(transient_hash(&address_repr))
    // };

    let victories_player1: AlignedValue = Fr::from(0u64).into();
    let victories_player2: AlignedValue = Fr::from(0u64).into();
    let ties: AlignedValue = Fr::from(0u64).into();

    let insert_to_state_array = |position: u64, value: StateValue| -> Vec<Op<ResultModeGather>> {
        vec![
            Op::Push {
                storage: false,
                value: StateValue::Cell(Arc::new(Fr::from(position).into())),
            },
            Op::Push {
                storage: true,
                value,
            },
            // NOTE: Ins doesn't remove the array (or merkle tree/map) from the stack.
            Op::Ins {
                cached: false,
                n: 1,
            },
        ]
    };
    let state_initialization_program = [
        insert_to_state_array(
            INDEX_PLAYER1_VICTORIES,
            StateValue::Cell(Arc::new(victories_player1.clone())),
        )
        .as_slice(),
        insert_to_state_array(
            INDEX_PLAYER2_VICTORIES,
            StateValue::Cell(Arc::new(victories_player2.clone())),
        )
        .as_slice(),
        insert_to_state_array(INDEX_TIES, StateValue::Cell(Arc::new(ties.clone()))).as_slice(),
        insert_to_state_array(
            INDEX_PLAYER1_PK,
            StateValue::Cell(Arc::new(player1.clone())),
        )
        .as_slice(),
        insert_to_state_array(
            INDEX_PLAYER2_PK,
            StateValue::Cell(Arc::new(player2.clone())),
        )
        .as_slice(),
        insert_to_state_array(INDEX_PLAYER1_COMMITMENT, StateValue::Null).as_slice(),
        insert_to_state_array(INDEX_PLAYER2_COMMITMENT, StateValue::Null).as_slice(),
    ]
    .concat();

    // this is the object that would be needed for the deploy tx.
    // it doesn't seem to be necessary to run the computation, but it's simpler.
    query_context
        .query::<ResultModeGather>(&state_initialization_program, None, &DUMMY_COST_MODEL)
        .unwrap()
}

// inputs are optional to allow generating the vk with dummy values (since the
// vk shouldn't depend on those, otherwise you could only make a single contract
// call)
fn commit_to_value_program(
    pk_index: Option<u64>,
    commitment: Option<AlignedValue>,
) -> Vec<Op<ResultModeGather>> {
    [
        // the array with the state is originally at the top of the stack
        // since idx will pop it, we need to create a copy first
        Op::Dup { n: 0 },
        // the index for idx
        // we could just pass the value directly, but this simplifies the
        // encoding of the inputs in the circuit since this way the next opcode
        // is just a constant.
        Op::Push {
            storage: false,
            value: pk_index
                .map(|pk_index| StateValue::Cell(Arc::new(Fr::from(pk_index).into())))
                .unwrap_or(StateValue::Cell(Arc::new(Fr::from(0).into()))),
        },
        // read the value at pk_index from the array, this should be one of:
        //   - INDEX_PLAYER1_PK;
        //   - INDEX_PLAYER2_PK;
        // we don't need to validate this however since we are already going to
        // constraint this value to be a hash of the private key.
        Op::Idx {
            cached: false,
            push_path: false,
            path: vec![Key::Stack],
        },
        // this puts the public key in the transcript as an output so that we
        // can prove that we know the private key.
        Op::Popeq {
            cached: false,
            result: (),
        },
        // this puts the index of the commitment for this player on the top of the stack
        Op::Push {
            storage: false,
            value: pk_index
                .map(|pk_index| {
                    StateValue::Cell(Arc::new(
                        Fr::from(pk_index + INDEX_PLAYER1_COMMITMENT - INDEX_PLAYER1_PK).into(),
                    ))
                })
                .unwrap_or(StateValue::Cell(Arc::new(Fr::from(0).into()))),
        },
        // this will put the state array at the top of the stack
        Op::Dup { n: 1 },
        // this puts the previous index at the top of the stack, we do this
        // because we are going to use it twice.
        Op::Dup { n: 1 },
        Op::Idx {
            cached: false,
            push_path: false,
            path: vec![Key::Stack],
        },
        // we want to ensure that this is null, so that players can't commit twice for the same round.
        // null is its own type, so we can put that constraint in the circuit.
        Op::Type {},
        Op::Popeq {
            cached: false,
            result: (),
        },
        Op::Push {
            storage: true,
            value: commitment
                .map(|commitment| StateValue::Cell(Arc::new(commitment)))
                .unwrap_or(StateValue::Cell(Arc::new(Fr::from(0).into()))),
        },
        // ins(1) pops:
        //    1. the value to insert
        //    2. the index into the container
        Op::Ins {
            cached: false,
            n: 1,
        },
    ]
    .to_vec()
}

// inputs are optional to allow generating the vk with dummy values (since the
// vk shouldn't depend on those, otherwise you could only make a single contract
// call)
fn open_commitments_program(winner: Option<Fr>) -> Vec<Op<ResultModeGather>> {
    [
        // first we get both commitments in the transcript so that we can verify
        // the openings in the proof.
        // we don't really need to get the actual openings into the program,
        // since we can just prove in zero knowledge that we are using the commited value.
        Op::Dup { n: 0 },
        Op::Idx {
            cached: false,
            push_path: false,
            path: vec![Key::Value(AlignedValue::from(INDEX_PLAYER1_COMMITMENT))],
        },
        Op::Popeq {
            cached: false,
            result: (),
        },
        Op::Dup { n: 0 },
        Op::Idx {
            cached: false,
            push_path: false,
            path: vec![Key::Value(AlignedValue::from(INDEX_PLAYER2_COMMITMENT))],
        },
        Op::Popeq {
            cached: false,
            result: (),
        },
        // we set the commitments to null, so that the next round can be played.
        Op::Push {
            storage: false,
            value: StateValue::Cell(Arc::new(AlignedValue::from(INDEX_PLAYER1_COMMITMENT))),
        },
        Op::Push {
            storage: true,
            value: StateValue::Null,
        },
        // ins(1) pops:
        //    1. the value to insert
        //    2. the index into the container
        Op::Ins {
            cached: false,
            n: 1,
        },
        Op::Push {
            storage: false,
            value: StateValue::Cell(Arc::new(AlignedValue::from(INDEX_PLAYER2_COMMITMENT))),
        },
        Op::Push {
            storage: true,
            value: StateValue::Null,
        },
        // ins(1) pops:
        //    1. the value to insert
        //    2. the index into the container
        Op::Ins {
            cached: false,
            n: 1,
        },
        // we increment the value at the index: winner (INDEX_PLAYER1_VICTORIES | INDEX_PLAYER2_VICTORIES | INDEX_TIES).
        Op::Push {
            storage: false,
            value: StateValue::Cell(Arc::new(AlignedValue::from(winner.unwrap_or(Fr::from(0))))),
        },
        Op::Dup { n: 1 }, // puts the state at the top of the stack
        Op::Dup { n: 1 }, // duplicates the index (since we need it twice, once for getting the value and then one to update).
        Op::Idx {
            cached: false,
            push_path: false,
            // this means the index is the winner variable (which is the input).
            path: vec![Key::Stack],
        },
        // increment the wins (or tie counter) by 1.
        Op::Addi { immediate: 1 },
        Op::Ins {
            cached: false,
            n: 1,
        },
    ]
    .to_vec()
}

fn build_ir_for_add_commitment(
    num_private_inputs: u32,
    pushed_inputs: HashSet<usize>,
    program: Vec<Op<ResultModeVerify>>,
) -> IrSource {
    let mut public_transcript_inputs = vec![];

    for op in &program {
        op.field_repr(&mut public_transcript_inputs);
    }

    let num_inputs = pushed_inputs.len() as u32;

    let (pis, mut i, dedup, output_indexes) = gen_transcript_constraints(program, pushed_inputs);

    let mut instructions = pis;

    for _ in 0..num_private_inputs {
        instructions.push(Instruction::PrivateInput { guard: None });
        i += 1;
    }

    IrSource {
        num_inputs,
        do_communications_commitment: false,
        instructions: Arc::new(
            instructions
                .into_iter()
                .chain(vec![
                    // i - 1 is the index of the last private input (the random part of the commitment)
                    // i - 2 is the commited value
                    // i - 3 is the public key
                    //
                    // First we check authentication
                    Instruction::TransientHash {
                        inputs: vec![i - 3],
                    }, // i
                    Instruction::ConstrainEq {
                        // this is the result of the hash
                        a: i,
                        // this is the result of popeq, which is the 'public key' (the hash of the secret)
                        b: output_indexes[0],
                    },
                    // check that the current commitment is Null
                    Instruction::ConstrainEq {
                        // this is the type of the commitment
                        a: output_indexes[1],
                        // 0x1 is Null, since the constant is already in the
                        // circuit, we just get the position of that to compare
                        // it to.
                        b: *dedup.get(&Fr::from(0x01)).unwrap(),
                    },
                    // here we check that the commitment is actually a commitment to one of:
                    //  - 0 (rocks)
                    //  - 1 (paper)
                    //  - 2 (scissors)
                    // first we check that the private inputs (the opening) are actually a decommitment.
                    Instruction::TransientHash {
                        // the random part goes before
                        inputs: vec![i - 1, i - 2],
                    },
                    Instruction::ConstrainEq {
                        // this is the result of the second hash
                        a: i + 1,
                        // the third value in `inputs` (the commitment)
                        b: 2,
                    },
                    // we prove that it's one of the allowed values
                    // NOTE: there may be a shorter way of doing this
                    Instruction::LoadImm { imm: Fr::from(0x0) }, // i + 2
                    Instruction::LoadImm { imm: Fr::from(0x2) }, // i + 3
                    Instruction::TestEq {
                        a: i - 2,
                        b: *dedup.get(&Fr::from(0x01)).unwrap(),
                    }, // i + 4
                    Instruction::TestEq { a: i - 2, b: i + 2 },  // i + 5
                    Instruction::TestEq { a: i - 2, b: i + 3 },  // i + 6
                    // use ADD to compute the OR, since there is no OR instruction
                    Instruction::Add { a: i + 4, b: i + 5 }, // i + 7
                    Instruction::Add { a: i + 6, b: i + 7 }, // i + 8
                    Instruction::Assert { cond: i + 8 },
                ])
                .collect(),
        ),
    }
}

fn build_ir_for_open_commitments(
    num_private_inputs: u32,
    pushed_inputs: HashSet<usize>,
    program: Vec<Op<ResultModeVerify>>,
) -> IrSource {
    let mut public_transcript_inputs = vec![];

    for op in &program {
        op.field_repr(&mut public_transcript_inputs);
    }

    let num_inputs = pushed_inputs.len() as u32;

    let (pis, mut i, dedup, output_indexes) = gen_transcript_constraints(program, pushed_inputs);

    let mut instructions = pis;

    for _ in 0..num_private_inputs {
        instructions.push(Instruction::PrivateInput { guard: None });
        i += 1;
    }

    IrSource {
        num_inputs,
        do_communications_commitment: false,
        instructions: Arc::new(
            instructions
                .into_iter()
                .chain(vec![
                    // i - 1 is the index of the last private input (the random part of the second commitment)
                    // i - 2 is the index of the last private input (the value part of the second commitment)

                    // i - 3 is the index of the last private input (the random part of the first commitment)
                    // i - 4 is the index of the last private input (the value part of the first commitment)
                    Instruction::TransientHash {
                        // the random part goes before
                        inputs: vec![i - 3, i - 4],
                    }, // i
                    Instruction::TransientHash {
                        // the random part goes before
                        inputs: vec![i - 1, i - 2],
                    }, // i + 1
                    Instruction::ConstrainEq {
                        a: i,
                        // the first popeq
                        b: output_indexes[0],
                    },
                    Instruction::ConstrainEq {
                        a: i + 1,
                        // the second popeq
                        b: output_indexes[1],
                    },
                    // game logic
                    // both values are the same (rocks - rocks, scissors - scissors, paper - paper)
                    Instruction::TestEq { a: i - 2, b: i - 4 }, // i + 2
                    Instruction::LoadImm {
                        imm: Fr::from(INDEX_TIES),
                    }, // i + 3
                    // the input (which is the index of the incremented variable) is the ties counter
                    // winner == INDEX_TIES
                    Instruction::TestEq { a: 0, b: i + 3 }, // i + 4
                    Instruction::ConstrainEq { a: i + 4, b: i + 2 },
                    //
                    // player 1 win condition
                    //
                    Instruction::LoadImm { imm: Fr::from(3) }, // i + 5
                    Instruction::LoadImm {
                        imm: Fr::from(INDEX_PLAYER1_VICTORIES),
                    }, // i + 6
                    // winner == INDEX_PLAYER1_VICTORIES
                    Instruction::TestEq { a: 0, b: i + 6 }, // i + 7
                    // -1
                    Instruction::Neg {
                        a: dedup[&Fr::from(1)],
                    }, // i + 8
                    // value1 - 1
                    Instruction::Add { a: i - 4, b: i + 8 }, // i + 9
                    // value2 == (value1 - 1)
                    Instruction::TestEq { a: i - 2, b: i + 9 }, // i + 10
                    // value1 - 1 + 3
                    Instruction::Add { a: i + 9, b: i + 5 }, // i + 11
                    // value2 == (value1 - 1 + 3)
                    Instruction::TestEq {
                        a: i - 2,
                        b: i + 11,
                    }, // i + 12
                    // this is: player1 wins
                    // value2 == (value1 - 1) || value2 == (value1 - 1 + 3)
                    Instruction::Add {
                        a: i + 10,
                        b: i + 12,
                    }, // i + 13
                    Instruction::ConstrainEq {
                        a: i + 13,
                        b: i + 7,
                    },
                    //
                    // player2 wins := player1 wins == tie
                    // this can only be true if both are false, since the conditions are disjoint
                    Instruction::TestEq {
                        a: i + 13,
                        b: i + 2,
                    }, // i + 14
                    // winner == INDEX_PLAYER2_VICTORIES
                    Instruction::TestEq {
                        a: 0,
                        b: dedup[&Fr::from(INDEX_PLAYER2_VICTORIES)],
                    }, // i + 15
                    Instruction::ConstrainEq {
                        a: i + 14,
                        b: i + 15,
                    },
                ])
                .collect(),
        ),
    }
}

// pub fn build_ir_for_open_commitments_rust(
//     num_private_inputs: u32,
//     pushed_inputs: HashSet<usize>,
//     program: Vec<Op<ResultModeVerify>>,
// ) -> IrSource {
//     let mut public_transcript_inputs = vec![];

//     for op in &program {
//         op.field_repr(&mut public_transcript_inputs);
//     }

//     let num_inputs = pushed_inputs.len() as u32;

//     let (pis, mut i, _dedup, output_indexes) = gen_transcript_constraints(program, pushed_inputs);

//     let mut instructions = pis;

//     for _ in 0..num_private_inputs {
//         instructions.push(Instruction::PrivateInput { guard: None });
//         i += 1;
//     }

//     IrSource {
//         num_inputs,
//         do_communications_commitment: false,
//         instructions: Arc::new(
//             instructions
//                 .into_iter()
//                 .chain(vec![
//                     // i - 1 is the index of the last private input (the random part of the second commitment)
//                     // i - 2 is the index of the last private input (the value part of the second commitment)

//                     // i - 3 is the index of the last private input (the random part of the first commitment)
//                     // i - 4 is the index of the last private input (the value part of the first commitment)
//                     Instruction::TransientHash {
//                         // the random part goes before
//                         inputs: vec![i - 3, i - 4],
//                     }, // i
//                     Instruction::TransientHash {
//                         // the random part goes before
//                         inputs: vec![i - 1, i - 2],
//                     }, // i + 1
//                     Instruction::ConstrainEq {
//                         a: i,
//                         // the first popeq
//                         b: output_indexes[0],
//                     },
//                     Instruction::ConstrainEq {
//                         a: i + 1,
//                         // the second popeq
//                         b: output_indexes[1],
//                     },
//                     // This checks the game logic in Rust.
//                     // The final goal would be probably to replace the IR
//                     // completely, but this works as an intermediate step.
//                     Instruction::RocksPaperScissors {
//                         a: i - 4,
//                         b: i - 2,
//                         // public input.
//                         winner: 0,
//                     },
//                 ])
//                 .collect(),
//         ),
//     }
// }

// encodes the inputs and private params
pub fn add_commitment_encode_params(
    sk: [u8; 32],
    program: Vec<Op<ResultModeVerify>>,
    pk_index: u64,
    commitment: AlignedValue,
    opening: (Fr, Fr),
) -> (Vec<Fr>, Vec<Fr>, Vec<Fr>, Vec<Fr>) {
    let mut inputs = vec![];

    AlignedValue::from(Fr::from(pk_index)).value_only_field_repr(&mut inputs);
    AlignedValue::from(Fr::from(
        pk_index + INDEX_PLAYER1_COMMITMENT - INDEX_PLAYER1_PK,
    ))
    .value_only_field_repr(&mut inputs);
    commitment.value_only_field_repr(&mut inputs);

    let mut public_transcript_inputs = vec![];
    let mut public_transcript_outputs = vec![];

    let mut private_transcript: Vec<Fr> = vec![];

    AlignedValue::from(sk).value_only_field_repr(&mut private_transcript);
    private_transcript.push(opening.0);
    private_transcript.push(opening.1);

    for op in &program {
        op.field_repr(&mut public_transcript_inputs);

        if let Op::Popeq { cached: _, result } = op {
            result.value_only_field_repr(&mut public_transcript_outputs);
        }
    }

    (
        inputs,
        public_transcript_inputs,
        public_transcript_outputs,
        private_transcript,
    )
}

// encodes the inputs and private params
pub fn open_commitments_encode_params(
    program: Vec<Op<ResultModeVerify>>,
    opening1: (Fr, Fr),
    opening2: (Fr, Fr),
    winner: Fr,
) -> (Vec<Fr>, Vec<Fr>, Vec<Fr>, Vec<Fr>) {
    let inputs = vec![winner];

    let mut public_transcript_inputs = vec![];
    let mut public_transcript_outputs = vec![];

    let private_transcript = vec![opening1.0, opening1.1, opening2.0, opening2.1];

    for op in &program {
        op.field_repr(&mut public_transcript_inputs);

        if let Op::Popeq { cached: _, result } = op {
            result.value_only_field_repr(&mut public_transcript_outputs);
        }
    }

    (
        inputs,
        public_transcript_inputs,
        public_transcript_outputs,
        private_transcript,
    )
}

pub fn make_add_commitments_circuit() -> IrSource {
    // NOTE: these have different alignments, so we need different dummy values
    //
    // The first one is the result of a state read (in practice it will have one
    // of the public keys), but we only need to match the alignment so that we
    // have the same constants
    //
    // The second value is a u8 so that it has the byte alignment, in the actual
    // execution it would be the result of the Type op.
    let mut dummy_reads = vec![AlignedValue::from(Fr::from(1)), AlignedValue::from(1u8)];
    dummy_reads.reverse();

    build_ir_for_add_commitment(
        3,
        vec![1, 4, 10].into_iter().collect(),
        commit_to_value_program(None, None)
            .into_iter()
            .map(|op| op.translate(|_| dummy_reads.pop().unwrap()))
            .collect(),
    )
}

pub fn make_openings_circuit() -> IrSource {
    let mut dummy_reads = vec![
        AlignedValue::from(Fr::from(1)),
        AlignedValue::from(Fr::from(1)),
    ];
    dummy_reads.reverse();

    build_ir_for_open_commitments(
        4,
        // 12 is the index of the push operation that adds the input we need to
        // know this information in order to no encode that as a constant
        vec![12].into_iter().collect(),
        open_commitments_program(None)
            .into_iter()
            .map(|op| op.translate(|_| dummy_reads.pop().unwrap()))
            .collect(),
    )
}

pub fn run_add_commitment(
    pk_index: u64,
    state: StateValue,
    commitment: AlignedValue,
) -> (Vec<Op<ResultModeVerify>>, QueryResults<ResultModeGather>) {
    let query_context = QueryContext::new(state, dummy_contract_address());

    let program = commit_to_value_program(Some(pk_index), Some(commitment));

    get_transcript(query_context, program)
}

pub fn run_open_commitments_program(
    state: StateValue,
    winner: Fr,
) -> (Vec<Op<ResultModeVerify>>, QueryResults<ResultModeGather>) {
    let query_context = QueryContext::new(state, dummy_contract_address());

    let program = open_commitments_program(Some(winner));

    get_transcript(query_context, program)
}

#[cfg(test)]
mod tests {
    use common::{gen_proof_and_check, keygen, read_kzg_params, ProofParams};
    use midnight_base_crypto::{
        hash::{transient_commit, transient_hash},
        proofs::{KeyLocation, Proof, ProofPreimage, ProverKey, VerifierKey},
    };
    use midnight_ledger::{
        coin_structure::coin::NATIVE_TOKEN,
        construct::ContractCallPrototype,
        serialize::{deserialize, NetworkId},
        structure::{ContractCalls, Transaction, DUMMY_PARAMETERS},
        zswap::{Offer, Output},
    };
    use midnight_onchain_runtime::transcript::Transcript;
    use midnight_zswap::{local::Seed, AuthorizedMint};
    use rand::{rngs::OsRng, Rng as _, SeedableRng as _};
    use rand_chacha::ChaCha20Rng;
    use std::{borrow::Cow, io::Cursor};

    // the secrets for authentication
    // this means the players are fixed for this particular example.
    pub const PLAYER1_SK: [u8; 32] = [2u8; 32];
    pub const PLAYER2_SK: [u8; 32] = [3u8; 32];

    use super::*;

    fn init_state() -> QueryResults<ResultModeGather> {
        let player1 = {
            let mut address_repr = vec![];
            AlignedValue::from(PLAYER1_SK).value_only_field_repr(&mut address_repr);
            transient_hash(&address_repr)
        };

        let player2 = {
            let mut address_repr = vec![];
            AlignedValue::from(PLAYER2_SK).value_only_field_repr(&mut address_repr);
            transient_hash(&address_repr)
        };

        initial_state(player1, player2)
    }

    /// Play a single round.
    /// This means:
    ///   1. Each player commits
    ///   2. Both commits are opened
    ///
    /// This takes and return the state so that multiple rounds can be chained.
    pub async fn play_round(
        rng: &mut ChaCha20Rng,
        current_state: StateValue,
        commit_ir: (IrSource, ProofParams),
        open_ir: (IrSource, ProofParams),
        value1: Fr,
        value2: Fr,
        // could be computed from the values, but left as a variable since it's
        // useful to test the failing case.
        winner: Fr,
    ) -> (StateValue, [Proof; 3]) {
        let opening1: Fr = rng.gen();

        let commitment: AlignedValue = transient_commit(&value1, opening1).into();
        let (transcript, query_result) =
            run_add_commitment(INDEX_PLAYER1_PK, current_state, commitment.clone());

        let (inputs, public_transcript_inputs, public_transcript_outputs, private_transcript) =
            add_commitment_encode_params(
                PLAYER1_SK,
                transcript,
                INDEX_PLAYER1_PK,
                commitment,
                (value1, opening1),
            );

        let proof1 = gen_proof_and_check(
            commit_ir.0.clone(),
            inputs,
            private_transcript,
            public_transcript_inputs,
            public_transcript_outputs,
            commit_ir.1.clone(),
        )
        .await;

        let opening2: Fr = rng.gen();

        let commitment: AlignedValue = transient_commit(&value2, opening2).into();
        let (transcript, query_result) = run_add_commitment(
            INDEX_PLAYER2_PK,
            query_result.context.state,
            commitment.clone(),
        );

        let (inputs, public_transcript_inputs, public_transcript_outputs, private_transcript) =
            add_commitment_encode_params(
                PLAYER2_SK,
                transcript,
                INDEX_PLAYER2_PK,
                commitment,
                (value2, opening2),
            );

        let proof2 = gen_proof_and_check(
            commit_ir.0,
            inputs,
            private_transcript,
            public_transcript_inputs,
            public_transcript_outputs,
            commit_ir.1.clone(),
        )
        .await;

        let (transcript, query_result) =
            run_open_commitments_program(query_result.context.state, winner);

        let (inputs, public_transcript_inputs, public_transcript_outputs, private_transcript) =
            open_commitments_encode_params(
                transcript,
                (value1, opening1),
                (value2, opening2),
                winner,
            );

        let proof3 = gen_proof_and_check(
            open_ir.0,
            inputs,
            private_transcript,
            public_transcript_inputs,
            public_transcript_outputs,
            open_ir.1.clone(),
        )
        .await;

        (query_result.context.state, [proof1, proof2, proof3])
    }

    #[tokio::test]
    async fn local_execution() {
        let commit_ir = make_add_commitments_circuit();
        let commit_proof_params = keygen(&commit_ir).await;

        let open_ir = make_openings_circuit();
        let open_proof_params = keygen(&open_ir).await;

        let state = init_state();

        // use a seed just to make debugging easier (consistent state between runs).
        let mut rng = ChaCha20Rng::from_seed([41; 32]);

        // scissors
        let value1 = Fr::from(1);
        // rocks
        let value2 = Fr::from(2);
        let winner = Fr::from(INDEX_PLAYER2_VICTORIES);

        let (state, _) = play_round(
            &mut rng,
            state.context.state,
            (commit_ir.clone(), commit_proof_params.clone()),
            (open_ir.clone(), open_proof_params.clone()),
            value1,
            value2,
            winner,
        )
        .await;

        // rocks
        let value1 = Fr::from(0);
        // scissors
        let value2 = Fr::from(2);
        let winner = Fr::from(INDEX_PLAYER1_VICTORIES);

        let (state, _) = play_round(
            &mut rng,
            state,
            (commit_ir.clone(), commit_proof_params.clone()),
            (open_ir.clone(), open_proof_params.clone()),
            value1,
            value2,
            winner,
        )
        .await;

        // paper
        let value1 = Fr::from(1);
        // paper
        let value2 = Fr::from(1);
        let winner = Fr::from(INDEX_TIES);

        let (state, _) = play_round(
            &mut rng,
            state,
            (commit_ir, commit_proof_params),
            (open_ir, open_proof_params),
            value1,
            value2,
            winner,
        )
        .await;

        for (i, expected) in [
            (INDEX_PLAYER1_VICTORIES, 1),
            (INDEX_PLAYER2_VICTORIES, 1),
            (INDEX_TIES, 1),
        ] {
            match &state {
                StateValue::Array(array) => match &array[i as usize] {
                    StateValue::Cell(val) => {
                        let mut writer = vec![];
                        val.value_only_field_repr(&mut writer);
                        assert_eq!(writer[0], Fr::from(expected))
                    }
                    _ => unreachable!(),
                },
                _ => unreachable!(),
            }
        }
    }

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

    #[tokio::test(flavor = "multi_thread")]
    pub async fn test_tx_io_example() {
        let commit_ir = make_add_commitments_circuit();
        let commit_proof_params = keygen(&commit_ir).await;
        assert!(!commit_ir.do_communications_commitment);

        let spend = decode_zswap_proof_params(SPEND_PK_RAW, SPEND_VK_RAW, SPEND_IR_RAW);
        let output = decode_zswap_proof_params(OUTPUT_PK_RAW, OUTPUT_VK_RAW, OUTPUT_IR_RAW);
        let sign = decode_zswap_proof_params(SIGN_PK_RAW, SIGN_VK_RAW, SIGN_IR_RAW);

        let (sk, index) = (PLAYER1_SK, INDEX_PLAYER1_PK);

        let value_fr = Fr::from(0);
        let opening = OsRng.gen();
        let commitment: AlignedValue = transient_commit(&value_fr, opening).into();

        let state = init_state();

        let (transcript, query_result) =
            run_add_commitment(index, state.context.state, commitment.clone());

        let (inputs, _public_transcript_inputs, _public_transcript_outputs, private_transcript) =
            add_commitment_encode_params(
                sk,
                transcript.clone(),
                index,
                commitment,
                (value_fr, opening),
            );

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
            output: AlignedValue::concat(vec![]),
            communication_commitment_rand: OsRng.gen(),
            key_location: KeyLocation(Cow::Borrowed("builtin")),
        });

        let call_resolver = (
            commit_proof_params.pk.clone(),
            commit_proof_params.vk.clone(),
            commit_ir.clone(),
        );

        let fees = 66821;

        let seed = Seed::random(&mut OsRng);
        let sk = seed.derive_coin_secret_key();
        let zswap_state = midnight_zswap::local::State::from_seed(&seed);

        let unspent_output_value = 100000;

        let nonce = OsRng.gen();
        let mint_info = coin_structure::coin::Info {
            nonce,
            type_: NATIVE_TOKEN,
            value: unspent_output_value,
        };

        // with real data this should be populated from the transaction history I guess
        let zswap_state = zswap_state
            .apply_mint(&AuthorizedMint::<ProofPreimage>::new(&mut OsRng, mint_info, &sk).unwrap());

        let (_zswap_state, input) = zswap_state
            .spend(
                &mut OsRng,
                &coin_structure::coin::QualifiedInfo {
                    nonce,
                    type_: NATIVE_TOKEN,
                    value: unspent_output_value,
                    mt_index: 0,
                },
            )
            .unwrap();

        let guaranted_coins = Offer {
            inputs: vec![input],
            outputs: vec![Output::new(
                &mut OsRng,
                &coin_structure::coin::Info {
                    nonce: OsRng.gen(),
                    type_: NATIVE_TOKEN,
                    value: unspent_output_value - fees,
                },
                &sk.public_key(),
                None,
            )
            .unwrap()],
            transient: vec![],
            deltas: vec![(NATIVE_TOKEN, fees as i128)],
        };

        let fallible_coins = None;

        let balanced_tx: Transaction<ProofPreimage> =
            Transaction::new(guaranted_coins, fallible_coins, Some(cc.clone()));

        let pp = read_kzg_params();

        let start = std::time::Instant::now();

        let balanced_tx = balanced_tx
            .prove(OsRng, &pp, |loc| match &*loc.0 {
                "midnight/zswap/spend" => Some(spend.clone()),
                "midnight/zswap/output" => Some(output.clone()),
                "midnight/zswap/sign" => Some(sign.clone()),
                _ => Some(call_resolver.clone()),
            })
            .await
            .unwrap();

        dbg!(start.elapsed().as_millis());

        let final_fee = balanced_tx.fees(&DUMMY_PARAMETERS).unwrap();

        assert!(fees >= final_fee);

        let without_funds: Transaction<ProofPreimage> = Transaction::new(
            Offer {
                inputs: vec![],
                outputs: vec![],
                transient: vec![],
                deltas: vec![],
            },
            None,
            Some(cc),
        );

        let start = std::time::Instant::now();

        let _balanced_tx = without_funds
            .prove(OsRng, &pp, |loc| match &*loc.0 {
                "midnight/zswap/spend" => Some(spend.clone()),
                "midnight/zswap/output" => Some(output.clone()),
                "midnight/zswap/sign" => Some(sign.clone()),
                _ => Some(call_resolver.clone()),
            })
            .await
            .unwrap();

        dbg!(start.elapsed().as_millis());
    }
}
