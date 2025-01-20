import init, { AlignedValue, AlignedValues, Alignment, Context, ContractStateBuilder, FrValue, FrValues, ImpactProgram, IrSource, Key, NetworkId, Ops, Rng, StateValue, initThreadPool, make_unbalanced_transaction, transient_commit, transient_hash } from './pkg/wasm.js';

const INDEX_PLAYER1_VICTORIES = 0n;
const INDEX_PLAYER2_VICTORIES = 1n;
const INDEX_TIES = 2n;

const INDEX_PLAYER1_PK = 3n;
const INDEX_PLAYER2_PK = 4n;

const INDEX_PLAYER1_COMMITMENT = 5n;
const INDEX_PLAYER2_COMMITMENT = 6n;
let rng: Rng;
let sk1: Uint8Array;
let sk2: Uint8Array;
let opening1_rand: FrValue | null;
let opening2_rand: FrValue | null;

let commitment1: boolean | null = null;
let commitment2: boolean | null = null;

let context: Context | undefined;

// function uint8ArrayToHex(uint8Array) {
//   return Array.from(uint8Array)
//     .map(byte => byte.toString(16).padStart(2, '0'))
//     .join('');
// }

function uint8ArrayToHex(uint8Array: Uint8Array) {
  return Array.from(uint8Array, function(byte) {
    return ('0' + (byte & 0xFF).toString(16)).slice(-2);
  }).join('');
}

async function run() {
  const statusLabel = document.getElementById("status") as HTMLLabelElement;

  const tx1 = document.getElementById("tx1") as HTMLTextAreaElement;
  const tx2 = document.getElementById("tx2") as HTMLTextAreaElement;
  const tx3 = document.getElementById("tx3") as HTMLTextAreaElement;

  tx1.value = "";
  tx2.value = "";
  tx3.value = "";

  const select1 = document.getElementById("rps-select1") as HTMLSelectElement;
  const select2 = document.getElementById("rps-select2") as HTMLSelectElement;

  const commit1Button = document.getElementById("commit1") as HTMLButtonElement;
  const commit2Button = document.getElementById("commit2") as HTMLButtonElement;

  commit1Button.disabled = true;
  commit2Button.disabled = true;

  statusLabel.innerText = "Initializing wasm module...";
  await init();

  statusLabel.innerText = "Initializing rayon threadpool...";
  await initThreadPool(navigator.hardwareConcurrency);

  statusLabel.innerText = "Ready";

  commit1Button.disabled = false;
  commit2Button.disabled = false;

  rng = Rng.new();

  sk1 = rng.random_32_bytes();
  sk2 = rng.random_32_bytes();

  console.log("sk1", uint8ArrayToHex(sk1));
  console.log("sk2", uint8ArrayToHex(sk2));

  const { commit_zkir, builder: commitProgram } = buildCommitProgram();
  const openProgramV = buildOpenProgram();

  const open_program = openProgramV.impact;
  const open_zkir = openProgramV.zkir;

  const commitPp = await commit_zkir.proof_params();
  console.log('commit verifier key', uint8ArrayToHex(commitPp.vk()));

  const openPp = await open_zkir.proof_params();
  console.log('open verifier key', uint8ArrayToHex(openPp.vk()));

  context = initializeContext();

  const ops = Ops.empty();
  ops.add(commit_zkir);
  ops.add(open_zkir);

  const deployTx = await context.unbalanced_deploy_tx(rng, ops);

  console.log('deployTx', uint8ArrayToHex(deployTx));

  const player1_sk = AlignedValue.from_bytes_32(sk1);
  const player2_sk = AlignedValue.from_bytes_32(sk2);

  setCounters();

  const openButton = document.getElementById("open") as HTMLButtonElement;

  commit1Button?.addEventListener("click", async () => {
    commit2Button.disabled = true;

    statusLabel.innerText = "Generating proof for player1";

    commit1Button.disabled = true;

    const value = BigInt(select1.value);
    opening1_rand = rng.random_fr();
    const commitment = transient_commit(FrValue.from_u64(value), opening1_rand);

    const startTime = performance.now();
    const unbalancedTx = await commitValue(opening1_rand, commitment, value, commitProgram, context!, commit_zkir, 'player1', player1_sk);
    const endTime = performance.now();

    statusLabel.innerText = `Generated unbalanced tx in: ${Math.floor(endTime - startTime)} ms`;

    tx1.value = uint8ArrayToHex(unbalancedTx);
    commitment1 = true;

    if (commitment1 && commitment2) {
      openButton.disabled = false;
    }

    if (!commitment2) {
      commit2Button.disabled = false;
    }
  });


  commit2Button?.addEventListener("click", async () => {
    commit1Button.disabled = true;
    statusLabel.innerText = "Generating proof for player2";

    commit2Button.disabled = true;

    opening2_rand = rng.random_fr();

    const startTime = performance.now();

    const value = BigInt(select2.value);
    const commitment = transient_commit(FrValue.from_u64(value), opening2_rand);

    const unbalancedTx = await commitValue(opening2_rand, commitment, value, commitProgram, context!, commit_zkir, 'player2', player2_sk);

    const endTime = performance.now();

    statusLabel.innerText = `Generated unbalanced tx in: ${Math.floor(endTime - startTime)} ms`;

    tx2.value = uint8ArrayToHex(unbalancedTx);
    commitment2 = true;

    if (commitment1 && commitment2) {
      openButton.disabled = false;
    }

    if (!commitment1) {
      commit1Button.disabled = false;
    }
  });

  openButton?.addEventListener("click", async () => {
    statusLabel.innerText = "Generating proof for commitments opening";

    const startTime = performance.now();
    const value1 = Number(select1.value);
    const value2 = Number(select2.value);

    const winner = value1 == value2 ? 2n : (value1 == (value2 + 1) % 3 ? 0n : 1n);

    const unbalancedTx = await openValues(context!, open_program, BigInt(value1), opening1_rand!, BigInt(value2), opening2_rand!, open_zkir, winner);

    tx3.value = uint8ArrayToHex(unbalancedTx);
    const endTime = performance.now();

    statusLabel.innerText = `Generated unbalanced tx in: ${Math.floor(endTime - startTime)} ms`;

    setCounters();

    commitment1 = null;
    commitment2 = null;
    opening1_rand = null;
    opening2_rand = null;

    commit1Button.disabled = false;
    commit2Button.disabled = false;

    openButton.disabled = true;
  });
}

function setCounters() {
  const state = context?.get_state();
  const countersLabel = document.getElementById("counters") as HTMLLabelElement;
  countersLabel.innerText = `p1|p2|ties:  ${[INDEX_PLAYER1_VICTORIES, INDEX_PLAYER2_VICTORIES, INDEX_TIES].map(n => state?.index_cell(Number(n))?.value_only_field_repr().to_string())}    (local ledger state)`;
}

async function commitValue(opening: FrValue, commitment: FrValue, value: bigint, commitProgram: ImpactProgram, context: Context, commit_zkir: IrSource, player: 'player1' | 'player2', sk: AlignedValue): Promise<Uint8Array> {
  const public_inputs = [
    FrValue.from_u64(player == 'player1' ? INDEX_PLAYER1_PK : INDEX_PLAYER2_PK).to_aligned_value(),
    FrValue.from_u64(player == 'player1' ? INDEX_PLAYER1_COMMITMENT : INDEX_PLAYER2_COMMITMENT).to_aligned_value(),
    commitment.to_aligned_value()
  ];

  const query_results = commitProgram.run(context, public_inputs.map(StateValue.cell));

  const private_transcript_outputs = AlignedValues.empty();

  private_transcript_outputs.push(sk.value_only_field_repr().to_aligned_value());
  private_transcript_outputs.push(FrValue.from_u64(value).to_aligned_value());
  private_transcript_outputs.push(opening.to_aligned_value());

  const tx = await make_unbalanced_transaction("commit", query_results, AlignedValues.from_array(public_inputs), private_transcript_outputs, commit_zkir, rng, context);

  return tx;
}

async function openValues(context: Context, open_program: ImpactProgram, value1: bigint, opening1: FrValue, value2: bigint, opening2: FrValue, open_zkir: IrSource, winner: bigint): Promise<Uint8Array> {
  console.log('state2', context.get_state().debug_repr());

  const execution_inputs = [StateValue.from_number(winner)];

  const query_results = open_program.run(context, execution_inputs);

  const private_transcript_outputs = AlignedValues.empty();

  private_transcript_outputs.push(FrValue.from_u64(value1).to_aligned_value());
  private_transcript_outputs.push(opening1.to_aligned_value());
  private_transcript_outputs.push(FrValue.from_u64(value2).to_aligned_value());
  private_transcript_outputs.push(opening2.to_aligned_value());

  const inputs = AlignedValues.empty();
  inputs.push(FrValue.from_u64(winner).to_aligned_value());

  const tx = await make_unbalanced_transaction("open", query_results, inputs, private_transcript_outputs, open_zkir, rng, context);

  return tx;
}

function buildCommitProgram() {
  const builder = ImpactProgram.empty("commit");

  builder.dup(0);
  builder.push_input(false, Alignment.single_field());
  builder.idx(false, false, [Key.stack()]);
  builder.popeq(false, Alignment.single_field());
  builder.push_input(false, Alignment.single_field());
  builder.dup(1);
  builder.dup(1);
  builder.idx(false, false, [Key.stack()]);
  builder.type();
  builder.popeq(false, Alignment.bytes(1));
  builder.push_input(true, Alignment.single_field());
  builder.ins(false, 1);

  console.log(builder.debug_repr());

  // secret key, value, and randomness (commitment opening)
  const num_private_inputs = 3;

  // generates the constraints for the transcript
  const commit_zkir = builder.build_base_zkir(num_private_inputs);

  // gets the indexes of the private 3 inputs.
  const private_inputs = commit_zkir.private_inputs();

  const public_key_hash = commit_zkir.transient_hash(new Uint32Array([private_inputs[0]]));

  // these are the reads (popeq).
  const output_indexes = commit_zkir.output_indexes();

  // checks that the user knows the private key
  commit_zkir.constrain_eq(public_key_hash, output_indexes[0]);

  // 1 is Null, so we check here that there is no currrent commitment.
  commit_zkir.constrain_eq(commit_zkir.get_or_insert_constant(FrValue.from_u64(1n)),
    output_indexes[1]
  );

  // compute the commitment
  const commitment_index = commit_zkir.transient_hash(new Uint32Array([private_inputs[2], private_inputs[1]]));
  // 2 is the first input
  commit_zkir.constrain_eq(commitment_index, 2);
  const zconst = commit_zkir.load_imm(FrValue.from_u64(0n));
  const tconst = commit_zkir.load_imm(FrValue.from_u64(2n));

  // we check that the value is either 0, 1 or 2.
  const teq1 = commit_zkir.test_eq(private_inputs[1], commit_zkir.get_or_insert_constant(FrValue.from_u64(1n)));
  const teq2 = commit_zkir.test_eq(private_inputs[1], zconst);
  const teq3 = commit_zkir.test_eq(private_inputs[1], tconst);

  // or as addition
  const fa = commit_zkir.add(teq1, teq2);
  const cond = commit_zkir.add(teq3, fa);
  commit_zkir.assert(cond);

  return { commit_zkir, builder };
}

function buildOpenProgram() {
  const builder = ImpactProgram.empty("open_commitments");

  builder.dup(0);
  builder.idx(false, false, [Key.value(AlignedValue.from_fr(FrValue.from_u64(INDEX_PLAYER1_COMMITMENT)))]);
  builder.popeq(false, Alignment.single_field());

  builder.dup(0);
  builder.idx(false, false, [Key.value(AlignedValue.from_fr(FrValue.from_u64(INDEX_PLAYER2_COMMITMENT)))]);
  builder.popeq(false, Alignment.single_field());

  builder.push_constant(false, StateValue.from_number(INDEX_PLAYER1_COMMITMENT));
  builder.push_constant(true, StateValue.null());
  builder.ins(false, 1);

  builder.push_constant(false, StateValue.from_number(INDEX_PLAYER2_COMMITMENT));
  builder.push_constant(true, StateValue.null());
  builder.ins(false, 1);

  builder.push_input(false, Alignment.single_field());
  builder.dup(1);
  builder.dup(1);
  builder.idx(false, false, [Key.stack()]);
  builder.addi(1);
  builder.ins(false, 1);

  console.log(builder.debug_repr());

  const num_private_inputs = 4;

  const zkir = builder.build_base_zkir(num_private_inputs);

  const private_inputs = zkir.private_inputs();

  const private1 = private_inputs[0]
  const private2 = private_inputs[2];

  const hash1 = zkir.transient_hash(new Uint32Array([private_inputs[1], private_inputs[0]]));
  const hash2 = zkir.transient_hash(new Uint32Array([private_inputs[3], private_inputs[2]]));

  const output_indexes = zkir.output_indexes();

  zkir.constrain_eq(hash1, output_indexes[0]);
  zkir.constrain_eq(hash2, output_indexes[1]);

  // game logic

  // tie check
  const values_are_the_same = zkir.test_eq(private1, private2);
  const index_ties = zkir.load_imm(FrValue.from_u64(INDEX_TIES));
  const winner_eq_ties = zkir.test_eq(0, index_ties);

  zkir.constrain_eq(winner_eq_ties, values_are_the_same);

  // player 1 wins
  const three = zkir.load_imm(FrValue.from_u64(3n));
  const index_player1_wins = zkir.load_imm(FrValue.from_u64(INDEX_PLAYER1_VICTORIES));
  const winner_equals_index1 = zkir.test_eq(0, index_player1_wins);
  const minus1 = zkir.neg(zkir.get_or_insert_constant(FrValue.from_u64(1n)));
  const private1_minus_1 = zkir.add(private1, minus1);
  const player1_wins1 = zkir.test_eq(private2, private1_minus_1);
  const private1_minus1_plus3 = zkir.add(private1_minus_1, three);
  const player1_wins2 = zkir.test_eq(private2, private1_minus1_plus3);
  const player1_wins = zkir.add(player1_wins1, player1_wins2);
  zkir.constrain_eq(player1_wins, winner_equals_index1);

  // player 2 wins
  const player2_wins = zkir.test_eq(player1_wins, values_are_the_same);
  const winner_equals_player2 = zkir.test_eq(0, zkir.get_or_insert_constant(FrValue.from_u64(INDEX_PLAYER2_VICTORIES)));
  zkir.constrain_eq(player2_wins, winner_equals_player2);

  return { zkir, impact: builder };
}

function initializeContext(): Context {
  const ledgerVariables = 7;
  const csb = ContractStateBuilder.initial_query_context(["commit"], ledgerVariables);

  csb.insert_to_state_array(0n, StateValue.cell(FrValue.from_u64(0n).to_aligned_value()));
  csb.insert_to_state_array(1n, StateValue.cell(FrValue.from_u64(0n).to_aligned_value()));
  csb.insert_to_state_array(2n, StateValue.cell(FrValue.from_u64(0n).to_aligned_value()));

  const address1_repr = AlignedValue.from_bytes_32(sk1).value_only_field_repr();
  const player1_pk = transient_hash(address1_repr);

  const address2_repr = AlignedValue.from_bytes_32(sk2).value_only_field_repr();
  const player2_pk = transient_hash(address2_repr);

  csb.insert_to_state_array(
    3n,
    StateValue.cell(player1_pk.to_aligned_value())
  );
  csb.insert_to_state_array(
    4n,
    StateValue.cell(player2_pk.to_aligned_value())
  );
  csb.insert_to_state_array(5n, StateValue.null());
  csb.insert_to_state_array(6n, StateValue.null());

  const context = Context.new(csb.get_state(), NetworkId.undeployed());
  return context;
}

window.addEventListener("DOMContentLoaded", () => {
  run();
});

