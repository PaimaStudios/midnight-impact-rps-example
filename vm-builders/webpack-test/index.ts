import init, { initThreadPool, Context, ContractStateBuilder, StateValue, FrValue, AlignedValue, transient_hash, Rng, NetworkId, Ops, ImpactProgram, Alignment, Key, IrSource, ParamsProver, AlignedValues, make_unbalanced_transaction } from 'midnight-vm-bindings';

const STATE_INDEX_A = 0n;
const STATE_INDEX_B = 1n;
const STATE_INDEX_C = 2n;
const STATE_INDEX_PK = 3n;

function uint8ArrayToHex(uint8Array: Uint8Array) {
  return Array.from(uint8Array, function(byte) {
    return ('0' + (byte & 0xFF).toString(16)).slice(-2);
  }).join('');
}

async function run() {
  console.log("Init module");

  await init();

  console.log("Finished init");

  console.log("Initializing thread pool");

  await initThreadPool(navigator.hardwareConcurrency);

  console.log("thread pool initialized");

  const rng = Rng.new();

  const admin_sk = AlignedValue.from_bytes_32(rng.random_32_bytes());

  const context = initializeContext(admin_sk);

  const ops = Ops.empty();

  const { zkir, program } = buildProgram();

  ops.add(zkir);

  const k = 9;
  const pp = ParamsProver.generate(rng, k);

  const deploy_tx = await context.unbalanced_deploy_tx(rng, ops, pp);

  console.log('deploy_tx', uint8ArrayToHex(deploy_tx));

  const public_inputs = [
    FrValue.from_u64(3n).to_aligned_value(),
    FrValue.from_u64(2n).to_aligned_value(),
    FrValue.from_u64(6n).to_aligned_value()
  ];

  const query_results = program.run(context, public_inputs.map(StateValue.cell));

  const private_transcript_outputs = AlignedValues.empty();

  private_transcript_outputs.push(admin_sk);

  const tx = await make_unbalanced_transaction(program.entry_point(), query_results, AlignedValues.from_array(public_inputs), private_transcript_outputs, zkir, rng, context, pp);

  console.log("contract call tx", uint8ArrayToHex(tx));

  return tx;

}

function initializeContext(admin_sk: AlignedValue): Context {
  const ledger_variables = 4;

  const csb = ContractStateBuilder.initial_query_context(["op1"], ledger_variables);

  csb.insert_to_state_array(STATE_INDEX_A, StateValue.null());
  csb.insert_to_state_array(STATE_INDEX_B, StateValue.null());
  csb.insert_to_state_array(STATE_INDEX_C, StateValue.null());

  const admin_pk = transient_hash(admin_sk.value_only_field_repr());

  csb.insert_to_state_array(
    STATE_INDEX_PK,
    StateValue.cell(admin_pk.to_aligned_value())
  );

  const context = Context.new(csb.get_state(), NetworkId.undeployed());

  return context;
}

function buildProgram(): { zkir: IrSource, program: ImpactProgram } {
  const builder = ImpactProgram.empty("op");

  // the state is in the top of the stack.
  builder.dup(0);

  // we read the public key of the admin from the state.
  // we can access this in the zkir through output_indexes()[0]
  builder.idx(false, false, [Key.value(AlignedValue.from_fr(FrValue.from_u64(STATE_INDEX_PK)))]);
  builder.popeq(false, Alignment.single_field());

  builder.push_constant(false, StateValue.from_number(STATE_INDEX_A));
  builder.push_input(true, Alignment.single_field());
  builder.ins(false, 1);

  builder.push_constant(false, StateValue.from_number(STATE_INDEX_B));
  builder.push_input(true, Alignment.single_field());
  builder.ins(false, 1);

  builder.push_constant(false, StateValue.from_number(STATE_INDEX_C));
  builder.push_input(true, Alignment.single_field());
  builder.ins(false, 1);

  console.log(builder.debug_repr());

  // only secret key
  const num_private_inputs = 1;

  // generates the static constraints for the transcript.
  // 
  // at this point the circuit allows any combination of a,b,c values, and any private key.
  const zkir = builder.build_base_zkir(num_private_inputs);

  console.log('zkir', zkir.debug_repr());

  // gets the indexes of the private inputs.
  const private_inputs = zkir.private_inputs();

  const public_key_hash = zkir.transient_hash(new Uint32Array([private_inputs[0]]));

  // these are the reads (popeq).
  const output_indexes = zkir.output_indexes();

  zkir.constrain_eq(output_indexes[0], public_key_hash);

  // inputs are always at the beginning of the memory, so:
  // 
  // 0 is the first push_input (A)
  // 1 is the second push_input (B)
  const a_plus_b = zkir.mul(0, 1);
  // 2 is the third push_input (C)
  zkir.constrain_eq(a_plus_b, 2);


  return { zkir, program: builder };
}


window.addEventListener("DOMContentLoaded", () => {
  run();
});
