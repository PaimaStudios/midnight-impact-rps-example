import init, { Context, Rng, initThreadPool } from './pkg/wasm.js';


async function run() {
  await init();

  await initThreadPool(navigator.hardwareConcurrency);

  const context = Context.new();

  const rng = Rng.new();

  const opening1 = rng.random_fr();
  const opening2 = rng.random_fr();

  const p1_value = 0;
  const p2_value = 2;

  await withTiming(async () => {
    await context.commit_to_value(0, p1_value, opening1, true);
  });

  await withTiming(async () => {
    await context.commit_to_value(1, p2_value, opening2, true);
  });

  await withTiming(async () => {
    await context.open(0, p1_value, opening1, p2_value, opening2);
  });

  const s = context.get_state();

  console.log(`state ${s}`);

  const context2 = Context.new();

  const _provedTx = await withTiming(async () => {
    const proofServerPayload = await context2.commit_to_value(1, p2_value, opening2, false);
    return await postToProofServer(proofServerPayload);
  });
}

async function postToProofServer(proofServerPayload) {
  const apiUrl = 'http://localhost:6300/prove-tx';

  const response = await fetch(apiUrl, {
    method: 'POST',
    body: await new Blob([proofServerPayload]).arrayBuffer(),
  });

  if (!response.ok) {
    throw new Error('Got error: ' + response.statusText);
  }

  return response.blob();

}

async function withTiming(f) {
  const startTime = performance.now();

  const r = await f();

  const endTime = performance.now();

  console.log(`took: ${endTime - startTime} ms`);

  return r;
}

run();
