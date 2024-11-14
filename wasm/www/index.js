import init, { Context, Rng, initThreadPool } from './pkg/wasm.js';

let rng;
let sk1;
let sk2;
let opening1_rand;
let opening2_rand;

let commitment1 = null;
let commitment2 = null;

let context;

function uint8ArrayToHex(uint8Array) {
  return Array.from(uint8Array)
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('');
}

async function run() {
  const statusLabel = document.getElementById("status");

  const tx1 = document.getElementById("tx1");
  const tx2 = document.getElementById("tx2");
  const tx3 = document.getElementById("tx3");

  tx1.value = "";
  tx2.value = "";
  tx3.value = "";

  const select1 = document.getElementById("rps-select1");
  const select2 = document.getElementById("rps-select2");

  const commit1Button = document.getElementById("commit1");
  const commit2Button = document.getElementById("commit2");

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

  sk1 = rng.random_sk();
  sk2 = rng.random_sk();

  console.log("sk1", sk1.to_hex());
  console.log("sk2", sk2.to_hex());

  context = Context.new(sk1.to_public(), sk2.to_public());

  setCounters();

  const openButton = document.getElementById("open");

  commit1Button?.addEventListener("click", async () => {
    commit2Button.disabled = true;

    statusLabel.innerText = "Generating proof for player1";

    opening1_rand = rng.random_fr();

    commit1Button.disabled = true;

    const startTime = performance.now();
    const unbalancedTx = await context.commit_to_value(rng, 0, sk1, Number(select1.value), opening1_rand, true);
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
    const unbalancedTx = await context.commit_to_value(rng, 1, sk2, Number(select2.value), opening2_rand, true);
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

    const winner = value1 == value2 ? 2 : (value1 == (value2 + 1) % 3 ? 0 : 1);

    const unbalancedTx = await context.open(rng, winner, value1, opening1_rand, value2, opening2_rand, true);

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

  // const s = context.get_state();

  // console.log(`state ${s}`);

  // const context2 = Context.new();

  // const _provedTx = await withTiming(async () => {
  //   const proofServerPayload = await context.commit_to_value(rng, 1, sk2, p2_value, opening2, false);
  //   return await postToProofServer(proofServerPayload);
  // });
}

function setCounters() {
  const state = context.get_state();
  const countersLabel = document.getElementById("counters");
  countersLabel.innerText = `p1|p2|ties:  ${state.map(n => n.toString())}`;
}

// async function postToProofServer(proofServerPayload) {
//   const apiUrl = 'http://localhost:6300/prove-tx';

//   const response = await fetch(apiUrl, {
//     method: 'POST',
//     body: await new Blob([proofServerPayload]).arrayBuffer(),
//   });

//   if (!response.ok) {
//     throw new Error('Got error: ' + response.statusText);
//   }

//   return response.blob();

// }

// async function withTiming(f) {
//   const startTime = performance.now();

//   const r = await f();

//   const endTime = performance.now();

//   console.log(`took: ${endTime - startTime} ms`);

//   return r;
// }

window.addEventListener("DOMContentLoaded", () => {
  run();
});
