#!/usr/bin/env node
/**
 * Generate a Plonk proof fixture for integration tests.
 *
 * Outputs: test/fixtures/plonk-proof-fixture.json
 *
 * Usage: node scripts/generate-plonk-fixture.mjs
 *
 * Prerequisites:
 *   - circom compiled: circuits/build/plonk_v2/worldline_stf_plonk_js/worldline_stf_plonk.wasm
 *   - zkey: circuits/zkeys/worldline_stf_plonk_v2.zkey
 *   - vkey: circuits/zkeys/worldline_stf_plonk_v2_vkey.json
 */

import * as snarkjs from "snarkjs";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, "..");

const WASM_PATH = path.join(
  ROOT,
  "circuits/build/plonk_v2/worldline_stf_plonk_js/worldline_stf_plonk.wasm"
);
const ZKEY_PATH = path.join(ROOT, "circuits/zkeys/worldline_stf_plonk_v2.zkey");
const VKEY_PATH = path.join(ROOT, "circuits/zkeys/worldline_stf_plonk_v2_vkey.json");
const OUTPUT_PATH = path.join(ROOT, "test/fixtures/plonk-proof-fixture.json");

// Canonical test inputs — shared across all three proof systems
const inputs = {
  preStateRoot: "1234567890",
  postStateRoot: "9876543210",
  batchCommitment: "5555555555",
  batchSize: "100",
  proverIds: ["101", "102", "103"],
  proofSystemIds: ["1", "2", "3"],
  quorumCount: "3",
};

async function main() {
  // Verify prerequisites
  for (const [name, p] of [["WASM", WASM_PATH], ["ZKEY", ZKEY_PATH], ["VKEY", VKEY_PATH]]) {
    if (!fs.existsSync(p)) {
      console.error(`Missing ${name}: ${p}`);
      console.error(
        "Run: circom circuits/src/worldline_stf_plonk.circom --wasm --r1cs --output circuits/build/plonk_v2"
      );
      process.exit(1);
    }
  }

  console.log("Generating Plonk proof...");
  const { proof, publicSignals } = await snarkjs.plonk.fullProve(inputs, WASM_PATH, ZKEY_PATH);

  // Verify before saving
  const vkey = JSON.parse(fs.readFileSync(VKEY_PATH, "utf-8"));
  const valid = await snarkjs.plonk.verify(vkey, publicSignals, proof);
  if (!valid) {
    console.error("FATAL: Generated proof does not verify!");
    process.exit(1);
  }

  // Convert proof to adapter format: abi.encode(uint256[24], uint256, uint256)
  // snarkjs plonk proof has: A, B, C, Z, T1, T2, T3, Wxi, Wxiw (9 G1 points)
  // and eval_a, eval_b, eval_c, eval_s1, eval_s2, eval_zw (6 Fr scalars)
  // Total: 9*2 + 6 = 24 uint256 words

  const toHex = (s) => "0x" + BigInt(s).toString(16).padStart(64, "0");

  const g1Keys = ["A", "B", "C", "Z", "T1", "T2", "T3", "Wxi", "Wxiw"];
  const evalKeys = ["eval_a", "eval_b", "eval_c", "eval_s1", "eval_s2", "eval_zw"];

  const proofWords = [];
  for (const key of g1Keys) {
    proofWords.push(toHex(proof[key][0]));
    proofWords.push(toHex(proof[key][1]));
  }
  for (const key of evalKeys) {
    proofWords.push(toHex(proof[key]));
  }

  if (proofWords.length !== 24) {
    console.error(`Expected 24 proof words, got ${proofWords.length}`);
    process.exit(1);
  }

  const stfCommitment = publicSignals[0];
  const proverSetDigest = publicSignals[1];

  const fixture = {
    proofSystem: "plonk",
    description:
      "Plonk proof fixture. Regenerate with: node scripts/generate-plonk-fixture.mjs",
    inputs,
    publicOutputs: {
      stfCommitment: toHex(stfCommitment),
      proverSetDigest: toHex(proverSetDigest),
    },
    proof: {
      words: proofWords,
    },
    rawSnarkjsProof: proof,
  };

  fs.mkdirSync(path.dirname(OUTPUT_PATH), { recursive: true });
  fs.writeFileSync(OUTPUT_PATH, JSON.stringify(fixture, null, 2) + "\n");
  console.log(`Fixture written: ${OUTPUT_PATH}`);
  console.log(`stfCommitment:   ${toHex(stfCommitment)}`);
  console.log(`proverSetDigest: ${toHex(proverSetDigest)}`);
  console.log("Verified: true");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
