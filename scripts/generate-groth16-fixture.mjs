#!/usr/bin/env node
/**
 * Generate a Groth16 proof fixture for integration tests.
 *
 * Outputs: test/fixtures/groth16-proof-fixture.json
 *
 * Usage: node scripts/generate-groth16-fixture.mjs
 *
 * Prerequisites:
 *   - circom compiled: circuits/artifacts/worldline_stf_js/worldline_stf.wasm
 *   - zkey: circuits/zkeys/worldline_stf_final.zkey
 *   - vkey: circuits/zkeys/worldline_stf_vkey.json
 */

import * as snarkjs from "snarkjs";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, "..");

const WASM_PATH = path.join(ROOT, "circuits/artifacts/worldline_stf_js/worldline_stf.wasm");
const ZKEY_PATH = path.join(ROOT, "circuits/zkeys/worldline_stf_final.zkey");
const VKEY_PATH = path.join(ROOT, "circuits/zkeys/worldline_stf_vkey.json");
const OUTPUT_PATH = path.join(ROOT, "test/fixtures/groth16-proof-fixture.json");

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
      console.error("Run: circom circuits/stf/worldline_stf.circom --wasm --r1cs --output circuits/artifacts");
      process.exit(1);
    }
  }

  console.log("Generating Groth16 proof...");
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, WASM_PATH, ZKEY_PATH);

  // Verify before saving
  const vkey = JSON.parse(fs.readFileSync(VKEY_PATH, "utf-8"));
  const valid = await snarkjs.groth16.verify(vkey, publicSignals, proof);
  if (!valid) {
    console.error("FATAL: Generated proof does not verify!");
    process.exit(1);
  }

  // Convert proof to Solidity format.
  // snarkjs proof format: { pi_a: [x, y, "1"], pi_b: [[x_c0, x_c1], [y_c0, y_c1], ["1","0"]], pi_c: [x, y, "1"] }
  // The snarkjs-generated Groth16Verifier expects G2 Fp2 components in REVERSED order:
  //   pB[0] = [x_c1, x_c0], pB[1] = [y_c1, y_c0]
  // This matches snarkjs.groth16.exportSolidityCallData() behavior.
  const pA = [proof.pi_a[0], proof.pi_a[1]];
  const pB = [
    [proof.pi_b[0][1], proof.pi_b[0][0]],
    [proof.pi_b[1][1], proof.pi_b[1][0]],
  ];
  const pC = [proof.pi_c[0], proof.pi_c[1]];
  const stfCommitment = publicSignals[0];
  const proverSetDigest = publicSignals[1];

  // Convert decimal strings to 0x hex (32 bytes each)
  const toHex = (s) => "0x" + BigInt(s).toString(16).padStart(64, "0");

  const fixture = {
    proofSystem: "groth16",
    description:
      "Groth16 proof fixture. Regenerate with: node scripts/generate-groth16-fixture.mjs",
    inputs,
    publicOutputs: {
      stfCommitment: toHex(stfCommitment),
      proverSetDigest: toHex(proverSetDigest),
    },
    proof: {
      pA: pA.map(toHex),
      pB: pB.map((row) => row.map(toHex)),
      pC: pC.map(toHex),
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
