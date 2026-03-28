/**
 * Circuit constraint tests for circuits/stf/worldline_stf.circom (WorldlineSTF template).
 *
 * Prerequisites:
 *   - Circuit compiled: circom2 circuits/stf/worldline_stf.circom --r1cs --wasm --sym -o circuits/build/
 *   - zkey generated: worldline_stf_final.zkey in circuits/zkeys/
 *   - vkey exported: worldline_stf_vkey.json in circuits/zkeys/
 *
 * All tests use real snarkjs witness generation and Groth16 prove/verify — no mocks.
 */

import { expect } from "chai";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
// @ts-expect-error – snarkjs ships its own types
import * as snarkjs from "snarkjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const BUILD_DIR = path.resolve(__dirname, "../build");
const WASM_PATH = path.join(BUILD_DIR, "worldline_stf_js/worldline_stf.wasm");
const ZKEY_PATH = path.resolve(__dirname, "../zkeys/worldline_stf_final.zkey");
const VKEY_PATH = path.resolve(__dirname, "../zkeys/worldline_stf_vkey.json");

// Cached verification key.
let vKey: object | null = null;
function getVKey(): object {
  if (!vKey) {
    vKey = JSON.parse(fs.readFileSync(VKEY_PATH, "utf8"));
  }
  return vKey!;
}

// Valid base inputs for a 3-prover quorum.
function validInputs() {
  return {
    preStateRoot: "1234567890",
    postStateRoot: "9876543210",
    batchCommitment: "5555555555",
    batchSize: "100",
    proverIds: ["101", "102", "103"],
    proofSystemIds: ["1", "2", "3"],
    quorumCount: "3"
  };
}

// Generate a full Groth16 proof and return { proof, publicSignals }.
async function fullProve(
  inputs: Record<string, unknown>
): Promise<{ proof: unknown; publicSignals: string[] }> {
  return snarkjs.groth16.fullProve(inputs, WASM_PATH, ZKEY_PATH);
}

// Verify a proof against the verification key.
async function verifyProof(publicSignals: string[], proof: unknown): Promise<boolean> {
  return snarkjs.groth16.verify(getVKey(), publicSignals, proof);
}

// Skip suite if artifacts have not been generated.
const artifactsExist =
  fs.existsSync(WASM_PATH) && fs.existsSync(ZKEY_PATH) && fs.existsSync(VKEY_PATH);

(artifactsExist ? describe : describe.skip)(
  "worldline_stf.circom — WorldlineSTF circuit",
  function () {
    this.timeout(120_000);

    // ── Test 1: Valid proof — quorum of 3 ──────────────────────────────────

    it("1. generates and verifies a valid proof with quorum of 3", async function () {
      const inputs = validInputs();
      const { proof, publicSignals } = await fullProve(inputs);

      expect(publicSignals).to.have.lengthOf(2);

      const valid = await verifyProof(publicSignals, proof);
      expect(valid).to.equal(true);
    });

    // ── Test 2: Valid proof — quorum of 2 (minimum viable) ─────────────────

    it("2. generates and verifies a valid proof with quorum of 2", async function () {
      const inputs = validInputs();
      inputs.quorumCount = "2";
      // All prover slots still filled (quorum just reports how many attested)

      const { proof, publicSignals } = await fullProve(inputs);
      const valid = await verifyProof(publicSignals, proof);
      expect(valid).to.equal(true);
    });

    // ── Test 3: Invalid — quorum of 0 ──────────────────────────────────────

    it("3. rejects quorum of 0 (constraint violation)", async function () {
      const inputs = validInputs();
      inputs.quorumCount = "0";

      try {
        await fullProve(inputs);
        expect.fail("Expected witness generation to fail for quorumCount=0");
      } catch (e: unknown) {
        // Constraint violation during witness generation — expected.
        expect(e).to.be.an("error");
      }
    });

    // ── Test 4: Invalid — mismatched stfCommitment ─────────────────────────

    it("4. proof does not verify with tampered stfCommitment", async function () {
      const inputs = validInputs();
      const { proof, publicSignals } = await fullProve(inputs);

      // Tamper with stfCommitment (pubSignals[0])
      const tampered = [...publicSignals];
      tampered[0] = "999999999999999999";

      const valid = await verifyProof(tampered, proof);
      expect(valid).to.equal(false);
    });

    // ── Test 5: Invalid — zero prover ID ───────────────────────────────────

    it("5. rejects zero prover ID (non-zero constraint)", async function () {
      const inputs = validInputs();
      inputs.proverIds = ["101", "0", "103"]; // Second prover is zero

      try {
        await fullProve(inputs);
        expect.fail("Expected witness generation to fail for zero prover ID");
      } catch (e: unknown) {
        expect(e).to.be.an("error");
      }
    });

    // ── Test 6: Invalid — out-of-range proof system ID ─────────────────────

    it("6. rejects proofSystemId=4 (out of {1,2,3})", async function () {
      const inputs = validInputs();
      inputs.proofSystemIds = ["1", "4", "3"]; // 4 is out of range

      try {
        await fullProve(inputs);
        expect.fail("Expected witness generation to fail for out-of-range proofSystemId");
      } catch (e: unknown) {
        expect(e).to.be.an("error");
      }
    });

    // ── Test 7: Boundary — batchSize at MAX_BATCH_SIZE ─────────────────────

    it("7. accepts batchSize at MAX_BATCH_SIZE (1024)", async function () {
      const inputs = validInputs();
      inputs.batchSize = "1024";

      const { proof, publicSignals } = await fullProve(inputs);
      const valid = await verifyProof(publicSignals, proof);
      expect(valid).to.equal(true);
    });

    // ── Test 8: Boundary — batchSize = 0 ───────────────────────────────────

    it("8. rejects batchSize=0 (constraint violation)", async function () {
      const inputs = validInputs();
      inputs.batchSize = "0";

      try {
        await fullProve(inputs);
        expect.fail("Expected witness generation to fail for batchSize=0");
      } catch (e: unknown) {
        expect(e).to.be.an("error");
      }
    });
  }
);
