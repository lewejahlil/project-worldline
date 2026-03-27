/**
 * Circuit constraint tests for circuits/worldline.circom (SquareHash template).
 *
 * Prerequisites — run these npm scripts before executing the tests:
 *   npm run c:ptau      # download Powers of Tau
 *   npm run c:compile   # compile circuit → WASM + r1cs
 *   npm run c:setup     # generate proving key (zkey)
 *
 * These tests use snarkjs to:
 *  1. Compute a witness from circuit inputs.
 *  2. Verify that the expected output signal value is produced.
 *  3. Generate and verify a full Groth16 proof for end-to-end coverage.
 */

import * as path from "path";
import * as fs from "fs";
// @ts-ignore – snarkjs ships its own types
import * as snarkjs from "snarkjs";

const ARTIFACTS_DIR = path.resolve(__dirname, "../artifacts");
const WASM_PATH = path.join(ARTIFACTS_DIR, "worldline_js/worldline.wasm");
const ZKEY_PATH = path.join(ARTIFACTS_DIR, "worldline_final.zkey");
const VKEY_PATH = path.join(ARTIFACTS_DIR, "verification_key.json");

// Derive the snarkjs vkey from the zkey once per suite (cached).
let vKey: object | null = null;
async function getVKey(): Promise<object> {
  if (!vKey) {
    vKey = JSON.parse(fs.readFileSync(VKEY_PATH, "utf8"));
  }
  return vKey!;
}

// Helper: compute witness for given inputs.
// INF-005: isValid output was removed from the circuit. The witness now
// only contains the constraint wire for `computed === publicHash`.
// A successful return means the constraints were satisfied.
async function computeWitness(inputs: Record<string, bigint | number>): Promise<void> {
  await snarkjs.wtns.calculate(inputs, WASM_PATH, {});
}

// Helper: generate a full proof and verify it on-chain (via snarkjs JS verifier).
async function proveAndVerify(inputs: Record<string, bigint | number>): Promise<boolean> {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, WASM_PATH, ZKEY_PATH);
  const vk = await getVKey();
  return snarkjs.groth16.verify(vk, publicSignals, proof);
}

// Skip the entire suite if artifacts have not been generated yet.
const artifactsExist =
  fs.existsSync(WASM_PATH) && fs.existsSync(ZKEY_PATH) && fs.existsSync(VKEY_PATH);

(artifactsExist ? describe : describe.skip)("worldline.circom – SquareHash circuit", function () {
  this.timeout(60_000); // Proving can take several seconds.

  // ── Witness computation ───────────────────────────────────────────────────

  describe("witness generation", function () {
    it("satisfies constraints when secret² == publicHash", async function () {
      await computeWitness({ secret: 5n, publicHash: 25n });
    });

    it("satisfies constraints for secret=3, publicHash=9", async function () {
      await computeWitness({ secret: 3n, publicHash: 9n });
    });

    it("satisfies constraints for edge case secret=0, publicHash=0", async function () {
      await computeWitness({ secret: 0n, publicHash: 0n });
    });

    it("satisfies constraints for secret=1, publicHash=1", async function () {
      await computeWitness({ secret: 1n, publicHash: 1n });
    });

    it("fails witness generation when secret² != publicHash (constraint violation)", async function () {
      // The circuit enforces `computed === publicHash`. If violated, snarkjs
      // throws during witness calculation — this is the expected behaviour.
      let threw = false;
      try {
        await computeWitness({ secret: 5n, publicHash: 26n });
      } catch (_) {
        threw = true;
      }
      if (!threw) {
        throw new Error("Expected witness generation to fail for invalid inputs");
      }
    });

    it("fails for secret=3, publicHash=10 (off by one)", async function () {
      let threw = false;
      try {
        await computeWitness({ secret: 3n, publicHash: 10n });
      } catch (_) {
        threw = true;
      }
      if (!threw) {
        throw new Error("Expected constraint violation");
      }
    });

    it("fails when publicHash=0 but secret is non-zero", async function () {
      let threw = false;
      try {
        await computeWitness({ secret: 2n, publicHash: 0n });
      } catch (_) {
        threw = true;
      }
      if (!threw) {
        throw new Error("Expected constraint violation");
      }
    });
  });

  // ── Full proof generation & verification ──────────────────────────────────

  describe("Groth16 proof", function () {
    it("generates and verifies a valid proof for secret=5, publicHash=25", async function () {
      const valid = await proveAndVerify({ secret: 5n, publicHash: 25n });
      if (!valid) throw new Error("Proof verification failed");
    });

    it("generates and verifies a valid proof for secret=0, publicHash=0", async function () {
      const valid = await proveAndVerify({ secret: 0n, publicHash: 0n });
      if (!valid) throw new Error("Proof verification failed");
    });

    it("generates and verifies a valid proof for secret=12, publicHash=144", async function () {
      const valid = await proveAndVerify({ secret: 12n, publicHash: 144n });
      if (!valid) throw new Error("Proof verification failed");
    });

    it("a proof for one input does not verify against different public signals", async function () {
      // Generate a valid proof for secret=3, publicHash=9.
      const { proof } = await snarkjs.groth16.fullProve(
        { secret: 3n, publicHash: 9n },
        WASM_PATH,
        ZKEY_PATH
      );
      const vk = await getVKey();
      // Attempt to verify with tampered public signals.
      // INF-005: Public signals are now just [publicHash] (isValid removed).
      const tamperedSignals = ["10"]; // publicHash=10 instead of 9
      const valid = await snarkjs.groth16.verify(vk, tamperedSignals, proof);
      if (valid) {
        throw new Error("Expected tampered proof verification to fail");
      }
    });
  });
});
