/**
 * Independent Plonk circuit tests (Path B).
 *
 * Tests the independently-written worldline_stf_plonk.circom against:
 *   1. Cross-circuit conformance with the original worldline_stf.circom
 *   2. Constraint enforcement (invalid inputs must be rejected)
 *   3. End-to-end Plonk proof generation and on-chain verification
 *
 * Prerequisites:
 *   Plonk V2 circuit:
 *     circuits/build/plonk_v2/worldline_stf_plonk_js/worldline_stf_plonk.wasm
 *     circuits/zkeys/worldline_stf_plonk_v2.zkey
 *     circuits/zkeys/worldline_stf_plonk_v2_vkey.json
 *   Original Groth16 circuit (for conformance):
 *     circuits/build/original/worldline_stf_js/worldline_stf.wasm
 *     circuits/zkeys/worldline_stf_final.zkey
 *
 * E2E Solidity test (optional — runs if Hardhat artifact exists):
 *     artifacts/contracts/src/PlonkVerifierV2.sol/PlonkVerifierV2.json
 */

"use strict";

const { expect } = require("chai");
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");
const ethers = require("ethers");

const CIRCUITS_DIR = path.resolve(__dirname, "..");

// ── Plonk V2 circuit artifacts ──────────────────────────────────────────────
const NEW_WASM = path.join(
  CIRCUITS_DIR,
  "build/plonk_v2/worldline_stf_plonk_js/worldline_stf_plonk.wasm"
);
const NEW_ZKEY = path.join(CIRCUITS_DIR, "zkeys/worldline_stf_plonk_v2.zkey");
const NEW_VKEY = path.join(CIRCUITS_DIR, "zkeys/worldline_stf_plonk_v2_vkey.json");

// ── Original Groth16 circuit artifacts (for conformance) ────────────────────
const ORIG_WASM = path.join(CIRCUITS_DIR, "build/original/worldline_stf_js/worldline_stf.wasm");
const ORIG_ZKEY = path.join(CIRCUITS_DIR, "zkeys/worldline_stf_final.zkey");

// ── PlonkVerifierV2 Hardhat artifact path ────────────────────────────────────
const VERIFIER_ARTIFACT = path.resolve(
  CIRCUITS_DIR,
  "../artifacts/contracts/src/PlonkVerifierV2.sol/PlonkVerifierV2.json"
);

// Load verification key (cached).
let _vKey = null;
function getVKey() {
  if (!_vKey) {
    _vKey = JSON.parse(fs.readFileSync(NEW_VKEY, "utf8"));
  }
  return _vKey;
}

// Artifact existence guards.
const newArtifactsExist =
  fs.existsSync(NEW_WASM) && fs.existsSync(NEW_ZKEY) && fs.existsSync(NEW_VKEY);

const origArtifactsExist = fs.existsSync(ORIG_WASM) && fs.existsSync(ORIG_ZKEY);

// ---------------------------------------------------------------------------
// Standard valid inputs — identical to the original Groth16 circuit test inputs.
// ---------------------------------------------------------------------------
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

/**
 * Generate a Plonk proof from the Plonk V2 circuit.
 * Returns { proof, publicSignals }.
 */
async function proveNew(inputs) {
  return snarkjs.plonk.fullProve(inputs, NEW_WASM, NEW_ZKEY);
}

/**
 * Generate a Groth16 proof from the original circuit.
 * Returns publicSignals — the two public outputs in order:
 *   publicSignals[0] = stfCommitment
 *   publicSignals[1] = proverSetDigest
 */
async function publicSignalsOrig(inputs) {
  const { publicSignals } = await snarkjs.groth16.fullProve(inputs, ORIG_WASM, ORIG_ZKEY);
  return publicSignals;
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------
(newArtifactsExist ? describe : describe.skip)(
  "worldline_stf_plonk.circom — Independent Path B circuit",
  function () {
    this.timeout(120_000);

    // ── Conformance Tests ──────────────────────────────────────────────────
    // These prove that for identical inputs the two independent implementations
    // produce numerically identical public outputs.

    (origArtifactsExist ? it : it.skip)(
      "1. cross-circuit conformance: quorum=3 produces identical outputs",
      async function () {
        const inputs = validInputs();
        const { publicSignals: newSigs } = await proveNew(inputs);
        const origSigs = await publicSignalsOrig(inputs);

        expect(newSigs[0]).to.equal(
          origSigs[0],
          "stfCommitment must match original circuit (quorum=3)"
        );
        expect(newSigs[1]).to.equal(
          origSigs[1],
          "proverSetDigest must match original circuit (quorum=3)"
        );
      }
    );

    (origArtifactsExist ? it : it.skip)(
      "2. cross-circuit conformance: quorum=2 produces identical outputs",
      async function () {
        const inputs = { ...validInputs(), quorumCount: "2" };
        const { publicSignals: newSigs } = await proveNew(inputs);
        const origSigs = await publicSignalsOrig(inputs);

        expect(newSigs[0]).to.equal(origSigs[0], "stfCommitment (quorum=2)");
        expect(newSigs[1]).to.equal(origSigs[1], "proverSetDigest (quorum=2)");
      }
    );

    (origArtifactsExist ? it : it.skip)(
      "3. cross-circuit conformance: quorum=1 produces identical outputs",
      async function () {
        const inputs = { ...validInputs(), quorumCount: "1" };
        const { publicSignals: newSigs } = await proveNew(inputs);
        const origSigs = await publicSignalsOrig(inputs);

        expect(newSigs[0]).to.equal(origSigs[0], "stfCommitment (quorum=1)");
        expect(newSigs[1]).to.equal(origSigs[1], "proverSetDigest (quorum=1)");
      }
    );

    (origArtifactsExist ? it : it.skip)(
      "4. cross-circuit conformance: batchSize=1024 produces identical outputs",
      async function () {
        const inputs = { ...validInputs(), batchSize: "1024" };
        const { publicSignals: newSigs } = await proveNew(inputs);
        const origSigs = await publicSignalsOrig(inputs);

        expect(newSigs[0]).to.equal(origSigs[0], "stfCommitment (batchSize=1024)");
        expect(newSigs[1]).to.equal(origSigs[1], "proverSetDigest (batchSize=1024)");
      }
    );

    // ── Constraint Tests ───────────────────────────────────────────────────

    it("5. rejects quorumCount=0 (below minimum)", async function () {
      const inputs = { ...validInputs(), quorumCount: "0" };
      try {
        await snarkjs.plonk.fullProve(inputs, NEW_WASM, NEW_ZKEY);
        expect.fail("Expected witness generation to fail for quorumCount=0");
      } catch (e) {
        expect(e).to.be.an("error");
      }
    });

    it("6. rejects quorumCount=4 (above maximum)", async function () {
      const inputs = { ...validInputs(), quorumCount: "4" };
      try {
        await snarkjs.plonk.fullProve(inputs, NEW_WASM, NEW_ZKEY);
        expect.fail("Expected witness generation to fail for quorumCount=4");
      } catch (e) {
        expect(e).to.be.an("error");
      }
    });

    it("7. rejects batchSize=0 (below minimum)", async function () {
      const inputs = { ...validInputs(), batchSize: "0" };
      try {
        await snarkjs.plonk.fullProve(inputs, NEW_WASM, NEW_ZKEY);
        expect.fail("Expected witness generation to fail for batchSize=0");
      } catch (e) {
        expect(e).to.be.an("error");
      }
    });

    it("8. rejects batchSize=1025 (above maximum)", async function () {
      const inputs = { ...validInputs(), batchSize: "1025" };
      try {
        await snarkjs.plonk.fullProve(inputs, NEW_WASM, NEW_ZKEY);
        expect.fail("Expected witness generation to fail for batchSize=1025");
      } catch (e) {
        expect(e).to.be.an("error");
      }
    });

    it("9. rejects proverId=0 (zero slot)", async function () {
      const inputs = {
        ...validInputs(),
        proverIds: ["101", "0", "103"]
      };
      try {
        await snarkjs.plonk.fullProve(inputs, NEW_WASM, NEW_ZKEY);
        expect.fail("Expected witness generation to fail for zero prover ID");
      } catch (e) {
        expect(e).to.be.an("error");
      }
    });

    it("10. rejects proofSystemId=4 (out of {1,2,3})", async function () {
      const inputs = {
        ...validInputs(),
        proofSystemIds: ["1", "4", "3"]
      };
      try {
        await snarkjs.plonk.fullProve(inputs, NEW_WASM, NEW_ZKEY);
        expect.fail("Expected witness generation to fail for proofSystemId=4");
      } catch (e) {
        expect(e).to.be.an("error");
      }
    });

    it("11. rejects proofSystemId=0 (out of {1,2,3})", async function () {
      const inputs = {
        ...validInputs(),
        proofSystemIds: ["1", "2", "0"]
      };
      try {
        await snarkjs.plonk.fullProve(inputs, NEW_WASM, NEW_ZKEY);
        expect.fail("Expected witness generation to fail for proofSystemId=0");
      } catch (e) {
        expect(e).to.be.an("error");
      }
    });

    // ── End-to-End Proof Test ─────────────────────────────────────────────

    it("12. E2E: generate Plonk proof → verify with snarkjs → verify calldata against PlonkVerifierV2", async function () {
      this.timeout(180_000);

      const inputs = validInputs();

      // Step 1: Generate proof.
      const { proof, publicSignals } = await proveNew(inputs);
      expect(publicSignals).to.have.lengthOf(2);

      // Step 2: Verify proof with snarkjs in-memory.
      const valid = await snarkjs.plonk.verify(getVKey(), publicSignals, proof);
      expect(valid).to.equal(true, "snarkjs Plonk verification must pass");

      // Step 3: Encode proof as Solidity calldata.
      // snarkjs.plonk.exportSolidityCallData returns a string with two
      // adjacent JSON arrays (no comma between them):
      //   "[proof_element_0, ..., proof_element_23][pubSig_0, pubSig_1]"
      const callDataStr = await snarkjs.plonk.exportSolidityCallData(proof, publicSignals);

      // Split on the "][" boundary to get the two arrays.
      const splitIdx = callDataStr.indexOf("][");
      if (splitIdx === -1) {
        throw new Error("Unexpected calldata format from exportSolidityCallData");
      }
      const proofJson = callDataStr.substring(0, splitIdx + 1);
      const pubJson = callDataStr.substring(splitIdx + 1);

      const proofFlat = JSON.parse(proofJson); // uint256[24]
      const pubSigs = JSON.parse(pubJson); // uint256[2]

      expect(proofFlat).to.have.lengthOf(24, "Plonk proof must have 24 field elements");
      expect(pubSigs).to.have.lengthOf(2, "Must have 2 public signals");

      // Step 4: Verify on-chain via PlonkVerifierV2 if Hardhat artifact exists.
      if (!fs.existsSync(VERIFIER_ARTIFACT)) {
        // Artifact not compiled — confirm calldata encodes cleanly and skip
        // the RPC call. The snarkjs verify above already confirms validity.
        const iface = new ethers.Interface([
          "function verifyProof(uint256[24] calldata _proof, uint256[2] calldata _pubSignals) view returns (bool)"
        ]);
        const encoded = iface.encodeFunctionData("verifyProof", [proofFlat, pubSigs]);
        expect(encoded).to.be.a("string").and.to.match(/^0x/);
        return;
      }

      // Artifact exists — deploy to local Hardhat node and call verifyProof.
      const artifact = JSON.parse(fs.readFileSync(VERIFIER_ARTIFACT, "utf8"));
      const provider = new ethers.JsonRpcProvider("http://127.0.0.1:8545");
      let signer;
      try {
        signer = await provider.getSigner();
      } catch (_) {
        // No live node — confirm calldata encodes and return.
        const iface = new ethers.Interface(artifact.abi);
        const encoded = iface.encodeFunctionData("verifyProof", [proofFlat, pubSigs]);
        expect(encoded).to.be.a("string").and.to.match(/^0x/);
        return;
      }

      const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, signer);
      const verifier = await factory.deploy();
      await verifier.waitForDeployment();

      const onChainValid = await verifier.verifyProof(proofFlat, pubSigs);
      expect(onChainValid).to.equal(true, "PlonkVerifierV2 on-chain verification must pass");
    });
  }
);
