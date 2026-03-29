/**
 * Prover API end-to-end encoding tests.
 *
 * Validates the full proof submission path for all three proof systems
 * (Groth16, Plonk, Halo2) through submitZkValidityProofRouted, including
 * encoding correctness, event emission, sequential window advancement,
 * and rejection of malformed inputs.
 */

import { expect } from "chai";
import { ethers } from "hardhat";
import {
  deployAllWithThreeAdapters,
  makeWindowFixture,
  makePlonkWindowFixture,
  makeHalo2WindowFixture,
  encodeProof,
  encodePlonkProof,
  encodeHalo2Proof,
  encodePublicInputs,
  computeStfCommitment,
  findEventLog,
  DOMAIN,
  PROGRAM_VKEY,
  POLICY_HASH,
  PROVER_SET_DIGEST,
  GENESIS_L2_BLOCK,
  HALO2_RAW_PROOF_BYTE_SIZE
} from "./deployment-fixtures";

// ── Tests ──────────────────────────────────────────────────────────────────

describe("Prover API — end-to-end encoding", function () {
  // ── 1. Groth16 full encoding path ──────────────────────────────────────

  it("Groth16 proof (ID=1) via submitZkValidityProofRouted — full encoding path", async function () {
    const [owner] = await ethers.getSigners();
    const { finalizer } = await deployAllWithThreeAdapters(owner);

    const { proof, publicInputs } = await makeWindowFixture(
      GENESIS_L2_BLOCK,
      GENESIS_L2_BLOCK + 100n
    );

    const tx = await (finalizer as any).submitZkValidityProofRouted(1, proof, publicInputs);
    const receipt = await tx.wait();

    const log = findEventLog(receipt, (finalizer as any).interface, "ZkProofAccepted");
    expect(log).to.not.be.null;
    expect(log.args.windowIndex).to.equal(0n);
    expect(log.args.programVKey).to.equal(PROGRAM_VKEY);
    expect(log.args.policyHash).to.equal(POLICY_HASH);

    expect(await (finalizer as any).nextWindowIndex()).to.equal(1n);
  });

  // ── 2. Plonk full encoding path ────────────────────────────────────────

  it("Plonk proof (ID=2) via submitZkValidityProofRouted — full encoding path", async function () {
    const [owner] = await ethers.getSigners();
    const { finalizer } = await deployAllWithThreeAdapters(owner);

    const { proof, publicInputs } = await makePlonkWindowFixture(
      GENESIS_L2_BLOCK,
      GENESIS_L2_BLOCK + 100n
    );

    const tx = await (finalizer as any).submitZkValidityProofRouted(2, proof, publicInputs);
    const receipt = await tx.wait();

    const log = findEventLog(receipt, (finalizer as any).interface, "ZkProofAccepted");
    expect(log).to.not.be.null;
    expect(log.args.windowIndex).to.equal(0n);
    expect(log.args.programVKey).to.equal(PROGRAM_VKEY);
    expect(log.args.policyHash).to.equal(POLICY_HASH);

    expect(await (finalizer as any).nextWindowIndex()).to.equal(1n);
  });

  // ── 3. Halo2 full encoding path ────────────────────────────────────────

  it("Halo2 proof (ID=3) via submitZkValidityProofRouted — full encoding path", async function () {
    const [owner] = await ethers.getSigners();
    const { finalizer } = await deployAllWithThreeAdapters(owner);

    const { proof, publicInputs } = await makeHalo2WindowFixture(
      GENESIS_L2_BLOCK,
      GENESIS_L2_BLOCK + 100n
    );

    const tx = await (finalizer as any).submitZkValidityProofRouted(3, proof, publicInputs);
    const receipt = await tx.wait();

    const log = findEventLog(receipt, (finalizer as any).interface, "ZkProofAccepted");
    expect(log).to.not.be.null;
    expect(log.args.windowIndex).to.equal(0n);
    expect(log.args.programVKey).to.equal(PROGRAM_VKEY);
    expect(log.args.policyHash).to.equal(POLICY_HASH);

    expect(await (finalizer as any).nextWindowIndex()).to.equal(1n);
  });

  // ── 4. All three proof systems accept sequential windows ───────────────

  it("all three proof systems accept sequential windows for same inputs", async function () {
    const [owner] = await ethers.getSigners();
    const { finalizer } = await deployAllWithThreeAdapters(owner);

    // Window 0 — Groth16 (ID=1)
    const fix0 = await makeWindowFixture(GENESIS_L2_BLOCK, GENESIS_L2_BLOCK + 100n);
    const r0 = await (
      await (finalizer as any).submitZkValidityProofRouted(1, fix0.proof, fix0.publicInputs)
    ).wait();
    expect(
      findEventLog(r0, (finalizer as any).interface, "ZkProofAccepted")?.args.windowIndex
    ).to.equal(0n);

    // Window 1 — Plonk (ID=2)
    const fix1 = await makePlonkWindowFixture(GENESIS_L2_BLOCK + 100n, GENESIS_L2_BLOCK + 200n);
    const r1 = await (
      await (finalizer as any).submitZkValidityProofRouted(2, fix1.proof, fix1.publicInputs)
    ).wait();
    expect(
      findEventLog(r1, (finalizer as any).interface, "ZkProofAccepted")?.args.windowIndex
    ).to.equal(1n);

    // Window 2 — Halo2 (ID=3)
    const fix2 = await makeHalo2WindowFixture(GENESIS_L2_BLOCK + 200n, GENESIS_L2_BLOCK + 300n);
    const r2 = await (
      await (finalizer as any).submitZkValidityProofRouted(3, fix2.proof, fix2.publicInputs)
    ).wait();
    expect(
      findEventLog(r2, (finalizer as any).interface, "ZkProofAccepted")?.args.windowIndex
    ).to.equal(2n);

    // All three windows accepted — nextWindowIndex advanced to 3
    expect(await (finalizer as any).nextWindowIndex()).to.equal(3n);
  });

  // ── 5. publicInputs word 7 (submissionBinding) is verified on-chain ────

  it("publicInputs word 7 (submissionBinding) is verified on-chain", async function () {
    const [owner] = await ethers.getSigners();
    const { finalizer } = await deployAllWithThreeAdapters(owner);

    const block = await ethers.provider.getBlock("latest");
    const wct = BigInt(block!.timestamp) + 7200n;
    const l2Start = GENESIS_L2_BLOCK;
    const l2End = l2Start + 100n;

    const proof = encodeProof(l2Start, l2End, wct);

    // Build publicInputs with a tampered word 7 (submissionBinding)
    const stfCommitment = computeStfCommitment(l2Start, l2End, wct);
    const tamperedBinding = ethers.keccak256(ethers.toUtf8Bytes("tampered-binding"));
    const publicInputs = ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "uint256", "uint256", "bytes32", "bytes32", "bytes32", "uint256", "bytes32"],
      [
        stfCommitment,
        l2Start,
        l2End,
        ethers.ZeroHash,
        ethers.ZeroHash,
        DOMAIN,
        wct,
        tamperedBinding // word 7 — should mismatch the expected binding
      ]
    );

    await expect(
      (finalizer as any).submitZkValidityProofRouted(1, proof, publicInputs)
    ).to.be.revertedWithCustomError(finalizer as any, "StfBindingMismatch");
  });

  // ── 6. stfCommitment mismatch between proof and publicInputs ───────────

  it("stfCommitment mismatch between proof and publicInputs is rejected", async function () {
    const [owner] = await ethers.getSigners();
    const { finalizer } = await deployAllWithThreeAdapters(owner);

    const block = await ethers.provider.getBlock("latest");
    const wct = BigInt(block!.timestamp) + 7200n;
    const l2Start = GENESIS_L2_BLOCK;
    const l2End = l2Start + 100n;

    // Encode proof with one stfCommitment (from different l2End)
    const proofWithWrongStf = encodeProof(l2Start, l2End + 50n, wct);

    // Encode publicInputs with the correct stfCommitment
    const publicInputs = encodePublicInputs(l2Start, l2End, wct);

    await expect(
      (finalizer as any).submitZkValidityProofRouted(1, proofWithWrongStf, publicInputs)
    ).to.be.revertedWithCustomError(finalizer as any, "StfMismatch");
  });

  // ── 7. publicInputs must be exactly 256 bytes ─────────────────────────

  it("publicInputs must be exactly 256 bytes", async function () {
    const [owner] = await ethers.getSigners();
    const { finalizer } = await deployAllWithThreeAdapters(owner);

    const { proof } = await makeWindowFixture(GENESIS_L2_BLOCK, GENESIS_L2_BLOCK + 100n);

    // Construct a too-short publicInputs (only 7 words = 224 bytes instead of 8 words = 256 bytes)
    const shortPublicInputs = ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "uint256", "uint256", "bytes32", "bytes32", "bytes32", "uint256"],
      [ethers.ZeroHash, 0n, 100n, ethers.ZeroHash, ethers.ZeroHash, DOMAIN, 9999n]
    );

    await expect(
      (finalizer as any).submitZkValidityProofRouted(1, proof, shortPublicInputs)
    ).to.be.revertedWithCustomError(finalizer as any, "BadInputsLen");
  });

  // ── 8. Halo2 proof encoding matches HALO2_PROOF_MIN_LEN floor ─────────

  it("Halo2 proof encoding matches HALO2_PROOF_MIN_LEN floor", async function () {
    const [owner] = await ethers.getSigners();
    const { halo2Adapter } = await deployAllWithThreeAdapters(owner);

    const block = await ethers.provider.getBlock("latest");
    const wct = BigInt(block!.timestamp) + 7200n;
    const l2Start = GENESIS_L2_BLOCK;
    const l2End = l2Start + 100n;

    const encodedProof = encodeHalo2Proof(l2Start, l2End, wct);

    // Read the on-chain constant from the deployed adapter
    const minLen = await (halo2Adapter as any).HALO2_PROOF_MIN_LEN();
    expect(minLen).to.equal(1600n);

    // The ABI-encoded Halo2 proof must be >= 1600 bytes (HALO2_PROOF_MIN_LEN)
    // Remove 0x prefix for byte length calculation
    const proofByteLength = (encodedProof.length - 2) / 2;
    expect(proofByteLength).to.be.gte(Number(minLen));
  });
});
