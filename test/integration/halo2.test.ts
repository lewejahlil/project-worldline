/**
 * Halo2 verifier integration tests.
 *
 * Exercises:
 *   1. Full stack deploy with all 3 proof system adapters
 *   2. Router registration for Groth16 (ID=1) and Halo2 (ID=3)
 *   3. Proof routing through each adapter
 *   4. Multi-prover heterogeneous submission
 */

import { expect } from "chai";
import { ethers } from "hardhat";
import {
  deployAllWithRouter,
  makeWindowFixture,
  findEventLog,
  GENESIS_L2_BLOCK,
  PROGRAM_VKEY,
  POLICY_HASH,
  computeStfCommitment,
  enablePermissionless
} from "./deployment-fixtures";

/**
 * Encode a Halo2 proof envelope matching the Halo2ZkAdapter format:
 *   abi.encode(bytes proofBytes, uint256 stfCommitment, uint256 proverSetDigest)
 *
 * The stfCommitment embedded in the proof must match the one in publicInputs
 * for the finalizer's StfMismatch check.
 */
function encodeHalo2ProofEnvelope(stfCommitment: string, proverSetDigest: string): string {
  // Create fake proof bytes of the expected length (1472 bytes)
  const proofBytes = ethers.hexlify(ethers.randomBytes(1472));
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["bytes", "uint256", "uint256"],
    [proofBytes, BigInt(stfCommitment), BigInt(proverSetDigest)]
  );
}

describe("Halo2 verifier integration", function () {
  this.timeout(120_000);

  // ── 1. Deploy full stack with all adapters ────────────────────────────────

  it("deploys full stack with Groth16 + Halo2 adapters registered", async function () {
    const [owner] = await ethers.getSigners();
    const { router } = await deployAllWithRouter(owner);

    // Deploy Halo2Verifier in mock mode
    const Halo2Verifier = await ethers.getContractFactory("Halo2Verifier", owner);
    const halo2Verifier = await Halo2Verifier.deploy(true);
    await halo2Verifier.waitForDeployment();

    // Deploy Halo2ZkAdapter
    const Halo2Adapter = await ethers.getContractFactory("Halo2ZkAdapter", owner);
    const halo2Adapter = await Halo2Adapter.deploy(
      await halo2Verifier.getAddress(),
      PROGRAM_VKEY,
      POLICY_HASH
    );
    await halo2Adapter.waitForDeployment();

    // Register Halo2 adapter at ID=3
    await (await (router as any).registerAdapter(3, await halo2Adapter.getAddress())).wait();

    // Verify both are registered
    expect(await (router as any).isSupported(1)).to.equal(true); // Groth16
    expect(await (router as any).isSupported(3)).to.equal(true); // Halo2
    expect(await (router as any).isSupported(2)).to.equal(false); // Plonk not yet
  });

  // ── 2. Router reports supported proof systems ─────────────────────────────

  it("router reports [1, 3] as supported proof systems after registration", async function () {
    const [owner] = await ethers.getSigners();
    const { router } = await deployAllWithRouter(owner);

    // Deploy and register Halo2 adapter
    const Halo2Verifier = await ethers.getContractFactory("Halo2Verifier", owner);
    const halo2Verifier = await Halo2Verifier.deploy(true);
    await halo2Verifier.waitForDeployment();

    const Halo2Adapter = await ethers.getContractFactory("Halo2ZkAdapter", owner);
    const halo2Adapter = await Halo2Adapter.deploy(
      await halo2Verifier.getAddress(),
      PROGRAM_VKEY,
      POLICY_HASH
    );
    await halo2Adapter.waitForDeployment();
    await (await (router as any).registerAdapter(3, await halo2Adapter.getAddress())).wait();

    const supported: number[] = [];
    for (let id = 0; id <= 5; id++) {
      if (await (router as any).isSupported(id)) supported.push(id);
    }
    expect(supported).to.deep.equal([1, 3]);
  });

  // ── 3. Submit Groth16 proof via ID=1 — regression test ────────────────────

  it("submits Groth16 proof via ID=1 through router (regression)", async function () {
    const [owner] = await ethers.getSigners();
    const { finalizer } = await deployAllWithRouter(owner);
    await enablePermissionless(finalizer);

    const { proof, publicInputs } = await makeWindowFixture(
      GENESIS_L2_BLOCK,
      GENESIS_L2_BLOCK + 100n
    );

    await expect((finalizer as any).submitZkValidityProofRouted(1, proof, publicInputs)).to.not.be
      .reverted;

    expect(await (finalizer as any).nextWindowIndex()).to.equal(1n);
  });

  // ── 4. Submit Halo2 proof via ID=3 — succeeds ────────────────────────────

  it("submits Halo2 proof via ID=3 through router", async function () {
    const [owner] = await ethers.getSigners();
    const { finalizer, router } = await deployAllWithRouter(owner);
    await enablePermissionless(finalizer);

    // Deploy Halo2 stack
    const Halo2Verifier = await ethers.getContractFactory("Halo2Verifier", owner);
    const halo2Verifier = await Halo2Verifier.deploy(true);
    await halo2Verifier.waitForDeployment();

    const Halo2Adapter = await ethers.getContractFactory("Halo2ZkAdapter", owner);
    const halo2Adapter = await Halo2Adapter.deploy(
      await halo2Verifier.getAddress(),
      PROGRAM_VKEY,
      POLICY_HASH
    );
    await halo2Adapter.waitForDeployment();
    await (await (router as any).registerAdapter(3, await halo2Adapter.getAddress())).wait();

    // Build the Halo2 proof envelope
    const block = await ethers.provider.getBlock("latest");
    const windowCloseTimestamp = BigInt(block!.timestamp) + 7200n;
    const stfCommitment = computeStfCommitment(
      GENESIS_L2_BLOCK,
      GENESIS_L2_BLOCK + 100n,
      windowCloseTimestamp
    );
    const proverSetDigest = ethers.keccak256(ethers.toUtf8Bytes("halo2-prover-set"));

    const halo2Proof = encodeHalo2ProofEnvelope(stfCommitment, proverSetDigest);

    // Encode public inputs (8 words: stfCommitment, l2Start, l2End, outputRoot, l1Hash, domain, ts, submissionBinding)
    const publicInputs = ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "uint256", "uint256", "bytes32", "bytes32", "bytes32", "uint256", "bytes32"],
      [
        stfCommitment,
        GENESIS_L2_BLOCK,
        GENESIS_L2_BLOCK + 100n,
        ethers.ZeroHash,
        ethers.ZeroHash,
        ethers.keccak256(ethers.toUtf8Bytes("integration-test-domain")),
        windowCloseTimestamp,
        stfCommitment // submissionBinding = keccak256(words 1–6) = stfCommitment for zero outputRoot/l1Hash
      ]
    );

    const tx = await (finalizer as any).submitZkValidityProofRouted(3, halo2Proof, publicInputs);
    const receipt = await tx.wait();

    const acceptedLog = findEventLog(receipt, (finalizer as any).interface, "ZkProofAccepted");

    expect(acceptedLog).to.not.be.null;
    expect(acceptedLog.args.windowIndex).to.equal(0n);
    expect(acceptedLog.args.programVKey).to.equal(PROGRAM_VKEY);
    expect(acceptedLog.args.policyHash).to.equal(POLICY_HASH);

    expect(await (finalizer as any).nextWindowIndex()).to.equal(1n);
  });

  // ── 5. Halo2ZkAdapter proofSystemId and expectedProofLength ───────────────

  it("Halo2ZkAdapter reports proofSystemId=3 and expectedProofLength=1600", async function () {
    const [owner] = await ethers.getSigners();

    const Halo2Verifier = await ethers.getContractFactory("Halo2Verifier", owner);
    const halo2Verifier = await Halo2Verifier.deploy(true);
    await halo2Verifier.waitForDeployment();

    const Halo2Adapter = await ethers.getContractFactory("Halo2ZkAdapter", owner);
    const halo2Adapter = await Halo2Adapter.deploy(
      await halo2Verifier.getAddress(),
      PROGRAM_VKEY,
      POLICY_HASH
    );
    await halo2Adapter.waitForDeployment();

    expect(await halo2Adapter.proofSystemId()).to.equal(3);
    expect(await halo2Adapter.expectedProofLength()).to.equal(1600);
  });

  // ── 6. Multi-prover: Groth16 + Halo2 sequential submission ───────────────

  it("submits Groth16 then Halo2 proofs for sequential windows", async function () {
    const [owner] = await ethers.getSigners();
    const { finalizer, router } = await deployAllWithRouter(owner);
    await enablePermissionless(finalizer);

    // Deploy Halo2 stack
    const Halo2Verifier = await ethers.getContractFactory("Halo2Verifier", owner);
    const halo2Verifier = await Halo2Verifier.deploy(true);
    await halo2Verifier.waitForDeployment();

    const Halo2Adapter = await ethers.getContractFactory("Halo2ZkAdapter", owner);
    const halo2Adapter = await Halo2Adapter.deploy(
      await halo2Verifier.getAddress(),
      PROGRAM_VKEY,
      POLICY_HASH
    );
    await halo2Adapter.waitForDeployment();
    await (await (router as any).registerAdapter(3, await halo2Adapter.getAddress())).wait();

    // Window 0: Groth16 (ID=1)
    const { proof: groth16Proof, publicInputs: groth16Inputs } = await makeWindowFixture(
      GENESIS_L2_BLOCK,
      GENESIS_L2_BLOCK + 100n
    );
    await (finalizer as any).submitZkValidityProofRouted(1, groth16Proof, groth16Inputs);
    expect(await (finalizer as any).nextWindowIndex()).to.equal(1n);

    // Window 1: Halo2 (ID=3)
    const block = await ethers.provider.getBlock("latest");
    const windowCloseTimestamp = BigInt(block!.timestamp) + 7200n;
    const l2Start = GENESIS_L2_BLOCK + 100n;
    const l2End = l2Start + 100n;
    const stfCommitment = computeStfCommitment(l2Start, l2End, windowCloseTimestamp);
    const proverSetDigest = ethers.keccak256(ethers.toUtf8Bytes("halo2-digest"));

    const halo2Proof = encodeHalo2ProofEnvelope(stfCommitment, proverSetDigest);
    const halo2Inputs = ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "uint256", "uint256", "bytes32", "bytes32", "bytes32", "uint256", "bytes32"],
      [
        stfCommitment,
        l2Start,
        l2End,
        ethers.ZeroHash,
        ethers.ZeroHash,
        ethers.keccak256(ethers.toUtf8Bytes("integration-test-domain")),
        windowCloseTimestamp,
        stfCommitment // submissionBinding = keccak256(words 1–6) = stfCommitment for zero outputRoot/l1Hash
      ]
    );

    await (finalizer as any).submitZkValidityProofRouted(3, halo2Proof, halo2Inputs);
    expect(await (finalizer as any).nextWindowIndex()).to.equal(2n);
  });

  // ── 7. Router thin path: routeProof for Halo2 ────────────────────────────

  it("routeProof thin path works for Halo2 adapter", async function () {
    const [owner] = await ethers.getSigners();
    const { router } = await deployAllWithRouter(owner);

    // Deploy Halo2 stack
    const Halo2Verifier = await ethers.getContractFactory("Halo2Verifier", owner);
    const halo2Verifier = await Halo2Verifier.deploy(true);
    await halo2Verifier.waitForDeployment();

    const Halo2Adapter = await ethers.getContractFactory("Halo2ZkAdapter", owner);
    const halo2Adapter = await Halo2Adapter.deploy(
      await halo2Verifier.getAddress(),
      PROGRAM_VKEY,
      POLICY_HASH
    );
    await halo2Adapter.waitForDeployment();
    await (await (router as any).registerAdapter(3, await halo2Adapter.getAddress())).wait();

    // Create proof envelope
    const stfVal = ethers.keccak256(ethers.toUtf8Bytes("stf-thin"));
    const digestVal = ethers.keccak256(ethers.toUtf8Bytes("digest-thin"));
    const proof = encodeHalo2ProofEnvelope(stfVal, digestVal);

    const tx = await (router as any).routeProof(3, proof, []);
    const receipt = await tx.wait();

    const routedLog = findEventLog(receipt, (router as any).interface, "ProofRouted");

    expect(routedLog).to.not.be.null;
    expect(routedLog.args.proofSystemId).to.equal(3);
    expect(routedLog.args.result).to.equal(true);
  });
});
