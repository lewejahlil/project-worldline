/**
 * Plonk adapter integration tests.
 *
 * Exercises PlonkZkAdapter registration in ProofRouter and end-to-end proof
 * submission via WorldlineFinalizer.submitZkValidityProofRouted().
 */

import { expect } from "chai";
import { ethers } from "hardhat";
import {
  deployAllWithPlonkRouter,
  makeWindowFixture,
  makePlonkWindowFixture,
  findEventLog,
  GENESIS_L2_BLOCK,
  PROGRAM_VKEY,
  POLICY_HASH,
  enablePermissionless
} from "./deployment-fixtures";

describe("Plonk adapter", function () {
  // ── 1. Deploy full stack with Groth16 + Plonk adapters ───────────────────

  it("deploys full stack with Groth16 (ID=1) and Plonk (ID=2) adapters registered", async function () {
    const [owner] = await ethers.getSigners();
    const { router, adapter, plonkAdapter } = await deployAllWithPlonkRouter(owner);

    // Groth16 at ID=1
    expect(await (router as any).isSupported(1)).to.equal(true);
    expect(await (router as any).getAdapter(1)).to.equal(await (adapter as any).getAddress());

    // Plonk at ID=2
    expect(await (router as any).isSupported(2)).to.equal(true);
    expect(await (router as any).getAdapter(2)).to.equal(await (plonkAdapter as any).getAddress());
  });

  // ── 2. Router reports ID=1 supported ─────────────────────────────────────

  it("router reports ID=1 (Groth16) supported", async function () {
    const [owner] = await ethers.getSigners();
    const { router } = await deployAllWithPlonkRouter(owner);
    expect(await (router as any).isSupported(1)).to.equal(true);
  });

  // ── 3. Router reports ID=2 supported ─────────────────────────────────────

  it("router reports ID=2 (Plonk) supported", async function () {
    const [owner] = await ethers.getSigners();
    const { router } = await deployAllWithPlonkRouter(owner);
    expect(await (router as any).isSupported(2)).to.equal(true);
  });

  // ── 4. Router reports [1, 2] as supported (IDs 0–5) ──────────────────────

  it("router reports exactly [1, 2] supported when scanning IDs 0–5", async function () {
    const [owner] = await ethers.getSigners();
    const { router } = await deployAllWithPlonkRouter(owner);

    const supported: number[] = [];
    for (let id = 0; id <= 5; id++) {
      if (await (router as any).isSupported(id)) supported.push(id);
    }
    expect(supported).to.deep.equal([1, 2]);
  });

  // ── 5. Submit Groth16 proof via ID=1 — succeeds (regression) ─────────────

  it("submits Groth16 proof via ID=1 — emits ZkProofAccepted (regression)", async function () {
    const [owner] = await ethers.getSigners();
    const { finalizer } = await deployAllWithPlonkRouter(owner);

    await enablePermissionless(finalizer);

    const { proof, publicInputs } = await makeWindowFixture(
      GENESIS_L2_BLOCK,
      GENESIS_L2_BLOCK + 100n
    );

    const tx = await (finalizer as any).submitZkValidityProofRouted(1, proof, publicInputs);
    const receipt = await tx.wait();

    const acceptedLog = findEventLog(receipt, (finalizer as any).interface, "ZkProofAccepted");

    expect(acceptedLog).to.not.be.null;
    expect(acceptedLog.args.windowIndex).to.equal(0n);
    expect(acceptedLog.args.programVKey).to.equal(PROGRAM_VKEY);
    expect(acceptedLog.args.policyHash).to.equal(POLICY_HASH);
    expect(await (finalizer as any).nextWindowIndex()).to.equal(1n);
  });

  // ── 6. Submit Plonk proof via ID=2 — thin path via routeProof ────────────

  it("submits Plonk proof via routeProof(2) on router — returns true (thin path)", async function () {
    const [owner] = await ethers.getSigners();
    const { router } = await deployAllWithPlonkRouter(owner);

    const { proof } = await makePlonkWindowFixture(GENESIS_L2_BLOCK, GENESIS_L2_BLOCK + 100n);

    // Call routeProof directly (thin path — just verifies the adapter is wired)
    const tx = await (router as any).routeProof(2, proof, []);
    const receipt = await tx.wait();

    const routedLog = findEventLog(receipt, (router as any).interface, "ProofRouted");

    expect(routedLog).to.not.be.null;
    expect(routedLog.args.proofSystemId).to.equal(2);
    expect(routedLog.args.result).to.equal(true);
  });

  // ── 7. Submit Plonk proof via ID=2 through finalizer — emits ZkProofAccepted

  it("submits Plonk proof via ID=2 through finalizer — emits ZkProofAccepted", async function () {
    const [owner] = await ethers.getSigners();
    const { finalizer } = await deployAllWithPlonkRouter(owner);

    await enablePermissionless(finalizer);

    const { proof, publicInputs } = await makePlonkWindowFixture(
      GENESIS_L2_BLOCK,
      GENESIS_L2_BLOCK + 100n
    );

    const tx = await (finalizer as any).submitZkValidityProofRouted(2, proof, publicInputs);
    const receipt = await tx.wait();

    const acceptedLog = findEventLog(receipt, (finalizer as any).interface, "ZkProofAccepted");

    expect(acceptedLog).to.not.be.null;
    expect(acceptedLog.args.windowIndex).to.equal(0n);
    expect(acceptedLog.args.programVKey).to.equal(PROGRAM_VKEY);
    expect(acceptedLog.args.policyHash).to.equal(POLICY_HASH);
    expect(await (finalizer as any).nextWindowIndex()).to.equal(1n);
  });

  // ── 8. Submit proof with ID=3 (Halo2, not registered) — reverts ──────────

  it("submitting with unregistered proofSystemId=3 reverts with AdapterNotRegistered", async function () {
    const [owner] = await ethers.getSigners();
    const { finalizer } = await deployAllWithPlonkRouter(owner);

    await enablePermissionless(finalizer);

    const { proof, publicInputs } = await makePlonkWindowFixture(
      GENESIS_L2_BLOCK,
      GENESIS_L2_BLOCK + 100n
    );

    await expect(
      (finalizer as any).submitZkValidityProofRouted(3, proof, publicInputs)
    ).to.be.revertedWithCustomError(
      await ethers.getContractAt("ProofRouter", await (finalizer as any).proofRouter()),
      "AdapterNotRegistered"
    );
  });
});
