/**
 * Quorum integration tests.
 *
 * Tests the authorised-submitter ("quorum") model of WorldlineFinalizer.
 * In the Worldline architecture, quorum is enforced by the ZK circuit (the
 * proverSetDigest encodes proverIds, proofSystemIds, and quorumCount). On-chain,
 * WorldlineFinalizer enforces an access-control layer: only registered submitters
 * (or owner) may call submitZkValidityProof when permissionless=false.
 *
 * These tests verify:
 *   - Multiple registered submitters can each contribute proofs.
 *   - Unregistered submitters are rejected (quorum "not met" from chain's view).
 *   - De-registering a submitter removes their ability to submit.
 *   - Re-registering restores submission rights.
 *
 * Each test deploys fresh contracts; no external devnet state is required.
 */

import { expect } from "chai";
import { ethers } from "hardhat";
import { deployAll, makeWindowFixture, GENESIS_L2_BLOCK } from "./helpers";

describe("Quorum — submitter access control", function () {
  // ── 1. Quorum met with exact count ────────────────────────────────────────

  it("quorum met with exact count: 2 submitters each contribute one proof", async function () {
    const [owner, prover1, prover2] = await ethers.getSigners();
    const { finalizer } = await deployAll(owner);

    // Register exactly 2 submitters
    await (await (finalizer as any).setSubmitter(prover1.address, true)).wait();
    await (await (finalizer as any).setSubmitter(prover2.address, true)).wait();

    // Prover 1 → window 0
    const fix0 = await makeWindowFixture(GENESIS_L2_BLOCK, GENESIS_L2_BLOCK + 100n);
    await (await (finalizer as any).connect(prover1).submitZkValidityProof(fix0.proof, fix0.publicInputs)).wait();

    // Prover 2 → window 1 (contiguous)
    const fix1 = await makeWindowFixture(GENESIS_L2_BLOCK + 100n, GENESIS_L2_BLOCK + 200n);
    await (await (finalizer as any).connect(prover2).submitZkValidityProof(fix1.proof, fix1.publicInputs)).wait();

    // Both contributions accepted
    expect(await (finalizer as any).nextWindowIndex()).to.equal(2n);
  });

  // ── 2. Quorum met with excess ──────────────────────────────────────────────

  it("quorum met with excess: 3 submitters each contribute one proof (quorum floor = 2)", async function () {
    const [owner, prover1, prover2, prover3] = await ethers.getSigners();
    const { finalizer } = await deployAll(owner);

    await (await (finalizer as any).setSubmitter(prover1.address, true)).wait();
    await (await (finalizer as any).setSubmitter(prover2.address, true)).wait();
    await (await (finalizer as any).setSubmitter(prover3.address, true)).wait();

    const provers = [prover1, prover2, prover3];
    let cursor = GENESIS_L2_BLOCK;

    for (let i = 0; i < provers.length; i++) {
      const l2End = cursor + 100n;
      const { proof, publicInputs } = await makeWindowFixture(cursor, l2End);
      await (await (finalizer as any).connect(provers[i]).submitZkValidityProof(proof, publicInputs)).wait();
      cursor = l2End;
    }

    // All 3 windows accepted
    expect(await (finalizer as any).nextWindowIndex()).to.equal(3n);
  });

  // ── 3. Quorum not met ─────────────────────────────────────────────────────

  it("quorum not met: unregistered account cannot submit in permissioned mode", async function () {
    const [owner, unregistered] = await ethers.getSigners();
    const { finalizer } = await deployAll(owner);

    // permissionless defaults to false — no submitters registered
    const { proof, publicInputs } = await makeWindowFixture(GENESIS_L2_BLOCK, GENESIS_L2_BLOCK + 100n);

    await expect(
      (finalizer as any).connect(unregistered).submitZkValidityProof(proof, publicInputs)
    ).to.be.revertedWithCustomError(finalizer as any, "NotAuthorized");

    // No windows accepted
    expect(await (finalizer as any).nextWindowIndex()).to.equal(0n);
  });

  // ── 4. Deregister drops below quorum ──────────────────────────────────────

  it("deregistering a submitter prevents further submissions from that account", async function () {
    const [owner, prover1, prover2, prover3] = await ethers.getSigners();
    const { finalizer } = await deployAll(owner);

    await (await (finalizer as any).setSubmitter(prover1.address, true)).wait();
    await (await (finalizer as any).setSubmitter(prover2.address, true)).wait();
    await (await (finalizer as any).setSubmitter(prover3.address, true)).wait();

    // All 3 submit window 0, 1, 2
    const provers = [prover1, prover2, prover3];
    let cursor = GENESIS_L2_BLOCK;
    for (let i = 0; i < provers.length; i++) {
      const l2End = cursor + 100n;
      const { proof, publicInputs } = await makeWindowFixture(cursor, l2End);
      await (await (finalizer as any).connect(provers[i]).submitZkValidityProof(proof, publicInputs)).wait();
      cursor = l2End;
    }

    // Deregister prover3
    await (await (finalizer as any).setSubmitter(prover3.address, false)).wait();
    expect(await (finalizer as any).submitters(prover3.address)).to.be.false;

    // prover3 can no longer submit
    const { proof: proof4, publicInputs: pi4 } = await makeWindowFixture(cursor, cursor + 100n);
    await expect(
      (finalizer as any).connect(prover3).submitZkValidityProof(proof4, pi4)
    ).to.be.revertedWithCustomError(finalizer as any, "NotAuthorized");

    // prover1 (still registered) can submit the next window
    const { proof: proof4b, publicInputs: pi4b } = await makeWindowFixture(cursor, cursor + 100n);
    await (await (finalizer as any).connect(prover1).submitZkValidityProof(proof4b, pi4b)).wait();
    expect(await (finalizer as any).nextWindowIndex()).to.equal(4n);
  });

  // ── 5. Re-register restores quorum ────────────────────────────────────────

  it("re-registering a deregistered submitter restores their submission rights", async function () {
    const [owner, prover1] = await ethers.getSigners();
    const { finalizer } = await deployAll(owner);

    await (await (finalizer as any).setSubmitter(prover1.address, true)).wait();

    // Submit window 0
    const fix0 = await makeWindowFixture(GENESIS_L2_BLOCK, GENESIS_L2_BLOCK + 100n);
    await (await (finalizer as any).connect(prover1).submitZkValidityProof(fix0.proof, fix0.publicInputs)).wait();

    // Deregister prover1
    await (await (finalizer as any).setSubmitter(prover1.address, false)).wait();

    // Submission reverts while deregistered
    const fix1 = await makeWindowFixture(GENESIS_L2_BLOCK + 100n, GENESIS_L2_BLOCK + 200n);
    await expect(
      (finalizer as any).connect(prover1).submitZkValidityProof(fix1.proof, fix1.publicInputs)
    ).to.be.revertedWithCustomError(finalizer as any, "NotAuthorized");

    // Re-register prover1
    await (await (finalizer as any).setSubmitter(prover1.address, true)).wait();
    expect(await (finalizer as any).submitters(prover1.address)).to.be.true;

    // Submission succeeds again (window 1 is still available)
    await (await (finalizer as any).connect(prover1).submitZkValidityProof(fix1.proof, fix1.publicInputs)).wait();
    expect(await (finalizer as any).nextWindowIndex()).to.equal(2n);
  });
});
