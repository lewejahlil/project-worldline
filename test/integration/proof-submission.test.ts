/**
 * Proof-submission integration tests.
 *
 * Verifies the input-validation and access-control rules enforced by
 * WorldlineFinalizer._submit() and Groth16ZkAdapter.verify().
 *
 * Each test deploys fresh contracts; no shared devnet state is required.
 */

import { expect } from "chai";
import { ethers } from "hardhat";
import {
  deployAll,
  makeWindowFixture,
  GENESIS_L2_BLOCK,
  DOMAIN,
  PROVER_SET_DIGEST
} from "./helpers";

describe("Proof submission", function () {
  // ── 1. Valid 320-byte Groth16 proof accepted ──────────────────────────────

  it("valid 320-byte Groth16 proof is accepted without reverting", async function () {
    const [owner] = await ethers.getSigners();
    const { finalizer } = await deployAll(owner);
    await (await (finalizer as any).setPermissionless(true)).wait();

    const { proof, publicInputs } = await makeWindowFixture(
      GENESIS_L2_BLOCK,
      GENESIS_L2_BLOCK + 100n
    );

    // Proof must be exactly 10 × 32 = 320 bytes ABI-encoded
    // ABI encoding adds a 32-byte length prefix per dynamic element; the raw payload is 320 bytes.
    // The adapter enforces PROD_PROOF_MIN_LEN = 320.
    await expect((finalizer as any).submitZkValidityProof(proof, publicInputs)).to.not.be.reverted;

    expect(await (finalizer as any).nextWindowIndex()).to.equal(1n);
  });

  // ── 2. Invalid proof length rejected ─────────────────────────────────────

  it("proof shorter than 320 bytes is rejected with ProofTooShort", async function () {
    const [owner] = await ethers.getSigners();
    const { adapter, finalizer } = await deployAll(owner);
    await (await (finalizer as any).setPermissionless(true)).wait();

    const { publicInputs } = await makeWindowFixture(GENESIS_L2_BLOCK, GENESIS_L2_BLOCK + 100n);

    // 128-byte proof (4 × 32 words) — well below the 320-byte minimum
    const shortProof = ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256[2]", "uint256[2]"],
      [
        [1n, 2n],
        [3n, 4n]
      ]
    );
    expect(ethers.getBytes(shortProof).length).to.equal(128);

    await expect(
      (finalizer as any).submitZkValidityProof(shortProof, publicInputs)
    ).to.be.revertedWithCustomError(adapter as any, "ProofTooShort");
  });

  // ── 3. Unregistered prover rejected ───────────────────────────────────────

  it("submission from an unregistered account reverts with NotAuthorized", async function () {
    const [owner, unregistered] = await ethers.getSigners();
    const { finalizer } = await deployAll(owner);
    // permissionless defaults to false; unregistered is neither owner nor submitter

    const { proof, publicInputs } = await makeWindowFixture(
      GENESIS_L2_BLOCK,
      GENESIS_L2_BLOCK + 100n
    );

    await expect(
      (finalizer as any).connect(unregistered).submitZkValidityProof(proof, publicInputs)
    ).to.be.revertedWithCustomError(finalizer as any, "NotAuthorized");
  });

  // ── 4. Deregistered prover rejected ───────────────────────────────────────

  it("deregistered prover cannot submit after being removed", async function () {
    const [owner, prover] = await ethers.getSigners();
    const { finalizer } = await deployAll(owner);

    // Register and submit window 0
    await (await (finalizer as any).setSubmitter(prover.address, true)).wait();
    const fix0 = await makeWindowFixture(GENESIS_L2_BLOCK, GENESIS_L2_BLOCK + 100n);
    await (
      await (finalizer as any).connect(prover).submitZkValidityProof(fix0.proof, fix0.publicInputs)
    ).wait();

    // Deregister
    await (await (finalizer as any).setSubmitter(prover.address, false)).wait();
    expect(await (finalizer as any).submitters(prover.address)).to.be.false;

    // Window 1 attempt from deregistered prover reverts
    const fix1 = await makeWindowFixture(GENESIS_L2_BLOCK + 100n, GENESIS_L2_BLOCK + 200n);
    await expect(
      (finalizer as any).connect(prover).submitZkValidityProof(fix1.proof, fix1.publicInputs)
    ).to.be.revertedWithCustomError(finalizer as any, "NotAuthorized");
  });

  // ── 5. Duplicate proof from same prover ───────────────────────────────────

  it("submitting the same proof+inputs twice fails on the second attempt", async function () {
    // NOTE: WorldlineFinalizer does not have a dedicated duplicate-proof guard.
    // The contiguity invariant (l2Start must equal lastL2EndBlock after the first
    // window) naturally prevents replay: the second identical submission carries
    // l2Start = genesisL2Block (0), but after window 0 lastL2EndBlock = 100, so
    // the check `l2Start != lastL2EndBlock` fires as NotContiguous.
    // This constitutes an implicit replay defence; ProofConsumed events provide
    // an off-chain audit trail (NUL-1 hardening).
    const [owner] = await ethers.getSigners();
    const { finalizer } = await deployAll(owner);
    await (await (finalizer as any).setPermissionless(true)).wait();

    const { proof, publicInputs } = await makeWindowFixture(
      GENESIS_L2_BLOCK,
      GENESIS_L2_BLOCK + 100n
    );

    // First submission succeeds
    await expect((finalizer as any).submitZkValidityProof(proof, publicInputs)).to.not.be.reverted;

    // Second identical submission reverts (NotContiguous: l2Start=0 != lastL2EndBlock=100)
    await expect(
      (finalizer as any).submitZkValidityProof(proof, publicInputs)
    ).to.be.revertedWithCustomError(finalizer as any, "NotContiguous");
  });
});
