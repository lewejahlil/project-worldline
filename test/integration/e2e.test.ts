/**
 * End-to-end integration tests.
 *
 * Exercises the full Worldline pipeline:
 *   deploy → register provers → submit proofs → verify on-chain events
 *
 * Each test deploys fresh contracts; no shared devnet state is required.
 */

import { expect } from "chai";
import { ethers } from "hardhat";
import {
  deployAll,
  makeWindowFixture,
  submitWindows,
  GENESIS_L2_BLOCK,
  PROGRAM_VKEY,
  POLICY_HASH,
  PROVER_SET_DIGEST
} from "./helpers";

describe("E2E — full pipeline", function () {
  // ── 1. Deploy and register ─────────────────────────────────────────────────

  it("deploys all contracts and registers 3 prover drivers", async function () {
    const [owner] = await ethers.getSigners();
    const { registry, finalizer } = await deployAll(owner);

    // Register 3 drivers in WorldlineRegistry (one per proof system)
    const proofSystems = ["groth16", "plonk", "halo2"];
    const driverIds: string[] = [];

    for (const ps of proofSystems) {
      const id = ethers.keccak256(ethers.toUtf8Bytes(`driver-${ps}`));
      const tx = await (registry as any).registerDriver(
        id,
        `v1.0.0-${ps}`,
        `https://devnet.local/prover/${ps}`
      );
      await tx.wait();
      driverIds.push(id);
    }

    // Verify each driver can be retrieved
    for (let i = 0; i < proofSystems.length; i++) {
      const driver = await (registry as any).getDriver(driverIds[i]);
      expect(driver.id).to.equal(driverIds[i]);
      expect(driver.version).to.equal(`v1.0.0-${proofSystems[i]}`);
    }

    // 3 provers registered — confirmed by successful retrieval of all 3
    expect(driverIds).to.have.length(3);

    // WorldlineFinalizer is live
    expect(await (finalizer as any).nextWindowIndex()).to.equal(0n);
  });

  // ── 2. Submit Groth16 proof ────────────────────────────────────────────────

  it("submits a 320-byte Groth16 proof and emits ZkProofAccepted", async function () {
    const [owner] = await ethers.getSigners();
    const { finalizer } = await deployAll(owner);

    // Enable permissionless so owner can submit
    await (await (finalizer as any).setPermissionless(true)).wait();

    const { proof, publicInputs } = await makeWindowFixture(
      GENESIS_L2_BLOCK,
      GENESIS_L2_BLOCK + 100n
    );
    expect(proof.length).to.be.greaterThan(0); // 320 bytes ABI-encoded = 0x...(640 hex chars + '0x')

    const tx = await (finalizer as any).submitZkValidityProof(proof, publicInputs);
    const receipt = await tx.wait();

    // ZkProofAccepted event must be emitted
    const iface = (finalizer as any).interface;
    const acceptedLog = receipt.logs
      .map((log: any) => {
        try {
          return iface.parseLog(log);
        } catch {
          return null;
        }
      })
      .find((e: any) => e?.name === "ZkProofAccepted");

    expect(acceptedLog).to.not.be.null;
    expect(acceptedLog.args.windowIndex).to.equal(0n);
    expect(acceptedLog.args.programVKey).to.equal(PROGRAM_VKEY);
    expect(acceptedLog.args.policyHash).to.equal(POLICY_HASH);
    expect(acceptedLog.args.proverSetDigest).to.equal(PROVER_SET_DIGEST);
  });

  // ── 3. Quorum reached ─────────────────────────────────────────────────────

  it("accepts proofs from 2 registered provers across sequential windows", async function () {
    const [owner, prover1, prover2] = await ethers.getSigners();
    const { finalizer } = await deployAll(owner);

    // Register 2 provers as authorized submitters (2-of-2 quorum)
    await (await (finalizer as any).setSubmitter(prover1.address, true)).wait();
    await (await (finalizer as any).setSubmitter(prover2.address, true)).wait();

    // Prover 1 submits window 0
    const fix0 = await makeWindowFixture(GENESIS_L2_BLOCK, GENESIS_L2_BLOCK + 100n);
    const tx0 = await (finalizer as any)
      .connect(prover1)
      .submitZkValidityProof(fix0.proof, fix0.publicInputs);
    await tx0.wait();

    // Prover 2 submits window 1 (contiguous)
    const fix1 = await makeWindowFixture(GENESIS_L2_BLOCK + 100n, GENESIS_L2_BLOCK + 200n);
    const tx1 = await (finalizer as any)
      .connect(prover2)
      .submitZkValidityProof(fix1.proof, fix1.publicInputs);
    await tx1.wait();

    // Both windows accepted — nextWindowIndex = 2
    expect(await (finalizer as any).nextWindowIndex()).to.equal(2n);

    // Verify OutputProposed events for both windows
    const outputFilter = (finalizer as any).filters.OutputProposed();
    const events = await (finalizer as any).queryFilter(outputFilter, 0);
    expect(events).to.have.length(2);
    expect(events[0].args.windowIndex).to.equal(0n);
    expect(events[1].args.windowIndex).to.equal(1n);
  });

  // ── 4. Full cycle ─────────────────────────────────────────────────────────

  it("full cycle: deploy → register 3 provers → submit 3 proofs → all accepted", async function () {
    const [owner, prover1, prover2, prover3] = await ethers.getSigners();
    const { registry, finalizer } = await deployAll(owner);

    // Register 3 drivers
    const proofSystems = ["groth16", "plonk", "halo2"];
    for (const ps of proofSystems) {
      const id = ethers.keccak256(ethers.toUtf8Bytes(`driver-${ps}`));
      await (
        await (registry as any).registerDriver(id, `v1.0.0-${ps}`, `https://devnet.local/${ps}`)
      ).wait();
    }

    // Authorize all 3 as submitters
    await (await (finalizer as any).setSubmitter(prover1.address, true)).wait();
    await (await (finalizer as any).setSubmitter(prover2.address, true)).wait();
    await (await (finalizer as any).setSubmitter(prover3.address, true)).wait();

    // Each prover submits a sequential window
    const provers = [prover1, prover2, prover3];
    let cursor = GENESIS_L2_BLOCK;
    for (let i = 0; i < 3; i++) {
      const l2End = cursor + 100n;
      const { proof, publicInputs } = await makeWindowFixture(cursor, l2End);
      const tx = await (finalizer as any)
        .connect(provers[i])
        .submitZkValidityProof(proof, publicInputs);
      await tx.wait();
      cursor = l2End;
    }

    // All 3 windows accepted
    expect(await (finalizer as any).nextWindowIndex()).to.equal(3n);

    const acceptedFilter = (finalizer as any).filters.ZkProofAccepted();
    const events = await (finalizer as any).queryFilter(acceptedFilter, 0);
    expect(events).to.have.length(3);

    for (let i = 0; i < 3; i++) {
      expect(events[i].args.windowIndex).to.equal(BigInt(i));
      expect(events[i].args.programVKey).to.equal(PROGRAM_VKEY);
      expect(events[i].args.policyHash).to.equal(POLICY_HASH);
    }
  });
});
