/**
 * GovernanceRotation.test.ts
 *
 * End-to-end test for the governance rotation pipeline:
 *   Deploy → Submit window 0 → Schedule new VKey/policy → Activate after timelock
 *   → Deploy new adapter → Set adapter → Verify old values fail → Verify new values succeed
 *
 * This test proves the full governance rotation flow works end-to-end.
 */

import { ethers } from "hardhat";
import { expect } from "chai";
import { loadFixture, time } from "@nomicfoundation/hardhat-toolbox/network-helpers";

const DOMAIN = ethers.keccak256(ethers.toUtf8Bytes("worldline-governance-test"));
const PROGRAM_VKEY_V1 = ethers.keccak256(ethers.toUtf8Bytes("program-vkey-v1"));
const POLICY_HASH_V1 = ethers.keccak256(ethers.toUtf8Bytes("policy-hash-v1"));
const PROGRAM_VKEY_V2 = ethers.keccak256(ethers.toUtf8Bytes("program-vkey-v2"));
const POLICY_HASH_V2 = ethers.keccak256(ethers.toUtf8Bytes("policy-hash-v2"));
const PROVER_DIGEST = ethers.keccak256(ethers.toUtf8Bytes("prover-set"));
const MIN_TIMELOCK = 86400; // 24 hours in seconds

describe("GovernanceRotation", function () {
  async function deployFullStack() {
    const [owner, submitter] = await ethers.getSigners();

    // 1. Deploy the demo Verifier
    const Verifier = await ethers.getContractFactory("Verifier");
    const verifier = await Verifier.deploy();

    // 2. Deploy WorldlineRegistry
    const Registry = await ethers.getContractFactory("WorldlineRegistry");
    const registry = await Registry.deploy(await verifier.getAddress());

    // 3. Deploy initial Groth16ZkAdapter (v1 pinned values, isDev=true)
    const Adapter = await ethers.getContractFactory("Groth16ZkAdapter");
    const adapterV1 = await Adapter.deploy(
      await verifier.getAddress(),
      PROGRAM_VKEY_V1,
      POLICY_HASH_V1,
      true // isDev
    );

    // 4. Deploy WorldlineFinalizer (1-hour max acceptance delay)
    const Finalizer = await ethers.getContractFactory("WorldlineFinalizer");
    const finalizer = await Finalizer.deploy(await adapterV1.getAddress(), DOMAIN, 3600);

    // 5. Deploy WorldlineOutputsRegistry (24-hour minimum timelock)
    const OutputsRegistry = await ethers.getContractFactory("WorldlineOutputsRegistry");
    const outputsRegistry = await OutputsRegistry.deploy(MIN_TIMELOCK);

    // 6. Deploy WorldlineCompat facade
    const Compat = await ethers.getContractFactory("WorldlineCompat");
    const compat = await Compat.deploy(await registry.getAddress());
    await registry.setCompatFacade(await compat.getAddress());

    // Enable permissionless submission for simplicity in tests
    await finalizer.setPermissionless(true);

    return {
      verifier,
      registry,
      adapterV1,
      finalizer,
      outputsRegistry,
      compat,
      owner,
      submitter
    };
  }

  function encodePublicInputs(
    stfCommitment: string,
    l2Start: bigint,
    l2End: bigint,
    domainSep: string,
    windowCloseTimestamp: bigint
  ): string {
    return ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "uint256", "uint256", "bytes32", "bytes32", "bytes32", "uint256"],
      [
        stfCommitment,
        l2Start,
        l2End,
        ethers.ZeroHash,
        ethers.ZeroHash,
        domainSep,
        windowCloseTimestamp
      ]
    );
  }

  function encodeProof(
    stfCommitment: string,
    programVKey: string,
    policyHash: string,
    proverSetDigest: string
  ): string {
    return ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "bytes32"],
      [stfCommitment, programVKey, policyHash, proverSetDigest]
    );
  }

  it("full governance rotation pipeline", async function () {
    const { verifier, adapterV1, finalizer, outputsRegistry, owner } =
      await loadFixture(deployFullStack);

    // ── Step 2: Submit valid proof through the Finalizer (window 0) ────────────
    const ts = BigInt(await time.latest()) + 100n;
    const stf0 = ethers.keccak256(ethers.toUtf8Bytes("stf-window-0"));
    const proof0 = encodeProof(stf0, PROGRAM_VKEY_V1, POLICY_HASH_V1, PROVER_DIGEST);
    const inputs0 = encodePublicInputs(stf0, 0n, 100n, DOMAIN, ts);

    await expect(finalizer.submitZkValidityProof(proof0, inputs0))
      .to.emit(finalizer, "OutputProposed")
      .withArgs(0n, ethers.ZeroHash, 0n, 100n, stf0)
      .and.to.emit(finalizer, "ZkProofAccepted")
      .withArgs(0n, PROGRAM_VKEY_V1, POLICY_HASH_V1, PROVER_DIGEST);

    expect(await finalizer.nextWindowIndex()).to.equal(1n);
    expect(await finalizer.lastL2EndBlock()).to.equal(100n);

    // ── Step 3: Schedule a new {programVKey, policyHash, oracle} ──────────────
    const domainKey = await outputsRegistry.domainKey(
      ethers.keccak256(ethers.toUtf8Bytes("chain-id")),
      ethers.keccak256(ethers.toUtf8Bytes("domain-tag"))
    );

    await expect(
      outputsRegistry.schedule(
        domainKey,
        PROGRAM_VKEY_V2,
        POLICY_HASH_V2,
        await adapterV1.getAddress()
      )
    ).to.emit(outputsRegistry, "OutputScheduled");

    // ── Step 4: Attempt to activate before timelock — must revert ─────────────
    await expect(outputsRegistry.activate(domainKey)).to.be.revertedWithCustomError(
      outputsRegistry,
      "TimelockNotElapsed"
    );

    // ── Step 5: Fast-forward past the timelock ─────────────────────────────────
    await time.increase(MIN_TIMELOCK + 1);

    // ── Step 6: Activate the new entry ────────────────────────────────────────
    await expect(outputsRegistry.activate(domainKey))
      .to.emit(outputsRegistry, "OutputActivated")
      .withArgs(domainKey, PROGRAM_VKEY_V2, POLICY_HASH_V2, await adapterV1.getAddress());

    const activeEntry = await outputsRegistry.getActiveEntry(domainKey);
    expect(activeEntry.programVKey).to.equal(PROGRAM_VKEY_V2);
    expect(activeEntry.policyHash).to.equal(POLICY_HASH_V2);

    // ── Step 7: Deploy a new adapter with the NEW pinned values ───────────────
    const Adapter = await ethers.getContractFactory("Groth16ZkAdapter");
    const adapterV2 = await Adapter.deploy(
      await verifier.getAddress(),
      PROGRAM_VKEY_V2,
      POLICY_HASH_V2,
      true // isDev
    );

    // ── Step 8: Schedule + activate the new adapter on the Finalizer ─────────
    // HI-001: setAdapter is replaced by a two-step timelocked process.
    await expect(finalizer.connect(owner).scheduleAdapterChange(await adapterV2.getAddress()))
      .to.emit(finalizer, "AdapterChangeScheduled");

    // Fast-forward past the adapter change delay (1 day default)
    await time.increase(86401);

    await expect(finalizer.connect(owner).activateAdapterChange())
      .to.emit(finalizer, "AdapterSet")
      .withArgs(await adapterV2.getAddress());

    expect(await finalizer.adapter()).to.equal(await adapterV2.getAddress());

    // ── Step 9: Submit proof with OLD v1 pinned values — must revert ──────────
    const ts2 = BigInt(await time.latest()) + 200n;
    const stf1bad = ethers.keccak256(ethers.toUtf8Bytes("stf-window-1-bad"));
    const proofBad = encodeProof(stf1bad, PROGRAM_VKEY_V1, POLICY_HASH_V1, PROVER_DIGEST);
    const inputsBad = encodePublicInputs(stf1bad, 100n, 200n, DOMAIN, ts2);

    await expect(
      finalizer.submitZkValidityProof(proofBad, inputsBad)
    ).to.be.revertedWithCustomError(adapterV2, "ProgramVKeyMismatch");

    // ── Step 10: Submit proof with NEW v2 pinned values — must succeed ─────────
    const stf1good = ethers.keccak256(ethers.toUtf8Bytes("stf-window-1-good"));
    const proofGood = encodeProof(stf1good, PROGRAM_VKEY_V2, POLICY_HASH_V2, PROVER_DIGEST);
    const inputsGood = encodePublicInputs(stf1good, 100n, 200n, DOMAIN, ts2);

    await expect(finalizer.submitZkValidityProof(proofGood, inputsGood))
      .to.emit(finalizer, "OutputProposed")
      .withArgs(1n, ethers.ZeroHash, 100n, 200n, stf1good)
      .and.to.emit(finalizer, "ZkProofAccepted")
      .withArgs(1n, PROGRAM_VKEY_V2, POLICY_HASH_V2, PROVER_DIGEST);

    expect(await finalizer.nextWindowIndex()).to.equal(2n);
    expect(await finalizer.lastL2EndBlock()).to.equal(200n);
  });
});
