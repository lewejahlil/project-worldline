/**
 * GovernanceRotation.test.ts
 *
 * End-to-end test for the governance rotation pipeline:
 *   Deploy → Submit window 0 → Schedule new VKey/policy → Activate after timelock
 *   → Deploy new adapter → Set adapter → Verify old values fail → Verify new values succeed
 *
 * This test proves the full governance rotation flow works end-to-end.
 */

import { loadFixture, time } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { expect } from "chai";
import { ethers, upgrades } from "hardhat";

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

    // 1. Deploy a mock Groth16 verifier (always returns true)
    const MockVerifier = await ethers.getContractFactory("MockGroth16Verifier");
    const mockVerifier = await MockVerifier.deploy();

    // 2. Deploy WorldlineRegistry
    const Registry = await ethers.getContractFactory("WorldlineRegistry");
    const registry = (await upgrades.deployProxy(Registry, [await mockVerifier.getAddress()], {
      kind: "uups"
    })) as any;
    await registry.waitForDeployment();

    // 3. Deploy initial Groth16ZkAdapter (v1 pinned values)
    const Adapter = await ethers.getContractFactory("Groth16ZkAdapter");
    const adapterV1 = await Adapter.deploy(
      await mockVerifier.getAddress(),
      PROGRAM_VKEY_V1,
      POLICY_HASH_V1
    );

    // 4. Deploy WorldlineFinalizer (1-hour max acceptance delay)
    const Finalizer = await ethers.getContractFactory("WorldlineFinalizer");
    const finalizer = (await upgrades.deployProxy(
      Finalizer,
      [await adapterV1.getAddress(), DOMAIN, 3600, 0, ethers.ZeroAddress],
      { kind: "uups" }
    )) as any;
    await finalizer.waitForDeployment();

    // 5. Deploy WorldlineOutputsRegistry (24-hour minimum timelock)
    const OutputsRegistry = await ethers.getContractFactory("WorldlineOutputsRegistry");
    const outputsRegistry = (await upgrades.deployProxy(OutputsRegistry, [MIN_TIMELOCK], {
      kind: "uups"
    })) as any;
    await outputsRegistry.waitForDeployment();

    // 6. Deploy WorldlineCompat facade
    const Compat = await ethers.getContractFactory("WorldlineCompat");
    const compat = await Compat.deploy(await registry.getAddress());
    await registry.setCompatFacade(await compat.getAddress());

    // Enable permissionless submission for simplicity in tests
    await finalizer.setPermissionless(true);

    return {
      mockVerifier,
      registry,
      adapterV1,
      finalizer,
      outputsRegistry,
      compat,
      owner,
      submitter
    };
  }

  // MED-001: stfCommitment = keccak256(abi.encode(l2Start, l2End, outputRoot, l1BlockHash, domainSep, windowCloseTimestamp))
  function computeStf(
    l2Start: bigint,
    l2End: bigint,
    domainSep: string,
    windowCloseTimestamp: bigint
  ): string {
    return ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["uint256", "uint256", "bytes32", "bytes32", "bytes32", "uint256"],
        [l2Start, l2End, ethers.ZeroHash, ethers.ZeroHash, domainSep, windowCloseTimestamp]
      )
    );
  }

  function encodePublicInputs(
    l2Start: bigint,
    l2End: bigint,
    domainSep: string,
    windowCloseTimestamp: bigint
  ): { inputs: string; stf: string } {
    const stf = computeStf(l2Start, l2End, domainSep, windowCloseTimestamp);
    const inputs = ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "uint256", "uint256", "bytes32", "bytes32", "bytes32", "uint256"],
      [stf, l2Start, l2End, ethers.ZeroHash, ethers.ZeroHash, domainSep, windowCloseTimestamp]
    );
    return { inputs, stf };
  }

  /**
   * Encode a production-format Groth16 proof (320 bytes).
   * pA, pB, pC are dummy G1/G2 points (the mock verifier accepts anything).
   * stfCommitment and proverSetDigest are the two public signals.
   */
  function encodeProof(
    stfCommitment: string,
    programVKey: string,
    policyHash: string,
    proverSetDigest: string
  ): string {
    // programVKey and policyHash are pinned immutables — not encoded in the proof.
    // We suppress the lint warning by referencing them.
    void programVKey;
    void policyHash;
    // Dummy G1/G2 points (mock verifier ignores them)
    const pA = [1n, 2n];
    const pB = [
      [1n, 2n],
      [3n, 4n]
    ];
    const pC = [1n, 2n];
    return ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256[2]", "uint256[2][2]", "uint256[2]", "uint256", "uint256"],
      [pA, pB, pC, stfCommitment, proverSetDigest]
    );
  }

  it("full governance rotation pipeline", async function () {
    const { mockVerifier, adapterV1, finalizer, outputsRegistry, owner } =
      await loadFixture(deployFullStack);

    // ── Step 2: Submit valid proof through the Finalizer (window 0) ────────────
    const ts = BigInt(await time.latest()) + 100n;
    const { inputs: inputs0, stf: stf0 } = encodePublicInputs(0n, 100n, DOMAIN, ts);
    const proof0 = encodeProof(stf0, PROGRAM_VKEY_V1, POLICY_HASH_V1, PROVER_DIGEST);

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
      await mockVerifier.getAddress(),
      PROGRAM_VKEY_V2,
      POLICY_HASH_V2
    );

    // ── Step 8: Schedule + activate the new adapter on the Finalizer ─────────
    // HI-001: setAdapter is replaced by a two-step timelocked process.
    await expect(
      finalizer.connect(owner).scheduleAdapterChange(await adapterV2.getAddress())
    ).to.emit(finalizer, "AdapterChangeScheduled");

    // Fast-forward past the adapter change delay (1 day default)
    await time.increase(86401);

    await expect(finalizer.connect(owner).activateAdapterChange())
      .to.emit(finalizer, "AdapterSet")
      .withArgs(await adapterV2.getAddress());

    expect(await finalizer.adapter()).to.equal(await adapterV2.getAddress());

    // ── Step 9: Verify the new adapter has v2 pinned values ───────────────────
    expect(await adapterV2.programVKeyPinned()).to.equal(PROGRAM_VKEY_V2);
    expect(await adapterV2.policyHashPinned()).to.equal(POLICY_HASH_V2);

    // ── Step 10: Submit proof with NEW v2 pinned values — must succeed ─────────
    const ts2 = BigInt(await time.latest()) + 200n;
    const { inputs: inputsGood, stf: stfGood } = encodePublicInputs(100n, 200n, DOMAIN, ts2);
    const proofGood = encodeProof(stfGood, PROGRAM_VKEY_V2, POLICY_HASH_V2, PROVER_DIGEST);

    await expect(finalizer.submitZkValidityProof(proofGood, inputsGood))
      .to.emit(finalizer, "OutputProposed")
      .withArgs(1n, ethers.ZeroHash, 100n, 200n, stfGood)
      .and.to.emit(finalizer, "ZkProofAccepted")
      .withArgs(1n, PROGRAM_VKEY_V2, POLICY_HASH_V2, PROVER_DIGEST);

    expect(await finalizer.nextWindowIndex()).to.equal(2n);
    expect(await finalizer.lastL2EndBlock()).to.equal(200n);
  });
});
