/**
 * Multi-prover quorum end-to-end tests.
 *
 * Proves the core architectural thesis: three independent proof systems (Groth16,
 * Plonk V2, Halo2) can each verify the same class of state transitions through
 * the ProofRouter, and that quorum logic works correctly across heterogeneous
 * proof types.
 *
 * Proof system setup:
 *   ID=1 — Groth16  : MockGroth16Verifier + Groth16ZkAdapter  (real adapter, mock verifier)
 *   ID=2 — Plonk V2 : MockPlonkVerifier   + PlonkZkAdapter    (real adapter, mock verifier)
 *   ID=3 — Halo2    : MockHalo2Verifier   + Halo2ZkAdapter    (real adapter, mock verifier)
 *
 * "Real proof" in this context means correctly-structured proof envelopes processed
 * through the production adapter logic (decode → extract signals → call verifier).
 * The mock verifiers (MockGroth16Verifier, MockPlonkVerifier, MockHalo2Verifier)
 * accept any cryptographically-valid-format input, enabling deterministic testing
 * without a live snarkjs ceremony.
 *
 * Note on quorum semantics:
 *   WorldlineFinalizer advances nextWindowIndex on each accepted proof. A window is
 *   contiguous and single-acceptance. "Multi-prover quorum" is demonstrated by
 *   submitting sequential windows from different proof systems — each using the same
 *   PROVER_SET_DIGEST encoding the quorum metadata. Tests 10–11 demonstrate the
 *   router-level enforcement that prevents a missing adapter from completing quorum.
 */

import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
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
  DOMAIN,
  PROGRAM_VKEY,
  POLICY_HASH,
  PROVER_SET_DIGEST,
  MAX_ACCEPTANCE_DELAY,
  GENESIS_L2_BLOCK
} from "./helpers";

// ── Utility: extract ZkProofAccepted from receipt ──────────────────────────

function findZkProofAccepted(receipt: any, iface: any) {
  for (const log of receipt.logs) {
    try {
      const parsed = iface.parseLog(log);
      if (parsed?.name === "ZkProofAccepted") return parsed;
    } catch {
      /* skip unparseable logs */
    }
  }
  return null;
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe("Multi-prover quorum — end-to-end", function () {
  // ── 1. Single Groth16 proof via router ──────────────────────────────────

  it("single Groth16 proof via router (ID=1) — emits ZkProofAccepted", async function () {
    const [owner] = await ethers.getSigners();
    const { finalizer } = await deployAllWithThreeAdapters(owner);

    const { proof, publicInputs } = await makeWindowFixture(
      GENESIS_L2_BLOCK,
      GENESIS_L2_BLOCK + 100n
    );

    const tx = await (finalizer as any).submitZkValidityProofRouted(1, proof, publicInputs);
    const receipt = await tx.wait();

    const log = findZkProofAccepted(receipt, (finalizer as any).interface);
    expect(log).to.not.be.null;
    expect(log.args.windowIndex).to.equal(0n);
    expect(log.args.programVKey).to.equal(PROGRAM_VKEY);
    expect(log.args.policyHash).to.equal(POLICY_HASH);
    expect(await (finalizer as any).nextWindowIndex()).to.equal(1n);
  });

  // ── 2. Single Plonk V2 proof via router ─────────────────────────────────

  it("single Plonk V2 proof via router (ID=2) — emits ZkProofAccepted", async function () {
    const [owner] = await ethers.getSigners();
    const { finalizer } = await deployAllWithThreeAdapters(owner);

    const { proof, publicInputs } = await makePlonkWindowFixture(
      GENESIS_L2_BLOCK,
      GENESIS_L2_BLOCK + 100n
    );

    const tx = await (finalizer as any).submitZkValidityProofRouted(2, proof, publicInputs);
    const receipt = await tx.wait();

    const log = findZkProofAccepted(receipt, (finalizer as any).interface);
    expect(log).to.not.be.null;
    expect(log.args.windowIndex).to.equal(0n);
    expect(log.args.programVKey).to.equal(PROGRAM_VKEY);
    expect(log.args.policyHash).to.equal(POLICY_HASH);
    expect(await (finalizer as any).nextWindowIndex()).to.equal(1n);
  });

  // ── 3. Single Halo2 proof via router ────────────────────────────────────

  it("single Halo2 proof via router (ID=3) — emits ZkProofAccepted", async function () {
    const [owner] = await ethers.getSigners();
    const { finalizer } = await deployAllWithThreeAdapters(owner);

    const { proof, publicInputs } = await makeHalo2WindowFixture(
      GENESIS_L2_BLOCK,
      GENESIS_L2_BLOCK + 100n
    );

    const tx = await (finalizer as any).submitZkValidityProofRouted(3, proof, publicInputs);
    const receipt = await tx.wait();

    const log = findZkProofAccepted(receipt, (finalizer as any).interface);
    expect(log).to.not.be.null;
    expect(log.args.windowIndex).to.equal(0n);
    expect(log.args.programVKey).to.equal(PROGRAM_VKEY);
    expect(log.args.policyHash).to.equal(POLICY_HASH);
    expect(await (finalizer as any).nextWindowIndex()).to.equal(1n);
  });

  // ── 4. Two-system quorum: Groth16 + Plonk ───────────────────────────────

  it("two-system quorum: Groth16 (ID=1) + Plonk (ID=2) — both windows accepted, count=2", async function () {
    const [owner] = await ethers.getSigners();
    const { finalizer } = await deployAllWithThreeAdapters(owner);

    // Window 0 — Groth16
    const fix0 = await makeWindowFixture(GENESIS_L2_BLOCK, GENESIS_L2_BLOCK + 100n);
    const tx0 = await (finalizer as any).submitZkValidityProofRouted(
      1,
      fix0.proof,
      fix0.publicInputs
    );
    const r0 = await tx0.wait();
    expect(findZkProofAccepted(r0, (finalizer as any).interface)).to.not.be.null;

    // Window 1 — Plonk (contiguous)
    const fix1 = await makePlonkWindowFixture(GENESIS_L2_BLOCK + 100n, GENESIS_L2_BLOCK + 200n);
    const tx1 = await (finalizer as any).submitZkValidityProofRouted(
      2,
      fix1.proof,
      fix1.publicInputs
    );
    const r1 = await tx1.wait();
    expect(findZkProofAccepted(r1, (finalizer as any).interface)).to.not.be.null;

    // Both windows accepted — quorum count = 2 proof systems contributed
    expect(await (finalizer as any).nextWindowIndex()).to.equal(2n);
  });

  // ── 5. Two-system quorum: Groth16 + Halo2 ───────────────────────────────

  it("two-system quorum: Groth16 (ID=1) + Halo2 (ID=3) — both windows accepted, count=2", async function () {
    const [owner] = await ethers.getSigners();
    const { finalizer } = await deployAllWithThreeAdapters(owner);

    const fix0 = await makeWindowFixture(GENESIS_L2_BLOCK, GENESIS_L2_BLOCK + 100n);
    await (
      await (finalizer as any).submitZkValidityProofRouted(1, fix0.proof, fix0.publicInputs)
    ).wait();

    const fix1 = await makeHalo2WindowFixture(GENESIS_L2_BLOCK + 100n, GENESIS_L2_BLOCK + 200n);
    const tx1 = await (finalizer as any).submitZkValidityProofRouted(
      3,
      fix1.proof,
      fix1.publicInputs
    );
    const r1 = await tx1.wait();

    expect(findZkProofAccepted(r1, (finalizer as any).interface)).to.not.be.null;
    expect(await (finalizer as any).nextWindowIndex()).to.equal(2n);
  });

  // ── 6. Two-system quorum: Plonk + Halo2 ─────────────────────────────────

  it("two-system quorum: Plonk (ID=2) + Halo2 (ID=3) — both windows accepted, count=2", async function () {
    const [owner] = await ethers.getSigners();
    const { finalizer } = await deployAllWithThreeAdapters(owner);

    const fix0 = await makePlonkWindowFixture(GENESIS_L2_BLOCK, GENESIS_L2_BLOCK + 100n);
    await (
      await (finalizer as any).submitZkValidityProofRouted(2, fix0.proof, fix0.publicInputs)
    ).wait();

    const fix1 = await makeHalo2WindowFixture(GENESIS_L2_BLOCK + 100n, GENESIS_L2_BLOCK + 200n);
    const tx1 = await (finalizer as any).submitZkValidityProofRouted(
      3,
      fix1.proof,
      fix1.publicInputs
    );
    const r1 = await tx1.wait();

    expect(findZkProofAccepted(r1, (finalizer as any).interface)).to.not.be.null;
    expect(await (finalizer as any).nextWindowIndex()).to.equal(2n);
  });

  // ── 7. Three-system quorum: all three ───────────────────────────────────

  it("three-system quorum: Groth16 + Plonk + Halo2 — all three windows accepted, count=3", async function () {
    const [owner] = await ethers.getSigners();
    const { finalizer } = await deployAllWithThreeAdapters(owner);

    // Window 0 — Groth16
    const fix0 = await makeWindowFixture(GENESIS_L2_BLOCK, GENESIS_L2_BLOCK + 100n);
    const r0 = await (
      await (finalizer as any).submitZkValidityProofRouted(1, fix0.proof, fix0.publicInputs)
    ).wait();
    expect(findZkProofAccepted(r0, (finalizer as any).interface)?.args.windowIndex).to.equal(0n);

    // Window 1 — Plonk V2
    const fix1 = await makePlonkWindowFixture(GENESIS_L2_BLOCK + 100n, GENESIS_L2_BLOCK + 200n);
    const r1 = await (
      await (finalizer as any).submitZkValidityProofRouted(2, fix1.proof, fix1.publicInputs)
    ).wait();
    expect(findZkProofAccepted(r1, (finalizer as any).interface)?.args.windowIndex).to.equal(1n);

    // Window 2 — Halo2
    const fix2 = await makeHalo2WindowFixture(GENESIS_L2_BLOCK + 200n, GENESIS_L2_BLOCK + 300n);
    const r2 = await (
      await (finalizer as any).submitZkValidityProofRouted(3, fix2.proof, fix2.publicInputs)
    ).wait();
    expect(findZkProofAccepted(r2, (finalizer as any).interface)?.args.windowIndex).to.equal(2n);

    // Three distinct proof systems contributed — quorum count = 3
    expect(await (finalizer as any).nextWindowIndex()).to.equal(3n);
  });

  // ── 8. Cross-system stfCommitment match ─────────────────────────────────

  it("cross-system stfCommitment match: all 3 proof systems return identical stfCommitment for the same batch", async function () {
    const [owner] = await ethers.getSigners();
    const { router } = await deployAllWithThreeAdapters(owner);

    const block = await ethers.provider.getBlock("latest");
    const wct = BigInt(block!.timestamp) + 7200n;
    const l2Start = GENESIS_L2_BLOCK;
    const l2End = l2Start + 100n;

    const proofG16 = encodeProof(l2Start, l2End, wct);
    const proofPlonk = encodePlonkProof(l2Start, l2End, wct);
    const proofHalo2 = encodeHalo2Proof(l2Start, l2End, wct);
    const publicInputs = encodePublicInputs(l2Start, l2End, wct);

    // Static-call routeProofAggregated to read return values without state effects
    const [, stfG16] = await (router as any).routeProofAggregated.staticCall(
      1,
      proofG16,
      publicInputs
    );
    const [, stfPlonk] = await (router as any).routeProofAggregated.staticCall(
      2,
      proofPlonk,
      publicInputs
    );
    const [, stfHalo2] = await (router as any).routeProofAggregated.staticCall(
      3,
      proofHalo2,
      publicInputs
    );

    // All three adapters must extract the same stfCommitment from their respective proof formats
    expect(stfG16).to.equal(stfPlonk);
    expect(stfPlonk).to.equal(stfHalo2);

    // Sanity: matches the independently-computed expected value
    const expected = computeStfCommitment(l2Start, l2End, wct);
    expect(stfG16).to.equal(expected);
  });

  // ── 9. Cross-system proverSetDigest match ────────────────────────────────

  it("cross-system proverSetDigest match: all 3 proof systems return identical proverSetDigest when the same digest is embedded", async function () {
    const [owner] = await ethers.getSigners();
    const { router } = await deployAllWithThreeAdapters(owner);

    const block = await ethers.provider.getBlock("latest");
    const wct = BigInt(block!.timestamp) + 7200n;
    const l2Start = GENESIS_L2_BLOCK;
    const l2End = l2Start + 100n;

    // Each proof format embeds the same PROVER_SET_DIGEST
    const proofG16 = encodeProof(l2Start, l2End, wct, DOMAIN, PROVER_SET_DIGEST);
    const proofPlonk = encodePlonkProof(l2Start, l2End, wct, DOMAIN, PROVER_SET_DIGEST);
    const proofHalo2 = encodeHalo2Proof(l2Start, l2End, wct, DOMAIN, PROVER_SET_DIGEST);
    const publicInputs = encodePublicInputs(l2Start, l2End, wct);

    const [, , , , psdG16] = await (router as any).routeProofAggregated.staticCall(
      1,
      proofG16,
      publicInputs
    );
    const [, , , , psdPlonk] = await (router as any).routeProofAggregated.staticCall(
      2,
      proofPlonk,
      publicInputs
    );
    const [, , , , psdHalo2] = await (router as any).routeProofAggregated.staticCall(
      3,
      proofHalo2,
      publicInputs
    );

    // All three adapters extract the embedded proverSetDigest identically
    expect(psdG16).to.equal(PROVER_SET_DIGEST);
    expect(psdPlonk).to.equal(PROVER_SET_DIGEST);
    expect(psdHalo2).to.equal(PROVER_SET_DIGEST);
    expect(psdG16).to.equal(psdPlonk);
    expect(psdPlonk).to.equal(psdHalo2);
  });

  // ── 10. Router rejects unregistered proof system ID ─────────────────────

  it("router rejects unregistered proofSystemId=4 — reverts with AdapterNotRegistered", async function () {
    const [owner] = await ethers.getSigners();
    const { finalizer } = await deployAllWithThreeAdapters(owner);

    // Use any correctly-encoded proof; the router will reject before it reaches the adapter
    const { proof, publicInputs } = await makeWindowFixture(
      GENESIS_L2_BLOCK,
      GENESIS_L2_BLOCK + 100n
    );

    await expect(
      (finalizer as any).submitZkValidityProofRouted(4, proof, publicInputs)
    ).to.be.revertedWithCustomError(
      await ethers.getContractAt("ProofRouter", await (finalizer as any).proofRouter()),
      "AdapterNotRegistered"
    );
  });

  // ── 11. Mixed quorum insufficient: only 2 of 3 adapters registered ───────

  it("mixed quorum insufficient: ID=3 not registered → third proof system cannot complete quorum", async function () {
    const [owner] = await ethers.getSigners();

    // Deploy router with only Groth16 (ID=1) and Plonk (ID=2) — no Halo2 adapter
    const MockGroth16 = await ethers.getContractFactory("MockGroth16Verifier", owner);
    const groth16Verifier = await MockGroth16.deploy();
    await groth16Verifier.waitForDeployment();

    const Groth16Adapter = await ethers.getContractFactory("Groth16ZkAdapter", owner);
    const groth16Adapter = await Groth16Adapter.deploy(
      await groth16Verifier.getAddress(),
      PROGRAM_VKEY,
      POLICY_HASH
    );
    await groth16Adapter.waitForDeployment();

    const MockPlonk = await ethers.getContractFactory("MockPlonkVerifier", owner);
    const plonkVerifier = await MockPlonk.deploy();
    await plonkVerifier.waitForDeployment();

    const PlonkAdapter = await ethers.getContractFactory("PlonkZkAdapter", owner);
    const plonkAdapter = await PlonkAdapter.deploy(
      await plonkVerifier.getAddress(),
      PROGRAM_VKEY,
      POLICY_HASH
    );
    await plonkAdapter.waitForDeployment();

    const Router = await ethers.getContractFactory("ProofRouter", owner);
    const router = await upgrades.deployProxy(Router, [], { kind: "uups" }) as any;
    await router.waitForDeployment();
    await (
      await (router as any).registerAdapter(1, await (groth16Adapter as any).getAddress())
    ).wait();
    await (
      await (router as any).registerAdapter(2, await (plonkAdapter as any).getAddress())
    ).wait();
    // ID=3 intentionally NOT registered — simulates quorum=3 requirement unachievable

    const Finalizer = await ethers.getContractFactory("WorldlineFinalizer", owner);
    const finalizer = await upgrades.deployProxy(
      Finalizer,
      [await groth16Adapter.getAddress(), DOMAIN, MAX_ACCEPTANCE_DELAY, GENESIS_L2_BLOCK, ethers.ZeroAddress],
      { kind: "uups" }
    ) as any;
    await finalizer.waitForDeployment();
    await (await (finalizer as any).setProofRouter(await (router as any).getAddress())).wait();
    await (await (finalizer as any).setPermissionless(true)).wait();

    // Window 0 — Groth16 ✓
    const fix0 = await makeWindowFixture(GENESIS_L2_BLOCK, GENESIS_L2_BLOCK + 100n);
    await (
      await (finalizer as any).submitZkValidityProofRouted(1, fix0.proof, fix0.publicInputs)
    ).wait();

    // Window 1 — Plonk ✓
    const fix1 = await makePlonkWindowFixture(GENESIS_L2_BLOCK + 100n, GENESIS_L2_BLOCK + 200n);
    await (
      await (finalizer as any).submitZkValidityProofRouted(2, fix1.proof, fix1.publicInputs)
    ).wait();

    expect(await (finalizer as any).nextWindowIndex()).to.equal(2n);

    // Window 2 — Halo2 ✗ (ID=3 not registered → quorum=3 cannot be met)
    const fix2 = await makeHalo2WindowFixture(GENESIS_L2_BLOCK + 200n, GENESIS_L2_BLOCK + 300n);
    await expect(
      (finalizer as any).submitZkValidityProofRouted(3, fix2.proof, fix2.publicInputs)
    ).to.be.revertedWithCustomError(
      await ethers.getContractAt("ProofRouter", await (finalizer as any).proofRouter()),
      "AdapterNotRegistered"
    );

    // nextWindowIndex still 2 — third proof system blocked, quorum=3 not achievable
    expect(await (finalizer as any).nextWindowIndex()).to.equal(2n);
  });
});
