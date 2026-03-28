/**
 * Proof routing integration tests.
 *
 * Exercises the ProofRouter + WorldlineFinalizer.submitZkValidityProofRouted()
 * integration. Deploys the full contract stack including the router.
 */

import { expect } from "chai";
import { ethers } from "hardhat";
import {
  deployAllWithRouter,
  makeWindowFixture,
  GENESIS_L2_BLOCK,
  DOMAIN,
  PROGRAM_VKEY,
  POLICY_HASH
} from "./helpers";
import { deployAll } from "./helpers";

describe("Proof routing", function () {
  // ── 1. Deploy full stack with router ────────────────────────────────────────

  it("deploys full stack with router and Groth16 adapter registered at ID=1", async function () {
    const [owner] = await ethers.getSigners();
    const { router, adapter } = await deployAllWithRouter(owner);

    // Groth16 adapter registered at proofSystemId=1
    expect(await (router as any).isSupported(1)).to.equal(true);
    expect(await (router as any).getAdapter(1)).to.equal(await (adapter as any).getAddress());

    // Other IDs not supported
    expect(await (router as any).isSupported(2)).to.equal(false);
    expect(await (router as any).isSupported(3)).to.equal(false);
  });

  // ── 2. Submit Groth16 proof through router ────────────────────────────────

  it("submits Groth16 proof through router — emits ZkProofAccepted", async function () {
    const [owner] = await ethers.getSigners();
    const { finalizer } = await deployAllWithRouter(owner);

    await (await (finalizer as any).setPermissionless(true)).wait();

    const { proof, publicInputs } = await makeWindowFixture(
      GENESIS_L2_BLOCK,
      GENESIS_L2_BLOCK + 100n
    );

    const tx = await (finalizer as any).submitZkValidityProofRouted(1, proof, publicInputs);
    const receipt = await tx.wait();

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

    expect(await (finalizer as any).nextWindowIndex()).to.equal(1n);
  });

  // ── 3. Query supported proof systems ─────────────────────────────────────

  it("router reports only ID=1 supported after initial deploy", async function () {
    const [owner] = await ethers.getSigners();
    const { router } = await deployAllWithRouter(owner);

    // Check IDs 0–5
    const supported: number[] = [];
    for (let id = 0; id <= 5; id++) {
      if (await (router as any).isSupported(id)) supported.push(id);
    }
    expect(supported).to.deep.equal([1]);
  });

  // ── 4. Submit with unsupported proofSystemId=2 — reverts ─────────────────

  it("submitting with unsupported proofSystemId=2 reverts", async function () {
    const [owner] = await ethers.getSigners();
    const { finalizer } = await deployAllWithRouter(owner);

    await (await (finalizer as any).setPermissionless(true)).wait();

    const { proof, publicInputs } = await makeWindowFixture(
      GENESIS_L2_BLOCK,
      GENESIS_L2_BLOCK + 100n
    );

    await expect(
      (finalizer as any).submitZkValidityProofRouted(2, proof, publicInputs)
    ).to.be.revertedWithCustomError(
      // The revert comes from ProofRouter.AdapterNotRegistered
      await ethers.getContractAt("ProofRouter", await (finalizer as any).proofRouter()),
      "AdapterNotRegistered"
    );
  });

  // ── 5. Register mock adapter at ID=2, submit proof — routes to mock ───────

  it("registers mock adapter at ID=2 and routes proof to it", async function () {
    const [owner] = await ethers.getSigners();
    const { finalizer, router } = await deployAllWithRouter(owner);

    await (await (finalizer as any).setPermissionless(true)).wait();

    // Deploy a mock adapter for proofSystemId=2
    const MockAdapter = await ethers.getContractFactory("MockZkAdapter", owner);
    const mockAdapter = await MockAdapter.deploy(
      2, // proofSystemId = 2 (Plonk placeholder)
      PROGRAM_VKEY,
      POLICY_HASH
    );
    await mockAdapter.waitForDeployment();

    // Register the mock at ID=2
    await (await (router as any).registerAdapter(2, await mockAdapter.getAddress())).wait();
    expect(await (router as any).isSupported(2)).to.equal(true);

    // Submit a proof via proofSystemId=2 (the mock will accept any proof)
    const { proof, publicInputs } = await makeWindowFixture(
      GENESIS_L2_BLOCK,
      GENESIS_L2_BLOCK + 100n
    );

    const tx = await (finalizer as any).submitZkValidityProofRouted(2, proof, publicInputs);
    const receipt = await tx.wait();

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

    expect(await (finalizer as any).nextWindowIndex()).to.equal(1n);
  });

  // ── 6. Backward compatibility — existing e2e flow still passes ────────────

  it("existing submitZkValidityProof (direct adapter) still works after router deployment", async function () {
    const [owner] = await ethers.getSigners();

    // Use the original deployAll (no router) — backward compat path
    const { finalizer } = await deployAll(owner);
    await (await (finalizer as any).setPermissionless(true)).wait();

    const { proof, publicInputs } = await makeWindowFixture(
      GENESIS_L2_BLOCK,
      GENESIS_L2_BLOCK + 100n
    );

    // Original path must still succeed
    await expect((finalizer as any).submitZkValidityProof(proof, publicInputs)).to.not.be.reverted;

    expect(await (finalizer as any).nextWindowIndex()).to.equal(1n);
  });

  // ── 7. submitZkValidityProofRouted without router set — reverts ────────────

  it("submitZkValidityProofRouted reverts with ProofRouterZero when router not configured", async function () {
    const [owner] = await ethers.getSigners();

    // deployAll without router
    const { finalizer } = await deployAll(owner);
    await (await (finalizer as any).setPermissionless(true)).wait();

    const { proof, publicInputs } = await makeWindowFixture(
      GENESIS_L2_BLOCK,
      GENESIS_L2_BLOCK + 100n
    );

    await expect(
      (finalizer as any).submitZkValidityProofRouted(1, proof, publicInputs)
    ).to.be.revertedWithCustomError(finalizer, "ProofRouterZero");
  });

  // ── 8. ProofRouted event emitted by router ────────────────────────────────

  it("ProofRouted event is emitted by router on routeProof", async function () {
    const [owner] = await ethers.getSigners();
    const { router, adapter } = await deployAllWithRouter(owner);

    const { proof } = await makeWindowFixture(GENESIS_L2_BLOCK, GENESIS_L2_BLOCK + 100n);

    // Call routeProof directly on router (thin path)
    const tx = await (router as any).routeProof(1, proof, []);
    const receipt = await tx.wait();

    const routerIface = (router as any).interface;
    const routedLog = receipt.logs
      .map((log: any) => {
        try {
          return routerIface.parseLog(log);
        } catch {
          return null;
        }
      })
      .find((e: any) => e?.name === "ProofRouted");

    expect(routedLog).to.not.be.null;
    expect(routedLog.args.proofSystemId).to.equal(1);
    expect(routedLog.args.result).to.equal(true);
  });
});
