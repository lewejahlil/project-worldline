/**
 * UUPS Upgrade Tests
 *
 * Verifies that WorldlineFinalizer, ProofRouter, WorldlineRegistry, and
 * WorldlineOutputsRegistry can be deployed behind UUPS proxies and (for the
 * first two) upgraded to V2 implementations while preserving state.
 */

import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import type { Signer } from "ethers";
import {
  DOMAIN,
  GENESIS_L2_BLOCK,
  MAX_ACCEPTANCE_DELAY,
  PROGRAM_VKEY,
  POLICY_HASH,
  makeWindowFixture
} from "./helpers";

// ── Constants ─────────────────────────────────────────────────────────────────

const MIN_TIMELOCK = 86400n; // 1 day (== MIN_TIMELOCK_FLOOR)

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Deploy a MockGroth16Verifier + Groth16ZkAdapter pair for the given signer. */
async function deployAdapterStack(deployer: Signer) {
  const MockVerifier = await ethers.getContractFactory("MockGroth16Verifier", deployer);
  const verifier = await MockVerifier.deploy();
  await verifier.waitForDeployment();

  const Adapter = await ethers.getContractFactory("Groth16ZkAdapter", deployer);
  const adapter = await Adapter.deploy(await verifier.getAddress(), PROGRAM_VKEY, POLICY_HASH);
  await adapter.waitForDeployment();

  return { verifier, adapter };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("UUPS Upgrade Tests", () => {
  let owner: Signer;
  let nonOwner: Signer;

  before(async () => {
    [owner, nonOwner] = await ethers.getSigners();
  });

  // ── WorldlineFinalizer ──────────────────────────────────────────────────────

  describe("WorldlineFinalizer upgrade", () => {
    let proxyAddr: string;
    let finalizerV1: any;

    it("deploys V1 behind proxy", async () => {
      const { adapter } = await deployAdapterStack(owner);

      const FinalizerFactory = await ethers.getContractFactory("WorldlineFinalizer", owner);
      const proxy = await upgrades.deployProxy(
        FinalizerFactory,
        [
          await adapter.getAddress(),
          DOMAIN,
          MAX_ACCEPTANCE_DELAY,
          GENESIS_L2_BLOCK,
          ethers.ZeroAddress
        ],
        { kind: "uups", initializer: "initialize" }
      );
      await proxy.waitForDeployment();

      proxyAddr = await proxy.getAddress();
      finalizerV1 = await ethers.getContractAt("WorldlineFinalizer", proxyAddr, owner);

      expect(proxyAddr).to.be.properAddress;
      expect(await finalizerV1.domainSeparator()).to.equal(DOMAIN);
    });

    it("V1: can register adapter and submit proof", async () => {
      // Enable permissionless submission so any signer can submit
      await finalizerV1.setPermissionless(true);

      const { proof, publicInputs } = await makeWindowFixture(
        GENESIS_L2_BLOCK,
        GENESIS_L2_BLOCK + 100n
      );
      const tx = await finalizerV1.submitZkValidityProof(proof, publicInputs);
      const receipt = await tx.wait();
      expect(receipt.status).to.equal(1);

      // nextWindowIndex should now be 1 after one successful submission
      expect(await finalizerV1.nextWindowIndex()).to.equal(1n);
    });

    it("upgrades to V2", async () => {
      const V2Factory = await ethers.getContractFactory("WorldlineFinalizerV2", owner);
      const upgraded = await upgrades.upgradeProxy(proxyAddr, V2Factory, {
        kind: "uups",
        unsafeAllow: ["missing-initializer"]
      });
      await upgraded.waitForDeployment();

      // The proxy address must not change
      expect(await upgraded.getAddress()).to.equal(proxyAddr);
    });

    it("V2: version() returns 2", async () => {
      const finalizerV2 = await ethers.getContractAt("WorldlineFinalizerV2", proxyAddr, owner);
      expect(await finalizerV2.version()).to.equal(2);
    });

    it("V2: all V1 state preserved (nextWindowIndex, adapter, domainSeparator)", async () => {
      const finalizerV2 = await ethers.getContractAt("WorldlineFinalizerV2", proxyAddr, owner);

      // nextWindowIndex should still be 1 from the V1 submission
      expect(await finalizerV2.nextWindowIndex()).to.equal(1n);
      // domainSeparator must match what was set at init
      expect(await finalizerV2.domainSeparator()).to.equal(DOMAIN);
      // adapter must be a non-zero address
      const adapterAddr = await finalizerV2.adapter();
      expect(adapterAddr).to.not.equal(ethers.ZeroAddress);
    });

    it("non-owner cannot upgrade — reverts", async () => {
      const V2 = await ethers.getContractFactory("WorldlineFinalizerV2", nonOwner);
      // Deploy a bare implementation (bypassing _disableInitializers guard is allowed here
      // since we just need an address to pass to upgradeToAndCall)
      const newImpl = await V2.deploy();
      await newImpl.waitForDeployment();

      const proxy = await ethers.getContractAt("WorldlineFinalizerV2", proxyAddr, nonOwner);
      await expect((proxy as any).upgradeToAndCall(await newImpl.getAddress(), "0x")).to.be
        .reverted;
    });
  });

  // ── ProofRouter ─────────────────────────────────────────────────────────────

  describe("ProofRouter upgrade", () => {
    let proxyAddr: string;
    let routerV1: any;
    let adapterAddr: string;

    it("deploys V1 behind proxy", async () => {
      const RouterFactory = await ethers.getContractFactory("ProofRouter", owner);
      const proxy = await upgrades.deployProxy(RouterFactory, [], { kind: "uups" });
      await proxy.waitForDeployment();

      proxyAddr = await proxy.getAddress();
      routerV1 = await ethers.getContractAt("ProofRouter", proxyAddr, owner);

      expect(proxyAddr).to.be.properAddress;
    });

    it("V1: can register adapter", async () => {
      const { adapter } = await deployAdapterStack(owner);
      adapterAddr = await adapter.getAddress();

      await (await routerV1.registerAdapter(1, adapterAddr)).wait();
      expect(await routerV1.getAdapter(1)).to.equal(adapterAddr);
    });

    it("upgrades to V2", async () => {
      const V2Factory = await ethers.getContractFactory("ProofRouterV2", owner);
      const upgraded = await upgrades.upgradeProxy(proxyAddr, V2Factory, {
        kind: "uups",
        unsafeAllow: ["missing-initializer"]
      });
      await upgraded.waitForDeployment();

      expect(await upgraded.getAddress()).to.equal(proxyAddr);
    });

    it("V2: version() returns 2", async () => {
      const routerV2 = await ethers.getContractAt("ProofRouterV2", proxyAddr, owner);
      expect(await routerV2.version()).to.equal(2);
    });

    it("V2: registered adapters are preserved", async () => {
      const routerV2 = await ethers.getContractAt("ProofRouterV2", proxyAddr, owner);
      expect(await routerV2.getAdapter(1)).to.equal(adapterAddr);
    });

    it("non-owner cannot upgrade — reverts", async () => {
      const V2 = await ethers.getContractFactory("ProofRouterV2", nonOwner);
      const newImpl = await V2.deploy();
      await newImpl.waitForDeployment();

      const proxy = await ethers.getContractAt("ProofRouterV2", proxyAddr, nonOwner);
      await expect((proxy as any).upgradeToAndCall(await newImpl.getAddress(), "0x")).to.be
        .reverted;
    });
  });

  // ── WorldlineRegistry ───────────────────────────────────────────────────────

  describe("WorldlineRegistry upgrade (verify proxy works)", () => {
    let registry: any;

    it("deploys behind proxy", async () => {
      const MockVerifier = await ethers.getContractFactory("MockGroth16Verifier", owner);
      const verifier = await MockVerifier.deploy();
      await verifier.waitForDeployment();

      const RegistryFactory = await ethers.getContractFactory("WorldlineRegistry", owner);
      const proxy = await upgrades.deployProxy(RegistryFactory, [await verifier.getAddress()], {
        kind: "uups"
      });
      await proxy.waitForDeployment();

      registry = await ethers.getContractAt("WorldlineRegistry", await proxy.getAddress(), owner);
      expect(await registry.getAddress()).to.be.properAddress;
      // defaultVerifier should be set from initialize
      expect(await registry.defaultVerifier()).to.equal(await verifier.getAddress());
    });

    it("can register circuit through proxy", async () => {
      const circuitId = ethers.keccak256(ethers.toUtf8Bytes("test-circuit-id"));
      await (
        await registry.registerCircuit(circuitId, "Test circuit", ethers.ZeroAddress, "ipfs://test")
      ).wait();

      const circuit = await registry.getCircuit(circuitId);
      expect(circuit.id).to.equal(circuitId);
    });
  });

  // ── WorldlineOutputsRegistry ────────────────────────────────────────────────

  describe("WorldlineOutputsRegistry upgrade (verify proxy works)", () => {
    let outputsRegistry: any;

    it("deploys behind proxy", async () => {
      const OutputsFactory = await ethers.getContractFactory("WorldlineOutputsRegistry", owner);
      const proxy = await upgrades.deployProxy(OutputsFactory, [MIN_TIMELOCK], { kind: "uups" });
      await proxy.waitForDeployment();

      outputsRegistry = await ethers.getContractAt(
        "WorldlineOutputsRegistry",
        await proxy.getAddress(),
        owner
      );
      expect(await outputsRegistry.getAddress()).to.be.properAddress;
      expect(await outputsRegistry.minTimelock()).to.equal(MIN_TIMELOCK);
    });

    it("can schedule and activate output entry through proxy", async () => {
      const chainIdHash = ethers.keccak256(ethers.toUtf8Bytes("chain-1"));
      const domainTag = ethers.keccak256(ethers.toUtf8Bytes("domain-tag-1"));
      const dKey = await outputsRegistry.domainKey(chainIdHash, domainTag);

      const programVKey = ethers.keccak256(ethers.toUtf8Bytes("program-vkey"));
      const policyHash = ethers.keccak256(ethers.toUtf8Bytes("policy-hash"));
      // Use a dummy non-zero oracle address
      const oracle = ethers.Wallet.createRandom().address;

      // Schedule the entry
      await (await outputsRegistry.schedule(dKey, programVKey, policyHash, oracle)).wait();

      // Fast-forward past the timelock by mining blocks with time increase
      await ethers.provider.send("evm_increaseTime", [Number(MIN_TIMELOCK) + 1]);
      await ethers.provider.send("evm_mine", []);

      // Activate the entry
      await (await outputsRegistry.activate(dKey)).wait();

      // Verify it's active
      expect(await outputsRegistry.isActive(dKey)).to.be.true;
    });
  });
});
