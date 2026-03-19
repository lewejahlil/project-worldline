import { ethers } from "hardhat";
import { expect } from "chai";
import { loadFixture, time } from "@nomicfoundation/hardhat-toolbox/network-helpers";

const CHAIN_HASH = ethers.keccak256(ethers.toUtf8Bytes("chain-1"));
const DOMAIN_TAG = ethers.keccak256(ethers.toUtf8Bytes("domain-tag"));
const PROGRAM_VKEY = ethers.keccak256(ethers.toUtf8Bytes("vkey"));
const POLICY_HASH = ethers.keccak256(ethers.toUtf8Bytes("policy"));

describe("WorldlineOutputsRegistry", function () {
  // 1 hour timelock for tests
  const MIN_TIMELOCK = 3600;

  async function deployFixture() {
    const [owner, oracle, stranger] = await ethers.getSigners();

    const Registry = await ethers.getContractFactory("WorldlineOutputsRegistry");
    const registry = await Registry.deploy(MIN_TIMELOCK);

    const dKey = await registry.domainKey(CHAIN_HASH, DOMAIN_TAG);

    return { registry, owner, oracle, stranger, dKey };
  }

  describe("deployment", function () {
    it("sets minimum timelock", async function () {
      const { registry } = await loadFixture(deployFixture);
      expect(await registry.minTimelock()).to.equal(MIN_TIMELOCK);
    });

    it("reverts if timelock is zero", async function () {
      const Registry = await ethers.getContractFactory("WorldlineOutputsRegistry");
      await expect(Registry.deploy(0)).to.be.revertedWithCustomError(
        Registry,
        "TimelockTooShort"
      );
    });
  });

  describe("domainKey", function () {
    it("computes deterministic key", async function () {
      const { registry, dKey } = await loadFixture(deployFixture);
      const expected = ethers.keccak256(
        ethers.solidityPacked(["bytes32", "bytes32"], [CHAIN_HASH, DOMAIN_TAG])
      );
      expect(dKey).to.equal(expected);
    });
  });

  describe("schedule", function () {
    it("owner can schedule an entry", async function () {
      const { registry, owner, oracle, dKey } = await loadFixture(deployFixture);
      await expect(
        registry.connect(owner).schedule(dKey, PROGRAM_VKEY, POLICY_HASH, oracle.address)
      ).to.emit(registry, "OutputScheduled");
    });

    it("non-owner cannot schedule", async function () {
      const { registry, stranger, oracle, dKey } = await loadFixture(deployFixture);
      await expect(
        registry.connect(stranger).schedule(dKey, PROGRAM_VKEY, POLICY_HASH, oracle.address)
      ).to.be.revertedWith("Ownable: caller is not the owner");
    });
  });

  describe("activate", function () {
    it("reverts if no pending entry", async function () {
      const { registry, dKey } = await loadFixture(deployFixture);
      await expect(registry.activate(dKey)).to.be.revertedWithCustomError(
        registry,
        "NoPendingEntry"
      );
    });

    it("reverts if timelock has not elapsed", async function () {
      const { registry, owner, oracle, dKey } = await loadFixture(deployFixture);
      await registry.connect(owner).schedule(dKey, PROGRAM_VKEY, POLICY_HASH, oracle.address);
      await expect(registry.activate(dKey)).to.be.revertedWithCustomError(
        registry,
        "TimelockNotElapsed"
      );
    });

    it("activates after timelock elapses", async function () {
      const { registry, owner, oracle, dKey } = await loadFixture(deployFixture);
      await registry.connect(owner).schedule(dKey, PROGRAM_VKEY, POLICY_HASH, oracle.address);

      // Fast forward past timelock
      await time.increase(MIN_TIMELOCK + 1);

      await expect(registry.activate(dKey))
        .to.emit(registry, "OutputActivated")
        .withArgs(dKey, PROGRAM_VKEY, POLICY_HASH, oracle.address);

      expect(await registry.isActive(dKey)).to.be.true;
      const entry = await registry.getActiveEntry(dKey);
      expect(entry.programVKey).to.equal(PROGRAM_VKEY);
      expect(entry.policyHash).to.equal(POLICY_HASH);
      expect(entry.oracle).to.equal(oracle.address);
    });

    it("anyone can activate after timelock (permissionless)", async function () {
      const { registry, owner, oracle, stranger, dKey } = await loadFixture(deployFixture);
      await registry.connect(owner).schedule(dKey, PROGRAM_VKEY, POLICY_HASH, oracle.address);
      await time.increase(MIN_TIMELOCK + 1);
      await expect(registry.connect(stranger).activate(dKey)).to.not.be.reverted;
    });
  });

  describe("getActiveEntry", function () {
    it("reverts if no active entry", async function () {
      const { registry, dKey } = await loadFixture(deployFixture);
      await expect(registry.getActiveEntry(dKey)).to.be.revertedWith("no active entry");
    });
  });

  describe("setMinTimelock", function () {
    it("owner can update timelock", async function () {
      const { registry, owner } = await loadFixture(deployFixture);
      await registry.connect(owner).setMinTimelock(7200);
      expect(await registry.minTimelock()).to.equal(7200);
    });

    it("reverts if set to zero", async function () {
      const { registry, owner } = await loadFixture(deployFixture);
      await expect(
        registry.connect(owner).setMinTimelock(0)
      ).to.be.revertedWithCustomError(registry, "TimelockTooShort");
    });
  });
});
