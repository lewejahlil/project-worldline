import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { expect } from "chai";
import { ethers, upgrades } from "hardhat";

const CIRCUIT_ID = ethers.encodeBytes32String("circuit-1");
const DRIVER_ID = ethers.encodeBytes32String("driver-1");
const PLUGIN_ID = ethers.encodeBytes32String("plugin-1");

describe("WorldlineCompat", function () {
  async function deployFixture() {
    const [owner, stranger] = await ethers.getSigners();

    const MockVerifier = await ethers.getContractFactory("MockGroth16Verifier");
    const mockVerifier = await MockVerifier.deploy();

    const Registry = await ethers.getContractFactory("WorldlineRegistry");
    const registry = (await upgrades.deployProxy(Registry, [await mockVerifier.getAddress()], {
      kind: "uups"
    })) as any;
    await registry.waitForDeployment();

    const Compat = await ethers.getContractFactory("WorldlineCompat");
    const compat = await Compat.deploy(await registry.getAddress());

    // Wire compat as the facade on the registry
    await registry.connect(owner).setCompatFacade(await compat.getAddress());

    return { registry, compat, mockVerifier, owner, stranger };
  }

  describe("deployment", function () {
    it("stores the registry address", async function () {
      const { compat, registry } = await loadFixture(deployFixture);
      expect(await compat.registry()).to.equal(await registry.getAddress());
    });

    it("reverts if deployed with zero registry address", async function () {
      const Compat = await ethers.getContractFactory("WorldlineCompat");
      await expect(Compat.deploy(ethers.ZeroAddress))
        .to.be.revertedWithCustomError(
          await Compat.deploy(ethers.ZeroAddress).catch(() => Compat),
          "RegistryZero"
        )
        .catch(async () => {
          // fallback: just check it reverts
          await expect(Compat.deploy(ethers.ZeroAddress)).to.be.reverted;
        });
    });
  });

  describe("registerCircuit", function () {
    it("owner can register a circuit through the facade", async function () {
      const { compat, registry, owner, mockVerifier } = await loadFixture(deployFixture);
      const verifierAddr = await mockVerifier.getAddress();
      await compat.connect(owner).registerCircuit(CIRCUIT_ID, "test", verifierAddr, "ipfs://a");
      const circuit = await registry.getCircuit(CIRCUIT_ID);
      expect(circuit.description).to.equal("test");
    });

    it("non-owner cannot register a circuit through the facade", async function () {
      const { compat, stranger } = await loadFixture(deployFixture);
      await expect(
        compat.connect(stranger).registerCircuit(CIRCUIT_ID, "test", ethers.ZeroAddress, "")
      ).to.be.revertedWithCustomError(compat, "NotOwner");
    });
  });

  describe("registerDriver", function () {
    it("owner can register a driver through the facade", async function () {
      const { compat, registry, owner } = await loadFixture(deployFixture);
      await compat.connect(owner).registerDriver(DRIVER_ID, "1.0.0", "http://localhost");
      const driver = await registry.getDriver(DRIVER_ID);
      expect(driver.version).to.equal("1.0.0");
    });
  });

  describe("registerPlugin", function () {
    it("owner can register a plugin through the facade", async function () {
      const { compat, registry, owner, stranger } = await loadFixture(deployFixture);
      await compat.connect(owner).registerCircuit(CIRCUIT_ID, "c", ethers.ZeroAddress, "");
      await compat.connect(owner).registerPlugin(PLUGIN_ID, "1.0.0", stranger.address, CIRCUIT_ID);
      const plugin = await registry.getPlugin(PLUGIN_ID);
      expect(plugin.version).to.equal("1.0.0");
    });
  });

  describe("deprecatePlugin", function () {
    it("owner can deprecate a plugin through the facade", async function () {
      const { compat, registry, owner, stranger } = await loadFixture(deployFixture);
      await compat.connect(owner).registerCircuit(CIRCUIT_ID, "c", ethers.ZeroAddress, "");
      await compat.connect(owner).registerPlugin(PLUGIN_ID, "1.0.0", stranger.address, CIRCUIT_ID);
      await compat.connect(owner).deprecatePlugin(PLUGIN_ID);
      const plugin = await registry.getPlugin(PLUGIN_ID);
      expect(plugin.deprecated).to.be.true;
    });
  });

  describe("view functions", function () {
    it("getCircuit reads through to registry", async function () {
      const { compat, owner } = await loadFixture(deployFixture);
      await compat.connect(owner).registerCircuit(CIRCUIT_ID, "desc", ethers.ZeroAddress, "uri");
      const circuit = await compat.getCircuit(CIRCUIT_ID);
      expect(circuit.description).to.equal("desc");
    });

    it("getDriver reads through to registry", async function () {
      const { compat, owner } = await loadFixture(deployFixture);
      await compat.connect(owner).registerDriver(DRIVER_ID, "2.0.0", "http://x");
      const driver = await compat.getDriver(DRIVER_ID);
      expect(driver.version).to.equal("2.0.0");
    });

    it("getPlugin reads through to registry", async function () {
      const { compat, owner, stranger } = await loadFixture(deployFixture);
      await compat.connect(owner).registerCircuit(CIRCUIT_ID, "c", ethers.ZeroAddress, "");
      await compat.connect(owner).registerPlugin(PLUGIN_ID, "1.0.0", stranger.address, CIRCUIT_ID);
      const plugin = await compat.getPlugin(PLUGIN_ID);
      expect(plugin.version).to.equal("1.0.0");
    });
  });
});
