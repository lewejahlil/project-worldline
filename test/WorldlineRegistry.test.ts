import { ethers } from "hardhat";
import { expect } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { WorldlineRegistry, Verifier } from "../typechain-types";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";

const CIRCUIT_ID = ethers.encodeBytes32String("circuit-1");
const DRIVER_ID = ethers.encodeBytes32String("driver-1");
const PLUGIN_ID = ethers.encodeBytes32String("plugin-1");
const ZERO_BYTES32 = ethers.ZeroHash;

describe("WorldlineRegistry", function () {
  async function deployFixture() {
    const [owner, admin, stranger] = await ethers.getSigners();

    const Verifier = await ethers.getContractFactory("Verifier");
    const verifier: Verifier = await Verifier.deploy();

    const Registry = await ethers.getContractFactory("WorldlineRegistry");
    const registry: WorldlineRegistry = await Registry.deploy(await verifier.getAddress());

    return { registry, verifier, owner, admin, stranger };
  }

  // ─── Deployment ──────────────────────────────────────────────────────────────

  describe("deployment", function () {
    it("sets the deployer as owner", async function () {
      const { registry, owner } = await loadFixture(deployFixture);
      expect(await registry.owner()).to.equal(owner.address);
    });

    it("stores the default verifier address", async function () {
      const { registry, verifier } = await loadFixture(deployFixture);
      expect(await registry.defaultVerifier()).to.equal(await verifier.getAddress());
    });

    it("reverts if deployed with zero verifier address", async function () {
      const Registry = await ethers.getContractFactory("WorldlineRegistry");
      await expect(Registry.deploy(ethers.ZeroAddress)).to.be.revertedWith("invalid verifier");
    });
  });

  // ─── Ownable ─────────────────────────────────────────────────────────────────

  describe("Ownable", function () {
    it("owner() returns the current owner", async function () {
      const { registry, owner } = await loadFixture(deployFixture);
      expect(await registry.owner()).to.equal(owner.address);
    });

    it("owner can transfer ownership", async function () {
      const { registry, owner, stranger } = await loadFixture(deployFixture);
      await expect(registry.connect(owner).transferOwnership(stranger.address))
        .to.emit(registry, "OwnershipTransferred")
        .withArgs(owner.address, stranger.address);
      expect(await registry.owner()).to.equal(stranger.address);
    });

    it("new owner can exercise ownership after transfer", async function () {
      const { registry, owner, stranger } = await loadFixture(deployFixture);
      await registry.connect(owner).transferOwnership(stranger.address);
      // stranger is now owner — they should be able to call setCompatFacade
      await expect(registry.connect(stranger).setCompatFacade(stranger.address)).to.not.be.reverted;
    });

    it("non-owner cannot transfer ownership", async function () {
      const { registry, stranger } = await loadFixture(deployFixture);
      await expect(
        registry.connect(stranger).transferOwnership(stranger.address)
      ).to.be.revertedWith("Ownable: caller is not the owner");
    });

    it("transferring ownership to zero address reverts", async function () {
      const { registry, owner } = await loadFixture(deployFixture);
      await expect(
        registry.connect(owner).transferOwnership(ethers.ZeroAddress)
      ).to.be.revertedWith("Ownable: new owner is the zero address");
    });
  });

  // ─── setCompatFacade ─────────────────────────────────────────────────────────

  describe("setCompatFacade", function () {
    it("owner can set the compat facade", async function () {
      const { registry, owner, stranger } = await loadFixture(deployFixture);
      await expect(registry.connect(owner).setCompatFacade(stranger.address))
        .to.emit(registry, "CompatFacadeSet")
        .withArgs(stranger.address);
      expect(await registry.compatFacade()).to.equal(stranger.address);
    });

    it("non-owner cannot set the compat facade", async function () {
      const { registry, stranger } = await loadFixture(deployFixture);
      await expect(registry.connect(stranger).setCompatFacade(stranger.address)).to.be.revertedWith(
        "Ownable: caller is not the owner"
      );
    });

    it("compat facade address can be set to zero (disabled)", async function () {
      const { registry, owner, stranger } = await loadFixture(deployFixture);
      await registry.connect(owner).setCompatFacade(stranger.address);
      await expect(registry.connect(owner).setCompatFacade(ethers.ZeroAddress))
        .to.emit(registry, "CompatFacadeSet")
        .withArgs(ethers.ZeroAddress);
      expect(await registry.compatFacade()).to.equal(ethers.ZeroAddress);
    });

    it("compat facade gains admin rights after being set", async function () {
      const { registry, owner, stranger } = await loadFixture(deployFixture);
      await registry.connect(owner).setCompatFacade(stranger.address);
      // stranger (as compatFacade) should be able to call admin-only functions
      await expect(
        registry
          .connect(stranger)
          .registerCircuit(CIRCUIT_ID, "via facade", ethers.ZeroAddress, "ipfs://x")
      ).to.not.be.reverted;
    });
  });

  // ─── registerCircuit ─────────────────────────────────────────────────────────

  describe("registerCircuit", function () {
    it("admin can register a circuit", async function () {
      const { registry, owner, verifier } = await loadFixture(deployFixture);
      const verifierAddr = await verifier.getAddress();
      await expect(
        registry
          .connect(owner)
          .registerCircuit(CIRCUIT_ID, "test circuit", verifierAddr, "ipfs://a")
      )
        .to.emit(registry, "CircuitRegistered")
        .withArgs(CIRCUIT_ID, verifierAddr);
    });

    it("non-admin cannot register a circuit", async function () {
      const { registry, stranger } = await loadFixture(deployFixture);
      await expect(
        registry
          .connect(stranger)
          .registerCircuit(CIRCUIT_ID, "test circuit", ethers.ZeroAddress, "")
      ).to.be.revertedWith("not authorised");
    });

    it("reverts on duplicate circuit ID", async function () {
      const { registry, owner } = await loadFixture(deployFixture);
      await registry.connect(owner).registerCircuit(CIRCUIT_ID, "first", ethers.ZeroAddress, "");
      await expect(
        registry.connect(owner).registerCircuit(CIRCUIT_ID, "second", ethers.ZeroAddress, "")
      ).to.be.revertedWith("circuit exists");
    });

    it("reverts when circuit ID is zero bytes32", async function () {
      const { registry, owner } = await loadFixture(deployFixture);
      await expect(
        registry.connect(owner).registerCircuit(ZERO_BYTES32, "desc", ethers.ZeroAddress, "")
      ).to.be.revertedWith("invalid circuit id");
    });

    it("registers with address(0) verifier (falls back to defaultVerifier)", async function () {
      const { registry, owner } = await loadFixture(deployFixture);
      await expect(
        registry.connect(owner).registerCircuit(CIRCUIT_ID, "desc", ethers.ZeroAddress, "uri")
      ).to.not.be.reverted;
    });
  });

  // ─── getCircuit ──────────────────────────────────────────────────────────────

  describe("getCircuit", function () {
    it("returns correct metadata for a registered circuit", async function () {
      const { registry, owner, verifier } = await loadFixture(deployFixture);
      const verifierAddr = await verifier.getAddress();
      await registry
        .connect(owner)
        .registerCircuit(CIRCUIT_ID, "my circuit", verifierAddr, "ipfs://abc");

      const circuit = await registry.getCircuit(CIRCUIT_ID);
      expect(circuit.id).to.equal(CIRCUIT_ID);
      expect(circuit.description).to.equal("my circuit");
      expect(circuit.verifier).to.equal(verifierAddr);
      expect(circuit.abiURI).to.equal("ipfs://abc");
    });

    it("reverts for an unknown circuit ID", async function () {
      const { registry } = await loadFixture(deployFixture);
      await expect(registry.getCircuit(CIRCUIT_ID)).to.be.revertedWith("circuit missing");
    });
  });

  // ─── registerDriver ──────────────────────────────────────────────────────────

  describe("registerDriver", function () {
    it("admin can register a driver", async function () {
      const { registry, owner } = await loadFixture(deployFixture);
      await expect(
        registry.connect(owner).registerDriver(DRIVER_ID, "1.0.0", "http://localhost:8545")
      )
        .to.emit(registry, "DriverRegistered")
        .withArgs(DRIVER_ID, "1.0.0");
    });

    it("non-admin cannot register a driver", async function () {
      const { registry, stranger } = await loadFixture(deployFixture);
      await expect(
        registry.connect(stranger).registerDriver(DRIVER_ID, "1.0.0", "http://localhost:8545")
      ).to.be.revertedWith("not authorised");
    });

    it("reverts on duplicate driver ID", async function () {
      const { registry, owner } = await loadFixture(deployFixture);
      await registry.connect(owner).registerDriver(DRIVER_ID, "1.0.0", "http://a");
      await expect(
        registry.connect(owner).registerDriver(DRIVER_ID, "2.0.0", "http://b")
      ).to.be.revertedWith("driver exists");
    });

    it("reverts when driver ID is zero bytes32", async function () {
      const { registry, owner } = await loadFixture(deployFixture);
      await expect(
        registry.connect(owner).registerDriver(ZERO_BYTES32, "1.0.0", "http://x")
      ).to.be.revertedWith("invalid driver id");
    });
  });

  // ─── getDriver ───────────────────────────────────────────────────────────────

  describe("getDriver", function () {
    it("returns correct metadata for a registered driver", async function () {
      const { registry, owner } = await loadFixture(deployFixture);
      await registry.connect(owner).registerDriver(DRIVER_ID, "1.2.3", "http://rpc.example.com");

      const driver = await registry.getDriver(DRIVER_ID);
      expect(driver.id).to.equal(DRIVER_ID);
      expect(driver.version).to.equal("1.2.3");
      expect(driver.endpoint).to.equal("http://rpc.example.com");
    });

    it("reverts for an unknown driver ID", async function () {
      const { registry } = await loadFixture(deployFixture);
      await expect(registry.getDriver(DRIVER_ID)).to.be.revertedWith("driver missing");
    });
  });

  // ─── registerPlugin ──────────────────────────────────────────────────────────

  describe("registerPlugin", function () {
    async function withCircuit(registry: WorldlineRegistry, owner: HardhatEthersSigner) {
      await registry
        .connect(owner)
        .registerCircuit(CIRCUIT_ID, "base circuit", ethers.ZeroAddress, "");
    }

    it("admin can register a plugin linked to an existing circuit", async function () {
      const { registry, owner, stranger } = await loadFixture(deployFixture);
      await withCircuit(registry, owner);
      await expect(
        registry.connect(owner).registerPlugin(PLUGIN_ID, "1.0.0", stranger.address, CIRCUIT_ID)
      )
        .to.emit(registry, "PluginRegistered")
        .withArgs(PLUGIN_ID, stranger.address);
    });

    it("non-admin cannot register a plugin", async function () {
      const { registry, stranger } = await loadFixture(deployFixture);
      await expect(
        registry.connect(stranger).registerPlugin(PLUGIN_ID, "1.0.0", stranger.address, CIRCUIT_ID)
      ).to.be.revertedWith("not authorised");
    });

    it("reverts on duplicate plugin ID", async function () {
      const { registry, owner, stranger } = await loadFixture(deployFixture);
      await withCircuit(registry, owner);
      await registry
        .connect(owner)
        .registerPlugin(PLUGIN_ID, "1.0.0", stranger.address, CIRCUIT_ID);
      await expect(
        registry.connect(owner).registerPlugin(PLUGIN_ID, "2.0.0", stranger.address, CIRCUIT_ID)
      ).to.be.revertedWith("plugin exists");
    });

    it("reverts when plugin ID is zero bytes32", async function () {
      const { registry, owner, stranger } = await loadFixture(deployFixture);
      await withCircuit(registry, owner);
      await expect(
        registry.connect(owner).registerPlugin(ZERO_BYTES32, "1.0.0", stranger.address, CIRCUIT_ID)
      ).to.be.revertedWith("invalid plugin id");
    });

    it("reverts when implementation address is zero", async function () {
      const { registry, owner } = await loadFixture(deployFixture);
      await withCircuit(registry, owner);
      await expect(
        registry.connect(owner).registerPlugin(PLUGIN_ID, "1.0.0", ethers.ZeroAddress, CIRCUIT_ID)
      ).to.be.revertedWith("invalid implementation");
    });

    it("reverts when referenced circuit does not exist", async function () {
      const { registry, owner, stranger } = await loadFixture(deployFixture);
      // circuit not registered
      await expect(
        registry.connect(owner).registerPlugin(PLUGIN_ID, "1.0.0", stranger.address, CIRCUIT_ID)
      ).to.be.revertedWith("circuit missing");
    });
  });

  // ─── deprecatePlugin ─────────────────────────────────────────────────────────

  describe("deprecatePlugin", function () {
    async function withPlugin(
      registry: WorldlineRegistry,
      owner: HardhatEthersSigner,
      implAddr: string
    ) {
      await registry.connect(owner).registerCircuit(CIRCUIT_ID, "c", ethers.ZeroAddress, "");
      await registry.connect(owner).registerPlugin(PLUGIN_ID, "1.0.0", implAddr, CIRCUIT_ID);
    }

    it("admin can deprecate a registered plugin", async function () {
      const { registry, owner, stranger } = await loadFixture(deployFixture);
      await withPlugin(registry, owner, stranger.address);
      await expect(registry.connect(owner).deprecatePlugin(PLUGIN_ID))
        .to.emit(registry, "PluginDeprecated")
        .withArgs(PLUGIN_ID);
    });

    it("deprecated flag is set to true after deprecation", async function () {
      const { registry, owner, stranger } = await loadFixture(deployFixture);
      await withPlugin(registry, owner, stranger.address);
      await registry.connect(owner).deprecatePlugin(PLUGIN_ID);
      const plugin = await registry.getPlugin(PLUGIN_ID);
      expect(plugin.deprecated).to.be.true;
    });

    it("non-admin cannot deprecate a plugin", async function () {
      const { registry, owner, stranger } = await loadFixture(deployFixture);
      await withPlugin(registry, owner, stranger.address);
      await expect(registry.connect(stranger).deprecatePlugin(PLUGIN_ID)).to.be.revertedWith(
        "not authorised"
      );
    });

    it("reverts when deprecating a non-existent plugin", async function () {
      const { registry, owner } = await loadFixture(deployFixture);
      await expect(registry.connect(owner).deprecatePlugin(PLUGIN_ID)).to.be.revertedWith(
        "plugin missing"
      );
    });
  });

  // ─── getPlugin ───────────────────────────────────────────────────────────────

  describe("getPlugin", function () {
    it("returns correct metadata for a registered plugin", async function () {
      const { registry, owner, stranger } = await loadFixture(deployFixture);
      await registry.connect(owner).registerCircuit(CIRCUIT_ID, "c", ethers.ZeroAddress, "");
      await registry
        .connect(owner)
        .registerPlugin(PLUGIN_ID, "2.3.4", stranger.address, CIRCUIT_ID);

      const plugin = await registry.getPlugin(PLUGIN_ID);
      expect(plugin.id).to.equal(PLUGIN_ID);
      expect(plugin.version).to.equal("2.3.4");
      expect(plugin.implementation).to.equal(stranger.address);
      expect(plugin.circuitId).to.equal(CIRCUIT_ID);
      expect(plugin.deprecated).to.be.false;
    });

    it("returns deprecated=true after deprecation", async function () {
      const { registry, owner, stranger } = await loadFixture(deployFixture);
      await registry.connect(owner).registerCircuit(CIRCUIT_ID, "c", ethers.ZeroAddress, "");
      await registry
        .connect(owner)
        .registerPlugin(PLUGIN_ID, "1.0.0", stranger.address, CIRCUIT_ID);
      await registry.connect(owner).deprecatePlugin(PLUGIN_ID);

      const plugin = await registry.getPlugin(PLUGIN_ID);
      expect(plugin.deprecated).to.be.true;
    });

    it("reverts for an unknown plugin ID", async function () {
      const { registry } = await loadFixture(deployFixture);
      await expect(registry.getPlugin(PLUGIN_ID)).to.be.revertedWith("plugin missing");
    });
  });

  // ─── verify ──────────────────────────────────────────────────────────────────

  describe("verify", function () {
    it("returns true for a valid proof using the defaultVerifier (circuit verifier=0)", async function () {
      const { registry, owner } = await loadFixture(deployFixture);
      // Register circuit with verifier=0 → falls back to defaultVerifier
      await registry.connect(owner).registerCircuit(CIRCUIT_ID, "sq", ethers.ZeroAddress, "");
      // 3² = 9
      expect(await registry.verify(CIRCUIT_ID, 3n, 9n)).to.be.true;
    });

    it("returns true for a valid proof using a circuit-specific verifier", async function () {
      const { registry, owner, verifier } = await loadFixture(deployFixture);
      const verifierAddr = await verifier.getAddress();
      await registry.connect(owner).registerCircuit(CIRCUIT_ID, "sq", verifierAddr, "");
      expect(await registry.verify(CIRCUIT_ID, 7n, 49n)).to.be.true;
    });

    it("reverts with InvalidProof for an invalid proof", async function () {
      const { registry, owner, verifier } = await loadFixture(deployFixture);
      await registry.connect(owner).registerCircuit(CIRCUIT_ID, "sq", ethers.ZeroAddress, "");
      // 3² ≠ 10
      await expect(registry.verify(CIRCUIT_ID, 3n, 10n)).to.be.revertedWithCustomError(
        verifier,
        "InvalidProof"
      );
    });

    it("reverts when circuit ID is not registered", async function () {
      const { registry } = await loadFixture(deployFixture);
      await expect(registry.verify(CIRCUIT_ID, 3n, 9n)).to.be.revertedWith("circuit missing");
    });
  });
});
