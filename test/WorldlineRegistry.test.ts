import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { WorldlineRegistry } from "../typechain-types";

const CIRCUIT_ID = ethers.encodeBytes32String("circuit-1");
const DRIVER_ID = ethers.encodeBytes32String("driver-1");
const PLUGIN_ID = ethers.encodeBytes32String("plugin-1");
const ZERO_BYTES32 = ethers.ZeroHash;

describe("WorldlineRegistry", function () {
  async function deployFixture() {
    const [owner, admin, stranger] = await ethers.getSigners();

    const MockVerifier = await ethers.getContractFactory("MockGroth16Verifier");
    const mockVerifier = await MockVerifier.deploy();

    const Registry = await ethers.getContractFactory("WorldlineRegistry");
    const registry: WorldlineRegistry = (await upgrades.deployProxy(
      Registry,
      [await mockVerifier.getAddress()],
      { kind: "uups" }
    )) as any;
    await registry.waitForDeployment();

    return { registry, mockVerifier, owner, admin, stranger };
  }

  // ─── Deployment ──────────────────────────────────────────────────────────────

  describe("deployment", function () {
    it("sets the deployer as owner", async function () {
      const { registry, owner } = await loadFixture(deployFixture);
      expect(await registry.owner()).to.equal(owner.address);
    });

    it("stores the default verifier address", async function () {
      const { registry, mockVerifier } = await loadFixture(deployFixture);
      expect(await registry.defaultVerifier()).to.equal(await mockVerifier.getAddress());
    });

    it("reverts if deployed with zero verifier address", async function () {
      const Registry = await ethers.getContractFactory("WorldlineRegistry");
      await expect(
        upgrades.deployProxy(Registry, [ethers.ZeroAddress], { kind: "uups" })
      ).to.be.revertedWithCustomError(Registry, "InvalidVerifier");
    });
  });

  // ─── Ownable ─────────────────────────────────────────────────────────────────

  describe("Ownable", function () {
    it("owner() returns the current owner", async function () {
      const { registry, owner } = await loadFixture(deployFixture);
      expect(await registry.owner()).to.equal(owner.address);
    });

    it("owner can initiate two-step ownership transfer", async function () {
      const { registry, owner, stranger } = await loadFixture(deployFixture);
      await expect(registry.connect(owner).transferOwnership(stranger.address))
        .to.emit(registry, "OwnershipTransferStarted")
        .withArgs(owner.address, stranger.address);
      // Owner not changed yet — pending owner must accept
      expect(await registry.owner()).to.equal(owner.address);
      expect(await registry.pendingOwner()).to.equal(stranger.address);
    });

    it("pending owner can accept ownership", async function () {
      const { registry, owner, stranger } = await loadFixture(deployFixture);
      await registry.connect(owner).transferOwnership(stranger.address);
      await expect(registry.connect(stranger).acceptOwnership())
        .to.emit(registry, "OwnershipTransferred")
        .withArgs(owner.address, stranger.address);
      expect(await registry.owner()).to.equal(stranger.address);
    });

    it("new owner can exercise ownership after transfer", async function () {
      const { registry, owner, stranger } = await loadFixture(deployFixture);
      await registry.connect(owner).transferOwnership(stranger.address);
      await registry.connect(stranger).acceptOwnership();
      // stranger is now owner — they should be able to call setCompatFacade
      await expect(registry.connect(stranger).setCompatFacade(stranger.address)).to.not.be.reverted;
    });

    it("non-owner cannot transfer ownership", async function () {
      const { registry, stranger } = await loadFixture(deployFixture);
      await expect(
        registry.connect(stranger).transferOwnership(stranger.address)
      ).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
    });

    it("transferring ownership to zero address sets pendingOwner to 0 (OZ v5 two-step)", async function () {
      const { registry, owner } = await loadFixture(deployFixture);
      // In OZ v5 Ownable2StepUpgradeable, transferOwnership(0) does NOT revert —
      // it sets pendingOwner = 0 which can be used to cancel a pending transfer.
      await expect(registry.connect(owner).transferOwnership(ethers.ZeroAddress)).to.not.be
        .reverted;
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
      await expect(
        registry.connect(stranger).setCompatFacade(stranger.address)
      ).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
    });

    it("compat facade can be disabled via timelocked two-step", async function () {
      const { registry, owner, stranger } = await loadFixture(deployFixture);
      // First-time wiring (instant, since compatFacade starts as address(0))
      await registry.connect(owner).setCompatFacade(stranger.address);
      // Now it's set — must use two-step schedule/activate to change
      await registry.connect(owner).scheduleCompatFacade(ethers.ZeroAddress);
      // Fast-forward past the facade change delay (1 day)
      await ethers.provider.send("evm_increaseTime", [86401]);
      await ethers.provider.send("evm_mine", []);
      await expect(registry.connect(owner).activateCompatFacade())
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
      const { registry, owner, mockVerifier } = await loadFixture(deployFixture);
      const verifierAddr = await mockVerifier.getAddress();
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
      ).to.be.revertedWithCustomError(registry, "NotAuthorised");
    });

    it("reverts on duplicate circuit ID", async function () {
      const { registry, owner } = await loadFixture(deployFixture);
      await registry.connect(owner).registerCircuit(CIRCUIT_ID, "first", ethers.ZeroAddress, "");
      await expect(
        registry.connect(owner).registerCircuit(CIRCUIT_ID, "second", ethers.ZeroAddress, "")
      ).to.be.revertedWithCustomError(registry, "CircuitExists");
    });

    it("reverts when circuit ID is zero bytes32", async function () {
      const { registry, owner } = await loadFixture(deployFixture);
      await expect(
        registry.connect(owner).registerCircuit(ZERO_BYTES32, "desc", ethers.ZeroAddress, "")
      ).to.be.revertedWithCustomError(registry, "InvalidCircuitId");
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
      const { registry, owner, mockVerifier } = await loadFixture(deployFixture);
      const verifierAddr = await mockVerifier.getAddress();
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
      await expect(registry.getCircuit(CIRCUIT_ID)).to.be.revertedWithCustomError(
        registry,
        "CircuitMissing"
      );
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
      ).to.be.revertedWithCustomError(registry, "NotAuthorised");
    });

    it("reverts on duplicate driver ID", async function () {
      const { registry, owner } = await loadFixture(deployFixture);
      await registry.connect(owner).registerDriver(DRIVER_ID, "1.0.0", "http://a");
      await expect(
        registry.connect(owner).registerDriver(DRIVER_ID, "2.0.0", "http://b")
      ).to.be.revertedWithCustomError(registry, "DriverExists");
    });

    it("reverts when driver ID is zero bytes32", async function () {
      const { registry, owner } = await loadFixture(deployFixture);
      await expect(
        registry.connect(owner).registerDriver(ZERO_BYTES32, "1.0.0", "http://x")
      ).to.be.revertedWithCustomError(registry, "InvalidDriverId");
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
      await expect(registry.getDriver(DRIVER_ID)).to.be.revertedWithCustomError(
        registry,
        "DriverMissing"
      );
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
      ).to.be.revertedWithCustomError(registry, "NotAuthorised");
    });

    it("reverts on duplicate plugin ID", async function () {
      const { registry, owner, stranger } = await loadFixture(deployFixture);
      await withCircuit(registry, owner);
      await registry
        .connect(owner)
        .registerPlugin(PLUGIN_ID, "1.0.0", stranger.address, CIRCUIT_ID);
      await expect(
        registry.connect(owner).registerPlugin(PLUGIN_ID, "2.0.0", stranger.address, CIRCUIT_ID)
      ).to.be.revertedWithCustomError(registry, "PluginExists");
    });

    it("reverts when plugin ID is zero bytes32", async function () {
      const { registry, owner, stranger } = await loadFixture(deployFixture);
      await withCircuit(registry, owner);
      await expect(
        registry.connect(owner).registerPlugin(ZERO_BYTES32, "1.0.0", stranger.address, CIRCUIT_ID)
      ).to.be.revertedWithCustomError(registry, "InvalidPluginId");
    });

    it("reverts when implementation address is zero", async function () {
      const { registry, owner } = await loadFixture(deployFixture);
      await withCircuit(registry, owner);
      await expect(
        registry.connect(owner).registerPlugin(PLUGIN_ID, "1.0.0", ethers.ZeroAddress, CIRCUIT_ID)
      ).to.be.revertedWithCustomError(registry, "InvalidImplementation");
    });

    it("reverts when referenced circuit does not exist", async function () {
      const { registry, owner, stranger } = await loadFixture(deployFixture);
      // circuit not registered
      await expect(
        registry.connect(owner).registerPlugin(PLUGIN_ID, "1.0.0", stranger.address, CIRCUIT_ID)
      ).to.be.revertedWithCustomError(registry, "CircuitMissing");
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
      await expect(
        registry.connect(stranger).deprecatePlugin(PLUGIN_ID)
      ).to.be.revertedWithCustomError(registry, "NotAuthorised");
    });

    it("reverts when deprecating a non-existent plugin", async function () {
      const { registry, owner } = await loadFixture(deployFixture);
      await expect(
        registry.connect(owner).deprecatePlugin(PLUGIN_ID)
      ).to.be.revertedWithCustomError(registry, "PluginMissing");
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
      await expect(registry.getPlugin(PLUGIN_ID)).to.be.revertedWithCustomError(
        registry,
        "PluginMissing"
      );
    });
  });
});
