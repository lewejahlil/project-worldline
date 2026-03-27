import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";

/**
 * End-to-end integration test exercising the full contract stack:
 * Deploy → Register → Prove → Verify
 */
describe("E2E Integration", function () {
  async function deployFullStack() {
    const [deployer] = await ethers.getSigners();

    // Deploy Verifier
    const Verifier = await ethers.getContractFactory("Verifier");
    const verifier = await Verifier.deploy();

    // Deploy Registry
    const Registry = await ethers.getContractFactory("WorldlineRegistry");
    const registry = await Registry.deploy(await verifier.getAddress());

    // Deploy Compat facade
    const Compat = await ethers.getContractFactory("WorldlineCompat");
    const compat = await Compat.deploy(await registry.getAddress());

    // Wire compat facade
    await registry.setCompatFacade(await compat.getAddress());

    return { verifier, registry, compat, deployer };
  }

  it("full lifecycle: deploy → register → verify via registry", async function () {
    const { verifier, registry, deployer } = await loadFixture(deployFullStack);

    const circuitId = ethers.encodeBytes32String("squarehash-v1");
    const pluginId = ethers.encodeBytes32String("squarehash-groth16");
    const driverId = ethers.encodeBytes32String("driver-local");

    // Register circuit
    await registry.registerCircuit(
      circuitId,
      "SquareHash demo circuit",
      await verifier.getAddress(),
      "ipfs://QmTest"
    );

    // Register driver
    await registry.registerDriver(driverId, "1.0.0", "http://localhost:8545");

    // Register plugin
    await registry.registerPlugin(pluginId, "1.0.0", deployer.address, circuitId);

    // Verify: 7² = 49
    const result = await registry.verify(circuitId, 7n, 49n);
    expect(result).to.be.true;

    // Verify: 12² = 144
    const result2 = await registry.verify(circuitId, 12n, 144n);
    expect(result2).to.be.true;

    // Read back metadata
    const circuit = await registry.getCircuit(circuitId);
    expect(circuit.description).to.equal("SquareHash demo circuit");

    const driver = await registry.getDriver(driverId);
    expect(driver.version).to.equal("1.0.0");

    const plugin = await registry.getPlugin(pluginId);
    expect(plugin.version).to.equal("1.0.0");
    expect(plugin.deprecated).to.be.false;
  });

  it("full lifecycle via compat facade", async function () {
    const { verifier, compat, deployer } = await loadFixture(deployFullStack);

    const circuitId = ethers.encodeBytes32String("compat-circuit");
    const pluginId = ethers.encodeBytes32String("compat-plugin");

    // Register through compat
    await compat.registerCircuit(
      circuitId,
      "Compat test circuit",
      await verifier.getAddress(),
      "ipfs://compat"
    );

    await compat.registerPlugin(pluginId, "2.0.0", deployer.address, circuitId);

    // Verify through compat
    const result = await compat.verify(circuitId, 5n, 25n);
    expect(result).to.be.true;

    // Read through compat
    const circuit = await compat.getCircuit(circuitId);
    expect(circuit.description).to.equal("Compat test circuit");
  });

  it("invalid proof reverts", async function () {
    const { verifier, registry } = await loadFixture(deployFullStack);

    const circuitId = ethers.encodeBytes32String("revert-test");
    await registry.registerCircuit(circuitId, "Revert test", await verifier.getAddress(), "");

    // 7² ≠ 50
    await expect(registry.verify(circuitId, 7n, 50n)).to.be.revertedWithCustomError(
      verifier,
      "InvalidProof"
    );
  });

  it("deprecating a plugin marks it but keeps it queryable", async function () {
    const { verifier, registry, deployer } = await loadFixture(deployFullStack);

    const circuitId = ethers.encodeBytes32String("dep-circuit");
    const pluginId = ethers.encodeBytes32String("dep-plugin");

    await registry.registerCircuit(circuitId, "c", await verifier.getAddress(), "");
    await registry.registerPlugin(pluginId, "1.0.0", deployer.address, circuitId);

    await registry.deprecatePlugin(pluginId);

    const plugin = await registry.getPlugin(pluginId);
    expect(plugin.deprecated).to.be.true;
    expect(plugin.implementation).to.equal(deployer.address);
  });
});
