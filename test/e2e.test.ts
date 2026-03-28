import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { expect } from "chai";
import { ethers, upgrades } from "hardhat";

/**
 * End-to-end integration test exercising the full contract stack:
 * Deploy → Register → Read back metadata
 */
describe("E2E Integration", function () {
  async function deployFullStack() {
    const [deployer] = await ethers.getSigners();

    // Deploy MockGroth16Verifier (always returns true)
    const MockVerifier = await ethers.getContractFactory("MockGroth16Verifier");
    const mockVerifier = await MockVerifier.deploy();

    // Deploy Registry
    const Registry = await ethers.getContractFactory("WorldlineRegistry");
    const registry = await upgrades.deployProxy(
      Registry,
      [await mockVerifier.getAddress()],
      { kind: "uups" }
    ) as any;
    await registry.waitForDeployment();

    // Deploy Compat facade
    const Compat = await ethers.getContractFactory("WorldlineCompat");
    const compat = await Compat.deploy(await registry.getAddress());

    // Wire compat facade
    await registry.setCompatFacade(await compat.getAddress());

    return { mockVerifier, registry, compat, deployer };
  }

  it("full lifecycle: deploy → register → read back metadata", async function () {
    const { mockVerifier, registry, deployer } = await loadFixture(deployFullStack);

    const circuitId = ethers.encodeBytes32String("squarehash-v1");
    const pluginId = ethers.encodeBytes32String("squarehash-groth16");
    const driverId = ethers.encodeBytes32String("driver-local");

    // Register circuit
    await registry.registerCircuit(
      circuitId,
      "SquareHash demo circuit",
      await mockVerifier.getAddress(),
      "ipfs://QmTest"
    );

    // Register driver
    await registry.registerDriver(driverId, "1.0.0", "http://localhost:8545");

    // Register plugin
    await registry.registerPlugin(pluginId, "1.0.0", deployer.address, circuitId);

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
    const { mockVerifier, compat, deployer } = await loadFixture(deployFullStack);

    const circuitId = ethers.encodeBytes32String("compat-circuit");
    const pluginId = ethers.encodeBytes32String("compat-plugin");

    // Register through compat
    await compat.registerCircuit(
      circuitId,
      "Compat test circuit",
      await mockVerifier.getAddress(),
      "ipfs://compat"
    );

    await compat.registerPlugin(pluginId, "2.0.0", deployer.address, circuitId);

    // Read through compat
    const circuit = await compat.getCircuit(circuitId);
    expect(circuit.description).to.equal("Compat test circuit");
  });

  it("deprecating a plugin marks it but keeps it queryable", async function () {
    const { mockVerifier, registry, deployer } = await loadFixture(deployFullStack);

    const circuitId = ethers.encodeBytes32String("dep-circuit");
    const pluginId = ethers.encodeBytes32String("dep-plugin");

    await registry.registerCircuit(circuitId, "c", await mockVerifier.getAddress(), "");
    await registry.registerPlugin(pluginId, "1.0.0", deployer.address, circuitId);

    await registry.deprecatePlugin(pluginId);

    const plugin = await registry.getPlugin(pluginId);
    expect(plugin.deprecated).to.be.true;
    expect(plugin.implementation).to.equal(deployer.address);
  });
});
