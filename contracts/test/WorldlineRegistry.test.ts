import { expect } from "chai";
import { ethers } from "hardhat";

describe("WorldlineRegistry", () => {
  async function deploy() {
    const [owner, other] = await ethers.getSigners();
    const verifierFactory = await ethers.getContractFactory("Verifier");
    const verifier = await verifierFactory.deploy();
    const registryFactory = await ethers.getContractFactory("WorldlineRegistry");
    const registry = await registryFactory.deploy(await verifier.getAddress());
    return { owner, other, verifier, registry };
  }

  it("registers and queries a circuit", async () => {
    const { registry } = await deploy();
    const circuitId = ethers.keccak256(ethers.toUtf8Bytes("square"));
    await registry.registerCircuit(circuitId, "Square circuit", ethers.ZeroAddress, "ipfs://circuit");
    const circuit = await registry.getCircuit(circuitId);
    expect(circuit.description).to.equal("Square circuit");
  });

  it("registers a plugin", async () => {
    const { registry } = await deploy();
    const circuitId = ethers.keccak256(ethers.toUtf8Bytes("square"));
    await registry.registerCircuit(circuitId, "Square circuit", ethers.ZeroAddress, "ipfs://circuit");
    const pluginId = ethers.keccak256(ethers.toUtf8Bytes("plugin"));
    await expect(
      registry.registerPlugin(pluginId, "1.0.0", ethers.ZeroAddress, circuitId)
    ).to.be.revertedWith("invalid implementation");
  });

  it("verifies a proof using the default verifier", async () => {
    const { registry, verifier } = await deploy();
    const circuitId = ethers.keccak256(ethers.toUtf8Bytes("square"));
    await registry.registerCircuit(circuitId, "Square circuit", ethers.ZeroAddress, "ipfs://circuit");
    await expect(registry.verify(circuitId, 3, 9)).to.not.be.reverted;
    await expect(registry.verify(circuitId, 3, 8)).to.be.revertedWithCustomError(verifier, "InvalidProof");
  });
});
