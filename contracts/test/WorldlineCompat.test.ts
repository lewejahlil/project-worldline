import { expect } from "chai";
import { ethers } from "hardhat";

describe("WorldlineCompat", () => {
  it("proxies registry calls", async () => {
    const verifierFactory = await ethers.getContractFactory("Verifier");
    const verifier = await verifierFactory.deploy();
    const registryFactory = await ethers.getContractFactory("WorldlineRegistry");
    const registry = await registryFactory.deploy(await verifier.getAddress());
    const compatFactory = await ethers.getContractFactory("WorldlineCompat");
    const compat = await compatFactory.deploy(await registry.getAddress());
    await registry.setCompatFacade(await compat.getAddress());

    const circuitId = ethers.id("compat");
    await compat.registerCircuit(circuitId, "Compat circuit", ethers.ZeroAddress, "ipfs://compat");
    const circuit = await compat.getCircuit(circuitId);
    expect(circuit.description).to.equal("Compat circuit");
  });
});
