import { ethers } from "hardhat";

async function main() {
  const verifier = await (await ethers.getContractFactory("Verifier")).deploy();
  const registry = await (await ethers.getContractFactory("WorldlineRegistry")).deploy(
    await verifier.getAddress()
  );
  const compat = await (await ethers.getContractFactory("WorldlineCompat")).deploy(
    await registry.getAddress()
  );
  await (await registry.setCompatFacade(await compat.getAddress())).wait();

  console.log(`Verifier: ${await verifier.getAddress()}`);
  console.log(`Registry: ${await registry.getAddress()}`);
  console.log(`Compat:   ${await compat.getAddress()}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
