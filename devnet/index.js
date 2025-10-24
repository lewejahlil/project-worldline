const { spawn } = require("child_process");
const { ethers } = require("ethers");
const path = require("path");
const fs = require("fs");

const ANVIL_PORT = 8545;
const ARTIFACTS = path.join(__dirname, "..", "contracts", "artifacts", "contracts", "src");

async function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function startAnvil() {
  const child = spawn("npx", ["anvil", "--port", String(ANVIL_PORT)], {
    stdio: "inherit"
  });

  process.on("exit", () => child.kill());
  await wait(2000);
  return child;
}

async function deploy() {
  const provider = new ethers.JsonRpcProvider(`http://127.0.0.1:${ANVIL_PORT}`);
  const [account] = await provider.listAccounts();
  const signer = await provider.getSigner(account);

  const verifierArtifact = require(path.join(ARTIFACTS, "zk", "Verifier.sol", "Verifier.json"));
  const registryArtifact = require(path.join(ARTIFACTS, "WorldlineRegistry.sol", "WorldlineRegistry.json"));
  const compatArtifact = require(path.join(ARTIFACTS, "WorldlineCompat.sol", "WorldlineCompat.json"));

  const verifierFactory = new ethers.ContractFactory(
    verifierArtifact.abi,
    verifierArtifact.bytecode,
    signer
  );
  const verifier = await verifierFactory.deploy();
  await verifier.waitForDeployment();

  const registryFactory = new ethers.ContractFactory(
    registryArtifact.abi,
    registryArtifact.bytecode,
    signer
  );
  const registry = await registryFactory.deploy(await verifier.getAddress());
  await registry.waitForDeployment();

  const compatFactory = new ethers.ContractFactory(
    compatArtifact.abi,
    compatArtifact.bytecode,
    signer
  );
  const compat = await compatFactory.deploy(await registry.getAddress());
  await compat.waitForDeployment();
  await (await registry.setCompatFacade(await compat.getAddress())).wait();

  console.log("Devnet ready:");
  console.log("  Verifier", await verifier.getAddress());
  console.log("  Registry", await registry.getAddress());
  console.log("  Compat  ", await compat.getAddress());

  const circuitId = ethers.id("square");
  await (await registry.registerCircuit(circuitId, "Square circuit", ethers.ZeroAddress, "ipfs://circuit"))
    .wait();
  const driverId = ethers.id("driver");
  await (await registry.registerDriver(driverId, "1.0.0", "http://localhost:3030")).wait();

  console.log("Seeded registry with sample data");
}

async function ensureArtifacts() {
  if (!fs.existsSync(ARTIFACTS)) {
    throw new Error(
      "Contracts not compiled. Run `npm run contracts:build` before starting the devnet."
    );
  }
}

(async () => {
  await ensureArtifacts();
  await startAnvil();
  await deploy();
})();
