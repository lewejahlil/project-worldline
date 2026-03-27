#!/usr/bin/env node

/**
 * Worldline devnet orchestration script.
 *
 * Spawns a local Anvil node, deploys the Worldline contracts, registers sample
 * data, and keeps running until Ctrl+C.
 *
 * Usage: npm run devnet
 */

import { spawn } from "child_process";
import fs from "fs";
import path from "path";
import { ethers } from "ethers";

const ANVIL_PORT = process.env.DEVNET_PORT || "8545";
const PRIVATE_KEY =
  process.env.PRIVATE_KEY || "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

function loadArtifact(name) {
  const artifactPath = path.resolve(
    __dirname,
    `../artifacts/contracts/src/${name}.sol/${name}.json`
  );
  if (!fs.existsSync(artifactPath)) {
    // Try nested paths for zk/ and utils/
    const altPaths = [
      path.resolve(__dirname, `../artifacts/contracts/src/zk/${name}.sol/${name}.json`),
      path.resolve(__dirname, `../artifacts/contracts/src/utils/${name}.sol/${name}.json`)
    ];
    for (const p of altPaths) {
      if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, "utf-8"));
    }
    throw new Error(`Artifact not found for ${name}. Run 'npm run contracts:build' first.`);
  }
  return JSON.parse(fs.readFileSync(artifactPath, "utf-8"));
}

async function deploy(wallet, name, ...args) {
  const artifact = loadArtifact(name);
  const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, wallet);
  const contract = await factory.deploy(...args);
  await contract.waitForDeployment();
  const addr = await contract.getAddress();
  console.log(`  ${name} deployed at ${addr}`);
  return contract;
}

async function main() {
  console.log(`Starting Anvil on port ${ANVIL_PORT}...`);

  const anvil = spawn("anvil", ["--port", ANVIL_PORT], {
    stdio: ["ignore", "pipe", "pipe"]
  });

  anvil.on("error", (err) => {
    console.error("Failed to start Anvil. Is it installed?", err.message);
    process.exit(1);
  });

  // Wait for Anvil to start
  await new Promise((resolve) => setTimeout(resolve, 2000));

  const provider = new ethers.JsonRpcProvider(`http://127.0.0.1:${ANVIL_PORT}`);
  const wallet = new ethers.Wallet(PRIVATE_KEY, provider);

  console.log(`Deployer: ${wallet.address}\n`);
  console.log("Deploying contracts...");

  try {
    // Deploy core contracts
    const verifier = await deploy(wallet, "Verifier");
    const registry = await deploy(wallet, "WorldlineRegistry", await verifier.getAddress());
    const compat = await deploy(wallet, "WorldlineCompat", await registry.getAddress());

    // Wire compat facade
    await registry.setCompatFacade(await compat.getAddress());
    console.log("  CompatFacade wired to registry\n");

    // Register sample data
    console.log("Registering sample data...");
    const circuitId = ethers.encodeBytes32String("squarehash-v1");
    const driverId = ethers.encodeBytes32String("driver-local");
    const pluginId = ethers.encodeBytes32String("squarehash-groth16");

    await registry.registerCircuit(
      circuitId,
      "SquareHash demo circuit",
      await verifier.getAddress(),
      "ipfs://QmPlaceholder"
    );
    console.log("  Circuit 'squarehash-v1' registered");

    await registry.registerDriver(driverId, "0.1.0", `http://127.0.0.1:${ANVIL_PORT}`);
    console.log("  Driver 'driver-local' registered");

    await registry.registerPlugin(pluginId, "1.0.0", wallet.address, circuitId);
    console.log("  Plugin 'squarehash-groth16' registered");

    // Verify a sample proof
    const result = await registry.verify(circuitId, 7n, 49n);
    console.log(`\n  Sample verify(7, 49) = ${result}`);

    console.log("\n--- Devnet ready ---");
    console.log(`  RPC: http://127.0.0.1:${ANVIL_PORT}`);
    console.log(`  Registry: ${await registry.getAddress()}`);
    console.log(`  Compat:   ${await compat.getAddress()}`);
    console.log(`  Verifier: ${await verifier.getAddress()}`);
    console.log("\nPress Ctrl+C to stop.\n");
  } catch (err) {
    console.error("Deployment failed:", err.message);
    anvil.kill();
    process.exit(1);
  }

  // Graceful shutdown
  process.on("SIGINT", () => {
    console.log("\nShutting down Anvil...");
    anvil.kill();
    process.exit(0);
  });

  process.on("SIGTERM", () => {
    anvil.kill();
    process.exit(0);
  });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
