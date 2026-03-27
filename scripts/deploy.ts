/**
 * Worldline production deployment script.
 *
 * Deploys the full contract stack in the correct dependency order, prints a
 * deployment summary, and writes the addresses to:
 *   deployments/<network>-<timestamp>.json
 *
 * Usage:
 *   # Hardhat local:
 *   npx hardhat run scripts/deploy.ts --network hardhat
 *
 *   # Testnet (set env vars first):
 *   SEPOLIA_RPC_URL=... PRIVATE_KEY=0x... \
 *     npx hardhat run scripts/deploy.ts --network sepolia
 *
 * Environment variables:
 *   DOMAIN_SEPARATOR        bytes32 domain separator (default: keccak256("worldline-testnet"))
 *   MAX_ACCEPTANCE_DELAY    seconds (default: 3600 = 1 hour)
 *   MIN_TIMELOCK            seconds (default: 86400 = 24 hours)
 *   PROGRAM_VKEY            bytes32 program verifying key (default: placeholder)
 *   POLICY_HASH             bytes32 policy hash (default: placeholder)
 *   IS_DEV_ADAPTER          "true" to deploy adapter in dev mode (default: "false")
 */

import { ethers, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log(
    `Network:    ${network.name} (chainId: ${(await ethers.provider.getNetwork()).chainId})`
  );
  console.log(`Deploying with: ${deployer.address}`);
  console.log();

  // ── Read configuration from environment ─────────────────────────────────────

  const DOMAIN_SEPARATOR =
    process.env["DOMAIN_SEPARATOR"] ?? ethers.keccak256(ethers.toUtf8Bytes("worldline-testnet"));

  const MAX_ACCEPTANCE_DELAY = parseInt(process.env["MAX_ACCEPTANCE_DELAY"] ?? "3600", 10);
  const MIN_TIMELOCK = parseInt(process.env["MIN_TIMELOCK"] ?? "86400", 10);

  const PROGRAM_VKEY =
    process.env["PROGRAM_VKEY"] ?? ethers.keccak256(ethers.toUtf8Bytes("program-vkey-testnet"));

  const POLICY_HASH =
    process.env["POLICY_HASH"] ?? ethers.keccak256(ethers.toUtf8Bytes("policy-hash-testnet"));

  const IS_DEV_ADAPTER = process.env["IS_DEV_ADAPTER"] === "true";

  const GENESIS_L2_BLOCK = parseInt(process.env["GENESIS_L2_BLOCK"] ?? "0", 10);

  console.log("Configuration:");
  console.log(`  DOMAIN_SEPARATOR:      ${DOMAIN_SEPARATOR}`);
  console.log(`  MAX_ACCEPTANCE_DELAY:  ${MAX_ACCEPTANCE_DELAY}s`);
  console.log(`  MIN_TIMELOCK:          ${MIN_TIMELOCK}s`);
  console.log(`  PROGRAM_VKEY:          ${PROGRAM_VKEY}`);
  console.log(`  POLICY_HASH:           ${POLICY_HASH}`);
  console.log(`  IS_DEV_ADAPTER:        ${IS_DEV_ADAPTER}`);
  console.log(`  GENESIS_L2_BLOCK:      ${GENESIS_L2_BLOCK}`);
  console.log();

  // ── 1. Deploy Verifier ──────────────────────────────────────────────────────
  console.log("1. Deploying Verifier…");
  const Verifier = await ethers.getContractFactory("Verifier");
  const verifier = await Verifier.deploy();
  await verifier.waitForDeployment();
  const verifierAddr = await verifier.getAddress();
  console.log(`   Verifier: ${verifierAddr}`);

  // ── 2. Deploy WorldlineRegistry ─────────────────────────────────────────────
  console.log("2. Deploying WorldlineRegistry…");
  const Registry = await ethers.getContractFactory("WorldlineRegistry");
  const registry = await Registry.deploy(verifierAddr);
  await registry.waitForDeployment();
  const registryAddr = await registry.getAddress();
  console.log(`   WorldlineRegistry: ${registryAddr}`);

  // ── 3. Deploy Groth16ZkAdapter ──────────────────────────────────────────────
  console.log("3. Deploying Groth16ZkAdapter…");
  const Adapter = await ethers.getContractFactory("Groth16ZkAdapter");
  const adapter = await Adapter.deploy(verifierAddr, PROGRAM_VKEY, POLICY_HASH, IS_DEV_ADAPTER);
  await adapter.waitForDeployment();
  const adapterAddr = await adapter.getAddress();
  console.log(`   Groth16ZkAdapter: ${adapterAddr} (isDev=${IS_DEV_ADAPTER})`);

  // ── 4. Deploy WorldlineFinalizer ────────────────────────────────────────────
  console.log("4. Deploying WorldlineFinalizer…");
  const Finalizer = await ethers.getContractFactory("WorldlineFinalizer");
  const finalizer = await Finalizer.deploy(adapterAddr, DOMAIN_SEPARATOR, MAX_ACCEPTANCE_DELAY, GENESIS_L2_BLOCK);
  await finalizer.waitForDeployment();
  const finalizerAddr = await finalizer.getAddress();
  console.log(`   WorldlineFinalizer: ${finalizerAddr}`);

  // ── 5. Deploy WorldlineOutputsRegistry ─────────────────────────────────────
  console.log("5. Deploying WorldlineOutputsRegistry…");
  const OutputsRegistry = await ethers.getContractFactory("WorldlineOutputsRegistry");
  const outputsRegistry = await OutputsRegistry.deploy(MIN_TIMELOCK);
  await outputsRegistry.waitForDeployment();
  const outputsRegistryAddr = await outputsRegistry.getAddress();
  console.log(`   WorldlineOutputsRegistry: ${outputsRegistryAddr}`);

  // ── 6. Deploy WorldlineCompat ───────────────────────────────────────────────
  console.log("6. Deploying WorldlineCompat…");
  const Compat = await ethers.getContractFactory("WorldlineCompat");
  const compat = await Compat.deploy(registryAddr);
  await compat.waitForDeployment();
  const compatAddr = await compat.getAddress();
  console.log(`   WorldlineCompat: ${compatAddr}`);

  // ── 7. Wire compat facade to registry ───────────────────────────────────────
  console.log("7. Wiring WorldlineCompat facade to WorldlineRegistry…");
  const wireTx = await registry.setCompatFacade(compatAddr);
  await wireTx.wait();
  console.log(`   setCompatFacade tx: ${wireTx.hash}`);

  // ── Print deployment summary ─────────────────────────────────────────────────
  const deploymentRecord = {
    network: network.name,
    chainId: (await ethers.provider.getNetwork()).chainId.toString(),
    timestamp: new Date().toISOString(),
    deployer: deployer.address,
    contracts: {
      Verifier: verifierAddr,
      WorldlineRegistry: registryAddr,
      Groth16ZkAdapter: adapterAddr,
      WorldlineFinalizer: finalizerAddr,
      WorldlineOutputsRegistry: outputsRegistryAddr,
      WorldlineCompat: compatAddr
    },
    config: {
      domainSeparator: DOMAIN_SEPARATOR,
      maxAcceptanceDelay: MAX_ACCEPTANCE_DELAY,
      minTimelock: MIN_TIMELOCK,
      programVKey: PROGRAM_VKEY,
      policyHash: POLICY_HASH,
      isDevAdapter: IS_DEV_ADAPTER,
      genesisL2Block: GENESIS_L2_BLOCK
    }
  };

  console.log("\n── Deployment Summary ────────────────────────────────────────────");
  console.log(JSON.stringify(deploymentRecord, null, 2));

  // ── Write addresses to file ──────────────────────────────────────────────────
  const deploymentsDir = path.join(__dirname, "../deployments");
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const outPath = path.join(deploymentsDir, `${network.name}-${ts}.json`);
  fs.writeFileSync(outPath, JSON.stringify(deploymentRecord, null, 2));
  console.log(`\nDeployment record written to: ${outPath}`);

  // ── Etherscan verification (optional) ────────────────────────────────────────
  const etherscanKey = process.env["ETHERSCAN_API_KEY"];
  if (etherscanKey && network.name !== "hardhat" && network.name !== "localhost") {
    console.log("\n── Etherscan Verification ────────────────────────────────────────");
    console.log("ETHERSCAN_API_KEY detected — attempting contract verification…");
    console.log("(Waiting 30 s for block explorer to index the contracts)");
    await new Promise((resolve) => setTimeout(resolve, 30_000));

    const { run } = await import("hardhat");

    const toVerify: Array<{ name: string; address: string; args: unknown[] }> = [
      { name: "Verifier", address: verifierAddr, args: [] },
      { name: "WorldlineRegistry", address: registryAddr, args: [verifierAddr] },
      {
        name: "Groth16ZkAdapter",
        address: adapterAddr,
        args: [verifierAddr, PROGRAM_VKEY, POLICY_HASH, IS_DEV_ADAPTER]
      },
      {
        name: "WorldlineFinalizer",
        address: finalizerAddr,
        args: [adapterAddr, DOMAIN_SEPARATOR, MAX_ACCEPTANCE_DELAY, GENESIS_L2_BLOCK]
      },
      {
        name: "WorldlineOutputsRegistry",
        address: outputsRegistryAddr,
        args: [MIN_TIMELOCK]
      },
      { name: "WorldlineCompat", address: compatAddr, args: [registryAddr] }
    ];

    for (const { name, address, args } of toVerify) {
      try {
        console.log(`  Verifying ${name} at ${address}…`);
        await run("verify:verify", { address, constructorArguments: args });
        console.log(`  ${name}: verified ✓`);
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        if (msg.includes("Already Verified")) {
          console.log(`  ${name}: already verified ✓`);
        } else {
          console.warn(`  ${name}: verification failed — ${msg}`);
        }
      }
    }
  } else if (!etherscanKey) {
    console.log(
      "\nSkipping Etherscan verification (ETHERSCAN_API_KEY not set). " +
        "Set it in .env to enable automatic verification."
    );
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
