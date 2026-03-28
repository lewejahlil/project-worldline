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
 *   MULTISIG_ADDRESS        (required on non-dev networks) multisig to transfer ownership to
 */

import * as fs from "fs";
import * as path from "path";
import { ethers, network } from "hardhat";

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

  const GENESIS_L2_BLOCK = parseInt(process.env["GENESIS_L2_BLOCK"] ?? "0", 10);

  // INF-002: Mandatory multisig address for ownership transfer on non-dev networks.
  const MULTISIG_ADDRESS = process.env["MULTISIG_ADDRESS"] ?? "";
  const isDevNetwork = network.name === "hardhat" || network.name === "localhost";
  if (!MULTISIG_ADDRESS && !isDevNetwork) {
    console.error(
      "ERROR: MULTISIG_ADDRESS environment variable is required for non-dev deployments."
    );
    console.error("Set MULTISIG_ADDRESS to the multisig that should own the deployed contracts.");
    process.exit(1);
  }

  console.log("Configuration:");
  console.log(`  DOMAIN_SEPARATOR:      ${DOMAIN_SEPARATOR}`);
  console.log(`  MAX_ACCEPTANCE_DELAY:  ${MAX_ACCEPTANCE_DELAY}s`);
  console.log(`  MIN_TIMELOCK:          ${MIN_TIMELOCK}s`);
  console.log(`  PROGRAM_VKEY:          ${PROGRAM_VKEY}`);
  console.log(`  POLICY_HASH:           ${POLICY_HASH}`);
  console.log(`  GENESIS_L2_BLOCK:      ${GENESIS_L2_BLOCK}`);
  console.log(`  MULTISIG_ADDRESS:      ${MULTISIG_ADDRESS || "(dev — no transfer)"}`);
  console.log();

  // ── 1. Deploy Groth16Verifier (real BN254 pairing verifier from snarkjs export) ──
  console.log("1. Deploying Groth16Verifier…");
  const Groth16Verifier = await ethers.getContractFactory("Groth16Verifier");
  const groth16Verifier = await Groth16Verifier.deploy();
  await groth16Verifier.waitForDeployment();
  const groth16VerifierAddr = await groth16Verifier.getAddress();
  console.log(`   Groth16Verifier: ${groth16VerifierAddr}`);

  // ── 2. Deploy WorldlineRegistry ─────────────────────────────────────────────
  console.log("2. Deploying WorldlineRegistry…");
  const Registry = await ethers.getContractFactory("WorldlineRegistry");
  const registry = await Registry.deploy(groth16VerifierAddr);
  await registry.waitForDeployment();
  const registryAddr = await registry.getAddress();
  console.log(`   WorldlineRegistry: ${registryAddr}`);

  // ── 3. Deploy Groth16ZkAdapter ──────────────────────────────────────────────
  console.log("3. Deploying Groth16ZkAdapter…");
  const Adapter = await ethers.getContractFactory("Groth16ZkAdapter");
  const adapter = await Adapter.deploy(groth16VerifierAddr, PROGRAM_VKEY, POLICY_HASH);
  await adapter.waitForDeployment();
  const adapterAddr = await adapter.getAddress();
  console.log(`   Groth16ZkAdapter: ${adapterAddr}`);

  // ── 4. Deploy WorldlineFinalizer ────────────────────────────────────────────
  console.log("4. Deploying WorldlineFinalizer…");
  const Finalizer = await ethers.getContractFactory("WorldlineFinalizer");
  const finalizer = await Finalizer.deploy(
    adapterAddr,
    DOMAIN_SEPARATOR,
    MAX_ACCEPTANCE_DELAY,
    GENESIS_L2_BLOCK
  );
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

  // ── 7. Deploy BlobKzgVerifier ─────────────────────────────────────────────
  console.log("7. Deploying BlobKzgVerifier…");
  const BlobKzgVerifier = await ethers.getContractFactory("BlobKzgVerifier");
  const blobKzgVerifier = await BlobKzgVerifier.deploy();
  await blobKzgVerifier.waitForDeployment();
  const blobKzgVerifierAddr = await blobKzgVerifier.getAddress();
  console.log(`   BlobKzgVerifier: ${blobKzgVerifierAddr}`);

  // ── 8. Wire BlobKzgVerifier to WorldlineFinalizer ──────────────────────────
  console.log("8. Wiring BlobKzgVerifier to WorldlineFinalizer…");
  const blobWireTx = await finalizer.setBlobKzgVerifier(blobKzgVerifierAddr);
  await blobWireTx.wait();
  console.log(`   setBlobKzgVerifier tx: ${blobWireTx.hash}`);

  // ── 9. Wire compat facade to registry ───────────────────────────────────────
  console.log("9. Wiring WorldlineCompat facade to WorldlineRegistry…");
  const wireTx = await registry.setCompatFacade(compatAddr);
  await wireTx.wait();
  console.log(`   setCompatFacade tx: ${wireTx.hash}`);

  // ── 10. Transfer ownership to multisig (INF-002 remediation) ────────────────
  if (MULTISIG_ADDRESS) {
    console.log(`10. Transferring ownership to multisig ${MULTISIG_ADDRESS}…`);

    // WorldlineFinalizer — two-step transfer (HI-003).
    const finalizerTx = await finalizer.transferOwnership(MULTISIG_ADDRESS);
    await finalizerTx.wait();
    console.log(
      `   WorldlineFinalizer.transferOwnership → ${MULTISIG_ADDRESS} (pending acceptance)`
    );

    // WorldlineRegistry — two-step transfer (HI-003).
    const registryTx = await registry.transferOwnership(MULTISIG_ADDRESS);
    await registryTx.wait();
    console.log(
      `   WorldlineRegistry.transferOwnership → ${MULTISIG_ADDRESS} (pending acceptance)`
    );

    // WorldlineOutputsRegistry — two-step transfer (HI-003).
    const outputsTx = await outputsRegistry.transferOwnership(MULTISIG_ADDRESS);
    await outputsTx.wait();
    console.log(
      `   WorldlineOutputsRegistry.transferOwnership → ${MULTISIG_ADDRESS} (pending acceptance)`
    );

    console.log(
      "   ⚠  Multisig must call acceptOwnership() on each contract to complete the transfer."
    );
  } else {
    console.log("10. Skipping ownership transfer (dev network).");
  }

  // ── 11. Post-deploy verification ─────────────────────────────────────────────
  console.log("11. Running post-deploy verification checks…");

  // Verify WorldlineRegistry owner
  const registryOwner = await registry.owner();
  if (registryOwner !== deployer.address) {
    throw new Error(
      `WorldlineRegistry owner mismatch: expected ${deployer.address}, got ${registryOwner}`
    );
  }
  console.log("   WorldlineRegistry.owner() matches deployer");

  // Verify WorldlineFinalizer adapter is set correctly
  const currentAdapter = await finalizer.adapter();
  if (currentAdapter !== adapterAddr) {
    throw new Error(
      `WorldlineFinalizer adapter mismatch: expected ${adapterAddr}, got ${currentAdapter}`
    );
  }
  console.log("   WorldlineFinalizer.adapter() matches deployed adapter");

  // Verify WorldlineFinalizer domain separator
  const currentDomain = await finalizer.domainSeparator();
  if (currentDomain !== DOMAIN_SEPARATOR) {
    throw new Error(`WorldlineFinalizer domainSeparator mismatch`);
  }
  console.log("   WorldlineFinalizer.domainSeparator() matches config");

  // Verify WorldlineFinalizer is not paused and nextWindowIndex is 0
  const isPaused = await finalizer.paused();
  if (isPaused) {
    throw new Error("WorldlineFinalizer is unexpectedly paused after deployment");
  }
  console.log("   WorldlineFinalizer is not paused");

  const nextWindow = await finalizer.nextWindowIndex();
  if (nextWindow !== 0n) {
    throw new Error(`WorldlineFinalizer.nextWindowIndex expected 0, got ${nextWindow}`);
  }
  console.log("   WorldlineFinalizer.nextWindowIndex() is 0");

  // Verify WorldlineOutputsRegistry owner
  const outputsOwner = await outputsRegistry.owner();
  if (outputsOwner !== deployer.address) {
    throw new Error(`WorldlineOutputsRegistry owner mismatch`);
  }
  console.log("   WorldlineOutputsRegistry.owner() matches deployer");

  // Verify WorldlineCompat is wired to registry
  const compatFacade = await registry.compatFacade();
  if (compatFacade !== compatAddr) {
    throw new Error(
      `WorldlineRegistry.compatFacade mismatch: expected ${compatAddr}, got ${compatFacade}`
    );
  }
  console.log("   WorldlineRegistry.compatFacade() matches deployed WorldlineCompat");

  // Verify BlobKzgVerifier is wired to finalizer
  const currentBlobVerifier = await finalizer.blobKzgVerifier();
  if (currentBlobVerifier !== blobKzgVerifierAddr) {
    throw new Error(
      `WorldlineFinalizer.blobKzgVerifier mismatch: expected ${blobKzgVerifierAddr}, got ${currentBlobVerifier}`
    );
  }
  console.log("   WorldlineFinalizer.blobKzgVerifier() matches deployed BlobKzgVerifier");

  // Verify BlobKzgVerifier blob base fee read
  const blobFee = await blobKzgVerifier.currentBlobBaseFee();
  console.log(`   BlobKzgVerifier.currentBlobBaseFee() = ${blobFee.toString()}`);

  console.log("   All post-deploy checks passed.");
  console.log();

  // ── Print deployment summary ─────────────────────────────────────────────────
  const deploymentRecord = {
    network: network.name,
    chainId: (await ethers.provider.getNetwork()).chainId.toString(),
    timestamp: new Date().toISOString(),
    deployer: deployer.address,
    contracts: {
      Groth16Verifier: groth16VerifierAddr,
      WorldlineRegistry: registryAddr,
      Groth16ZkAdapter: adapterAddr,
      WorldlineFinalizer: finalizerAddr,
      WorldlineOutputsRegistry: outputsRegistryAddr,
      WorldlineCompat: compatAddr,
      BlobKzgVerifier: blobKzgVerifierAddr
    },
    config: {
      domainSeparator: DOMAIN_SEPARATOR,
      maxAcceptanceDelay: MAX_ACCEPTANCE_DELAY,
      minTimelock: MIN_TIMELOCK,
      programVKey: PROGRAM_VKEY,
      policyHash: POLICY_HASH,
      genesisL2Block: GENESIS_L2_BLOCK,
      multisigAddress: MULTISIG_ADDRESS || null
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
      { name: "Groth16Verifier", address: groth16VerifierAddr, args: [] },
      { name: "WorldlineRegistry", address: registryAddr, args: [groth16VerifierAddr] },
      {
        name: "Groth16ZkAdapter",
        address: adapterAddr,
        args: [groth16VerifierAddr, PROGRAM_VKEY, POLICY_HASH]
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
      { name: "WorldlineCompat", address: compatAddr, args: [registryAddr] },
      { name: "BlobKzgVerifier", address: blobKzgVerifierAddr, args: [] }
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
