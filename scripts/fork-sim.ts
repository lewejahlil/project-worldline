#!/usr/bin/env ts-node
/**
 * Worldline mainnet fork simulation.
 *
 * Assumes Anvil is already running in fork mode (start with:
 *   anvil --fork-url $FORK_RPC_URL --port 8545
 * or let this script connect to an externally managed fork instance).
 *
 * Steps:
 *   1. Connect to a fork Anvil instance (FORK_RPC_URL → Anvil).
 *   2. Deploy the full Worldline contract suite to the fork.
 *   3. Submit a synthetic 4-proof aggregated window and verify finalization.
 *   4. Log: block number at fork, gas used per step, total ETH cost estimate.
 *
 * Usage:
 *   # With external Anvil already running in fork mode:
 *   npm run sim:fork
 *
 *   # Override the Anvil RPC (default: http://127.0.0.1:8545):
 *   ANVIL_RPC_URL=http://127.0.0.1:8545 npm run sim:fork
 *
 * Environment variables:
 *   FORK_RPC_URL    Ethereum mainnet (or other) RPC to fork from.
 *                   Defaults to https://eth.llamarpc.com (public endpoint).
 *   ANVIL_RPC_URL   Local Anvil fork endpoint. Defaults to http://127.0.0.1:8545.
 *   PRIVATE_KEY     Deployer private key (default: Anvil account 0).
 *
 * NOTE: This script is NOT added to CI. It requires an external RPC and a
 *       locally running Anvil fork instance. See BENCHMARKS.md for usage.
 */

import * as fs from "fs";
import * as path from "path";
import { ethers } from "ethers";

// ── Configuration ─────────────────────────────────────────────────────────────

const FORK_RPC_URL = process.env["FORK_RPC_URL"] ?? "https://eth.llamarpc.com";
const ANVIL_RPC_URL = process.env["ANVIL_RPC_URL"] ?? "http://127.0.0.1:8545";
const PRIVATE_KEY =
  process.env["PRIVATE_KEY"] ??
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const DOMAIN = ethers.keccak256(ethers.toUtf8Bytes("worldline-fork-sim-domain"));
const PROGRAM_VKEY = ethers.keccak256(ethers.toUtf8Bytes("program-vkey-fork-sim"));
const POLICY_HASH = ethers.keccak256(ethers.toUtf8Bytes("policy-hash-fork-sim"));
const PROVER_DIGEST = ethers.keccak256(ethers.toUtf8Bytes("prover-set-fork-sim"));
const MAX_ACCEPTANCE_DELAY = 7200; // 2 hours

// ── Artifact loader ──────────────────────────────────────────────────────────

function loadArtifact(name: string): { abi: ethers.InterfaceAbi; bytecode: string } {
  const basePaths = [
    path.resolve(__dirname, `../artifacts/contracts/src/${name}.sol/${name}.json`),
    path.resolve(__dirname, `../artifacts/contracts/src/zk/${name}.sol/${name}.json`),
    path.resolve(__dirname, `../artifacts/contracts/src/utils/${name}.sol/${name}.json`),
    path.resolve(__dirname, `../artifacts/contracts/src/test/${name}.sol/${name}.json`)
  ];
  for (const p of basePaths) {
    if (fs.existsSync(p)) {
      return JSON.parse(fs.readFileSync(p, "utf-8"));
    }
  }
  throw new Error(
    `Artifact not found for ${name}. Run 'npm run contracts:build' first.\n` +
      `Searched:\n${basePaths.join("\n")}`
  );
}

// ── Deployment helper ────────────────────────────────────────────────────────

async function deployContract(
  wallet: ethers.Wallet,
  name: string,
  ...args: unknown[]
): Promise<{ contract: ethers.BaseContract; gasUsed: bigint; txHash: string }> {
  const artifact = loadArtifact(name);
  const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, wallet);
  const tx = await factory.getDeployTransaction(...args);
  const sentTx = await wallet.sendTransaction(tx);
  const receipt = await sentTx.wait();
  if (!receipt || receipt.status !== 1) {
    throw new Error(`Deployment of ${name} failed`);
  }
  const contract = new ethers.Contract(receipt.contractAddress!, artifact.abi, wallet);
  return { contract, gasUsed: receipt.gasUsed, txHash: receipt.hash };
}

// ── Proof encoding ────────────────────────────────────────────────────────────

function encodePublicInputs(
  stfCommitment: string,
  l2Start: bigint,
  l2End: bigint,
  windowCloseTimestamp: bigint
): string {
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["bytes32", "uint256", "uint256", "bytes32", "bytes32", "bytes32", "uint256"],
    [stfCommitment, l2Start, l2End, ethers.ZeroHash, ethers.ZeroHash, DOMAIN, windowCloseTimestamp]
  );
}

function encodeProof(stfCommitment: string): string {
  // Production format: pA[2], pB[2][2], pC[2], stfCommitment, proverSetDigest (320 bytes)
  const pA = [1n, 2n];
  const pB = [
    [1n, 2n],
    [3n, 4n]
  ];
  const pC = [1n, 2n];
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["uint256[2]", "uint256[2][2]", "uint256[2]", "uint256", "uint256"],
    [pA, pB, pC, stfCommitment, PROVER_DIGEST]
  );
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log("=== Worldline Mainnet Fork Simulation ===");
  console.log(`Fork source:  ${FORK_RPC_URL}`);
  console.log(`Anvil fork:   ${ANVIL_RPC_URL}`);

  const provider = new ethers.JsonRpcProvider(ANVIL_RPC_URL);
  const wallet = new ethers.Wallet(PRIVATE_KEY, provider);

  // ── Step 1: Connect and log fork block ──────────────────────────────────────
  const forkBlock = await provider.getBlockNumber();
  const forkGasPrice = (await provider.getFeeData()).gasPrice ?? 0n;
  const network = await provider.getNetwork();

  console.log(`\n[fork] Block number at fork:  ${forkBlock}`);
  console.log(`[fork] Chain ID:               ${network.chainId}`);
  console.log(`[fork] Gas price (Gwei):       ${ethers.formatUnits(forkGasPrice, "gwei")}`);
  console.log(`[fork] Deployer:               ${wallet.address}`);

  const gasLog: Array<{ step: string; gasUsed: bigint; ethCost: string }> = [];

  function logGas(step: string, gasUsed: bigint): void {
    const ethCost = ethers.formatEther(gasUsed * forkGasPrice);
    gasLog.push({ step, gasUsed, ethCost });
    console.log(
      `  [gas] ${step}: ${gasUsed.toLocaleString()} gas` +
        (forkGasPrice > 0n ? ` (~${ethCost} ETH)` : "")
    );
  }

  // ── Step 2: Deploy full contract suite ──────────────────────────────────────
  console.log("\n[2] Deploying contracts to fork…");

  const { contract: verifier, gasUsed: g1 } = await deployContract(wallet, "MockGroth16Verifier");
  logGas("MockGroth16Verifier deploy", g1);

  const { contract: registry, gasUsed: g2 } = await deployContract(
    wallet,
    "WorldlineRegistry",
    await verifier.getAddress()
  );
  logGas("WorldlineRegistry deploy", g2);

  const { contract: adapter, gasUsed: g3 } = await deployContract(
    wallet,
    "Groth16ZkAdapter",
    await verifier.getAddress(),
    PROGRAM_VKEY,
    POLICY_HASH
  );
  logGas("Groth16ZkAdapter deploy", g3);

  const { contract: finalizer, gasUsed: g4 } = await deployContract(
    wallet,
    "WorldlineFinalizer",
    await adapter.getAddress(),
    DOMAIN,
    MAX_ACCEPTANCE_DELAY
  );
  logGas("WorldlineFinalizer deploy", g4);

  const { contract: outputsRegistry, gasUsed: g5 } = await deployContract(
    wallet,
    "WorldlineOutputsRegistry",
    86400
  );
  logGas("WorldlineOutputsRegistry deploy", g5);

  const { contract: compat, gasUsed: g6 } = await deployContract(
    wallet,
    "WorldlineCompat",
    await registry.getAddress()
  );
  logGas("WorldlineCompat deploy", g6);

  // Wire compat facade
  const registryAbi = ["function setCompatFacade(address) external"];
  const registryWithSigner = new ethers.Contract(await registry.getAddress(), registryAbi, wallet);
  const wireTx = await (await registryWithSigner.setCompatFacade(await compat.getAddress())).wait();
  logGas("setCompatFacade", wireTx!.gasUsed);

  // Enable permissionless submission
  const finalizerAbi = [
    "function setPermissionless(bool) external",
    "function submitZkValidityProof(bytes calldata proof, bytes calldata publicInputs) external",
    "function nextWindowIndex() view returns (uint256)"
  ];
  const finalizerWithSigner = new ethers.Contract(
    await finalizer.getAddress(),
    finalizerAbi,
    wallet
  );
  await (await finalizerWithSigner.setPermissionless(true)).wait();

  console.log(`[2] Full suite deployed. Finalizer: ${await finalizer.getAddress()}`);

  // Suppress unused variable warnings
  void outputsRegistry;

  // ── Step 3: Submit a 4-proof aggregated window ─────────────────────────────
  console.log("\n[3] Submitting 4-proof aggregated window…");
  const latestBlock = await provider.getBlock("latest");
  const ts = BigInt(latestBlock!.timestamp) + BigInt(MAX_ACCEPTANCE_DELAY) - BigInt(60);
  let l2Cursor = BigInt(0);

  for (let i = 0; i < 4; i++) {
    const l2Start = l2Cursor;
    const l2End = l2Cursor + BigInt(100);
    const stf = ethers.keccak256(ethers.toUtf8Bytes(`stf-fork-sim-window-${i}`));
    const proof = encodeProof(stf);
    const inputs = encodePublicInputs(stf, l2Start, l2End, ts);

    const receipt = await (await finalizerWithSigner.submitZkValidityProof(proof, inputs)).wait();
    logGas(`submitZkValidityProof window ${i}`, receipt!.gasUsed);
    l2Cursor = l2End;
  }

  // ── Step 4: Verify finalization succeeded ──────────────────────────────────
  console.log("\n[4] Verifying finalization…");
  const nextWindow = await finalizerWithSigner.nextWindowIndex();
  if (nextWindow !== BigInt(4)) {
    throw new Error(`Expected nextWindowIndex=4, got ${nextWindow}`);
  }
  console.log(`[4] nextWindowIndex = ${nextWindow} ✓ — finalization confirmed.`);

  // ── Summary ────────────────────────────────────────────────────────────────
  console.log("\n── Fork Simulation Gas Summary ──────────────────────────────────");
  console.log(`Block number at fork:  ${forkBlock}`);
  console.log(`Gas price (Gwei):      ${ethers.formatUnits(forkGasPrice, "gwei")}`);
  console.log("");

  let totalGas = 0n;
  for (const entry of gasLog) {
    console.log(
      `  ${entry.step.padEnd(40)} ${entry.gasUsed.toLocaleString().padStart(12)} gas` +
        (forkGasPrice > 0n ? `  (~${entry.ethCost} ETH)` : "")
    );
    totalGas += entry.gasUsed;
  }

  const totalEth = forkGasPrice > 0n ? ethers.formatEther(totalGas * forkGasPrice) : "N/A";
  console.log("");
  console.log(`  ${"TOTAL".padEnd(40)} ${totalGas.toLocaleString().padStart(12)} gas`);
  if (forkGasPrice > 0n) {
    console.log(`  Total ETH cost estimate:       ~${totalEth} ETH`);
  }

  console.log("\n=== Fork simulation PASSED ✓ ===");
}

main().catch((err) => {
  console.error("\n=== Fork simulation FAILED ===");
  console.error(err);
  process.exit(1);
});
