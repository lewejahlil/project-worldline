/**
 * Worldline mainnet fork simulation.
 *
 * Run with: npx hardhat run scripts/fork-sim.ts --network hardhat
 *
 * No environment variables required — uses public RPC as default.
 * Set MAINNET_RPC_URL to override the fork source.
 */

import { ethers, network } from "hardhat";
import { FORK_CONFIG } from "./fork-sim-config";

const DOMAIN = ethers.keccak256(ethers.toUtf8Bytes("worldline-fork-sim-domain"));
const PROGRAM_VKEY = ethers.keccak256(ethers.toUtf8Bytes("program-vkey-fork-sim"));
const POLICY_HASH = ethers.keccak256(ethers.toUtf8Bytes("policy-hash-fork-sim"));
const PROVER_DIGEST = ethers.keccak256(ethers.toUtf8Bytes("prover-set-fork-sim"));
const MAX_ACCEPTANCE_DELAY = 7200; // 2 hours
const GENESIS_L2_BLOCK = 0n;

function computeStfCommitment(
  l2Start: bigint,
  l2End: bigint,
  windowCloseTimestamp: bigint
): string {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256", "uint256", "bytes32", "bytes32", "bytes32", "uint256"],
      [l2Start, l2End, ethers.ZeroHash, ethers.ZeroHash, DOMAIN, windowCloseTimestamp]
    )
  );
}

function encodeProof(l2Start: bigint, l2End: bigint, windowCloseTimestamp: bigint): string {
  const stfCommitment = computeStfCommitment(l2Start, l2End, windowCloseTimestamp);
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["uint256[2]", "uint256[2][2]", "uint256[2]", "uint256", "uint256"],
    [
      [1n, 2n],
      [[1n, 2n], [3n, 4n]],
      [1n, 2n],
      BigInt(stfCommitment),
      BigInt(PROVER_DIGEST)
    ]
  );
}

function encodePublicInputs(
  l2Start: bigint,
  l2End: bigint,
  windowCloseTimestamp: bigint
): string {
  const stfCommitment = computeStfCommitment(l2Start, l2End, windowCloseTimestamp);
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["bytes32", "uint256", "uint256", "bytes32", "bytes32", "bytes32", "uint256"],
    [stfCommitment, l2Start, l2End, ethers.ZeroHash, ethers.ZeroHash, DOMAIN, windowCloseTimestamp]
  );
}

async function main(): Promise<void> {
  console.log("=== Worldline Mainnet Fork Simulation ===");
  console.log(`Fork RPC:  ${FORK_CONFIG.rpcUrl}`);
  console.log(`Network:   ${network.name}`);

  const [deployer] = await ethers.getSigners();
  const forkBlock = await ethers.provider.getBlockNumber();
  const feeData = await ethers.provider.getFeeData();
  const gasPrice = feeData.gasPrice ?? 0n;
  const chainId = (await ethers.provider.getNetwork()).chainId;

  console.log(`\n[fork] Block number at fork:  ${forkBlock}`);
  console.log(`[fork] Chain ID:               ${chainId}`);
  console.log(`[fork] Gas price (Gwei):       ${ethers.formatUnits(gasPrice, "gwei")}`);
  console.log(`[fork] Deployer:               ${deployer.address}`);

  const gasLog: Array<{ step: string; gasUsed: bigint }> = [];

  function logGas(step: string, gasUsed: bigint): void {
    gasLog.push({ step, gasUsed });
    const ethCost = gasPrice > 0n ? ` (~${ethers.formatEther(gasUsed * gasPrice)} ETH)` : "";
    console.log(`  [gas] ${step}: ${gasUsed.toLocaleString()} gas${ethCost}`);
  }

  // ── Step 2: Deploy full contract suite ──────────────────────────────────────
  console.log("\n[2] Deploying contracts to fork…");

  const MockVerifier = await ethers.getContractFactory("MockGroth16Verifier");
  const verifier = await MockVerifier.deploy();
  await verifier.waitForDeployment();
  const deployReceipt1 = await ethers.provider.getTransactionReceipt(verifier.deploymentTransaction()!.hash);
  logGas("MockGroth16Verifier deploy", deployReceipt1!.gasUsed);

  const Adapter = await ethers.getContractFactory("Groth16ZkAdapter");
  const adapter = await Adapter.deploy(await verifier.getAddress(), PROGRAM_VKEY, POLICY_HASH);
  await adapter.waitForDeployment();
  const deployReceipt2 = await ethers.provider.getTransactionReceipt(adapter.deploymentTransaction()!.hash);
  logGas("Groth16ZkAdapter deploy", deployReceipt2!.gasUsed);

  const Registry = await ethers.getContractFactory("WorldlineRegistry");
  const registry = await Registry.deploy(await verifier.getAddress());
  await registry.waitForDeployment();
  const deployReceipt3 = await ethers.provider.getTransactionReceipt(registry.deploymentTransaction()!.hash);
  logGas("WorldlineRegistry deploy", deployReceipt3!.gasUsed);

  const Finalizer = await ethers.getContractFactory("WorldlineFinalizer");
  const finalizer = await Finalizer.deploy(
    await adapter.getAddress(),
    DOMAIN,
    MAX_ACCEPTANCE_DELAY,
    GENESIS_L2_BLOCK
  );
  await finalizer.waitForDeployment();
  const deployReceipt4 = await ethers.provider.getTransactionReceipt(finalizer.deploymentTransaction()!.hash);
  logGas("WorldlineFinalizer deploy", deployReceipt4!.gasUsed);

  console.log(`\n  Verifier:   ${await verifier.getAddress()}`);
  console.log(`  Adapter:    ${await adapter.getAddress()}`);
  console.log(`  Registry:   ${await registry.getAddress()}`);
  console.log(`  Finalizer:  ${await finalizer.getAddress()}`);

  // Enable permissionless submission
  const setPermTx = await (finalizer as any).setPermissionless(true);
  const setPermReceipt = await setPermTx.wait();
  logGas("setPermissionless", setPermReceipt!.gasUsed);

  // Register a driver
  const driverId = ethers.keccak256(ethers.toUtf8Bytes("driver-groth16-fork"));
  const regTx = await (registry as any).registerDriver(driverId, "v1.0.0-fork", "https://fork.local/prover");
  const regReceipt = await regTx.wait();
  logGas("registerDriver", regReceipt!.gasUsed);

  // ── Step 3: Submit 4 sequential windows ─────────────────────────────────────
  console.log("\n[3] Submitting 4 sequential windows…");
  const latestBlock = await ethers.provider.getBlock("latest");
  const ts = BigInt(latestBlock!.timestamp) + BigInt(MAX_ACCEPTANCE_DELAY) - 60n;
  let l2Cursor = GENESIS_L2_BLOCK;

  for (let i = 0; i < 4; i++) {
    const l2Start = l2Cursor;
    const l2End = l2Cursor + 100n;
    const proof = encodeProof(l2Start, l2End, ts);
    const inputs = encodePublicInputs(l2Start, l2End, ts);

    const tx = await (finalizer as any).submitZkValidityProof(proof, inputs);
    const receipt = await tx.wait();
    logGas(`submitZkValidityProof window ${i}`, receipt!.gasUsed);
    l2Cursor = l2End;
  }

  // ── Step 4: Verify ─────────────────────────────────────────────────────────
  console.log("\n[4] Verifying finalization…");
  const nextWindow = await (finalizer as any).nextWindowIndex();
  if (nextWindow !== 4n) {
    throw new Error(`Expected nextWindowIndex=4, got ${nextWindow}`);
  }
  console.log(`[4] nextWindowIndex = ${nextWindow} ✓`);

  // ── Gas summary ─────────────────────────────────────────────────────────────
  console.log("\n── Fork Simulation Gas Summary ─────────────────────────────────────");
  let totalGas = 0n;
  for (const entry of gasLog) {
    const ethCost = gasPrice > 0n ? `  (~${ethers.formatEther(entry.gasUsed * gasPrice)} ETH)` : "";
    console.log(`  ${entry.step.padEnd(42)} ${entry.gasUsed.toLocaleString().padStart(12)} gas${ethCost}`);
    totalGas += entry.gasUsed;
  }
  console.log(`  ${"TOTAL".padEnd(42)} ${totalGas.toLocaleString().padStart(12)} gas`);

  console.log("\n=== Fork simulation PASSED ✓ ===");
}

main().catch((err) => {
  console.error("\n=== Fork simulation FAILED ===");
  console.error(err);
  process.exit(1);
});
