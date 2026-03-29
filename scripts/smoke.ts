/**
 * Worldline post-deployment smoke test.
 *
 * On dev networks (hardhat/localhost): deploys a fresh mini stack with
 * MockGroth16Verifier so the full proof-submission path can be exercised
 * without needing a live ZK prover.
 *
 * On real networks (sepolia, etc.): reads the most recent deployment JSON,
 * verifies contracts are live, tests admin functions, and attempts proof
 * submission (requires a real prover for full success).
 *
 * Usage:
 *   npx hardhat run scripts/smoke.ts --network hardhat
 *   npx hardhat run scripts/smoke.ts --network sepolia
 */

import * as fs from "fs";
import * as path from "path";
import { ethers, network, upgrades } from "hardhat";

const PROVER_SET_DIGEST = ethers.keccak256(ethers.toUtf8Bytes("smoke-prover-set-digest"));
const GENESIS_L2_BLOCK = 0n;

function computeStfCommitment(
  l2Start: bigint,
  l2End: bigint,
  windowCloseTimestamp: bigint,
  domain: string
): string {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256", "uint256", "bytes32", "bytes32", "bytes32", "uint256"],
      [l2Start, l2End, ethers.ZeroHash, ethers.ZeroHash, domain, windowCloseTimestamp]
    )
  );
}

function encodeProof(
  l2Start: bigint,
  l2End: bigint,
  windowCloseTimestamp: bigint,
  domain: string
): string {
  const stfCommitment = computeStfCommitment(l2Start, l2End, windowCloseTimestamp, domain);
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["uint256[2]", "uint256[2][2]", "uint256[2]", "uint256", "uint256"],
    [
      [1n, 2n],
      [
        [1n, 2n],
        [3n, 4n]
      ],
      [1n, 2n],
      BigInt(stfCommitment),
      BigInt(PROVER_SET_DIGEST)
    ]
  );
}

function encodePublicInputs(
  l2Start: bigint,
  l2End: bigint,
  windowCloseTimestamp: bigint,
  domain: string
): string {
  const stfCommitment = computeStfCommitment(l2Start, l2End, windowCloseTimestamp, domain);
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["bytes32", "uint256", "uint256", "bytes32", "bytes32", "bytes32", "uint256"],
    [stfCommitment, l2Start, l2End, ethers.ZeroHash, ethers.ZeroHash, domain, windowCloseTimestamp]
  );
}

/**
 * Deploy a fresh mini stack backed by MockGroth16Verifier for dev dry-runs.
 * Returns the finalizer address and the domain separator used.
 */
async function deployMockStack(deployer: Awaited<ReturnType<typeof ethers.getSigner>>): Promise<{
  finalizerAddr: string;
  domain: string;
}> {
  const DOMAIN = ethers.keccak256(ethers.toUtf8Bytes("worldline-smoke-mock-domain"));
  const PROGRAM_VKEY = ethers.keccak256(ethers.toUtf8Bytes("smoke-program-vkey"));
  const POLICY_HASH = ethers.keccak256(ethers.toUtf8Bytes("smoke-policy-hash"));
  const MAX_DELAY = 3600;

  const MockVerifier = await ethers.getContractFactory("MockGroth16Verifier", deployer);
  const mockVerifier = await MockVerifier.deploy();
  await mockVerifier.waitForDeployment();

  const Adapter = await ethers.getContractFactory("Groth16ZkAdapter", deployer);
  const adapter = await Adapter.deploy(await mockVerifier.getAddress(), PROGRAM_VKEY, POLICY_HASH);
  await adapter.waitForDeployment();

  const BlobKzgVerifier = await ethers.getContractFactory("BlobKzgVerifier", deployer);
  const blobKzgVerifier = await BlobKzgVerifier.deploy();
  await blobKzgVerifier.waitForDeployment();
  const blobKzgVerifierAddr = await blobKzgVerifier.getAddress();

  const FinalizerFactory = await ethers.getContractFactory("WorldlineFinalizer", deployer);
  const finalizerProxy = await upgrades.deployProxy(
    FinalizerFactory,
    [await adapter.getAddress(), DOMAIN, MAX_DELAY, GENESIS_L2_BLOCK, blobKzgVerifierAddr],
    { kind: "uups", initializer: "initialize" }
  );
  await finalizerProxy.waitForDeployment();
  const finalizerAddr = await finalizerProxy.getAddress();

  return { finalizerAddr, domain: DOMAIN };
}

async function main(): Promise<void> {
  console.log("=== Worldline Smoke Test ===");
  console.log(`Network: ${network.name}`);

  const [deployer] = await ethers.getSigners();
  console.log(`Smoke test signer: ${deployer.address}`);

  const isDevNetwork = network.name === "hardhat" || network.name === "localhost";

  let finalizerAddr: string;
  let domain: string;

  if (isDevNetwork) {
    // On dev networks, deploy a fresh mock stack — the real Groth16Verifier
    // requires valid BN254 proofs which can't be generated without the prover tool.
    console.log("\n[dev] Deploying fresh mock stack for smoke test…");
    ({ finalizerAddr, domain } = await deployMockStack(deployer));
    console.log(`[dev] MockGroth16Verifier-backed stack deployed`);
    console.log(`[dev] WorldlineFinalizer: ${finalizerAddr}`);
  } else {
    // On real networks, read from the most recent deployment JSON.
    const deploymentsDir = path.join(__dirname, "../deployments");
    if (!fs.existsSync(deploymentsDir)) {
      console.error("ERROR: deployments/ directory not found. Run deploy.ts first.");
      process.exit(1);
    }

    const files = fs
      .readdirSync(deploymentsDir)
      .filter((f) => f.startsWith(network.name + "-") && f.endsWith(".json"))
      .sort();

    if (files.length === 0) {
      console.error(`ERROR: No deployment file found for network '${network.name}'.`);
      process.exit(1);
    }

    const latestFile = files[files.length - 1];
    console.log(`\nUsing deployment: ${latestFile}`);
    const deployment = JSON.parse(fs.readFileSync(path.join(deploymentsDir, latestFile), "utf-8"));
    const wlFinalizer = deployment.contracts.WorldlineFinalizer;
    finalizerAddr =
      wlFinalizer && typeof wlFinalizer === "object" && "proxy" in wlFinalizer
        ? wlFinalizer.proxy
        : wlFinalizer;
    domain =
      deployment.config?.domainSeparator ??
      ethers.keccak256(ethers.toUtf8Bytes("worldline-testnet"));
  }

  let allPassed = true;

  function log(step: string, ok: boolean, detail?: string): void {
    const icon = ok ? "✓" : "✗ FAIL";
    console.log(`  [${icon}] ${step}${detail ? ": " + detail : ""}`);
    if (!ok) allPassed = false;
  }

  // ── Step 1: Connect to finalizer ──────────────────────────────────────────
  console.log("\n[1] Connecting to WorldlineFinalizer…");
  const Finalizer = await ethers.getContractAt("WorldlineFinalizer", finalizerAddr);
  const initialWindow = await (Finalizer as any).nextWindowIndex();
  log("WorldlineFinalizer connected", true, `nextWindowIndex=${initialWindow}`);

  // ── Step 2: Enable permissionless submission ──────────────────────────────
  console.log("\n[2] Enabling permissionless submission…");
  try {
    const tx = await (Finalizer as any).connect(deployer).setPermissionless(true);
    await tx.wait();
    log("setPermissionless(true)", true, `tx=${tx.hash}`);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    log("setPermissionless(true)", false, msg);
  }

  // ── Step 3: Submit a proof ────────────────────────────────────────────────
  console.log("\n[3] Submitting ZK validity proof…");
  try {
    const latestBlock = await ethers.provider.getBlock("latest");
    const windowCloseTimestamp = BigInt(latestBlock!.timestamp) + 3540n; // ~59 min ahead

    const l2Start = GENESIS_L2_BLOCK;
    const l2End = l2Start + 100n;
    const proof = encodeProof(l2Start, l2End, windowCloseTimestamp, domain);
    const publicInputs = encodePublicInputs(l2Start, l2End, windowCloseTimestamp, domain);

    const tx = await (Finalizer as any)
      .connect(deployer)
      .submitZkValidityProof(proof, publicInputs);
    const receipt = await tx.wait();
    log("submitZkValidityProof", true, `gasUsed=${receipt!.gasUsed}, tx=${tx.hash}`);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    log("submitZkValidityProof", false, msg);
  }

  // ── Step 4: Verify state change ───────────────────────────────────────────
  console.log("\n[4] Verifying state change…");
  try {
    const newWindow = await (Finalizer as any).nextWindowIndex();
    const increased = newWindow > initialWindow;
    log("nextWindowIndex increased", increased, `${initialWindow} → ${newWindow}`);
  } catch (e: unknown) {
    log("nextWindowIndex check", false, String(e));
  }

  // ── Step 5: Clean up (disable permissionless) ─────────────────────────────
  console.log("\n[5] Cleaning up…");
  try {
    const tx = await (Finalizer as any).connect(deployer).setPermissionless(false);
    await tx.wait();
    log("setPermissionless(false)", true);
  } catch (e: unknown) {
    // Non-fatal on cleanup
    console.warn(`  [warn] setPermissionless(false): ${String(e)}`);
  }

  // ── Summary ───────────────────────────────────────────────────────────────
  console.log(`\n── Smoke Test ${allPassed ? "PASSED ✓" : "FAILED ✗"} ──`);
  if (!allPassed) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
