/**
 * Post-deployment verification script.
 *
 * Reads the most recent deployment file from deployments/ and verifies
 * that each contract is live and correctly linked.
 *
 * Usage:
 *   npx hardhat run scripts/verify-deployment.ts --network <network>
 */

import * as fs from "fs";
import * as path from "path";
import { ethers, network } from "hardhat";

async function main(): Promise<void> {
  console.log("=== Worldline Deployment Verification ===");
  console.log(`Network: ${network.name}`);

  // ── Find most recent deployment file ────────────────────────────────────────
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
  const deploymentPath = path.join(deploymentsDir, latestFile);
  console.log(`\nReading deployment: ${latestFile}`);

  const deployment = JSON.parse(fs.readFileSync(deploymentPath, "utf-8"));
  const { contracts } = deployment;

  let passed = 0;
  let failed = 0;

  function check(name: string, result: boolean, detail?: string): void {
    if (result) {
      console.log(`  ✓ ${name}${detail ? ": " + detail : ""}`);
      passed++;
    } else {
      console.error(`  ✗ FAIL ${name}${detail ? ": " + detail : ""}`);
      failed++;
    }
  }

  // ── Verify each contract is live ────────────────────────────────────────────
  console.log("\n[1] Checking contracts are live…");

  // Groth16Verifier — no read function, just check code exists
  const verifierCode = await ethers.provider.getCode(contracts.Groth16Verifier);
  check("Groth16Verifier bytecode", verifierCode !== "0x", contracts.Groth16Verifier);

  // WorldlineRegistry
  const Registry = await ethers.getContractAt("WorldlineRegistry", contracts.WorldlineRegistry);
  try {
    const owner = await (Registry as any).owner();
    check("WorldlineRegistry.owner()", owner !== ethers.ZeroAddress, owner);
  } catch (e) {
    check("WorldlineRegistry.owner()", false, String(e));
  }

  // Groth16ZkAdapter — check bytecode
  const adapterCode = await ethers.provider.getCode(contracts.Groth16ZkAdapter);
  check("Groth16ZkAdapter bytecode", adapterCode !== "0x", contracts.Groth16ZkAdapter);

  // WorldlineFinalizer
  const Finalizer = await ethers.getContractAt("WorldlineFinalizer", contracts.WorldlineFinalizer);
  try {
    const nextWindow = await (Finalizer as any).nextWindowIndex();
    check("WorldlineFinalizer.nextWindowIndex()", true, nextWindow.toString());
  } catch (e) {
    check("WorldlineFinalizer.nextWindowIndex()", false, String(e));
  }

  // WorldlineOutputsRegistry
  const OutputsRegistry = await ethers.getContractAt(
    "WorldlineOutputsRegistry",
    contracts.WorldlineOutputsRegistry
  );
  try {
    const owner = await (OutputsRegistry as any).owner();
    check("WorldlineOutputsRegistry.owner()", owner !== ethers.ZeroAddress, owner);
  } catch (e) {
    check("WorldlineOutputsRegistry.owner()", false, String(e));
  }

  // WorldlineCompat
  const compatCode = await ethers.provider.getCode(contracts.WorldlineCompat);
  check("WorldlineCompat bytecode", compatCode !== "0x", contracts.WorldlineCompat);

  // BlobKzgVerifier
  try {
    const BlobVerifier = await ethers.getContractAt("BlobKzgVerifier", contracts.BlobKzgVerifier);
    const blobFee = await (BlobVerifier as any).currentBlobBaseFee();
    check("BlobKzgVerifier.currentBlobBaseFee()", true, blobFee.toString());
  } catch (e) {
    check("BlobKzgVerifier.currentBlobBaseFee()", false, String(e));
  }

  // ── Verify contract linkage ──────────────────────────────────────────────────
  console.log("\n[2] Checking contract linkage…");

  try {
    const adapterOnFinalizer = await (Finalizer as any).adapter();
    check(
      "WorldlineFinalizer.adapter() → Groth16ZkAdapter",
      adapterOnFinalizer.toLowerCase() === contracts.Groth16ZkAdapter.toLowerCase(),
      adapterOnFinalizer
    );
  } catch (e) {
    check("WorldlineFinalizer.adapter()", false, String(e));
  }

  try {
    const blobOnFinalizer = await (Finalizer as any).blobKzgVerifier();
    check(
      "WorldlineFinalizer.blobKzgVerifier() → BlobKzgVerifier",
      blobOnFinalizer.toLowerCase() === contracts.BlobKzgVerifier.toLowerCase(),
      blobOnFinalizer
    );
  } catch (e) {
    check("WorldlineFinalizer.blobKzgVerifier()", false, String(e));
  }

  try {
    const compatOnRegistry = await (Registry as any).compatFacade();
    check(
      "WorldlineRegistry.compatFacade() → WorldlineCompat",
      compatOnRegistry.toLowerCase() === contracts.WorldlineCompat.toLowerCase(),
      compatOnRegistry
    );
  } catch (e) {
    check("WorldlineRegistry.compatFacade()", false, String(e));
  }

  try {
    const domainOnFinalizer = await (Finalizer as any).domainSeparator();
    check(
      "WorldlineFinalizer.domainSeparator() set",
      domainOnFinalizer !== ethers.ZeroHash,
      domainOnFinalizer
    );
  } catch (e) {
    check("WorldlineFinalizer.domainSeparator()", false, String(e));
  }

  // ── Summary ──────────────────────────────────────────────────────────────────
  console.log(`\n── Summary: ${passed} passed, ${failed} failed ──`);
  if (failed > 0) {
    console.error("\nVerification FAILED.");
    process.exit(1);
  }
  console.log("\nVerification PASSED. ✓");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
