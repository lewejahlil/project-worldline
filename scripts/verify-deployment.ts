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
import { ethers, network, upgrades } from "hardhat";

/**
 * Resolve a contract address from the deployment record. Supports both plain
 * address strings and {proxy, implementation} objects (for UUPS proxied contracts).
 */
function getAddr(contracts: Record<string, unknown>, name: string): string {
  const val = contracts[name];
  if (typeof val === "string") return val;
  if (val && typeof val === "object" && "proxy" in val) return (val as any).proxy;
  throw new Error(`Contract ${name} not found in deployment`);
}

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
  const groth16VerifierAddr = getAddr(contracts, "Groth16Verifier");
  const verifierCode = await ethers.provider.getCode(groth16VerifierAddr);
  check("Groth16Verifier bytecode", verifierCode !== "0x", groth16VerifierAddr);

  // WorldlineRegistry (proxy)
  const registryAddr = getAddr(contracts, "WorldlineRegistry");
  const Registry = await ethers.getContractAt("WorldlineRegistry", registryAddr);
  try {
    const owner = await (Registry as any).owner();
    check("WorldlineRegistry.owner()", owner !== ethers.ZeroAddress, owner);
  } catch (e) {
    check("WorldlineRegistry.owner()", false, String(e));
  }

  // Groth16ZkAdapter — check bytecode
  const adapterAddr = getAddr(contracts, "Groth16ZkAdapter");
  const adapterCode = await ethers.provider.getCode(adapterAddr);
  check("Groth16ZkAdapter bytecode", adapterCode !== "0x", adapterAddr);

  // WorldlineFinalizer (proxy)
  const finalizerAddr = getAddr(contracts, "WorldlineFinalizer");
  const Finalizer = await ethers.getContractAt("WorldlineFinalizer", finalizerAddr);
  try {
    const nextWindow = await (Finalizer as any).nextWindowIndex();
    check("WorldlineFinalizer initialized", true, `nextWindowIndex=${nextWindow.toString()}`);
  } catch (e) {
    check("WorldlineFinalizer initialized", false, String(e));
  }

  // WorldlineOutputsRegistry (proxy)
  const outputsRegistryAddr = getAddr(contracts, "WorldlineOutputsRegistry");
  const OutputsRegistry = await ethers.getContractAt(
    "WorldlineOutputsRegistry",
    outputsRegistryAddr
  );
  try {
    const owner = await (OutputsRegistry as any).owner();
    check("WorldlineOutputsRegistry.owner()", owner !== ethers.ZeroAddress, owner);
  } catch (e) {
    check("WorldlineOutputsRegistry.owner()", false, String(e));
  }

  // WorldlineCompat
  const compatAddr = getAddr(contracts, "WorldlineCompat");
  const compatCode = await ethers.provider.getCode(compatAddr);
  check("WorldlineCompat bytecode", compatCode !== "0x", compatAddr);

  // BlobKzgVerifier
  const blobKzgVerifierAddr = getAddr(contracts, "BlobKzgVerifier");
  try {
    const BlobVerifier = await ethers.getContractAt("BlobKzgVerifier", blobKzgVerifierAddr);
    const blobFee = await (BlobVerifier as any).currentBlobBaseFee();
    check("BlobKzgVerifier.currentBlobBaseFee()", true, blobFee.toString());
  } catch (e) {
    check("BlobKzgVerifier.currentBlobBaseFee()", false, String(e));
  }

  // ── Verify UUPS proxy implementation addresses ───────────────────────────────
  console.log("\n[2] Checking UUPS proxy implementations…");

  // WorldlineRegistry implementation
  try {
    const registryRaw = contracts["WorldlineRegistry"];
    if (registryRaw && typeof registryRaw === "object" && "implementation" in registryRaw) {
      const storedImpl = (registryRaw as any).implementation as string;
      const liveImpl = await upgrades.erc1967.getImplementationAddress(registryAddr);
      check(
        "WorldlineRegistry implementation",
        liveImpl !== ethers.ZeroAddress && liveImpl.toLowerCase() === storedImpl.toLowerCase(),
        liveImpl
      );
    } else {
      // Legacy plain-address format — just verify ERC1967 slot is readable
      const implAddr = await upgrades.erc1967.getImplementationAddress(registryAddr);
      check("WorldlineRegistry implementation", implAddr !== ethers.ZeroAddress, implAddr);
    }
  } catch (e) {
    check("WorldlineRegistry implementation", false, String(e));
  }

  // WorldlineFinalizer implementation
  try {
    const finalizerRaw = contracts["WorldlineFinalizer"];
    if (finalizerRaw && typeof finalizerRaw === "object" && "implementation" in finalizerRaw) {
      const storedImpl = (finalizerRaw as any).implementation as string;
      const liveImpl = await upgrades.erc1967.getImplementationAddress(finalizerAddr);
      check(
        "WorldlineFinalizer implementation",
        liveImpl !== ethers.ZeroAddress && liveImpl.toLowerCase() === storedImpl.toLowerCase(),
        liveImpl
      );
    } else {
      const implAddr = await upgrades.erc1967.getImplementationAddress(finalizerAddr);
      check("WorldlineFinalizer implementation", implAddr !== ethers.ZeroAddress, implAddr);
    }
  } catch (e) {
    check("WorldlineFinalizer implementation", false, String(e));
  }

  // WorldlineOutputsRegistry implementation
  try {
    const outputsRaw = contracts["WorldlineOutputsRegistry"];
    if (outputsRaw && typeof outputsRaw === "object" && "implementation" in outputsRaw) {
      const storedImpl = (outputsRaw as any).implementation as string;
      const liveImpl = await upgrades.erc1967.getImplementationAddress(outputsRegistryAddr);
      check(
        "WorldlineOutputsRegistry implementation",
        liveImpl !== ethers.ZeroAddress && liveImpl.toLowerCase() === storedImpl.toLowerCase(),
        liveImpl
      );
    } else {
      const implAddr = await upgrades.erc1967.getImplementationAddress(outputsRegistryAddr);
      check("WorldlineOutputsRegistry implementation", implAddr !== ethers.ZeroAddress, implAddr);
    }
  } catch (e) {
    check("WorldlineOutputsRegistry implementation", false, String(e));
  }

  // ── Verify contract linkage ──────────────────────────────────────────────────
  console.log("\n[3] Checking contract linkage…");

  try {
    const adapterOnFinalizer = await (Finalizer as any).adapter();
    check(
      "WorldlineFinalizer.adapter() → Groth16ZkAdapter",
      adapterOnFinalizer.toLowerCase() === adapterAddr.toLowerCase(),
      adapterOnFinalizer
    );
  } catch (e) {
    check("WorldlineFinalizer.adapter()", false, String(e));
  }

  try {
    const blobOnFinalizer = await (Finalizer as any).blobKzgVerifier();
    check(
      "WorldlineFinalizer.blobKzgVerifier() → BlobKzgVerifier",
      blobOnFinalizer.toLowerCase() === blobKzgVerifierAddr.toLowerCase(),
      blobOnFinalizer
    );
  } catch (e) {
    check("WorldlineFinalizer.blobKzgVerifier()", false, String(e));
  }

  try {
    const compatOnRegistry = await (Registry as any).compatFacade();
    check(
      "WorldlineRegistry.compatFacade() → WorldlineCompat",
      compatOnRegistry.toLowerCase() === compatAddr.toLowerCase(),
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
  console.log("\nVerification PASSED.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
