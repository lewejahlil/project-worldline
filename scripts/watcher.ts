/**
 * Reference watcher that monitors WorldlineFinalizer events and verifies
 * proof provenance. In production, this would run continuously; here it
 * processes a batch of historical events.
 *
 * Usage:
 *   ts-node scripts/watcher.ts [--verify-manifest <path>]
 *
 * Environment variables:
 *   RPC_URL                  RPC endpoint (default: http://localhost:8545)
 *   FINALIZER_ADDRESS        Address of the WorldlineFinalizer contract
 *   EXPECTED_POLICY_HASH     0x-prefixed expected policy hash (optional)
 *   FROM_BLOCK               Start block for event query (default: 0)
 */

import { ethers } from "ethers";
import * as fs from "fs";
import * as path from "path";
import { canonicalKeccak } from "./canonical-json";

// ── ABIs ──────────────────────────────────────────────────────────────────────

const FINALIZER_ABI = [
  "event OutputProposed(uint256 indexed windowIndex, bytes32 outputRoot, uint256 l2Start, uint256 l2End, bytes32 stfCommitment)",
  "event ZkProofAccepted(uint256 indexed windowIndex, bytes32 programVKey, bytes32 policyHash, bytes32 proverSetDigest)"
];

// ── Types ─────────────────────────────────────────────────────────────────────

interface WindowRecord {
  windowIndex: bigint;
  outputRoot: string;
  l2Start: bigint;
  l2End: bigint;
  stfCommitment: string;
  programVKey?: string;
  policyHash?: string;
  proverSetDigest?: string;
}

interface WatcherSummary {
  totalWindows: number;
  anomalies: string[];
}

// ── Watcher ───────────────────────────────────────────────────────────────────

async function runWatcher(opts: {
  rpcUrl: string;
  finalizerAddress: string;
  expectedPolicyHash: string | undefined;
  fromBlock: number;
  verifyManifestPath: string | undefined;
}): Promise<WatcherSummary> {
  const provider = new ethers.JsonRpcProvider(opts.rpcUrl);
  const finalizer = new ethers.Contract(opts.finalizerAddress, FINALIZER_ABI, provider);

  const anomalies: string[] = [];

  console.log(`Querying events from block ${opts.fromBlock}…`);

  // Fetch OutputProposed events
  const proposedFilter = finalizer.filters["OutputProposed"]();
  const acceptedFilter = finalizer.filters["ZkProofAccepted"]();

  const proposedEvents = await finalizer.queryFilter(proposedFilter, opts.fromBlock);
  const acceptedEvents = await finalizer.queryFilter(acceptedFilter, opts.fromBlock);

  // Build a map of windowIndex → WindowRecord
  const windows = new Map<string, WindowRecord>();

  for (const ev of proposedEvents) {
    const args = (ev as ethers.EventLog).args;
    const idx = args[0] as bigint;
    windows.set(idx.toString(), {
      windowIndex: idx,
      outputRoot: args[1] as string,
      l2Start: args[2] as bigint,
      l2End: args[3] as bigint,
      stfCommitment: args[4] as string
    });
    console.log(
      `[Window ${idx}] OutputProposed l2Start=${args[2]} l2End=${args[3]} outputRoot=${args[1]} stfCommitment=${args[4]}`
    );
  }

  for (const ev of acceptedEvents) {
    const args = (ev as ethers.EventLog).args;
    const idx = args[0] as bigint;
    const rec = windows.get(idx.toString());
    if (rec) {
      rec.programVKey = args[1] as string;
      rec.policyHash = args[2] as string;
      rec.proverSetDigest = args[3] as string;
    }
    console.log(
      `[Window ${idx}] ZkProofAccepted programVKey=${args[1]} policyHash=${args[2]} proverSetDigest=${args[3]}`
    );
  }

  // Sort windows by index for analysis
  const sortedWindows = Array.from(windows.values()).sort((a, b) =>
    a.windowIndex < b.windowIndex ? -1 : a.windowIndex > b.windowIndex ? 1 : 0
  );

  // Check for non-contiguous window indices
  for (let i = 1; i < sortedWindows.length; i++) {
    const prev = sortedWindows[i - 1];
    const curr = sortedWindows[i];
    if (curr.windowIndex !== prev.windowIndex + 1n) {
      const msg = `⚠️  Gap detected: window ${prev.windowIndex} → window ${curr.windowIndex} (expected ${prev.windowIndex + 1n})`;
      console.warn(msg);
      anomalies.push(msg);
    }
  }

  // Validate policyHash against expected value
  if (opts.expectedPolicyHash) {
    for (const w of sortedWindows) {
      if (w.policyHash && w.policyHash.toLowerCase() !== opts.expectedPolicyHash.toLowerCase()) {
        const msg = `⚠️  [Window ${w.windowIndex}] policyHash mismatch: expected ${opts.expectedPolicyHash}, got ${w.policyHash}`;
        console.warn(msg);
        anomalies.push(msg);
      }
    }
  }

  // Verify proverSetDigest against manifest file (if provided)
  if (opts.verifyManifestPath) {
    console.log(`\nVerifying manifest against ${opts.verifyManifestPath}…`);
    try {
      const manifestRaw = fs.readFileSync(opts.verifyManifestPath, "utf-8");
      const manifestJson = JSON.parse(manifestRaw);
      const computedDigest = canonicalKeccak(manifestJson);
      console.log(`Computed manifest digest: ${computedDigest}`);

      for (const w of sortedWindows) {
        if (w.proverSetDigest) {
          if (w.proverSetDigest.toLowerCase() === computedDigest.toLowerCase()) {
            console.log(`[Window ${w.windowIndex}] ✓ proverSetDigest matches manifest`);
          } else {
            const msg = `⚠️  [Window ${w.windowIndex}] proverSetDigest mismatch: on-chain=${w.proverSetDigest} computed=${computedDigest}`;
            console.warn(msg);
            anomalies.push(msg);
          }
        }
      }
    } catch (e) {
      const msg = `⚠️  Failed to load or verify manifest: ${e}`;
      console.warn(msg);
      anomalies.push(msg);
    }
  }

  return { totalWindows: sortedWindows.length, anomalies };
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  const args = process.argv.slice(2);

  // Parse --verify-manifest flag
  let verifyManifestPath: string | undefined;
  const manifestFlagIdx = args.indexOf("--verify-manifest");
  if (manifestFlagIdx !== -1 && args[manifestFlagIdx + 1]) {
    verifyManifestPath = path.resolve(args[manifestFlagIdx + 1]);
  }

  const rpcUrl = process.env["RPC_URL"] ?? "http://localhost:8545";
  const finalizerAddress = process.env["FINALIZER_ADDRESS"] ?? "";
  const expectedPolicyHash = process.env["EXPECTED_POLICY_HASH"];
  const fromBlock = parseInt(process.env["FROM_BLOCK"] ?? "0", 10);

  if (!finalizerAddress) {
    console.error("Error: FINALIZER_ADDRESS environment variable is required");
    console.error("Usage: FINALIZER_ADDRESS=0x... ts-node scripts/watcher.ts");
    process.exit(1);
  }

  console.log("Worldline Reference Watcher");
  console.log(`  RPC URL:          ${rpcUrl}`);
  console.log(`  Finalizer:        ${finalizerAddress}`);
  console.log(`  From block:       ${fromBlock}`);
  console.log(`  Expected policy:  ${expectedPolicyHash ?? "(not set)"}`);
  console.log(`  Manifest path:    ${verifyManifestPath ?? "(not set)"}`);
  console.log();

  const summary = await runWatcher({
    rpcUrl,
    finalizerAddress,
    expectedPolicyHash,
    fromBlock,
    verifyManifestPath
  });

  console.log("\n── Summary ──────────────────────────────────────────────────");
  console.log(`Total windows processed: ${summary.totalWindows}`);
  if (summary.anomalies.length === 0) {
    console.log("No anomalies detected. ✓");
  } else {
    console.log(`Anomalies detected (${summary.anomalies.length}):`);
    for (const a of summary.anomalies) {
      console.log(`  ${a}`);
    }
    process.exit(1);
  }
}

if (require.main === module) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
