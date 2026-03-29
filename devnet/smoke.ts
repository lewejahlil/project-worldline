#!/usr/bin/env ts-node
/**
 * Worldline devnet smoke test.
 *
 * End-to-end validation that runs without manual intervention:
 *   1. Launches Anvil with deterministic accounts and fixed chain ID.
 *   2. Deploys all contracts via the same sequence as scripts/deploy.ts.
 *   3. Submits 3 synthetic proof windows through WorldlineFinalizer.
 *   4. Runs the watcher logic for 3 finalization cycles and verifies events.
 *   5. Exits 0 on success, 1 on any failure.
 *
 * Usage:
 *   npm run devnet:smoke
 *   # or directly:
 *   ts-node devnet/smoke.ts
 *
 * Environment variables:
 *   DEVNET_PORT   Anvil port (default: 8545)
 *   PRIVATE_KEY   Deployer key (default: Anvil account 0)
 */

import { spawn, ChildProcess } from "child_process";
import * as fs from "fs";
import * as net from "net";
import * as path from "path";
import { ethers } from "ethers";

const ANVIL_PORT = process.env["DEVNET_PORT"] ?? "8545";
const PRIVATE_KEY =
  process.env["PRIVATE_KEY"] ??
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
// When set to "1", skip spawning Anvil (assumes one is already running on ANVIL_PORT).
// Used by the CI job which starts Anvil in a dedicated shell step.
const SKIP_ANVIL_LAUNCH = process.env["SKIP_ANVIL_LAUNCH"] === "1";
const CHAIN_ID = 31337;
const MAX_ACCEPTANCE_DELAY = 3600;

const DOMAIN = ethers.keccak256(ethers.toUtf8Bytes("worldline-smoke-domain"));
const PROGRAM_VKEY = ethers.keccak256(ethers.toUtf8Bytes("program-vkey-smoke"));
const POLICY_HASH = ethers.keccak256(ethers.toUtf8Bytes("policy-hash-smoke"));
const PROVER_DIGEST = ethers.keccak256(ethers.toUtf8Bytes("prover-set-smoke"));

const FINALIZER_ABI = [
  "event OutputProposed(uint256 indexed windowIndex, bytes32 outputRoot, uint256 l2Start, uint256 l2End, bytes32 stfCommitment)",
  "event ZkProofAccepted(uint256 indexed windowIndex, bytes32 programVKey, bytes32 policyHash, bytes32 proverSetDigest)",
  "function submitZkValidityProof(bytes calldata proof, bytes calldata publicInputs) external",
  "function setPermissionless(bool _permissionless) external",
  "function nextWindowIndex() view returns (uint256)"
];

// ── Artifact loader ─────────────────────────────────────────────────────────

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

function loadProxyArtifact(): { abi: ethers.InterfaceAbi; bytecode: string } {
  const p = path.resolve(
    __dirname,
    "../artifacts/@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol/ERC1967Proxy.json"
  );
  if (fs.existsSync(p)) {
    return JSON.parse(fs.readFileSync(p, "utf-8"));
  }
  throw new Error("ERC1967Proxy artifact not found. Run 'npm run contracts:build' first.");
}

async function deployContract(
  wallet: ethers.Signer,
  name: string,
  ...args: unknown[]
): Promise<ethers.BaseContract> {
  const artifact = loadArtifact(name);
  const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, wallet);
  const contract = await factory.deploy(...args);
  await contract.waitForDeployment();
  const addr = await contract.getAddress();
  console.log(`  [deploy] ${name} → ${addr}`);
  return contract as ethers.BaseContract;
}

async function deployProxy(
  wallet: ethers.Signer,
  name: string,
  initAbi: string[],
  initArgs: unknown[]
): Promise<ethers.BaseContract> {
  const implArtifact = loadArtifact(name);
  const implFactory = new ethers.ContractFactory(implArtifact.abi, implArtifact.bytecode, wallet);
  const impl = await implFactory.deploy();
  await impl.waitForDeployment();

  const initIface = new ethers.Interface(initAbi);
  const initData = initIface.encodeFunctionData("initialize", initArgs);

  const proxyArtifact = loadProxyArtifact();
  const proxyFactory = new ethers.ContractFactory(
    proxyArtifact.abi,
    proxyArtifact.bytecode,
    wallet
  );
  const proxy = await proxyFactory.deploy(await impl.getAddress(), initData);
  await proxy.waitForDeployment();
  const proxyAddr = await proxy.getAddress();
  console.log(`  [deploy] ${name} (UUPS proxy) → ${proxyAddr}`);
  return new ethers.Contract(proxyAddr, implArtifact.abi, wallet) as ethers.BaseContract;
}

// ── Proof encoding (matches WorldlineFinalizer test helpers) ─────────────────

// MED-001: stfCommitment must equal keccak256(abi.encode(l2Start, l2End, outputRoot,
// l1BlockHash, domainSeparator, windowCloseTimestamp)) to pass the on-chain binding check.
function computeStfCommitment(
  l2Start: bigint,
  l2End: bigint,
  windowCloseTimestamp: bigint
): string {
  const encoded = ethers.AbiCoder.defaultAbiCoder().encode(
    ["uint256", "uint256", "bytes32", "bytes32", "bytes32", "uint256"],
    [l2Start, l2End, ethers.ZeroHash, ethers.ZeroHash, DOMAIN, windowCloseTimestamp]
  );
  return ethers.keccak256(encoded);
}

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

// ── Watcher logic (inline — verifies events for N cycles) ───────────────────

async function runWatcherCheck(
  provider: ethers.JsonRpcProvider,
  finalizerAddress: string,
  expectedWindows: number
): Promise<void> {
  const finalizer = new ethers.Contract(finalizerAddress, FINALIZER_ABI, provider);

  console.log(`\n[watcher] Querying finalization events…`);

  const proposedFilter = finalizer.filters["OutputProposed"]();
  const acceptedFilter = finalizer.filters["ZkProofAccepted"]();

  const proposedEvents = await finalizer.queryFilter(proposedFilter, 0);
  const acceptedEvents = await finalizer.queryFilter(acceptedFilter, 0);

  console.log(
    `[watcher] Found ${proposedEvents.length} OutputProposed, ${acceptedEvents.length} ZkProofAccepted`
  );

  if (proposedEvents.length !== expectedWindows) {
    throw new Error(
      `Expected ${expectedWindows} OutputProposed events, got ${proposedEvents.length}`
    );
  }
  if (acceptedEvents.length !== expectedWindows) {
    throw new Error(
      `Expected ${expectedWindows} ZkProofAccepted events, got ${acceptedEvents.length}`
    );
  }

  // Verify contiguity and policy hash for each window
  for (let i = 0; i < proposedEvents.length; i++) {
    const proposedArgs = (proposedEvents[i] as ethers.EventLog).args;
    const acceptedArgs = (acceptedEvents[i] as ethers.EventLog).args;

    const windowIndex = proposedArgs[0] as bigint;
    const emittedPolicyHash = acceptedArgs[2] as string;

    if (windowIndex !== BigInt(i)) {
      throw new Error(`Window index mismatch: expected ${i}, got ${windowIndex}`);
    }
    if (emittedPolicyHash.toLowerCase() !== POLICY_HASH.toLowerCase()) {
      throw new Error(
        `Policy hash mismatch at window ${i}: expected ${POLICY_HASH}, got ${emittedPolicyHash}`
      );
    }

    console.log(`[watcher] ✓ Window ${i}: OutputProposed + ZkProofAccepted verified`);
  }

  console.log(`[watcher] All ${expectedWindows} finalization cycles verified. ✓`);
}

// ── Main ────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log("=== Worldline Devnet Smoke Test ===");
  console.log(`Anvil port: ${ANVIL_PORT}`);

  // ── Step 1: Launch Anvil (skipped when SKIP_ANVIL_LAUNCH=1) ─────────────────
  let anvil: ChildProcess | null = null;

  if (SKIP_ANVIL_LAUNCH) {
    console.log("\n[1] Using externally-managed Anvil (SKIP_ANVIL_LAUNCH=1).");
  } else {
    console.log("\n[1] Launching Anvil…");
    anvil = spawn("anvil", ["--port", ANVIL_PORT, "--chain-id", String(CHAIN_ID)], {
      stdio: ["ignore", "pipe", "pipe"]
    });

    anvil.on("error", (err: Error) => {
      console.error("Failed to start Anvil:", err.message);
      process.exit(1);
    });

    // Wait for Anvil to be ready.
    // Foundry 1.x writes the startup banner to stderr; we also poll the TCP port
    // as a fallback in case output is buffered or the message changes across versions.
    await new Promise<void>((resolve, reject) => {
      const anvilProc = anvil!;
      let settled = false;
      const done = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        clearInterval(poll);
        anvilProc.stdout?.off("data", onData);
        anvilProc.stderr?.off("data", onData);
        resolve();
      };

      const timeout = setTimeout(() => {
        if (settled) return;
        settled = true;
        clearInterval(poll);
        anvilProc.stdout?.off("data", onData);
        anvilProc.stderr?.off("data", onData);
        reject(new Error("Anvil startup timeout"));
      }, 60_000);

      const onData = (data: Buffer) => {
        if (data.toString().includes("Listening on")) done();
      };
      anvilProc.stdout?.on("data", onData);
      anvilProc.stderr?.on("data", onData);

      // Poll the TCP port every 500 ms — works regardless of which stream Anvil uses.
      const poll = setInterval(() => {
        const sock = net.createConnection({ port: Number(ANVIL_PORT), host: "127.0.0.1" });
        sock.on("connect", () => {
          sock.destroy();
          done();
        });
        sock.on("error", () => sock.destroy());
      }, 500);
    });
    console.log("[1] Anvil ready.");
  }

  const provider = new ethers.JsonRpcProvider(`http://127.0.0.1:${ANVIL_PORT}`);
  // NonceManager prevents nonce races when multiple deploys are sent sequentially.
  const wallet = new ethers.NonceManager(new ethers.Wallet(PRIVATE_KEY, provider));
  console.log(`[1] Deployer: ${await wallet.getAddress()}`);

  try {
    // ── Step 2: Deploy all contracts ─────────────────────────────────────────
    console.log("\n[2] Deploying contracts…");

    const verifier = await deployContract(wallet, "MockGroth16Verifier");
    const registry = await deployProxy(
      wallet,
      "WorldlineRegistry",
      ["function initialize(address verifier) external"],
      [await verifier.getAddress()]
    );
    const adapter = await deployContract(
      wallet,
      "Groth16ZkAdapter",
      await verifier.getAddress(),
      PROGRAM_VKEY,
      POLICY_HASH
    );
    const finalizer = await deployProxy(wallet, "WorldlineFinalizer", [
      "function initialize(address _adapter, bytes32 _domainSeparator, uint256 _maxAcceptanceDelay, uint256 _genesisL2Block, address _blobKzgVerifier) external"
    ], [await adapter.getAddress(), DOMAIN, MAX_ACCEPTANCE_DELAY, 0, ethers.ZeroAddress]);
    const outputsRegistry = await deployProxy(
      wallet,
      "WorldlineOutputsRegistry",
      ["function initialize(uint256 _minTimelock) external"],
      [86400]
    );
    const compat = await deployContract(wallet, "WorldlineCompat", await registry.getAddress());

    // Wire compat facade
    const registryContract = new ethers.Contract(
      await registry.getAddress(),
      ["function setCompatFacade(address) external"],
      wallet
    );
    await (await registryContract.setCompatFacade(await compat.getAddress())).wait();
    console.log("  [wire] setCompatFacade ✓");

    // Enable permissionless submission for smoke test
    const finalizerContract = new ethers.Contract(
      await finalizer.getAddress(),
      FINALIZER_ABI,
      wallet
    );
    await (await finalizerContract.setPermissionless(true)).wait();

    const finalizerAddress = await finalizer.getAddress();
    console.log(`[2] All contracts deployed. Finalizer: ${finalizerAddress}`);

    // Suppress unused variable warnings
    void outputsRegistry;

    // ── Step 3: Submit 3 synthetic proof windows ──────────────────────────────
    console.log("\n[3] Submitting 3 synthetic proof windows…");
    const latestBlock = await provider.getBlock("latest");
    const ts = BigInt(latestBlock!.timestamp) + BigInt(3600);
    let l2Cursor = BigInt(0);

    for (let i = 0; i < 3; i++) {
      const l2Start = l2Cursor;
      const l2End = l2Cursor + BigInt(100);
      // MED-001: stfCommitment must be keccak256(abi.encode(l2Start, l2End, outputRoot,
      // l1BlockHash, domainSep, windowCloseTimestamp)) to pass on-chain binding check.
      const stf = computeStfCommitment(l2Start, l2End, ts);
      const proof = encodeProof(stf);
      const inputs = encodePublicInputs(stf, l2Start, l2End, ts);

      const tx = await finalizerContract.submitZkValidityProof(proof, inputs);
      await tx.wait();
      console.log(`  [submit] Window ${i}: l2Start=${l2Start} l2End=${l2End} ✓`);
      l2Cursor = l2End;
    }
    console.log("[3] 3 proof windows submitted.");

    // ── Step 4: Watcher — verify 3 finalization cycles ────────────────────────
    console.log("\n[4] Running watcher for 3 finalization cycles…");
    await runWatcherCheck(provider, finalizerAddress, 3);
    console.log("[4] Watcher completed successfully.");

    // ── Done ─────────────────────────────────────────────────────────────────
    console.log("\n=== Smoke test PASSED ✓ ===");
  } catch (err) {
    console.error("\n=== Smoke test FAILED ===");
    console.error(err);
    anvil?.kill("SIGTERM");
    process.exit(1);
  }

  anvil?.kill("SIGTERM");
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
