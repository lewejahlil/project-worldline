/**
 * Shared test helpers for integration tests.
 *
 * Provides contract deployment, proof encoding, and public-input construction
 * utilities that mirror the patterns established in devnet/smoke.ts.
 */

import { ethers, upgrades } from "hardhat";
import type { ContractFactory, Signer } from "ethers";

// ── Constants ────────────────────────────────────────────────────────────────

export const DOMAIN = ethers.keccak256(ethers.toUtf8Bytes("integration-test-domain"));
export const PROGRAM_VKEY = ethers.keccak256(ethers.toUtf8Bytes("integration-program-vkey"));
export const POLICY_HASH = ethers.keccak256(ethers.toUtf8Bytes("integration-policy-hash"));
export const PROVER_SET_DIGEST = ethers.keccak256(
  ethers.toUtf8Bytes("integration-prover-digest-2of3")
);
export const MAX_ACCEPTANCE_DELAY = 3600; // 1 hour
export const GENESIS_L2_BLOCK = 0n;
/** Groth16 proof byte size: pA[2] + pB[2][2] + pC[2] + stfCommitment + proverSetDigest */
export const GROTH16_PROOF_BYTE_SIZE = 320;
/** Plonk proof byte size: uint256[24] proofWords + stfCommitment + proverSetDigest */
export const PLONK_PROOF_BYTE_SIZE = 832;
/** Halo2 raw proof byte size (KZG/BN254 commitment scheme) */
export const HALO2_RAW_PROOF_BYTE_SIZE = 1472;
/** Maximum batch size enforced by circuit constraints */
export const MAX_BATCH_SIZE = 1024;

// ── Deployment helpers ───────────────────────────────────────────────────────

export interface DeployedContracts {
  verifier: Awaited<ReturnType<ContractFactory["deploy"]>>;
  adapter: Awaited<ReturnType<ContractFactory["deploy"]>>;
  registry: Awaited<ReturnType<ContractFactory["deploy"]>>; // proxy
  finalizer: Awaited<ReturnType<ContractFactory["deploy"]>>; // proxy
  registryImplAddr?: string;
  finalizerImplAddr?: string;
}

export interface DeployedContractsWithRouter extends DeployedContracts {
  router: Awaited<ReturnType<ContractFactory["deploy"]>>; // proxy
  routerImplAddr?: string;
}

export interface DeployedContractsWithPlonkRouter extends DeployedContractsWithRouter {
  plonkVerifier: Awaited<ReturnType<ContractFactory["deploy"]>>;
  plonkAdapter: Awaited<ReturnType<ContractFactory["deploy"]>>;
}

export interface ThreeAdapterSetup {
  router: Awaited<ReturnType<ContractFactory["deploy"]>>;
  finalizer: Awaited<ReturnType<ContractFactory["deploy"]>>;
  groth16Adapter: Awaited<ReturnType<ContractFactory["deploy"]>>;
  plonkAdapter: Awaited<ReturnType<ContractFactory["deploy"]>>;
  halo2Adapter: Awaited<ReturnType<ContractFactory["deploy"]>>;
}

/**
 * Deploy the full Worldline contract stack for integration testing.
 * Uses MockGroth16Verifier so no real ZK proofs are required.
 */
export async function deployAll(deployer?: Signer): Promise<DeployedContracts> {
  const MockVerifier = await ethers.getContractFactory("MockGroth16Verifier", deployer);
  const verifier = await MockVerifier.deploy();
  await verifier.waitForDeployment();

  const Adapter = await ethers.getContractFactory("Groth16ZkAdapter", deployer);
  const adapter = await Adapter.deploy(await verifier.getAddress(), PROGRAM_VKEY, POLICY_HASH);
  await adapter.waitForDeployment();

  const Registry = await ethers.getContractFactory("WorldlineRegistry", deployer);
  const registryProxy = await upgrades.deployProxy(Registry, [await verifier.getAddress()], {
    kind: "uups"
  });
  await registryProxy.waitForDeployment();
  const registryImplAddr = await upgrades.erc1967.getImplementationAddress(
    await registryProxy.getAddress()
  );

  const Finalizer = await ethers.getContractFactory("WorldlineFinalizer", deployer);
  const finalizerProxy = await upgrades.deployProxy(
    Finalizer,
    [
      await adapter.getAddress(),
      DOMAIN,
      MAX_ACCEPTANCE_DELAY,
      GENESIS_L2_BLOCK,
      ethers.ZeroAddress
    ],
    { kind: "uups", initializer: "initialize" }
  );
  await finalizerProxy.waitForDeployment();
  const finalizerImplAddr = await upgrades.erc1967.getImplementationAddress(
    await finalizerProxy.getAddress()
  );

  return {
    verifier,
    adapter,
    registry: registryProxy,
    finalizer: finalizerProxy,
    registryImplAddr,
    finalizerImplAddr
  };
}

/**
 * Deploy the full Worldline contract stack including the ProofRouter.
 * Registers the Groth16ZkAdapter at proofSystemId=1 in the router and
 * configures WorldlineFinalizer to use the router.
 */
export async function deployAllWithRouter(deployer?: Signer): Promise<DeployedContractsWithRouter> {
  const base = await deployAll(deployer);

  const Router = await ethers.getContractFactory("ProofRouter", deployer);
  const routerProxy = await upgrades.deployProxy(Router, [], { kind: "uups" });
  await routerProxy.waitForDeployment();
  const routerImplAddr = await upgrades.erc1967.getImplementationAddress(
    await routerProxy.getAddress()
  );

  // Register Groth16 adapter at proofSystemId=1
  await (
    await (routerProxy as any).registerAdapter(1, await (base.adapter as any).getAddress())
  ).wait();

  // Wire router into finalizer
  await (
    await (base.finalizer as any).setProofRouter(await (routerProxy as any).getAddress())
  ).wait();

  return { ...base, router: routerProxy, routerImplAddr };
}

/**
 * Deploy the full Worldline contract stack including a ProofRouter with both
 * Groth16 (ID=1) and Plonk (ID=2) adapters registered.
 * Uses mock verifiers so no real ZK proofs are required.
 */
export async function deployAllWithPlonkRouter(
  deployer?: Signer
): Promise<DeployedContractsWithPlonkRouter> {
  const base = await deployAllWithRouter(deployer);

  // Deploy MockPlonkVerifier
  const MockPlonk = await ethers.getContractFactory("MockPlonkVerifier", deployer);
  const plonkVerifier = await MockPlonk.deploy();
  await plonkVerifier.waitForDeployment();

  // Deploy PlonkZkAdapter
  const PlonkAdapter = await ethers.getContractFactory("PlonkZkAdapter", deployer);
  const plonkAdapter = await PlonkAdapter.deploy(
    await plonkVerifier.getAddress(),
    PROGRAM_VKEY,
    POLICY_HASH
  );
  await plonkAdapter.waitForDeployment();

  // Register Plonk adapter at proofSystemId=2
  await (
    await (base.router as any).registerAdapter(2, await (plonkAdapter as any).getAddress())
  ).wait();

  return { ...base, plonkVerifier, plonkAdapter };
}

/**
 * Deploy the full Worldline contract stack with all three proof system adapters registered:
 *   ID=1 → MockGroth16Verifier + Groth16ZkAdapter
 *   ID=2 → MockPlonkVerifier   + PlonkZkAdapter
 *   ID=3 → MockHalo2Verifier   + Halo2ZkAdapter
 *
 * ProofRouter has all three registered; WorldlineFinalizer is wired to the router
 * and set to permissionless mode.
 */
export async function deployAllWithThreeAdapters(deployer?: Signer): Promise<ThreeAdapterSetup> {
  // ── ID=1: Groth16 ────────────────────────────────────────────────────────
  const MockGroth16 = await ethers.getContractFactory("MockGroth16Verifier", deployer);
  const groth16Verifier = await MockGroth16.deploy();
  await groth16Verifier.waitForDeployment();

  const Groth16Adapter = await ethers.getContractFactory("Groth16ZkAdapter", deployer);
  const groth16Adapter = await Groth16Adapter.deploy(
    await groth16Verifier.getAddress(),
    PROGRAM_VKEY,
    POLICY_HASH
  );
  await groth16Adapter.waitForDeployment();

  // ── ID=2: Plonk (V2 circuit via MockPlonkVerifier) ───────────────────────
  const MockPlonk = await ethers.getContractFactory("MockPlonkVerifier", deployer);
  const plonkVerifier = await MockPlonk.deploy();
  await plonkVerifier.waitForDeployment();

  const PlonkAdapter = await ethers.getContractFactory("PlonkZkAdapter", deployer);
  const plonkAdapter = await PlonkAdapter.deploy(
    await plonkVerifier.getAddress(),
    PROGRAM_VKEY,
    POLICY_HASH
  );
  await plonkAdapter.waitForDeployment();

  // ── ID=3: Halo2 (MockHalo2Verifier + Halo2ZkAdapter) ─────────────────────
  const MockHalo2 = await ethers.getContractFactory("MockHalo2Verifier", deployer);
  const halo2Verifier = await MockHalo2.deploy();
  await halo2Verifier.waitForDeployment();

  const Halo2Adapter = await ethers.getContractFactory("Halo2ZkAdapter", deployer);
  const halo2Adapter = await Halo2Adapter.deploy(
    await halo2Verifier.getAddress(),
    PROGRAM_VKEY,
    POLICY_HASH
  );
  await halo2Adapter.waitForDeployment();

  // ── ProofRouter: register all three ──────────────────────────────────────
  const Router = await ethers.getContractFactory("ProofRouter", deployer);
  const router = await upgrades.deployProxy(Router, [], { kind: "uups" });
  await router.waitForDeployment();

  await (
    await (router as any).registerAdapter(1, await (groth16Adapter as any).getAddress())
  ).wait();
  await (await (router as any).registerAdapter(2, await (plonkAdapter as any).getAddress())).wait();
  await (await (router as any).registerAdapter(3, await (halo2Adapter as any).getAddress())).wait();

  // ── WorldlineFinalizer: wire router, set permissionless ───────────────────
  const Finalizer = await ethers.getContractFactory("WorldlineFinalizer", deployer);
  const finalizer = await upgrades.deployProxy(
    Finalizer,
    [
      await groth16Adapter.getAddress(),
      DOMAIN,
      MAX_ACCEPTANCE_DELAY,
      GENESIS_L2_BLOCK,
      ethers.ZeroAddress
    ],
    { kind: "uups", initializer: "initialize" }
  );
  await finalizer.waitForDeployment();
  await (await (finalizer as any).setProofRouter(await (router as any).getAddress())).wait();
  await (await (finalizer as any).setPermissionless(true)).wait();

  return { router, finalizer, groth16Adapter, plonkAdapter, halo2Adapter };
}

// ── Proof encoding helpers ───────────────────────────────────────────────────

/**
 * Compute the MED-001 submission binding:
 *   keccak256(abi.encode(l2Start, l2End, outputRoot, l1BlockHash, domainSeparator, windowCloseTimestamp))
 *
 * This value is placed at publicInputs word 7 (submissionBinding). Tests also use it as
 * the stfCommitment stand-in at word 0 (the real circuit outputs a Poseidon hash).
 */
export function computeStfCommitment(
  l2Start: bigint,
  l2End: bigint,
  windowCloseTimestamp: bigint,
  domain: string = DOMAIN
): string {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256", "uint256", "bytes32", "bytes32", "bytes32", "uint256"],
      [l2Start, l2End, ethers.ZeroHash, ethers.ZeroHash, domain, windowCloseTimestamp]
    )
  );
}

/**
 * Encode the 8-word (256-byte) public inputs expected by WorldlineFinalizer._submit().
 *   Word 0: stfCommitment (test uses the keccak binding as a Poseidon stand-in).
 *   Words 1–6: l2Start, l2End, outputRoot, l1BlockHash, domainSeparator, windowCloseTimestamp.
 *   Word 7: submissionBinding = keccak256(abi.encode(words 1–6)) — MED-001 digest.
 */
export function encodePublicInputs(
  l2Start: bigint,
  l2End: bigint,
  windowCloseTimestamp: bigint,
  domain: string = DOMAIN
): string {
  const stfCommitment = computeStfCommitment(l2Start, l2End, windowCloseTimestamp, domain);
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["bytes32", "uint256", "uint256", "bytes32", "bytes32", "bytes32", "uint256", "bytes32"],
    [
      stfCommitment,
      l2Start,
      l2End,
      ethers.ZeroHash,
      ethers.ZeroHash,
      domain,
      windowCloseTimestamp,
      stfCommitment
    ]
  );
}

/**
 * Encode a production-format 320-byte Groth16 proof:
 *   pA[2], pB[2][2], pC[2], stfCommitment, proverSetDigest
 *
 * The stfCommitment embedded in the proof must match the one in publicInputs
 * (checked by StfMismatch). MockGroth16Verifier always returns true so the
 * BN254 pairing step is skipped in tests.
 */
export function encodeProof(
  l2Start: bigint,
  l2End: bigint,
  windowCloseTimestamp: bigint,
  domain: string = DOMAIN,
  proverSetDigest: string = PROVER_SET_DIGEST
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
      BigInt(proverSetDigest)
    ]
  );
}

/**
 * Returns { proof, publicInputs } for a single window submission.
 */
export async function makeWindowFixture(
  l2Start: bigint,
  l2End: bigint,
  domain: string = DOMAIN,
  proverSetDigest: string = PROVER_SET_DIGEST
): Promise<{ proof: string; publicInputs: string }> {
  const block = await ethers.provider.getBlock("latest");
  const windowCloseTimestamp = BigInt(block!.timestamp) + BigInt(7200); // 2 hours ahead
  return {
    proof: encodeProof(l2Start, l2End, windowCloseTimestamp, domain, proverSetDigest),
    publicInputs: encodePublicInputs(l2Start, l2End, windowCloseTimestamp, domain)
  };
}

/**
 * Encode a production-format 832-byte Plonk proof:
 *   uint256[24] proofWords, stfCommitment, proverSetDigest
 *
 * The stfCommitment embedded in the proof must match the one in publicInputs
 * (checked by StfMismatch). MockPlonkVerifier always returns true so the
 * BN254 pairing step is skipped in tests.
 */
export function encodePlonkProof(
  l2Start: bigint,
  l2End: bigint,
  windowCloseTimestamp: bigint,
  domain: string = DOMAIN,
  proverSetDigest: string = PROVER_SET_DIGEST
): string {
  const stfCommitment = computeStfCommitment(l2Start, l2End, windowCloseTimestamp, domain);
  // 24 dummy proof words
  const proofWords = Array.from({ length: 24 }, (_, i) => BigInt(i + 1));
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["uint256[24]", "uint256", "uint256"],
    [proofWords, BigInt(stfCommitment), BigInt(proverSetDigest)]
  );
}

/**
 * Returns { proof, publicInputs } for a single window submission using a Plonk proof.
 */
export async function makePlonkWindowFixture(
  l2Start: bigint,
  l2End: bigint,
  domain: string = DOMAIN,
  proverSetDigest: string = PROVER_SET_DIGEST
): Promise<{ proof: string; publicInputs: string }> {
  const block = await ethers.provider.getBlock("latest");
  const windowCloseTimestamp = BigInt(block!.timestamp) + BigInt(7200); // 2 hours ahead
  return {
    proof: encodePlonkProof(l2Start, l2End, windowCloseTimestamp, domain, proverSetDigest),
    publicInputs: encodePublicInputs(l2Start, l2End, windowCloseTimestamp, domain)
  };
}

/**
 * Encode a Halo2 proof envelope:
 *   bytes   proofBytes       — 1472 bytes of dummy data (MockHalo2Verifier accepts any)
 *   uint256 stfCommitment    — embedded stfCommitment (extracted by Halo2ZkAdapter)
 *   uint256 proverSetDigest  — embedded proverSetDigest
 *
 * ABI encoding: 32(offset) + 32(uint256) + 32(uint256) + 32(length) + 1472(data) = 1600 bytes
 * which exactly meets the Halo2ZkAdapter HALO2_PROOF_MIN_LEN = 1600 floor.
 */
export function encodeHalo2Proof(
  l2Start: bigint,
  l2End: bigint,
  windowCloseTimestamp: bigint,
  domain: string = DOMAIN,
  proverSetDigest: string = PROVER_SET_DIGEST
): string {
  const stfCommitment = computeStfCommitment(l2Start, l2End, windowCloseTimestamp, domain);
  const rawProofBytes = new Uint8Array(HALO2_RAW_PROOF_BYTE_SIZE); // 1472 zero bytes; mock verifier accepts any input
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["bytes", "uint256", "uint256"],
    [rawProofBytes, BigInt(stfCommitment), BigInt(proverSetDigest)]
  );
}

/**
 * Returns { proof, publicInputs } for a single window submission using a Halo2 proof.
 */
export async function makeHalo2WindowFixture(
  l2Start: bigint,
  l2End: bigint,
  domain: string = DOMAIN,
  proverSetDigest: string = PROVER_SET_DIGEST
): Promise<{ proof: string; publicInputs: string }> {
  const block = await ethers.provider.getBlock("latest");
  const windowCloseTimestamp = BigInt(block!.timestamp) + BigInt(7200); // 2 hours ahead
  return {
    proof: encodeHalo2Proof(l2Start, l2End, windowCloseTimestamp, domain, proverSetDigest),
    publicInputs: encodePublicInputs(l2Start, l2End, windowCloseTimestamp, domain)
  };
}

// ── Event log helpers ───────────────────────────────────────────────────────

/**
 * Find a named event in a transaction receipt by parsing each log against the
 * given contract interface. Returns the first matching parsed log, or null.
 *
 * Consolidates the repeated `receipt.logs.map(parseLog).find(name)` pattern
 * and the `findZkProofAccepted` helper that appeared across integration tests.
 */
export function findEventLog(receipt: any, iface: any, eventName: string): any {
  for (const log of receipt.logs) {
    try {
      const parsed = iface.parseLog(log);
      if (parsed?.name === eventName) return parsed;
    } catch {
      /* skip logs from other contracts / unparseable topics */
    }
  }
  return null;
}

/**
 * Enable permissionless mode on a finalizer contract.
 * Replaces the inline `(finalizer as any).setPermissionless(true)` pattern.
 */
export async function enablePermissionless(
  finalizer: Awaited<ReturnType<ContractFactory["deploy"]>>
): Promise<void> {
  await (await (finalizer as any).setPermissionless(true)).wait();
}

/**
 * Submit N sequential windows starting at l2Start=0, each 100 blocks wide.
 * Returns the tx receipts.
 */
export async function submitWindows(
  finalizer: Awaited<ReturnType<ContractFactory["deploy"]>>,
  count: number,
  signer?: Signer
): Promise<unknown[]> {
  const receipts: unknown[] = [];
  let cursor = GENESIS_L2_BLOCK;
  const contract = signer ? (finalizer as any).connect(signer) : (finalizer as any);

  for (let i = 0; i < count; i++) {
    const l2End = cursor + 100n;
    const { proof, publicInputs } = await makeWindowFixture(cursor, l2End);
    const tx = await contract.submitZkValidityProof(proof, publicInputs);
    receipts.push(await tx.wait());
    cursor = l2End;
  }
  return receipts;
}
