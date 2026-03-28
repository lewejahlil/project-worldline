/**
 * Shared test helpers for integration tests.
 *
 * Provides contract deployment, proof encoding, and public-input construction
 * utilities that mirror the patterns established in devnet/smoke.ts.
 */

import { ethers } from "hardhat";
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

// ── Deployment helpers ───────────────────────────────────────────────────────

export interface DeployedContracts {
  verifier: Awaited<ReturnType<ContractFactory["deploy"]>>;
  adapter: Awaited<ReturnType<ContractFactory["deploy"]>>;
  registry: Awaited<ReturnType<ContractFactory["deploy"]>>;
  finalizer: Awaited<ReturnType<ContractFactory["deploy"]>>;
}

export interface DeployedContractsWithRouter extends DeployedContracts {
  router: Awaited<ReturnType<ContractFactory["deploy"]>>;
}

export interface DeployedContractsWithPlonkRouter extends DeployedContractsWithRouter {
  plonkVerifier: Awaited<ReturnType<ContractFactory["deploy"]>>;
  plonkAdapter: Awaited<ReturnType<ContractFactory["deploy"]>>;
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
  const registry = await Registry.deploy(await verifier.getAddress());
  await registry.waitForDeployment();

  const Finalizer = await ethers.getContractFactory("WorldlineFinalizer", deployer);
  const finalizer = await Finalizer.deploy(
    await adapter.getAddress(),
    DOMAIN,
    MAX_ACCEPTANCE_DELAY,
    GENESIS_L2_BLOCK
  );
  await finalizer.waitForDeployment();

  return { verifier, adapter, registry, finalizer };
}

/**
 * Deploy the full Worldline contract stack including the ProofRouter.
 * Registers the Groth16ZkAdapter at proofSystemId=1 in the router and
 * configures WorldlineFinalizer to use the router.
 */
export async function deployAllWithRouter(deployer?: Signer): Promise<DeployedContractsWithRouter> {
  const base = await deployAll(deployer);

  const Router = await ethers.getContractFactory("ProofRouter", deployer);
  const router = await Router.deploy();
  await router.waitForDeployment();

  // Register Groth16 adapter at proofSystemId=1
  await (await (router as any).registerAdapter(1, await (base.adapter as any).getAddress())).wait();

  // Wire router into finalizer
  await (await (base.finalizer as any).setProofRouter(await (router as any).getAddress())).wait();

  return { ...base, router };
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

// ── Proof encoding helpers ───────────────────────────────────────────────────

/**
 * Compute the stfCommitment as the contract expects:
 *   keccak256(abi.encode(l2Start, l2End, outputRoot, l1BlockHash, domainSeparator, windowCloseTimestamp))
 *
 * MED-001: the on-chain binding check will reject any proof whose stfCommitment
 * doesn't match this exact encoding.
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
 * Encode the 7-word (224-byte) public inputs expected by WorldlineFinalizer._submit().
 */
export function encodePublicInputs(
  l2Start: bigint,
  l2End: bigint,
  windowCloseTimestamp: bigint,
  domain: string = DOMAIN
): string {
  const stfCommitment = computeStfCommitment(l2Start, l2End, windowCloseTimestamp, domain);
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["bytes32", "uint256", "uint256", "bytes32", "bytes32", "bytes32", "uint256"],
    [stfCommitment, l2Start, l2End, ethers.ZeroHash, ethers.ZeroHash, domain, windowCloseTimestamp]
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
