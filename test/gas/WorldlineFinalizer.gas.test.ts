/**
 * Gas benchmark helpers for WorldlineFinalizer.submitZkValidityProof().
 *
 * Run with:  REPORT_GAS=true npx hardhat test test/gas/WorldlineFinalizer.gas.test.ts
 *
 * Measures gas consumption at batch sizes 1, 4, and 16 sequential proof windows.
 * Each "batch size N" test submits N contiguous windows through the finalizer so
 * the gas reporter can show per-call and cumulative costs.
 *
 * NOTE: Do NOT modify existing test files; this file lives in test/gas/ as a helper.
 */

import { time } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { ethers, upgrades } from "hardhat";
import { enablePermissionless } from "../integration/deployment-fixtures";

const DOMAIN = ethers.keccak256(ethers.toUtf8Bytes("worldline-gas-bench-domain"));
const PROGRAM_VKEY = ethers.keccak256(ethers.toUtf8Bytes("program-vkey-gas"));
const POLICY_HASH = ethers.keccak256(ethers.toUtf8Bytes("policy-hash-gas"));
const PROVER_DIGEST = ethers.keccak256(ethers.toUtf8Bytes("prover-set-gas"));

async function deployStack() {
  const [owner] = await ethers.getSigners();

  const MockVerifier = await ethers.getContractFactory("MockGroth16Verifier");
  const verifier = await MockVerifier.deploy();

  const Adapter = await ethers.getContractFactory("Groth16ZkAdapter");
  const adapter = await Adapter.deploy(await verifier.getAddress(), PROGRAM_VKEY, POLICY_HASH);

  const Finalizer = await ethers.getContractFactory("WorldlineFinalizer");
  const finalizer = (await upgrades.deployProxy(
    Finalizer,
    [await adapter.getAddress(), DOMAIN, 3600, 0, ethers.ZeroAddress],
    { kind: "uups" }
  )) as any;
  await finalizer.waitForDeployment();
  await enablePermissionless(finalizer);

  return { finalizer, owner };
}

function computeStf(l2Start: bigint, l2End: bigint, windowCloseTimestamp: bigint): string {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256", "uint256", "bytes32", "bytes32", "bytes32", "uint256"],
      [l2Start, l2End, ethers.ZeroHash, ethers.ZeroHash, DOMAIN, windowCloseTimestamp]
    )
  );
}

function encodePublicInputs(
  l2Start: bigint,
  l2End: bigint,
  windowCloseTimestamp: bigint
): { inputs: string; stf: string } {
  const stf = computeStf(l2Start, l2End, windowCloseTimestamp);
  const inputs = ethers.AbiCoder.defaultAbiCoder().encode(
    ["bytes32", "uint256", "uint256", "bytes32", "bytes32", "bytes32", "uint256", "bytes32"],
    [stf, l2Start, l2End, ethers.ZeroHash, ethers.ZeroHash, DOMAIN, windowCloseTimestamp, stf]
  );
  return { inputs, stf };
}

function encodeProof(stfCommitment: string): string {
  // Production format: pA[2], pB[2][2], pC[2], stfCommitment, proverSetDigest (320 bytes)
  const pA = [1, 2];
  const pB = [
    [3, 4],
    [5, 6]
  ];
  const pC = [7, 8];
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["uint256[2]", "uint256[2][2]", "uint256[2]", "uint256", "uint256"],
    [pA, pB, pC, stfCommitment, PROVER_DIGEST]
  );
}

describe("GasBenchmark: WorldlineFinalizer.submitZkValidityProof", function () {
  this.timeout(120_000);

  async function submitWindows(batchSize: number): Promise<void> {
    const { finalizer } = await deployStack();
    const ts = BigInt(await time.latest()) + 3600n;
    let l2Cursor = 0n;

    for (let i = 0; i < batchSize; i++) {
      const l2Start = l2Cursor;
      const l2End = l2Cursor + 100n;
      const { inputs, stf } = encodePublicInputs(l2Start, l2End, ts);
      const proof = encodeProof(stf);
      await finalizer.submitZkValidityProof(proof, inputs);
      l2Cursor = l2End;
    }
  }

  it("batch size 1 — single verifyAndFinalize call", async function () {
    await submitWindows(1);
  });

  it("batch size 4 — four sequential verifyAndFinalize calls", async function () {
    await submitWindows(4);
  });

  it("batch size 16 — sixteen sequential verifyAndFinalize calls", async function () {
    await submitWindows(16);
  });
});
