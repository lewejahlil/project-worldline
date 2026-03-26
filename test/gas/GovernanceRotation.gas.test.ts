/**
 * Gas benchmark helpers for the full GovernanceRotation 10-step sequence.
 *
 * Run with:  REPORT_GAS=true npx hardhat test test/gas/GovernanceRotation.gas.test.ts
 *
 * Steps measured:
 *  1. Deploy Verifier
 *  2. Deploy WorldlineRegistry
 *  3. Deploy Groth16ZkAdapter (v1)
 *  4. Deploy WorldlineFinalizer
 *  5. Deploy WorldlineOutputsRegistry
 *  6. Deploy WorldlineCompat + wire
 *  7. submitZkValidityProof (window 0)
 *  8. schedule new VKey/policy
 *  9. activate after timelock
 * 10. Deploy Groth16ZkAdapter (v2) + setAdapter
 *
 * NOTE: Do NOT modify existing test files; this file lives in test/gas/ as a helper.
 */

import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-toolbox/network-helpers";

const DOMAIN = ethers.keccak256(ethers.toUtf8Bytes("worldline-gov-gas-domain"));
const PROGRAM_VKEY_V1 = ethers.keccak256(ethers.toUtf8Bytes("program-vkey-v1-gas"));
const POLICY_HASH_V1 = ethers.keccak256(ethers.toUtf8Bytes("policy-hash-v1-gas"));
const PROGRAM_VKEY_V2 = ethers.keccak256(ethers.toUtf8Bytes("program-vkey-v2-gas"));
const POLICY_HASH_V2 = ethers.keccak256(ethers.toUtf8Bytes("policy-hash-v2-gas"));
const PROVER_DIGEST = ethers.keccak256(ethers.toUtf8Bytes("prover-set-gas"));
const MIN_TIMELOCK = 86400;

function computeStf(l2Start: bigint, l2End: bigint, ts: bigint): string {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256", "uint256", "bytes32", "bytes32", "bytes32", "uint256"],
      [l2Start, l2End, ethers.ZeroHash, ethers.ZeroHash, DOMAIN, ts]
    )
  );
}

function encodeProof(stf: string, vkey: string, policy: string): string {
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["bytes32", "bytes32", "bytes32", "bytes32"],
    [stf, vkey, policy, PROVER_DIGEST]
  );
}

function encodeInputs(l2Start: bigint, l2End: bigint, ts: bigint): { inputs: string; stf: string } {
  const stf = computeStf(l2Start, l2End, ts);
  const inputs = ethers.AbiCoder.defaultAbiCoder().encode(
    ["bytes32", "uint256", "uint256", "bytes32", "bytes32", "bytes32", "uint256"],
    [stf, l2Start, l2End, ethers.ZeroHash, ethers.ZeroHash, DOMAIN, ts]
  );
  return { inputs, stf };
}

describe("GasBenchmark: GovernanceRotation full 10-step sequence", function () {
  this.timeout(180_000);

  it("full governance rotation gas total", async function () {
    // Step 1: Deploy Verifier
    const Verifier = await ethers.getContractFactory("Verifier");
    const verifier = await Verifier.deploy();

    // Step 2: Deploy WorldlineRegistry
    const Registry = await ethers.getContractFactory("WorldlineRegistry");
    const registry = await Registry.deploy(await verifier.getAddress());

    // Step 3: Deploy Groth16ZkAdapter v1
    const Adapter = await ethers.getContractFactory("Groth16ZkAdapter");
    const adapterV1 = await Adapter.deploy(
      await verifier.getAddress(),
      PROGRAM_VKEY_V1,
      POLICY_HASH_V1,
      true
    );

    // Step 4: Deploy WorldlineFinalizer
    const Finalizer = await ethers.getContractFactory("WorldlineFinalizer");
    const finalizer = await Finalizer.deploy(await adapterV1.getAddress(), DOMAIN, 3600);
    await finalizer.setPermissionless(true);

    // Step 5: Deploy WorldlineOutputsRegistry
    const OutputsRegistry = await ethers.getContractFactory("WorldlineOutputsRegistry");
    const outputsRegistry = await OutputsRegistry.deploy(MIN_TIMELOCK);

    // Step 6: Deploy WorldlineCompat + wire
    const Compat = await ethers.getContractFactory("WorldlineCompat");
    const compat = await Compat.deploy(await registry.getAddress());
    await registry.setCompatFacade(await compat.getAddress());

    // Step 7: Submit window 0 proof
    const ts = BigInt(await time.latest()) + 3600n;
    const { inputs: inputs0, stf: stf0 } = encodeInputs(0n, 100n, ts);
    await finalizer.submitZkValidityProof(
      encodeProof(stf0, PROGRAM_VKEY_V1, POLICY_HASH_V1),
      inputs0
    );

    // Step 8: Schedule new VKey/policy
    const domainKey = await outputsRegistry.domainKey(
      ethers.keccak256(ethers.toUtf8Bytes("chain-id")),
      ethers.keccak256(ethers.toUtf8Bytes("domain-tag"))
    );
    await outputsRegistry.schedule(
      domainKey,
      PROGRAM_VKEY_V2,
      POLICY_HASH_V2,
      await adapterV1.getAddress()
    );

    // Step 9: Fast-forward past timelock and activate
    await time.increase(MIN_TIMELOCK + 1);
    await outputsRegistry.activate(domainKey);

    // Step 10: Deploy Groth16ZkAdapter v2 + set adapter on finalizer
    const adapterV2 = await Adapter.deploy(
      await verifier.getAddress(),
      PROGRAM_VKEY_V2,
      POLICY_HASH_V2,
      true
    );
    // HI-001: Two-step timelocked adapter change
    await finalizer.scheduleAdapterChange(await adapterV2.getAddress());
    await time.increase(86401); // past adapter change delay
    await finalizer.activateAdapterChange();
  });
});
