/**
 * Gas benchmark helpers for Groth16Verifier.verifyProof().
 *
 * Run with:  REPORT_GAS=true npx hardhat test test/gas/Groth16Verifier.gas.test.ts
 *
 * NOTE: The placeholder Groth16Verifier only operates on chainId 31337 (Hardhat).
 *       On any other network it reverts with NotProductionVerifier().
 *
 * NOTE: Do NOT modify existing test files; this file lives in test/gas/ as a helper.
 */

import { ethers } from "hardhat";

describe("GasBenchmark: Groth16Verifier.verifyProof", function () {
  this.timeout(60_000);

  it("single Groth16 BN254 proof verify latency", async function () {
    const Groth16Verifier = await ethers.getContractFactory("Groth16Verifier");
    const verifier = await Groth16Verifier.deploy();

    // Placeholder proof elements — all zeros.
    // The dev-mode verifier ignores these values and returns true on chainId 31337.
    const pA: [bigint, bigint] = [0n, 0n];
    const pB: [[bigint, bigint], [bigint, bigint]] = [
      [0n, 0n],
      [0n, 0n]
    ];
    const pC: [bigint, bigint] = [0n, 0n];
    const pubSignals: [bigint, bigint] = [0n, 0n];

    await verifier.verifyProof(pA, pB, pC, pubSignals);
  });
});
