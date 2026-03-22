// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IZkAggregatorVerifier} from "../interfaces/IZkAggregatorVerifier.sol";
import {Verifier} from "./Verifier.sol";
import {Groth16Verifier} from "./Groth16Verifier.sol";

/// @title Groth16ZkAdapter
/// @notice Adapter that pins a Groth16 verifier address, a programVKey, and a policyHash.
///         Extracts four public signals from the proof, validates that programVKey and
///         policyHash match the pinned values, then delegates cryptographic verification
///         to the underlying verifier.
///
/// @dev Production verification flow:
///      1. Caller submits `(proof, publicInputs)` to the Finalizer.
///      2. Finalizer calls `adapter.verify(proof, publicInputs)`.
///      3. Adapter decodes the four public signals from `proof`.
///      4. Adapter checks programVKey and policyHash against pinned values.
///      5. In production (IS_DEV_MODE=false): adapter decodes the Groth16 proof
///         components (pA, pB, pC, pubSignals) from `proof` and calls the verifier.
///      6. Adapter returns (valid=true, stfCommitment, programVKey, policyHash, proverSetDigest).
///
/// @dev DEV MODE (IS_DEV_MODE=true): Skips full Groth16 verification for the 224-byte
///      Finalizer path. Only calls the demo Verifier for the 64-byte test path.
///      Always deploy with isDev=false on non-Hardhat networks.
contract Groth16ZkAdapter is IZkAggregatorVerifier {
    error ProgramVKeyMismatch();
    error PolicyHashMismatch();
    error ProofInvalid();

    /// @notice True when running in development/test mode.
    /// @dev PRODUCTION TODO: Always deploy with isDev=false on non-Hardhat networks.
    ///      Dev mode skips full Groth16 cryptographic verification.
    bool public immutable IS_DEV_MODE;

    /// @notice Address of the verifier contract.
    ///         In dev mode: expects a Verifier (demo square-hash contract).
    ///         In prod mode: expects a Groth16Verifier (snarkjs-generated BN254 verifier).
    address public immutable verifierAddress;

    bytes32 public immutable programVKeyPinned;
    bytes32 public immutable policyHashPinned;

    /// @param _verifier          Address of the verifier contract.
    ///                           Dev mode: deploy a Verifier; Prod mode: deploy Groth16Verifier.
    /// @param _programVKeyPinned The pinned program verifying key.
    /// @param _policyHashPinned  The pinned policy hash.
    /// @param _isDev             True for development/test deployments; false for production.
    ///
    /// @dev PRODUCTION TODO: Callers MUST pass _isDev=false for mainnet/testnet deployments.
    ///      When false, the constructor does not enforce chainid 31337, but the underlying
    ///      placeholder Groth16Verifier will reject any non-Hardhat calls until replaced.
    constructor(
        address _verifier,
        bytes32 _programVKeyPinned,
        bytes32 _policyHashPinned,
        bool _isDev
    ) {
        IS_DEV_MODE = _isDev;
        verifierAddress = _verifier;
        programVKeyPinned = _programVKeyPinned;
        policyHashPinned = _policyHashPinned;
    }

    /// @inheritdoc IZkAggregatorVerifier
    /// @dev Decodes four public signals from the `proof` parameter. In dev mode the
    ///      64-byte path calls the demo Verifier; the 224-byte Finalizer path skips
    ///      cryptographic verification (PRODUCTION TODO). In production mode, the
    ///      Groth16Verifier is called for all inputs.
    function verify(
        bytes calldata proof,
        bytes calldata publicInputs
    )
        external
        view
        override
        returns (
            bool valid,
            bytes32 stfCommitment,
            bytes32 programVKey,
            bytes32 policyHash,
            bytes32 proverSetDigest
        )
    {
        // Decode the four public signals from the proof payload.
        // In production these are extracted from the Groth16 public inputs; here
        // they are ABI-encoded directly in the proof bytes for the dev workflow.
        (stfCommitment, programVKey, policyHash, proverSetDigest) = abi.decode(
            proof,
            (bytes32, bytes32, bytes32, bytes32)
        );

        // Enforce pinned values. These checks are necessary in BOTH dev and prod modes.
        // PRODUCTION TODO: Pinned-value checks are necessary but NOT sufficient —
        //   real Groth16 verification (below) is required for security.
        if (programVKey != programVKeyPinned) revert ProgramVKeyMismatch();
        if (policyHash != policyHashPinned) revert PolicyHashMismatch();

        if (IS_DEV_MODE) {
            // ── Dev mode: lightweight verification only ───────────────────────────
            //
            // PRODUCTION TODO: Remove dev-mode skip path before mainnet deployment.
            // Dev mode does NOT provide cryptographic security. It is only suitable
            // for local Hardhat testing and CI.

            if (publicInputs.length == 64) {
                // 64-byte path: call the demo Verifier (SquareHash circuit).
                // This exercises the verifier call flow without a full proving setup.
                (uint256 secret, uint256 publicHash) = abi.decode(
                    publicInputs,
                    (uint256, uint256)
                );
                // Reverts with InvalidProof() if secret² != publicHash.
                Verifier(verifierAddress).verifyProof(secret, publicHash);
            }
            // PRODUCTION TODO: For the 224-byte Finalizer path, real Groth16
            //   verification is intentionally skipped in dev mode. Production MUST
            //   wire the Groth16Verifier call below (see !IS_DEV_MODE branch).
        } else {
            // ── Production mode: full Groth16 verification on ALL code paths ─────
            //
            // PRODUCTION TODO: Once circuit artifacts are generated, decode the
            // full Groth16 proof components from the `proof` parameter. The proof
            // bytes should be ABI-encoded as:
            //   (pA[2], pB[2][2], pC[2], pubSignals[2], stfCommitment, programVKey,
            //    policyHash, proverSetDigest)
            //
            // Until the real proof format is finalised, this path calls the
            // placeholder Groth16Verifier with zero-filled components. The
            // placeholder returns true only on chainid 31337 (Hardhat), preventing
            // accidental use before the real verifier is wired in.
            uint256[2] memory pA;
            uint256[2][2] memory pB;
            uint256[2] memory pC;
            uint256[2] memory pubSignals;

            // PRODUCTION TODO: Replace placeholder component extraction with:
            //   (pA, pB, pC, pubSignals, stfCommitment, programVKey, policyHash,
            //    proverSetDigest) = abi.decode(proof, (...));
            bool ok = Groth16Verifier(verifierAddress).verifyProof(pA, pB, pC, pubSignals);
            if (!ok) revert ProofInvalid();
        }

        valid = true;
    }
}
