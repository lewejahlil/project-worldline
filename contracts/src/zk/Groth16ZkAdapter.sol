// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IZkAggregatorVerifier} from "../interfaces/IZkAggregatorVerifier.sol";
import {Verifier} from "./Verifier.sol";
import {Groth16Verifier} from "./Groth16Verifier.sol";

/// @title Groth16ZkAdapter
/// @notice Adapter that pins a Groth16 verifier address, a programVKey, and a policyHash.
///         Extracts public signals from the proof, validates that programVKey and
///         policyHash match the pinned values, then delegates cryptographic verification
///         to the underlying verifier.
///
/// @dev Production proof ABI encoding (PRODUCTION IMPLEMENTED — CRI-003 remediation):
///
///      proof = abi.encode(
///          uint256[2] pA,           // Groth16 proof element A (G1 point)
///          uint256[2][2] pB,        // Groth16 proof element B (G2 point)
///          uint256[2] pC,           // Groth16 proof element C (G1 point)
///          uint256 stfCommitment,   // pubSignals[0]: keccak of 7 ABI words
///          uint256 proverSetDigest  // pubSignals[1]: keccak of canonical manifest
///      )
///
///      Total: 10 × 32 = 320 bytes (ABI-encoded).
///
///      The two public signals (stfCommitment, proverSetDigest) are extracted from the
///      proof bytes AND passed as pubSignals to the Groth16 verifier, ensuring they are
///      cryptographically bound to the proof.
///
///      programVKey and policyHash are pinned immutables. They are NOT included in
///      pubSignals — the circuit does not constrain them directly.
///      // TODO(circuit-team): If the outer circuit adds programVKey and policyHash as
///      // public inputs, update pubSignals to [stfCommitment, proverSetDigest,
///      // programVKey, policyHash] and adjust PROD_PROOF_MIN_LEN accordingly.
///
/// @dev DEV MODE (IS_DEV_MODE=true): Skips full Groth16 verification for the 224-byte
///      Finalizer path. Only calls the demo Verifier for the 64-byte test path.
///      Always deploy with isDev=false on non-Hardhat networks.
contract Groth16ZkAdapter is IZkAggregatorVerifier {
    error ProgramVKeyMismatch();
    error PolicyHashMismatch();
    error ProofInvalid();
    error ProofTooShort(uint256 required, uint256 given);

    /// @notice Minimum byte length of a production Groth16 proof.
    /// @dev 10 ABI-encoded uint256 words: pA(2) + pB(4) + pC(2) + stfCommitment(1) + proverSetDigest(1).
    uint256 public constant PROD_PROOF_MIN_LEN = 320;

    /// @notice True when running in development/test mode.
    /// @dev Always deploy with isDev=false on non-Hardhat networks.
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
    /// @dev In dev mode the 64-byte path calls the demo Verifier; the 224-byte Finalizer
    ///      path skips cryptographic verification. In production mode, the full Groth16
    ///      proof is decoded and verified with pubSignals cryptographically bound to the proof.
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
        if (IS_DEV_MODE) {
            // ── Dev mode ──────────────────────────────────────────────────────────
            // Decode the four public signals from the proof payload (dev layout).
            (stfCommitment, programVKey, policyHash, proverSetDigest) = abi.decode(
                proof,
                (bytes32, bytes32, bytes32, bytes32)
            );

            // Enforce pinned values.
            if (programVKey != programVKeyPinned) revert ProgramVKeyMismatch();
            if (policyHash != policyHashPinned) revert PolicyHashMismatch();

            if (publicInputs.length == 64) {
                // 64-byte path: call the demo Verifier (SquareHash circuit).
                (uint256 secret, uint256 publicHash) = abi.decode(
                    publicInputs,
                    (uint256, uint256)
                );
                Verifier(verifierAddress).verifyProof(secret, publicHash);
            }
        } else {
            // ── Production mode: full Groth16 verification ────────────────────────
            // PRODUCTION IMPLEMENTED (CRI-003 remediation).
            //
            // Decode the production proof layout:
            //   (pA[2], pB[2][2], pC[2], stfCommitment, proverSetDigest)
            if (proof.length < PROD_PROOF_MIN_LEN) {
                revert ProofTooShort(PROD_PROOF_MIN_LEN, proof.length);
            }

            uint256[2] memory pA;
            uint256[2][2] memory pB;
            uint256[2] memory pC;
            uint256 stfCommitmentUint;
            uint256 proverSetDigestUint;

            (pA, pB, pC, stfCommitmentUint, proverSetDigestUint) = abi.decode(
                proof,
                (uint256[2], uint256[2][2], uint256[2], uint256, uint256)
            );

            stfCommitment = bytes32(stfCommitmentUint);
            proverSetDigest = bytes32(proverSetDigestUint);

            // Pinned values: programVKey and policyHash are not in the proof.
            programVKey = programVKeyPinned;
            policyHash = policyHashPinned;

            // Construct pubSignals from the decoded values so they are
            // cryptographically bound to the Groth16 proof.
            uint256[2] memory pubSignals;
            pubSignals[0] = stfCommitmentUint;
            pubSignals[1] = proverSetDigestUint;

            bool ok = Groth16Verifier(verifierAddress).verifyProof(pA, pB, pC, pubSignals);
            if (!ok) revert ProofInvalid();
        }

        valid = true;
    }
}
