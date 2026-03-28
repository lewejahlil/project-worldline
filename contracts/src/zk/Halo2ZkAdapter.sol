// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IZkAggregatorVerifier} from "../interfaces/IZkAggregatorVerifier.sol";
import {IZkAdapter} from "../IZkAdapter.sol";
import {Halo2Verifier} from "./Halo2Verifier.sol";

/// @title Halo2ZkAdapter
/// @notice Adapter that pins a Halo2 KZG verifier address, a programVKey, and a policyHash.
///         Extracts public instances from the proof envelope, validates structure,
///         then delegates cryptographic verification to the underlying Halo2Verifier.
///
/// @dev Halo2 proof envelope ABI encoding (adapter-specific format):
///
///      proof = abi.encode(
///          bytes   proofBytes,         // Raw Halo2 KZG proof (variable length, ~1472 bytes)
///          uint256 stfCommitment,      // Public instance[0]
///          uint256 proverSetDigest     // Public instance[1]
///      )
///
///      The two public instances are extracted from the envelope and passed to the
///      Halo2Verifier alongside the raw proof bytes. This mirrors the Groth16 adapter
///      pattern where public signals are embedded in the proof envelope.
///
///      programVKey and policyHash are pinned immutables (not in the proof).
contract Halo2ZkAdapter is IZkAggregatorVerifier, IZkAdapter {
    error ProofInvalid();
    error ProofTooShort(uint256 required, uint256 given);

    /// @notice Minimum byte length of a Halo2 proof envelope.
    /// @dev Raw proof (~1472 bytes) + 2 × 32 bytes for stfCommitment and proverSetDigest.
    ///      ABI encoding overhead: offset(32) + length(32) + proof(1472 padded to 1504) + 2*32 = 1600.
    ///      We use a conservative minimum that accounts for ABI encoding overhead.
    uint256 public constant HALO2_PROOF_MIN_LEN = 1600;

    /// @notice Address of the Halo2Verifier contract.
    address public immutable verifierAddress;

    bytes32 public immutable programVKeyPinned;
    bytes32 public immutable policyHashPinned;

    /// @param _verifier          Address of the Halo2Verifier contract.
    /// @param _programVKeyPinned The pinned program verifying key.
    /// @param _policyHashPinned  The pinned policy hash.
    constructor(
        address _verifier,
        bytes32 _programVKeyPinned,
        bytes32 _policyHashPinned
    ) {
        verifierAddress = _verifier;
        programVKeyPinned = _programVKeyPinned;
        policyHashPinned = _policyHashPinned;
    }

    // ── IZkAdapter implementation ────────────────────────────────────────────

    /// @inheritdoc IZkAdapter
    function proofSystemId() external pure override(IZkAdapter) returns (uint8) {
        return 3; // Halo2
    }

    /// @inheritdoc IZkAdapter
    function expectedProofLength() external pure override(IZkAdapter) returns (uint256) {
        return HALO2_PROOF_MIN_LEN;
    }

    /// @inheritdoc IZkAdapter
    function verify(
        bytes calldata proof,
        bytes32[] calldata /* publicInputs */
    ) external view override(IZkAdapter) returns (bool valid) {
        if (proof.length < HALO2_PROOF_MIN_LEN) {
            revert ProofTooShort(HALO2_PROOF_MIN_LEN, proof.length);
        }

        (
            bytes memory proofBytes,
            uint256 stfCommitmentUint,
            uint256 proverSetDigestUint
        ) = abi.decode(proof, (bytes, uint256, uint256));

        uint256[] memory instances = new uint256[](2);
        instances[0] = stfCommitmentUint;
        instances[1] = proverSetDigestUint;

        valid = Halo2Verifier(verifierAddress).verifyProof(proofBytes, instances);
    }

    // ── IZkAggregatorVerifier implementation ─────────────────────────────────

    /// @inheritdoc IZkAggregatorVerifier
    function verify(
        bytes calldata proof,
        bytes calldata publicInputs
    )
        external
        view
        override(IZkAggregatorVerifier)
        returns (
            bool valid,
            bytes32 stfCommitment,
            bytes32 programVKey,
            bytes32 policyHash,
            bytes32 proverSetDigest
        )
    {
        // Suppress unused parameter warning
        publicInputs;

        if (proof.length < HALO2_PROOF_MIN_LEN) {
            revert ProofTooShort(HALO2_PROOF_MIN_LEN, proof.length);
        }

        (
            bytes memory proofBytes,
            uint256 stfCommitmentUint,
            uint256 proverSetDigestUint
        ) = abi.decode(proof, (bytes, uint256, uint256));

        stfCommitment = bytes32(stfCommitmentUint);
        proverSetDigest = bytes32(proverSetDigestUint);

        // Pinned values
        programVKey = programVKeyPinned;
        policyHash = policyHashPinned;

        // Construct instances array for the verifier
        uint256[] memory instances = new uint256[](2);
        instances[0] = stfCommitmentUint;
        instances[1] = proverSetDigestUint;

        bool ok = Halo2Verifier(verifierAddress).verifyProof(proofBytes, instances);
        if (!ok) revert ProofInvalid();

        valid = true;
    }
}
