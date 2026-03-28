// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IZkAggregatorVerifier
/// @notice Adapter interface for pluggable ZK proof verification strategies.
///         Each adapter implementation pins a specific proof system (e.g. Groth16/BN254)
///         and returns structured verification results.
interface IZkAggregatorVerifier {
    /// @notice Verify a ZK proof and extract the four canonical public signals.
    /// @param proof      The encoded proof bytes (format depends on the adapter).
    /// @param publicInputs The 224-byte ABI-encoded public inputs.
    /// @return valid          Whether the proof is valid.
    /// @return stfCommitment  Keccak of the seven ABI words binding the STF output.
    /// @return programVKey    The verifying key identifying the STF program.
    /// @return policyHash     Hash of the canonical policy JSON.
    /// @return proverSetDigest Keccak of the canonical manifest JSON.
    function verify(
        bytes calldata proof,
        bytes calldata publicInputs
    )
        external
        view
        returns (
            bool valid,
            bytes32 stfCommitment,
            bytes32 programVKey,
            bytes32 policyHash,
            bytes32 proverSetDigest
        );
}
