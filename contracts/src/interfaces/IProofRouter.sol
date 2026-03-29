// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IProofRouter
/// @notice Minimal interface for interacting with ProofRouter from WorldlineFinalizer.
///         Only exposes the aggregated routing path used by the finalizer.
interface IProofRouter {
    /// @notice Rich aggregated routing path. Forwards the proof to the registered adapter
    ///         and returns the full verification tuple consumed by WorldlineFinalizer.
    /// @param proofSystemId  Proof system to route to (1=Groth16, 2=Plonk, 3=Halo2).
    /// @param proof          Encoded proof bytes.
    /// @param publicInputs   256-byte ABI-encoded public inputs (8 words).
    function routeProofAggregated(
        uint8 proofSystemId,
        bytes calldata proof,
        bytes calldata publicInputs
    )
        external
        returns (
            bool valid,
            bytes32 stfCommitment,
            bytes32 programVKey,
            bytes32 policyHash,
            bytes32 proverSetDigest
        );

    /// @notice Return true if an adapter is registered for the given proof system ID.
    function isSupported(uint8 proofSystemId) external view returns (bool);
}
