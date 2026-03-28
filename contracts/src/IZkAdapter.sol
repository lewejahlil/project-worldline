// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IZkAdapter
/// @notice Lightweight interface that all ZK proof-system adapters must implement.
///         Used by ProofRouter to dispatch proofs to the correct verifier based on
///         the proof system ID reported by each adapter.
///
/// @dev Adapters that integrate with WorldlineFinalizer via the aggregated route must
///      ALSO implement IZkAggregatorVerifier (which returns the full verification tuple).
///      IZkAdapter serves as the registration and thin-routing interface.
interface IZkAdapter {
    /// @notice Verify a ZK proof against pre-decoded public inputs.
    /// @param proof        Encoded proof bytes (adapter-specific format).
    /// @param publicInputs Pre-decoded public input words.
    /// @return valid       Whether the proof is cryptographically valid.
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool valid);

    /// @notice The numeric identifier of the proof system implemented by this adapter.
    ///         Must match the ID supplied when registering with ProofRouter.
    ///         Convention: 1 = Groth16, 2 = Plonk, 3 = Halo2.
    ///         Declared view (not pure) so implementations may read immutable storage.
    function proofSystemId() external view returns (uint8);

    /// @notice Minimum byte length a valid proof must have for this adapter.
    ///         Used by ProofRouter for early length validation.
    ///         Declared view (not pure) so implementations may read immutable storage.
    function expectedProofLength() external view returns (uint256);
}
