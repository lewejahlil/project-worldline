// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IBlobSubmission
/// @notice Interface for EIP-4844 blob-carrying proof submissions.
///         Extends the standard submission path with blob hash verification.
interface IBlobSubmission {
    /// @notice Emitted when a blob-carrying proof is submitted.
    /// @param windowIndex    The sequential window index.
    /// @param blobHash       The versioned hash of the blob at index 0.
    /// @param blobDataHash   Caller-supplied hash of the blob data payload.
    event BlobSubmitted(
        uint256 indexed windowIndex,
        bytes32 blobHash,
        bytes32 blobDataHash
    );

    /// @notice Submit a ZK validity proof carried in an EIP-4844 blob transaction.
    /// @param proof              Encoded proof bytes.
    /// @param publicInputs       224-byte ABI-encoded public inputs.
    /// @param expectedBlobHash   Expected versioned hash of blob at index 0.
    /// @param blobDataHash       Hash of the actual blob data payload (for indexer reference).
    function submitZkValidityProofWithBlob(
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 expectedBlobHash,
        bytes32 blobDataHash
    ) external;
}
