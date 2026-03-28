// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title BlobVerifier
/// @notice Utility library for EIP-4844 blob hash verification.
///         Provides helpers to read `blobhash(index)` and verify versioned hashes
///         against caller-supplied expected values.
/// @dev Requires Solidity 0.8.24+ and evmVersion "cancun" for native blobhash() support.
library BlobVerifier {
    /// @dev EIP-4844 versioned hash version byte (SHA-256 truncated).
    uint8 internal constant VERSIONED_HASH_VERSION = 0x01;

    error BlobHashMismatch(uint256 index, bytes32 expected, bytes32 actual);
    error InvalidVersionedHash(bytes32 hash);
    error NoBlobAtIndex(uint256 index);

    /// @notice Read the versioned hash of the blob at `index` in the current transaction.
    /// @param index Blob index (0-based).
    /// @return hash The versioned hash, or bytes32(0) if no blob exists at that index.
    function getBlobHash(uint256 index) internal view returns (bytes32) {
        return blobhash(index);
    }

    /// @notice Verify that the blob at `index` has the expected versioned hash.
    /// @param index    Blob index (0-based).
    /// @param expected The expected versioned hash.
    function verifyBlobHash(uint256 index, bytes32 expected) internal view {
        bytes32 actual = getBlobHash(index);
        if (actual == bytes32(0)) revert NoBlobAtIndex(index);
        if (actual != expected) revert BlobHashMismatch(index, expected, actual);
    }

    /// @notice Check that a versioned hash has the correct version byte (0x01).
    /// @param hash The versioned hash to validate.
    function validateVersionByte(bytes32 hash) internal pure {
        if (uint8(uint256(hash) >> 248) != VERSIONED_HASH_VERSION) {
            revert InvalidVersionedHash(hash);
        }
    }
}
