// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BlobVerifier} from "./BlobVerifier.sol";

/// @title BlobVerifierHarness
/// @dev Test harness that exposes BlobVerifier library functions as external calls.
contract BlobVerifierHarness {
    // Re-export errors for test matching
    error BlobHashMismatch(uint256 index, bytes32 expected, bytes32 actual);
    error InvalidVersionedHash(bytes32 hash);
    error NoBlobAtIndex(uint256 index);

    function getBlobHash(uint256 index) external view returns (bytes32) {
        return BlobVerifier.getBlobHash(index);
    }

    function verifyBlobHash(uint256 index, bytes32 expected) external view {
        BlobVerifier.verifyBlobHash(index, expected);
    }

    function validateVersionByte(bytes32 hash) external pure {
        BlobVerifier.validateVersionByte(hash);
    }
}
