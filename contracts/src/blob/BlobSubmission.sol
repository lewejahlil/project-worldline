// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IBlobSubmission} from "./IBlobSubmission.sol";
import {BlobVerifier} from "./BlobVerifier.sol";
import {BlobKzgVerifier} from "./BlobKzgVerifier.sol";

/// @title BlobSubmission
/// @notice Implements IBlobSubmission by routing blob verification through either
///         BlobKzgVerifier (full KZG point evaluation) or BlobVerifier (hash-only),
///         depending on whether KZG commitment bytes are provided.
contract BlobSubmission is IBlobSubmission {
    BlobKzgVerifier public immutable kzgVerifier;

    error KzgVerifierZero();

    /// @param _kzgVerifier Address of the deployed BlobKzgVerifier contract.
    constructor(address _kzgVerifier) {
        if (_kzgVerifier == address(0)) revert KzgVerifierZero();
        kzgVerifier = BlobKzgVerifier(_kzgVerifier);
    }

    /// @inheritdoc IBlobSubmission
    function submitZkValidityProofWithBlob(
        bytes calldata,
        bytes calldata,
        bytes32 expectedBlobHash,
        bytes32 blobDataHash
    ) external {
        // Hash-only mode: verify blob hash at index 0 matches expected value
        BlobVerifier.verifyBlobHash(0, expectedBlobHash);

        emit BlobSubmitted(0, expectedBlobHash, blobDataHash);
    }

    /// @notice Submit a ZK validity proof with full KZG point evaluation verification.
    /// @param blobIndex          Index of the blob in the transaction's sidecar.
    /// @param openingPoint       z value for point evaluation.
    /// @param claimedValue       y value: claimed evaluation p(z) = y.
    /// @param commitment         KZG commitment (48 bytes).
    /// @param kzgProof           KZG proof (48 bytes).
    /// @param batchId            Identifier for the proof batch.
    /// @param maxBlobBaseFee     Maximum blob base fee caller accepts (wei).
    /// @param blobDataHash       Hash of blob data payload for indexer reference.
    function submitZkValidityProofWithKzg(
        bytes calldata,
        bytes calldata,
        uint256 blobIndex,
        bytes32 openingPoint,
        bytes32 claimedValue,
        bytes calldata commitment,
        bytes calldata kzgProof,
        bytes32 batchId,
        uint256 maxBlobBaseFee,
        bytes32 blobDataHash
    ) external {
        // Full KZG verification via the point evaluation precompile
        kzgVerifier.verifyBlob(
            blobIndex,
            openingPoint,
            claimedValue,
            commitment,
            kzgProof,
            batchId,
            maxBlobBaseFee
        );

        bytes32 versionedHash = blobhash(blobIndex);
        emit BlobSubmitted(0, versionedHash, blobDataHash);
    }
}
