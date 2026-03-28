// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title BlobKzgVerifier
 * @notice On-chain verification of KZG proofs for EIP-4844 blob data submitted
 *         alongside ZK proof batches. Uses the point evaluation precompile (0x0A)
 *         to verify that a blob commitment evaluates to a claimed value at a given point.
 *
 * EIP-4844 blob verification flow:
 *   1. Submitter constructs a blob containing proof batch data (off-chain).
 *   2. Submitter sends a type-3 BlobTx with the blob sidecar attached.
 *   3. This contract retrieves the versioned hash via blobhash(index).
 *   4. This contract calls the point evaluation precompile with the KZG proof.
 *   5. If verification passes, the proof batch is accepted.
 *
 * @dev The point evaluation precompile input format (192 bytes total):
 *      versioned_hash (32) || opening_point (32) || claimed_value (32)
 *      || commitment (48) || proof (48)
 */
contract BlobKzgVerifier {
    // Point evaluation precompile — EIP-4844
    address private constant POINT_EVALUATION_PRECOMPILE =
        0x000000000000000000000000000000000000000A;

    uint256 private constant POINT_EVAL_GAS = 50_000;
    uint256 private constant COMMITMENT_LENGTH = 48;
    uint256 private constant PROOF_LENGTH = 48;

    // BLS12-381 field modulus — opening point and claimed value must be below this
    uint256 private constant BLS_MODULUS =
        52435875175126190479447740508185965837690552500527637822603658699938581184513;

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    error BlobHashZero(uint256 index);
    error InvalidCommitmentLength(uint256 provided);
    error InvalidProofLength(uint256 provided);
    error PointOutOfField(uint256 point);
    error ClaimOutOfField(uint256 claim);
    error PointEvaluationFailed(bytes32 versionedHash);
    error BlobBaseFeeExceedsMax(uint256 actual, uint256 maximum);

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    event BlobVerified(
        bytes32 indexed versionedHash,
        bytes32 indexed batchId,
        uint256 blobIndex
    );

    // -------------------------------------------------------------------------
    // External functions
    // -------------------------------------------------------------------------

    /**
     * @notice Verifies that a blob at `blobIndex` in the current transaction matches
     *         the provided KZG commitment and proof.
     *
     * @param blobIndex       Index of the blob in the current transaction's sidecar
     * @param openingPoint    z value: field element at which the polynomial is evaluated
     * @param claimedValue    y value: the claimed evaluation p(z) = y
     * @param commitment      KZG commitment to the blob polynomial (48 bytes)
     * @param proof           KZG proof (48 bytes)
     * @param batchId         Identifier for the proof batch associated with this blob
     * @param maxBlobBaseFee  Maximum blob base fee caller accepts (wei). Reverts if exceeded.
     */
    function verifyBlob(
        uint256 blobIndex,
        bytes32 openingPoint,
        bytes32 claimedValue,
        bytes calldata commitment,
        bytes calldata proof,
        bytes32 batchId,
        uint256 maxBlobBaseFee
    ) external {
        // Blob base fee gate — reject if market has spiked above caller's tolerance
        if (block.blobbasefee > maxBlobBaseFee) {
            revert BlobBaseFeeExceedsMax(block.blobbasefee, maxBlobBaseFee);
        }

        // Cheap input validation before the expensive precompile call
        if (commitment.length != COMMITMENT_LENGTH) {
            revert InvalidCommitmentLength(commitment.length);
        }
        if (proof.length != PROOF_LENGTH) {
            revert InvalidProofLength(proof.length);
        }
        if (uint256(openingPoint) >= BLS_MODULUS) {
            revert PointOutOfField(uint256(openingPoint));
        }
        if (uint256(claimedValue) >= BLS_MODULUS) {
            revert ClaimOutOfField(uint256(claimedValue));
        }

        // Retrieve versioned hash from the blob sidecar
        bytes32 versionedHash = blobhash(blobIndex);
        if (versionedHash == bytes32(0)) {
            revert BlobHashZero(blobIndex);
        }

        // Build the 192-byte precompile input:
        // versioned_hash (32) || opening_point (32) || claimed_value (32)
        // || commitment (48) || proof (48)
        bytes memory input = abi.encodePacked(
            versionedHash,
            openingPoint,
            claimedValue,
            commitment,
            proof
        );

        // Call the point evaluation precompile
        (bool success, ) = POINT_EVALUATION_PRECOMPILE.staticcall{
            gas: POINT_EVAL_GAS
        }(input);

        if (!success) {
            revert PointEvaluationFailed(versionedHash);
        }

        emit BlobVerified(versionedHash, batchId, blobIndex);
    }

    /**
     * @notice Returns the versioned hash for a blob at the given index in the
     *         current transaction. Returns bytes32(0) if index is out of bounds.
     */
    function getBlobHash(uint256 index) external view returns (bytes32) {
        return blobhash(index);
    }

    /**
     * @notice Returns the current blob base fee. Callers can use this to decide
     *         whether to submit a blob transaction now or wait for lower fees.
     */
    function currentBlobBaseFee() external view returns (uint256) {
        return block.blobbasefee;
    }
}
