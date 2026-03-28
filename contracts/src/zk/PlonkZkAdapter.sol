// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IZkAggregatorVerifier} from "../interfaces/IZkAggregatorVerifier.sol";
import {IZkAdapter} from "../IZkAdapter.sol";
import {PlonkVerifier} from "../PlonkVerifier.sol";

/// @title PlonkZkAdapter
/// @notice Adapter that wraps the snarkjs-generated Plonk verifier.
///         Implements IZkAdapter (thin path) and IZkAggregatorVerifier (rich path).
///
/// @dev Plonk proof ABI encoding:
///
///      proof = abi.encode(uint256[24] _proof, uint256 stfCommitment, uint256 proverSetDigest)
///
///      The first 768 bytes are the 24-word Plonk proof passed to PlonkVerifier.verifyProof().
///      The last 64 bytes encode stfCommitment and proverSetDigest as uint256 words.
///
///      Total: 24*32 + 32 + 32 = 832 bytes.
///
///      PlonkVerifier.verifyProof takes:
///        _proof: uint256[24]     — the 24-word Plonk proof
///        _pubSignals: uint256[2] — [stfCommitment, proverSetDigest]
contract PlonkZkAdapter is IZkAggregatorVerifier, IZkAdapter {
    error ProofInvalid();
    error ProofTooShort(uint256 required, uint256 given);

    /// @notice Byte length: uint256[24] proof + uint256 stfCommitment + uint256 proverSetDigest.
    uint256 public constant PROD_PROOF_MIN_LEN = 832; // 24*32 + 32 + 32

    /// @notice Address of the PlonkVerifier contract (snarkjs-generated BN254 verifier).
    address public immutable verifierAddress;

    bytes32 public immutable programVKeyPinned;
    bytes32 public immutable policyHashPinned;

    /// @param _verifier          Address of the PlonkVerifier contract.
    /// @param _programVKeyPinned The pinned program verifying key.
    /// @param _policyHashPinned  The pinned policy hash.
    constructor(address _verifier, bytes32 _programVKeyPinned, bytes32 _policyHashPinned) {
        verifierAddress = _verifier;
        programVKeyPinned = _programVKeyPinned;
        policyHashPinned = _policyHashPinned;
    }

    // ── IZkAdapter implementation ────────────────────────────────────────────

    /// @inheritdoc IZkAdapter
    function proofSystemId() external pure override(IZkAdapter) returns (uint8) {
        return 2; // Plonk
    }

    /// @inheritdoc IZkAdapter
    function expectedProofLength() external pure override(IZkAdapter) returns (uint256) {
        return PROD_PROOF_MIN_LEN;
    }

    /// @inheritdoc IZkAdapter
    /// @dev Thin verify overload for IZkAdapter compatibility (takes bytes32[] public inputs).
    ///      Delegates to the same Plonk pairing verifier as the aggregated path.
    ///      The publicInputs array is unused by the Plonk adapter — signals are
    ///      embedded in the proof bytes per the production encoding.
    function verify(
        bytes calldata proof,
        bytes32[] calldata /* publicInputs */
    ) external view override(IZkAdapter) returns (bool valid) {
        if (proof.length < PROD_PROOF_MIN_LEN) {
            revert ProofTooShort(PROD_PROOF_MIN_LEN, proof.length);
        }

        (uint256[24] memory _proof, uint256 stfCommitmentUint, uint256 proverSetDigestUint) =
            abi.decode(proof, (uint256[24], uint256, uint256));

        uint256[2] memory pubSignals;
        pubSignals[0] = stfCommitmentUint;
        pubSignals[1] = proverSetDigestUint;

        valid = PlonkVerifier(verifierAddress).verifyProof(_proof, pubSignals);
    }

    // ── IZkAggregatorVerifier implementation ─────────────────────────────────

    /// @inheritdoc IZkAggregatorVerifier
    /// @dev Decodes the full Plonk proof, extracts pubSignals, and delegates
    ///      cryptographic verification to the real BN254 pairing verifier.
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
        // Suppress unused parameter warning — publicInputs reserved for future use.
        publicInputs;

        // Cheap length check before any decoding.
        if (proof.length < PROD_PROOF_MIN_LEN) {
            revert ProofTooShort(PROD_PROOF_MIN_LEN, proof.length);
        }

        (uint256[24] memory _proof, uint256 stfCommitmentUint, uint256 proverSetDigestUint) =
            abi.decode(proof, (uint256[24], uint256, uint256));

        stfCommitment = bytes32(stfCommitmentUint);
        proverSetDigest = bytes32(proverSetDigestUint);

        // Pinned values: programVKey and policyHash are not in the proof.
        programVKey = programVKeyPinned;
        policyHash = policyHashPinned;

        uint256[2] memory pubSignals;
        pubSignals[0] = stfCommitmentUint;
        pubSignals[1] = proverSetDigestUint;

        bool ok = PlonkVerifier(verifierAddress).verifyProof(_proof, pubSignals);
        if (!ok) revert ProofInvalid();

        valid = true;
    }
}
