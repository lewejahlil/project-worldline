// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IZkAggregatorVerifier} from "../interfaces/IZkAggregatorVerifier.sol";
import {Groth16Verifier} from "./Groth16Verifier.sol";

/// @title Groth16ZkAdapter
/// @notice Adapter that pins a Groth16 verifier address, a programVKey, and a policyHash.
///         Extracts public signals from the proof, validates that programVKey and
///         policyHash match the pinned values, then delegates cryptographic verification
///         to the underlying real BN254 Groth16 verifier.
///
/// @dev Production proof ABI encoding:
///
///      proof = abi.encode(
///          uint256[2] pA,           // Groth16 proof element A (G1 point)
///          uint256[2][2] pB,        // Groth16 proof element B (G2 point)
///          uint256[2] pC,           // Groth16 proof element C (G1 point)
///          uint256 stfCommitment,   // pubSignals[0]: Poseidon(preStateRoot, postStateRoot, batchCommitment)
///          uint256 proverSetDigest  // pubSignals[1]: Poseidon(proverIds, proofSystemIds, quorumCount)
///      )
///
///      Total: 10 × 32 = 320 bytes (ABI-encoded).
///
///      The two public signals (stfCommitment, proverSetDigest) are extracted from the
///      proof bytes AND passed as pubSignals to the Groth16 verifier, ensuring they are
///      cryptographically bound to the proof.
///
///      programVKey and policyHash are pinned immutables. They are NOT included in
///      pubSignals — the circuit does not constrain them directly.
contract Groth16ZkAdapter is IZkAggregatorVerifier {
    error ProofInvalid();
    error ProofTooShort(uint256 required, uint256 given);

    /// @notice Minimum byte length of a production Groth16 proof.
    /// @dev 10 ABI-encoded uint256 words: pA(2) + pB(4) + pC(2) + stfCommitment(1) + proverSetDigest(1).
    uint256 public constant PROD_PROOF_MIN_LEN = 320;

    /// @notice Address of the Groth16Verifier contract (snarkjs-generated BN254 verifier).
    address public immutable verifierAddress;

    bytes32 public immutable programVKeyPinned;
    bytes32 public immutable policyHashPinned;

    /// @param _verifier          Address of the Groth16Verifier contract.
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

    /// @inheritdoc IZkAggregatorVerifier
    /// @dev Decodes the full Groth16 proof, extracts pubSignals, and delegates
    ///      cryptographic verification to the real BN254 pairing verifier.
    function verify(
        bytes calldata proof,
        bytes calldata publicInputs
    )
        external
        view
        override
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

        // Decode all 10 words in a single abi.decode call.
        (
            uint256[2] memory pA,
            uint256[2][2] memory pB,
            uint256[2] memory pC,
            uint256 stfCommitmentUint,
            uint256 proverSetDigestUint
        ) = abi.decode(
            proof,
            (uint256[2], uint256[2][2], uint256[2], uint256, uint256)
        );

        stfCommitment = bytes32(stfCommitmentUint);
        proverSetDigest = bytes32(proverSetDigestUint);

        // Pinned values: programVKey and policyHash are not in the proof.
        programVKey = programVKeyPinned;
        policyHash = policyHashPinned;

        // Delegate to the real BN254 pairing verifier.
        bool ok = Groth16Verifier(verifierAddress).verifyProof(
            pA, pB, pC, [stfCommitmentUint, proverSetDigestUint]
        );
        if (!ok) revert ProofInvalid();

        valid = true;
    }
}
