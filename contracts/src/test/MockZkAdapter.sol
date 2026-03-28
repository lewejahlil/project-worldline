// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IZkAdapter} from "../IZkAdapter.sol";
import {IZkAggregatorVerifier} from "../interfaces/IZkAggregatorVerifier.sol";

/// @notice Test-only mock ZK adapter that implements both IZkAdapter and IZkAggregatorVerifier.
///         Always returns true and echoes back the stfCommitment from the first 32 bytes of proof
///         (for use with the finalizer's StfMismatch check).
contract MockZkAdapter is IZkAdapter, IZkAggregatorVerifier {
    uint8 private immutable _psId;
    bytes32 public immutable programVKeyPinned;
    bytes32 public immutable policyHashPinned;

    constructor(uint8 psId, bytes32 _programVKey, bytes32 _policyHash) {
        _psId = psId;
        programVKeyPinned = _programVKey;
        policyHashPinned = _policyHash;
    }

    // ── IZkAdapter ────────────────────────────────────────────────────────────

    function proofSystemId() external view override(IZkAdapter) returns (uint8) {
        return _psId;
    }

    function expectedProofLength() external pure override(IZkAdapter) returns (uint256) {
        return 0;
    }

    function verify(
        bytes calldata,
        bytes32[] calldata
    ) external pure override(IZkAdapter) returns (bool) {
        return true;
    }

    // ── IZkAggregatorVerifier ─────────────────────────────────────────────────

    /// @dev Extracts stfCommitment from the first 32 bytes of proof so the finalizer's
    ///      StfMismatch check passes (the finalizer compares this against the publicInputs-derived
    ///      stfCommitment, which the caller has placed at proof[0:32]).
    function verify(
        bytes calldata proof,
        bytes calldata
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
        valid = true;
        // Echo back the stfCommitment embedded in the proof for the finalizer's StfMismatch check.
        // For a real 320-byte Groth16 proof the stfCommitment is at offset 8*32 = 256 (after pA, pB, pC).
        // For our mock we decode as (uint256[2], uint256[2][2], uint256[2], uint256, uint256) if >= 320 bytes,
        // otherwise we just use the first 32 bytes.
        if (proof.length >= 320) {
            (,,,uint256 stfUint,) = abi.decode(proof, (uint256[2], uint256[2][2], uint256[2], uint256, uint256));
            stfCommitment = bytes32(stfUint);
        } else if (proof.length >= 32) {
            stfCommitment = abi.decode(proof[:32], (bytes32));
        }
        programVKey = programVKeyPinned;
        policyHash = policyHashPinned;
        proverSetDigest = keccak256(abi.encodePacked("mock-prover-set-digest", _psId));
    }
}
