// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Test-only mock that always returns true for verifyProof.
contract MockGroth16Verifier {
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[2] calldata
    ) external pure returns (bool) {
        return true;
    }
}
