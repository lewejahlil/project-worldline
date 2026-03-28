// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Test-only mock that always returns true for verifyProof. For testing only.
contract MockPlonkVerifier {
    function verifyProof(uint256[24] calldata /* _proof */, uint256[2] calldata /* _pubSignals */)
        external
        pure
        returns (bool)
    {
        return true;
    }
}
