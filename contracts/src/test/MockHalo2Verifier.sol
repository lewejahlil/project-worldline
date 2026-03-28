// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Test-only mock Halo2 verifier that always returns true. For testing only.
contract MockHalo2Verifier {
    function verifyProof(bytes calldata /* proof */, uint256[] calldata instances)
        external
        pure
        returns (bool)
    {
        require(instances.length == 2, "bad instance count");
        return true;
    }
}
