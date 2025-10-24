// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract ExampleVerifier {
    function verify(bytes calldata proof, bytes calldata publicInputsRaw)
        external
        pure
        returns (
            bool valid,
            bytes32 stfCommitment,
            bytes32 programVKey,
            bytes32 policyHash,
            bytes32 proverSetDigest
        )
    {
        if (proof.length == 0) {
            return (false, bytes32(0), bytes32(0), bytes32(0), bytes32(0));
        }
        // Echo stfCommitment from the first 32 bytes of RAW 160B inputs.
        // This matches the oracle's ABI layout and avoids fixed-point pitfalls.
        assembly {
            stfCommitment := calldataload(add(publicInputsRaw.offset, 0))
        }
        programVKey = bytes32(uint256(0xA11CE));
        policyHash = bytes32(uint256(0xB0B));
        proverSetDigest = keccak256(abi.encodePacked(uint256(0xCAFE)));
        return (true, stfCommitment, programVKey, policyHash, proverSetDigest);
    }
}
