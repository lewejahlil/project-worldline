// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

interface IAggregatorVerifier {
    function verify(
        bytes calldata proof,
        bytes calldata publicInputsRaw
    )
        external
        view
        returns (
            bool valid,
            bytes32 stfCommitment,
            bytes32 programVKey,
            bytes32 policyHash,
            bytes32 proverSetDigest
        );
}
