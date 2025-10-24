// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {IAggregatorVerifier} from "./interfaces/IAggregatorVerifier.sol";

contract AggregatorAdapter {
    error VerifyFailed();

    address public immutable verifier;
    bytes32 public immutable programVKey;
    bytes32 public immutable policyHash;

    constructor(address _verifier, bytes32 _programVKey, bytes32 _policyHash) {
        verifier = _verifier;
        programVKey = _programVKey;
        policyHash = _policyHash;
    }

    function verifyAndParse(
        bytes calldata proof,
        bytes calldata publicInputsRaw
    )
        external
        view
        returns (
            bytes32 stfCommitment,
            bytes32 _programVKey,
            bytes32 _policyHash,
            bytes32 proverSetDigest
        )
    {
        (
            bool ok,
            bytes32 commit,
            bytes32 vk,
            bytes32 pol,
            bytes32 provSet
        ) = IAggregatorVerifier(verifier).verify(proof, publicInputsRaw);

        if (!ok || vk != programVKey || pol != policyHash) {
            revert VerifyFailed();
        }
        return (commit, vk, pol, provSet);
    }
}
