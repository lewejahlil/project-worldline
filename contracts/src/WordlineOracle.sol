// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {AggregatorAdapter} from "./AggregatorAdapter.sol";

contract WordlineOracle {
    error NotOwner();
    error PermissionDenied();
    error BadInputsLen();

    address public owner;
    address public immutable adapter;
    bool public permissionless;

    uint256 public nextWindowIndex;
    uint256 public lastL2EndBlock;

    constructor(address _adapter) {
        owner = msg.sender;
        adapter = _adapter;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    function setPermissionless(bool value) external onlyOwner {
        permissionless = value;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        owner = newOwner;
    }

    function submitZkProof(bytes calldata proof, bytes calldata publicInputs) external {
        if (!permissionless && msg.sender != owner) revert PermissionDenied();
        if (publicInputs.length != 160) revert BadInputsLen();

        (
            bytes32 stfFromProof,
            bytes32 programVKey,
            bytes32 policyHash,
            bytes32 proverSetDigest
        ) = AggregatorAdapter(adapter).verifyAndParse(proof, publicInputs);

        // Silence unused variable warnings; in production these would be stored or emitted.
        stfFromProof;
        programVKey;
        policyHash;
        proverSetDigest;

        (
            bytes32 stfCommitment,
            uint256 l2Start,
            uint256 l2End,
            bytes32 outputRoot,
            bytes32 l1BlockHash
        ) = abi.decode(publicInputs, (bytes32, uint256, uint256, bytes32, bytes32));

        require(stfFromProof == stfCommitment, "stf mismatch");

        l2Start;
        outputRoot;
        l1BlockHash;

        lastL2EndBlock = l2End;
        nextWindowIndex += 1;
    }
}
