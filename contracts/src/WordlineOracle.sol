/* SPDX-License-Identifier: Apache-2.0 */
pragma solidity ^0.8.24;

import {AggregatorAdapter} from "./AggregatorAdapter.sol";

contract WordlineOracle {
    AggregatorAdapter public immutable adapter;
    uint256 public immutable maxPending;

    event ProofSubmitted(address indexed caller, bytes32 inputsHash);

    constructor(address adapter_, uint256 maxPending_) {
        adapter = AggregatorAdapter(adapter_);
        maxPending = maxPending_;
    }

    function submitZkProof(bytes calldata proof, bytes calldata publicInputs) external {
        bool ok = adapter.verify(proof, publicInputs);
        require(ok, "verify failed");
        emit ProofSubmitted(msg.sender, keccak256(publicInputs));
    }
}
