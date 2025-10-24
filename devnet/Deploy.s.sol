// SPDX-License-Identifier: MIT-0
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "forge-std/console2.sol";
import {ExampleVerifier} from "../contracts/src/dev/ExampleVerifier.sol";
import {AggregatorAdapter} from "../contracts/src/AggregatorAdapter.sol";
import {WordlineOracle} from "../contracts/src/WordlineOracle.sol";

contract Deploy is Script {
    function run() external {
        vm.startBroadcast();
        ExampleVerifier v = new ExampleVerifier();
        AggregatorAdapter adapter = new AggregatorAdapter(
            address(v),
            bytes32(uint256(0xA11CE)),
            bytes32(uint256(0xB0B))
        );
        WordlineOracle oracle = new WordlineOracle(address(adapter), 5);
        vm.stopBroadcast();

        console2.log("verifier", address(v));
        console2.log("adapter", address(adapter));
        console2.log("oracle", address(oracle));
    }
}
