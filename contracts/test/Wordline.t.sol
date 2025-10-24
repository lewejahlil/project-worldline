// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {WordlineOracle} from "../src/WordlineOracle.sol";
import {AggregatorAdapter} from "../src/AggregatorAdapter.sol";
import {ExampleVerifier} from "../src/dev/ExampleVerifier.sol";

interface Vm {
    function prank(address) external;
    function expectRevert(bytes4) external;
}

contract WordlineTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    WordlineOracle public oracle;
    AggregatorAdapter public adapter;
    ExampleVerifier public verifier;

    constructor() {
        verifier = new ExampleVerifier();
        adapter = new AggregatorAdapter(
            address(verifier),
            bytes32(uint256(0xA11CE)),
            bytes32(uint256(0xB0B))
        );
        oracle = new WordlineOracle(address(adapter));
    }

    function _pack(
        bytes32 stf,
        uint256 s,
        uint256 e,
        bytes32 out,
        bytes32 h
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(stf, s, e, out, h);
    }

    function assertEq(uint256 a, uint256 b) internal pure {
        require(a == b, "not equal");
    }

    function test_submit_proof_permissionless_first_valid() public {
        oracle.setPermissionless(true);
        bytes memory proof = "proof";
        bytes memory inputs = _pack(
            bytes32(uint256(0xDEAD)),
            1,
            10,
            bytes32(uint256(0x1234)),
            bytes32(uint256(0x5555))
        );
        vm.prank(address(0xBEEF));
        oracle.submitZkProof(proof, inputs);
        assertEq(oracle.nextWindowIndex(), 1);
        assertEq(oracle.lastL2EndBlock(), 10);
    }

    function test_reject_wrong_length() public {
        bytes memory dummy = "p";
        vm.expectRevert(WordlineOracle.BadInputsLen.selector);
        oracle.submitZkProof(dummy, hex"00");
    }
}
