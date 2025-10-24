// SPDX-License-Identifier: MIT-0
pragma solidity ^0.8.24;

contract ExampleVerifier {
    function verify(bytes calldata proof, bytes calldata) external pure returns (bool) {
        return proof.length > 0;
    }
}
