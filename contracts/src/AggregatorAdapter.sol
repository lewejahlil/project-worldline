/* SPDX-License-Identifier: Apache-2.0 */
pragma solidity ^0.8.24;

import {ExampleVerifier} from "./dev/ExampleVerifier.sol";

contract AggregatorAdapter {
    address public immutable verifier;
    bytes32 public immutable stateRoot;
    bytes32 public immutable proofHash;

    constructor(address _verifier, bytes32 _stateRoot, bytes32 _proofHash) {
        verifier = _verifier;
        stateRoot = _stateRoot;
        proofHash = _proofHash;
    }

    function verify(bytes calldata proof, bytes calldata publicInputs) external view returns (bool) {
        return ExampleVerifier(verifier).verify(proof, publicInputs);
    }
}
