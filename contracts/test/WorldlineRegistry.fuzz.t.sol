// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/WorldlineRegistry.sol";
import "../src/zk/Verifier.sol";

/// @title WorldlineRegistry Fuzz Tests
/// @notice Property-based tests for the WorldlineRegistry contract.
contract WorldlineRegistryFuzzTest is Test {
    WorldlineRegistry registry;
    Verifier verifier;

    function setUp() public {
        verifier = new Verifier();
        registry = new WorldlineRegistry(address(verifier));
    }

    /// @notice Any non-zero circuit ID with a description can be registered exactly once.
    function testFuzz_registerCircuit(bytes32 id, string calldata desc) public {
        vm.assume(id != bytes32(0));
        vm.assume(bytes(desc).length > 0);

        registry.registerCircuit(id, desc, address(0), "");

        // Second registration should revert
        vm.expectRevert(WorldlineRegistry.CircuitExists.selector);
        registry.registerCircuit(id, desc, address(0), "");
    }

    /// @notice getCircuit returns the exact metadata that was registered.
    function testFuzz_getCircuitRoundtrip(bytes32 id, string calldata desc, string calldata uri) public {
        vm.assume(id != bytes32(0));
        vm.assume(bytes(desc).length > 0);

        registry.registerCircuit(id, desc, address(verifier), uri);

        WorldlineRegistry.Circuit memory c = registry.getCircuit(id);
        assertEq(c.id, id);
        assertEq(c.description, desc);
        assertEq(c.verifier, address(verifier));
        assertEq(c.abiURI, uri);
    }

    /// @notice Verifier accepts any (secret, secret²) pair that doesn't overflow.
    function testFuzz_verifyProof(uint128 secret) public {
        uint256 s = uint256(secret);
        uint256 h = s * s;

        bytes32 cid = bytes32(uint256(1));
        registry.registerCircuit(cid, "fuzz", address(0), "");

        bool result = registry.verify(cid, s, h);
        assertTrue(result);
    }

    /// @notice Verifier rejects mismatched pairs.
    function testFuzz_verifyProofRejects(uint128 secret, uint256 wrongHash) public {
        uint256 s = uint256(secret);
        uint256 correctHash = s * s;
        vm.assume(wrongHash != correctHash);

        bytes32 cid = bytes32(uint256(2));
        registry.registerCircuit(cid, "fuzz-reject", address(0), "");

        vm.expectRevert(Verifier.InvalidProof.selector);
        registry.verify(cid, s, wrongHash);
    }

    /// @notice Registering a driver with any non-zero ID succeeds once.
    function testFuzz_registerDriver(bytes32 id, string calldata version, string calldata endpoint) public {
        vm.assume(id != bytes32(0));
        vm.assume(bytes(version).length > 0);

        registry.registerDriver(id, version, endpoint);

        vm.expectRevert(WorldlineRegistry.DriverExists.selector);
        registry.registerDriver(id, version, endpoint);
    }
}
