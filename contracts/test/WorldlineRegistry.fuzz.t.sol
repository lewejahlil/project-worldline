// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/WorldlineRegistry.sol";

/// @title WorldlineRegistry Fuzz Tests
/// @notice Property-based tests for the WorldlineRegistry contract.
contract WorldlineRegistryFuzzTest is Test {
    WorldlineRegistry registry;

    function setUp() public {
        registry = new WorldlineRegistry(address(1));
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

        registry.registerCircuit(id, desc, address(1), uri);

        WorldlineRegistry.Circuit memory c = registry.getCircuit(id);
        assertEq(c.id, id);
        assertEq(c.description, desc);
        assertEq(c.verifier, address(1));
        assertEq(c.abiURI, uri);
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
