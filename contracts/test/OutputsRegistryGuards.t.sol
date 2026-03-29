// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../src/WorldlineRegistry.sol";
import "../src/WorldlineCompat.sol";
import "../src/WorldlineOutputsRegistry.sol";

/// @title Outputs Registry & Registry Guards — HI-004, MED-003, MED-004, MED-005
contract OutputsRegistryGuardsTest is Test {
    WorldlineRegistry registry;
    WorldlineCompat compat;
    WorldlineOutputsRegistry outputsRegistry;

    address owner;
    address stranger;

    function setUp() public {
        owner = address(this);
        stranger = address(0xBEEF);

        WorldlineRegistry regImpl = new WorldlineRegistry();
        ERC1967Proxy regProxy = new ERC1967Proxy(
            address(regImpl),
            abi.encodeCall(WorldlineRegistry.initialize, (address(1)))
        );
        registry = WorldlineRegistry(address(regProxy));
        compat = new WorldlineCompat(address(registry));

        WorldlineOutputsRegistry outImpl = new WorldlineOutputsRegistry();
        ERC1967Proxy outProxy = new ERC1967Proxy(
            address(outImpl),
            abi.encodeCall(WorldlineOutputsRegistry.initialize, (1 days))
        );
        outputsRegistry = WorldlineOutputsRegistry(address(outProxy));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // MED-003: Zero-value guards on schedule()
    // ═══════════════════════════════════════════════════════════════════════════

    /// @notice schedule() reverts with OracleZero when oracle is address(0).
    function test_schedule_revert_oracleZero() public {
        bytes32 dk = outputsRegistry.domainKey(bytes32(uint256(1)), bytes32(uint256(2)));
        vm.expectRevert(WorldlineOutputsRegistry.OracleZero.selector);
        outputsRegistry.schedule(dk, bytes32(uint256(1)), bytes32(uint256(1)), address(0));
    }

    /// @notice schedule() reverts with VKeyZero when programVKey is bytes32(0).
    function test_schedule_revert_vkeyZero() public {
        bytes32 dk = outputsRegistry.domainKey(bytes32(uint256(1)), bytes32(uint256(2)));
        vm.expectRevert(WorldlineOutputsRegistry.VKeyZero.selector);
        outputsRegistry.schedule(dk, bytes32(0), bytes32(uint256(1)), address(0x1));
    }

    /// @notice schedule() reverts with PolicyHashZero when policyHash is bytes32(0).
    function test_schedule_revert_policyHashZero() public {
        bytes32 dk = outputsRegistry.domainKey(bytes32(uint256(1)), bytes32(uint256(2)));
        vm.expectRevert(WorldlineOutputsRegistry.PolicyHashZero.selector);
        outputsRegistry.schedule(dk, bytes32(uint256(1)), bytes32(0), address(0x1));
    }

    /// @notice schedule() succeeds with all non-zero values.
    function test_schedule_succeeds_nonZeroValues() public {
        bytes32 dk = outputsRegistry.domainKey(bytes32(uint256(1)), bytes32(uint256(2)));
        outputsRegistry.schedule(dk, bytes32(uint256(1)), bytes32(uint256(1)), address(0x1));
        // Just verify it doesn't revert
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // MED-005: Timelocked setCompatFacade
    // ═══════════════════════════════════════════════════════════════════════════

    /// @notice First-time setCompatFacade works (compatFacade == address(0)).
    function test_setCompatFacade_firstTime() public {
        registry.setCompatFacade(address(compat));
        assertEq(registry.compatFacade(), address(compat));
    }

    /// @notice setCompatFacade reverts after facade is already set.
    function test_setCompatFacade_revert_alreadySet() public {
        registry.setCompatFacade(address(compat));
        vm.expectRevert(
            abi.encodeWithSelector(WorldlineRegistry.FacadeTimelockActive.selector, 0)
        );
        registry.setCompatFacade(address(0x1234));
    }

    /// @notice scheduleCompatFacade + immediate activate reverts.
    function test_activateCompatFacade_revert_timelockActive() public {
        registry.setCompatFacade(address(compat));
        registry.scheduleCompatFacade(address(0x1234));
        vm.expectRevert(
            abi.encodeWithSelector(
                WorldlineRegistry.FacadeTimelockActive.selector,
                block.timestamp + 1 days
            )
        );
        registry.activateCompatFacade();
    }

    /// @notice scheduleCompatFacade + warp + activate succeeds.
    function test_activateCompatFacade_afterTimelock() public {
        registry.setCompatFacade(address(compat));
        registry.scheduleCompatFacade(address(0x1234));
        vm.warp(block.timestamp + 1 days + 1);
        registry.activateCompatFacade();
        assertEq(registry.compatFacade(), address(0x1234));
    }

    /// @notice activateCompatFacade reverts when nothing is scheduled.
    function test_activateCompatFacade_revert_noPending() public {
        vm.expectRevert(WorldlineRegistry.NoPendingFacade.selector);
        registry.activateCompatFacade();
    }

    /// @notice scheduleCompatFacade(address(0)) disables facade after timelock.
    function test_scheduleCompatFacade_disableFacade() public {
        registry.setCompatFacade(address(compat));
        registry.scheduleCompatFacade(address(0));
        vm.warp(block.timestamp + 1 days + 1);
        registry.activateCompatFacade();
        assertEq(registry.compatFacade(), address(0));
    }

    /// @notice setFacadeChangeDelay reverts below MIN_FACADE_DELAY.
    function test_setFacadeChangeDelay_revert_belowFloor() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                WorldlineRegistry.FacadeDelayTooShort.selector,
                1 days,
                1 hours
            )
        );
        registry.setFacadeChangeDelay(1 hours);
    }

    /// @notice setFacadeChangeDelay succeeds at MIN_FACADE_DELAY.
    function test_setFacadeChangeDelay_atFloor() public {
        registry.setFacadeChangeDelay(1 days);
        assertEq(registry.facadeChangeDelay(), 1 days);
    }

    /// @notice Non-owner cannot schedule facade change.
    function test_scheduleCompatFacade_revert_notOwner() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(bytes4(keccak256("OwnableUnauthorizedAccount(address)")), stranger)
        );
        registry.scheduleCompatFacade(address(compat));
    }
}
