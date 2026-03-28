// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/WorldlineRegistry.sol";
import "../src/WorldlineCompat.sol";
import "../src/WorldlineOutputsRegistry.sol";
import "../src/zk/Verifier.sol";

/// @title Chunk 5 Tests — HI-004, MED-003, MED-004, MED-005
contract Chunk5Test is Test {
    WorldlineRegistry registry;
    WorldlineCompat compat;
    WorldlineOutputsRegistry outputsRegistry;
    Verifier verifier;

    address owner;
    address stranger;

    function setUp() public {
        owner = address(this);
        stranger = address(0xBEEF);

        verifier = new Verifier();
        registry = new WorldlineRegistry(address(verifier));
        compat = new WorldlineCompat(address(registry));
        outputsRegistry = new WorldlineOutputsRegistry(1 days);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // HI-004: verify() dev-only guard (chainid == 31337)
    // ═══════════════════════════════════════════════════════════════════════════

    /// @notice verify() works on chainid 31337 (Foundry/Hardhat default).
    function test_verify_worksOnDevnet() public {
        // Foundry default chainid is 31337
        bytes32 cid = bytes32(uint256(1));
        registry.registerCircuit(cid, "test", address(0), "");
        bool result = registry.verify(cid, 5, 25);
        assertTrue(result);
    }

    /// @notice verify() reverts with DevOnly on non-devnet chain.
    function test_verify_revert_nonDevnet() public {
        bytes32 cid = bytes32(uint256(1));
        registry.registerCircuit(cid, "test", address(0), "");

        // Switch to mainnet chainid
        vm.chainId(1);
        vm.expectRevert(WorldlineRegistry.DevOnly.selector);
        registry.verify(cid, 5, 25);
    }

    /// @notice WorldlineCompat.verify() also reverts on non-devnet chain.
    function test_compatVerify_revert_nonDevnet() public {
        // Wire facade first
        registry.setCompatFacade(address(compat));

        bytes32 cid = bytes32(uint256(1));
        registry.registerCircuit(cid, "test", address(0), "");

        vm.chainId(1);
        vm.expectRevert(WorldlineCompat.DevOnly.selector);
        compat.verify(cid, 5, 25);
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
    // MED-004: Verifier secret range check
    // ═══════════════════════════════════════════════════════════════════════════

    /// @notice verifyProof reverts with SecretTooLarge for secret >= 2^128.
    function test_verifyProof_revert_secretTooLarge() public {
        uint256 bigSecret = uint256(1) << 128;
        vm.expectRevert(Verifier.SecretTooLarge.selector);
        verifier.verifyProof(bigSecret, 0);
    }

    /// @notice verifyProof works for secret just below 2^128.
    function test_verifyProof_maxValidSecret() public view {
        uint256 maxSecret = (uint256(1) << 128) - 1;
        uint256 hash = maxSecret * maxSecret;
        verifier.verifyProof(maxSecret, hash);
        // Should not revert
    }

    /// @notice verifyProof reverts with InvalidProof for wrong hash (not overflow).
    function test_verifyProof_revert_invalidProof() public {
        vm.expectRevert(Verifier.InvalidProof.selector);
        verifier.verifyProof(5, 26); // 5*5 = 25, not 26
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
        vm.expectRevert(Ownable.NotOwner.selector);
        registry.scheduleCompatFacade(address(compat));
    }
}
