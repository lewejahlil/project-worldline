// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../src/utils/Ownable.sol";
import "../src/WorldlineOutputsRegistry.sol";
import "../src/WorldlineFinalizer.sol";
import "../src/zk/Groth16ZkAdapter.sol";

/// @notice View-compatible mock that always returns true for Groth16 verification.
contract ViewMockGroth16Verifier {
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[2] calldata
    ) external pure returns (bool) {
        return true;
    }
}

/// @title Concrete Ownable for testing the abstract contract.
contract OwnableHarness is Ownable {
    function protectedAction() external onlyOwner {}
}

/// @title AccessControl Tests — HI-001, HI-002, HI-003
/// @notice Tests for two-step ownership, minTimelock floor, and timelocked adapter changes.
contract AccessControlTest is Test {
    OwnableHarness ownable;
    WorldlineOutputsRegistry outputsRegistry;
    WorldlineFinalizer finalizer;
    Groth16ZkAdapter adapter;

    address owner;
    address stranger;

    bytes32 constant DOMAIN = keccak256("access-control-test");
    bytes32 constant PROGRAM_VKEY = keccak256("vkey");
    bytes32 constant POLICY_HASH = keccak256("policy");

    function setUp() public {
        owner = address(this);
        stranger = address(0xBEEF);

        ownable = new OwnableHarness();

        WorldlineOutputsRegistry outImpl = new WorldlineOutputsRegistry();
        ERC1967Proxy outProxy = new ERC1967Proxy(
            address(outImpl),
            abi.encodeCall(WorldlineOutputsRegistry.initialize, (1 days))
        );
        outputsRegistry = WorldlineOutputsRegistry(address(outProxy));

        ViewMockGroth16Verifier mock = new ViewMockGroth16Verifier();
        adapter = new Groth16ZkAdapter(address(mock), PROGRAM_VKEY, POLICY_HASH);

        WorldlineFinalizer finImpl = new WorldlineFinalizer();
        ERC1967Proxy finProxy = new ERC1967Proxy(
            address(finImpl),
            abi.encodeCall(WorldlineFinalizer.initialize, (address(adapter), DOMAIN, 3600, 0, address(0)))
        );
        finalizer = WorldlineFinalizer(address(finProxy));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // HI-003: Two-step ownership transfer
    // ═══════════════════════════════════════════════════════════════════════════

    /// @notice transferOwnership sets pendingOwner but does not change owner.
    function test_transferOwnership_setsPending() public {
        ownable.transferOwnership(stranger);
        assertEq(ownable.pendingOwner(), stranger);
        assertEq(ownable.owner(), owner); // not yet changed
    }

    /// @notice acceptOwnership completes the transfer.
    function test_acceptOwnership_completesTransfer() public {
        ownable.transferOwnership(stranger);
        vm.prank(stranger);
        ownable.acceptOwnership();
        assertEq(ownable.owner(), stranger);
        assertEq(ownable.pendingOwner(), address(0));
    }

    /// @notice Old owner cannot call acceptOwnership.
    function test_acceptOwnership_revert_notPendingOwner() public {
        ownable.transferOwnership(stranger);
        // owner (this) tries to accept — must revert
        vm.expectRevert(Ownable.NotPendingOwner.selector);
        ownable.acceptOwnership();
    }

    /// @notice acceptOwnership reverts when no transfer is pending.
    function test_acceptOwnership_revert_noPendingTransfer() public {
        vm.prank(stranger);
        vm.expectRevert(Ownable.NoPendingTransfer.selector);
        ownable.acceptOwnership();
    }

    /// @notice transferOwnership reverts with zero address.
    function test_transferOwnership_revert_zeroAddress() public {
        vm.expectRevert(Ownable.NewOwnerIsZero.selector);
        ownable.transferOwnership(address(0));
    }

    /// @notice Non-owner cannot call transferOwnership.
    function test_transferOwnership_revert_notOwner() public {
        vm.prank(stranger);
        vm.expectRevert(Ownable.NotOwner.selector);
        ownable.transferOwnership(stranger);
    }

    /// @notice After transfer, new owner can use onlyOwner functions.
    function test_newOwner_canCallProtected() public {
        ownable.transferOwnership(stranger);
        vm.prank(stranger);
        ownable.acceptOwnership();
        // stranger is now owner
        vm.prank(stranger);
        ownable.protectedAction(); // should not revert
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // HI-002: MIN_TIMELOCK_FLOOR on WorldlineOutputsRegistry
    // ═══════════════════════════════════════════════════════════════════════════

    /// @notice initialize reverts if timelock < 1 day.
    function test_outputsRegistry_constructor_revert_timelockTooShort() public {
        WorldlineOutputsRegistry impl = new WorldlineOutputsRegistry();
        vm.expectRevert(
            abi.encodeWithSelector(
                WorldlineOutputsRegistry.TimelockTooShort.selector,
                1 days,
                12 hours
            )
        );
        new ERC1967Proxy(
            address(impl),
            abi.encodeCall(WorldlineOutputsRegistry.initialize, (12 hours))
        );
    }

    /// @notice setMinTimelock(0.5 days) reverts with TimelockTooShort.
    function test_setMinTimelock_revert_belowFloor() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                WorldlineOutputsRegistry.TimelockTooShort.selector,
                1 days,
                12 hours
            )
        );
        outputsRegistry.setMinTimelock(12 hours);
    }

    /// @notice setMinTimelock(1 days) succeeds.
    function test_setMinTimelock_atFloor() public {
        outputsRegistry.setMinTimelock(1 days);
        assertEq(outputsRegistry.minTimelock(), 1 days);
    }

    /// @notice setMinTimelock(2 days) succeeds.
    function test_setMinTimelock_aboveFloor() public {
        outputsRegistry.setMinTimelock(2 days);
        assertEq(outputsRegistry.minTimelock(), 2 days);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // HI-001: Timelocked adapter changes on WorldlineFinalizer
    // ═══════════════════════════════════════════════════════════════════════════

    /// @notice scheduleAdapterChange + immediate activateAdapterChange reverts.
    function test_activateAdapter_revert_timelockActive() public {
        ViewMockGroth16Verifier newMock = new ViewMockGroth16Verifier();
        Groth16ZkAdapter newAdapter = new Groth16ZkAdapter(
            address(newMock), PROGRAM_VKEY, POLICY_HASH
        );
        finalizer.scheduleAdapterChange(address(newAdapter));

        vm.expectRevert(
            abi.encodeWithSelector(
                WorldlineFinalizer.TimelockActive.selector,
                block.timestamp + 1 days
            )
        );
        finalizer.activateAdapterChange();
    }

    /// @notice scheduleAdapterChange + warp past delay + activateAdapterChange succeeds.
    function test_activateAdapter_afterTimelock() public {
        ViewMockGroth16Verifier newMock = new ViewMockGroth16Verifier();
        Groth16ZkAdapter newAdapter = new Groth16ZkAdapter(
            address(newMock), PROGRAM_VKEY, POLICY_HASH
        );
        finalizer.scheduleAdapterChange(address(newAdapter));

        vm.warp(block.timestamp + 1 days + 1);

        finalizer.activateAdapterChange();
        assertEq(address(finalizer.adapter()), address(newAdapter));
    }

    /// @notice activateAdapterChange reverts when nothing is scheduled.
    function test_activateAdapter_revert_noPending() public {
        vm.expectRevert(WorldlineFinalizer.NoPendingAdapter.selector);
        finalizer.activateAdapterChange();
    }

    /// @notice scheduleAdapterChange reverts with zero address.
    function test_scheduleAdapter_revert_zeroAddress() public {
        vm.expectRevert(WorldlineFinalizer.AdapterZero.selector);
        finalizer.scheduleAdapterChange(address(0));
    }

    /// @notice setAdapterChangeDelay reverts below MIN_ADAPTER_DELAY.
    function test_setAdapterDelay_revert_belowFloor() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                WorldlineFinalizer.AdapterDelayTooShort.selector,
                1 days,
                1 hours
            )
        );
        finalizer.setAdapterChangeDelay(1 hours);
    }

    /// @notice setAdapterChangeDelay succeeds at MIN_ADAPTER_DELAY.
    function test_setAdapterDelay_atFloor() public {
        finalizer.setAdapterChangeDelay(1 days);
        assertEq(finalizer.adapterChangeDelay(), 1 days);
    }

    /// @notice Non-owner cannot schedule adapter change.
    function test_scheduleAdapter_revert_notOwner() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(bytes4(keccak256("OwnableUnauthorizedAccount(address)")), stranger)
        );
        finalizer.scheduleAdapterChange(address(adapter));
    }
}
