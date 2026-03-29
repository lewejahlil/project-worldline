// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./WorldlineTestBase.t.sol";

/// @title Finalizer Genesis & Events — LOW-003, LOW-004, LOW-005
/// @notice Unit tests for genesis block validation, ManifestAnnounced event,
///         and CEI pattern (state update before external call).
contract FinalizerGenesisAndEventsTest is WorldlineTestBase {
    event ManifestAnnounced(bytes32 indexed proverSetDigest, bytes metaLocator);

    uint256 constant GENESIS_BLOCK = 42;

    function setUp() public {
        vm.warp(100_000);
        _deployFinalizer(3600, GENESIS_BLOCK);
        finalizer.setPermissionless(true);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // LOW-003: Genesis L2 block validation
    // ═══════════════════════════════════════════════════════════════════════════

    /// @notice genesisL2Block is stored correctly.
    function test_genesisL2Block_stored() public view {
        assertEq(finalizer.genesisL2Block(), GENESIS_BLOCK);
    }

    /// @notice Window 0 must start at genesisL2Block.
    function test_genesisWindow_acceptsCorrectStart() public {
        uint256 ts = block.timestamp + 100;
        bytes32 stf = computeStf(GENESIS_BLOCK, GENESIS_BLOCK + 100, ts);
        bytes memory proof = encodeProof(stf);
        bytes memory inputs = encodeInputs(GENESIS_BLOCK, GENESIS_BLOCK + 100, ts);
        finalizer.submitZkValidityProof(proof, inputs);
        assertEq(finalizer.nextWindowIndex(), 1);
    }

    /// @notice Window 0 with wrong l2Start reverts with GenesisStartMismatch.
    function test_genesisWindow_rejectsWrongStart() public {
        uint256 ts = block.timestamp + 100;
        bytes32 stf = computeStf(0, 100, ts);
        bytes memory proof = encodeProof(stf);
        bytes memory inputs = encodeInputs(0, 100, ts);
        vm.expectRevert(
            abi.encodeWithSelector(WorldlineFinalizer.GenesisStartMismatch.selector, GENESIS_BLOCK, 0)
        );
        finalizer.submitZkValidityProof(proof, inputs);
    }

    /// @notice genesisL2Block=0 (default) accepts l2Start=0 for window 0.
    function test_genesisBlockZero_acceptsZeroStart() public {
        _deployFinalizer(3600, 0);
        WorldlineFinalizer f2 = finalizer; // re-deployed by _deployFinalizer
        f2.setPermissionless(true);
        uint256 ts = block.timestamp + 100;
        bytes32 stf = computeStf(0, 100, ts);
        bytes memory proof = encodeProof(stf);
        bytes memory inputs = encodeInputs(0, 100, ts);
        f2.submitZkValidityProof(proof, inputs);
        assertEq(f2.nextWindowIndex(), 1);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // LOW-004: ManifestAnnounced event emission
    // ═══════════════════════════════════════════════════════════════════════════

    /// @notice submitZkValidityProofWithMeta emits ManifestAnnounced.
    function test_manifestAnnounced_emitted() public {
        uint256 ts = block.timestamp + 100;
        bytes32 stf = computeStf(GENESIS_BLOCK, GENESIS_BLOCK + 100, ts);
        bytes memory proof = encodeProof(stf);
        bytes memory inputs = encodeInputs(GENESIS_BLOCK, GENESIS_BLOCK + 100, ts);
        bytes memory locator = hex"deadbeef";

        vm.expectEmit(true, false, false, true);
        emit ManifestAnnounced(PROVER_DIGEST, locator);
        finalizer.submitZkValidityProofWithMeta(proof, inputs, locator);
    }

    /// @notice submitZkValidityProofWithMeta with empty locator still emits.
    function test_manifestAnnounced_emptyLocator() public {
        uint256 ts = block.timestamp + 100;
        bytes32 stf = computeStf(GENESIS_BLOCK, GENESIS_BLOCK + 100, ts);
        bytes memory proof = encodeProof(stf);
        bytes memory inputs = encodeInputs(GENESIS_BLOCK, GENESIS_BLOCK + 100, ts);

        vm.expectEmit(true, false, false, true);
        emit ManifestAnnounced(PROVER_DIGEST, "");
        finalizer.submitZkValidityProofWithMeta(proof, inputs, "");
    }

    /// @notice submitZkValidityProof (without meta) does NOT emit ManifestAnnounced.
    function test_noManifestAnnounced_withoutMeta() public {
        uint256 ts = block.timestamp + 100;
        bytes32 stf = computeStf(GENESIS_BLOCK, GENESIS_BLOCK + 100, ts);
        bytes memory proof = encodeProof(stf);
        bytes memory inputs = encodeInputs(GENESIS_BLOCK, GENESIS_BLOCK + 100, ts);

        vm.recordLogs();
        finalizer.submitZkValidityProof(proof, inputs);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 manifestSig = keccak256("ManifestAnnounced(bytes32,bytes)");
        for (uint256 i = 0; i < logs.length; i++) {
            assertTrue(logs[i].topics[0] != manifestSig, "ManifestAnnounced should not be emitted");
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // LOW-005: CEI — state updated before adapter.verify()
    // ═══════════════════════════════════════════════════════════════════════════

    /// @notice After a successful submission, nextWindowIndex and lastL2EndBlock are updated.
    function test_stateUpdatedAfterSubmit() public {
        uint256 ts = block.timestamp + 100;
        bytes memory inputs = encodeInputs(GENESIS_BLOCK, GENESIS_BLOCK + 100, ts);
        bytes32 stf = computeStf(GENESIS_BLOCK, GENESIS_BLOCK + 100, ts);
        bytes memory proof = encodeProof(stf);

        assertEq(finalizer.nextWindowIndex(), 0);
        assertEq(finalizer.lastL2EndBlock(), 0);

        finalizer.submitZkValidityProof(proof, inputs);

        assertEq(finalizer.nextWindowIndex(), 1);
        assertEq(finalizer.lastL2EndBlock(), GENESIS_BLOCK + 100);
    }
}
