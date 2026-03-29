// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
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

/// @title Finalizer Genesis & Events — LOW-003, LOW-004, LOW-005
/// @notice Unit tests for genesis block validation, ManifestAnnounced event,
///         and CEI pattern (state update before external call).
contract FinalizerGenesisAndEventsTest is Test {
    event ManifestAnnounced(bytes32 indexed proverSetDigest, bytes metaLocator);

    WorldlineFinalizer finalizer;
    Groth16ZkAdapter adapter;

    bytes32 constant DOMAIN = keccak256("finalizer-test-domain");
    bytes32 constant PROGRAM_VKEY = keccak256("program-vkey");
    bytes32 constant POLICY_HASH = keccak256("policy-hash");
    bytes32 constant PROVER_DIGEST = keccak256("prover-set");
    uint256 constant GENESIS_BLOCK = 42;

    function setUp() public {
        vm.warp(100_000);
        ViewMockGroth16Verifier mock = new ViewMockGroth16Verifier();
        adapter = new Groth16ZkAdapter(address(mock), PROGRAM_VKEY, POLICY_HASH);
        WorldlineFinalizer finImpl = new WorldlineFinalizer();
        ERC1967Proxy finProxy = new ERC1967Proxy(
            address(finImpl),
            abi.encodeCall(WorldlineFinalizer.initialize, (address(adapter), DOMAIN, 3600, GENESIS_BLOCK, address(0)))
        );
        finalizer = WorldlineFinalizer(address(finProxy));
        finalizer.setPermissionless(true);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    function computeStf(
        uint256 l2Start,
        uint256 l2End,
        uint256 windowCloseTimestamp
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(l2Start, l2End, bytes32(0), bytes32(0), DOMAIN, windowCloseTimestamp));
    }

    function encodeInputs(
        uint256 l2Start,
        uint256 l2End,
        uint256 windowCloseTimestamp
    ) internal pure returns (bytes memory) {
        bytes32 stf = computeStf(l2Start, l2End, windowCloseTimestamp);
        return abi.encode(stf, l2Start, l2End, bytes32(0), bytes32(0), DOMAIN, windowCloseTimestamp);
    }

    function encodeProof(bytes32 stf) internal pure returns (bytes memory) {
        // Production format: pA[2], pB[2][2], pC[2], stfCommitment, proverSetDigest
        uint256[2] memory pA = [uint256(1), uint256(2)];
        uint256[2][2] memory pB = [[uint256(3), uint256(4)], [uint256(5), uint256(6)]];
        uint256[2] memory pC = [uint256(7), uint256(8)];
        return abi.encode(pA, pB, pC, uint256(stf), uint256(PROVER_DIGEST));
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
        WorldlineFinalizer f2Impl = new WorldlineFinalizer();
        ERC1967Proxy f2Proxy = new ERC1967Proxy(
            address(f2Impl),
            abi.encodeCall(WorldlineFinalizer.initialize, (address(adapter), DOMAIN, 3600, 0, address(0)))
        );
        WorldlineFinalizer f2 = WorldlineFinalizer(address(f2Proxy));
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
    ///         This is an indirect test; the CEI fix is structural (code ordering).
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
