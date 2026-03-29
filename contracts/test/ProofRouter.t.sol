// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../src/ProofRouter.sol";
import "../src/IZkAdapter.sol";
import "../src/interfaces/IZkAggregatorVerifier.sol";

// ── Mock adapters ────────────────────────────────────────────────────────────

/// @notice Mock adapter that implements both IZkAdapter and IZkAggregatorVerifier.
///         Always returns the configured result. Configurable proofSystemId.
contract MockZkAdapter is IZkAdapter, IZkAggregatorVerifier {
    uint8 private immutable _psId;
    bool private immutable _result;
    bytes32 private immutable _stfCommitment;
    bytes32 private immutable _programVKey;
    bytes32 private immutable _policyHash;
    bytes32 private immutable _proverSetDigest;

    constructor(
        uint8 psId,
        bool result,
        bytes32 stfCommitment_,
        bytes32 programVKey_,
        bytes32 policyHash_,
        bytes32 proverSetDigest_
    ) {
        _psId = psId;
        _result = result;
        _stfCommitment = stfCommitment_;
        _programVKey = programVKey_;
        _policyHash = policyHash_;
        _proverSetDigest = proverSetDigest_;
    }

    // ── IZkAdapter ───────────────────────────────────────────────────────────

    function proofSystemId() external view override(IZkAdapter) returns (uint8) {
        return _psId;
    }

    function expectedProofLength() external pure override(IZkAdapter) returns (uint256) {
        return 0; // test mock — any length accepted
    }

    function verify(bytes calldata, bytes32[] calldata) external view override(IZkAdapter) returns (bool) {
        return _result;
    }

    // ── IZkAggregatorVerifier ────────────────────────────────────────────────

    function verify(bytes calldata, bytes calldata)
        external
        view
        override(IZkAggregatorVerifier)
        returns (bool valid, bytes32 stfCommitment, bytes32 programVKey, bytes32 policyHash, bytes32 proverSetDigest)
    {
        valid = _result;
        stfCommitment = _stfCommitment;
        programVKey = _programVKey;
        policyHash = _policyHash;
        proverSetDigest = _proverSetDigest;
    }
}

/// @notice Mock adapter that reports a mismatched proofSystemId (always returns 99).
contract MismatchedIdAdapter is IZkAdapter {
    function proofSystemId() external pure override returns (uint8) {
        return 99;
    }

    function expectedProofLength() external pure override returns (uint256) {
        return 0;
    }

    function verify(bytes calldata, bytes32[] calldata) external pure override returns (bool) {
        return true;
    }
}

// ── Test contract ────────────────────────────────────────────────────────────

/// @title ProofRouterTest
/// @notice Forge tests for the ProofRouter contract.
contract ProofRouterTest is Test {
    ProofRouter router;
    address owner;
    address stranger;

    bytes32 constant STF = keccak256("stf");
    bytes32 constant VKEY = keccak256("vkey");
    bytes32 constant POL = keccak256("pol");
    bytes32 constant DIG = keccak256("dig");

    function setUp() public {
        owner = address(this);
        stranger = address(0xBEEF);
        ProofRouter routerImpl = new ProofRouter();
        ERC1967Proxy routerProxy = new ERC1967Proxy(address(routerImpl), abi.encodeCall(ProofRouter.initialize, ()));
        router = ProofRouter(address(routerProxy));
    }

    // ── Helper ───────────────────────────────────────────────────────────────

    function _mockAdapter(uint8 psId) internal returns (MockZkAdapter) {
        return new MockZkAdapter(psId, true, STF, VKEY, POL, DIG);
    }

    // ── Test 1: Register Groth16 adapter (id=1) — succeeds, event emitted ───

    function test_registerAdapter_groth16_succeeds() public {
        MockZkAdapter adapter = _mockAdapter(1);

        vm.expectEmit(true, false, false, true);
        emit ProofRouter.AdapterRegistered(1, address(adapter));

        router.registerAdapter(1, address(adapter));

        assertEq(router.getAdapter(1), address(adapter));
        assertTrue(router.isSupported(1));
    }

    // ── Test 2: Register adapter with mismatched proofSystemId — reverts ────

    function test_registerAdapter_mismatchedId_reverts() public {
        MismatchedIdAdapter adapter = new MismatchedIdAdapter();

        // adapter reports 99, but we try to register at id=1 → mismatch
        vm.expectRevert(abi.encodeWithSelector(ProofRouter.ProofSystemIdMismatch.selector, 1, 99));
        router.registerAdapter(1, address(adapter));
    }

    // ── Test 3: Register duplicate proofSystemId — reverts ──────────────────

    function test_registerAdapter_duplicate_reverts() public {
        MockZkAdapter a1 = _mockAdapter(1);
        router.registerAdapter(1, address(a1));

        MockZkAdapter a2 = _mockAdapter(1);
        vm.expectRevert(abi.encodeWithSelector(ProofRouter.AdapterAlreadyRegistered.selector, 1));
        router.registerAdapter(1, address(a2));
    }

    // ── Test 4: Remove adapter — schedules removal, then activates after delay ─

    function test_removeAdapter_schedulesRemoval() public {
        MockZkAdapter adapter = _mockAdapter(1);
        router.registerAdapter(1, address(adapter));
        assertTrue(router.isSupported(1));

        // removeAdapter now schedules a timelocked removal
        vm.expectEmit(true, false, false, true);
        emit ProofRouter.AdapterRemovalScheduled(1, block.timestamp + 1 days);

        router.removeAdapter(1);

        // Adapter is still active during the timelock window
        assertTrue(router.isSupported(1));
        assertEq(router.getAdapter(1), address(adapter));
        assertEq(router.getAdapterRemovalActivation(1), block.timestamp + 1 days);

        // Warp past the timelock
        vm.warp(block.timestamp + 1 days + 1);

        vm.expectEmit(true, false, false, false);
        emit ProofRouter.AdapterRemoved(1);

        router.activateAdapterRemoval(1);

        assertFalse(router.isSupported(1));
        assertEq(router.getAdapter(1), address(0));
        assertEq(router.getAdapterRemovalActivation(1), 0);
    }

    // ── Test 5: Route proof to registered Groth16 adapter — succeeds ────────

    function test_routeProof_groth16_succeeds() public {
        MockZkAdapter adapter = _mockAdapter(1);
        router.registerAdapter(1, address(adapter));

        bytes memory proof = hex"deadbeef";
        bytes32[] memory inputs = new bytes32[](0);

        vm.expectEmit(true, false, false, true);
        emit ProofRouter.ProofRouted(1, true);

        bool result = router.routeProof(1, proof, inputs);
        assertTrue(result);
    }

    // ── Test 6: Route proof to unregistered proofSystemId — reverts ─────────

    function test_routeProof_unregistered_reverts() public {
        bytes memory proof = hex"deadbeef";
        bytes32[] memory inputs = new bytes32[](0);

        vm.expectRevert(abi.encodeWithSelector(ProofRouter.AdapterNotRegistered.selector, 2));
        router.routeProof(2, proof, inputs);
    }

    // ── Test 7: Non-owner cannot register adapter — reverts ─────────────────

    function test_registerAdapter_nonOwner_reverts() public {
        MockZkAdapter adapter = _mockAdapter(1);

        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("OwnableUnauthorizedAccount(address)")), stranger));
        router.registerAdapter(1, address(adapter));
    }

    // ── Test 8: Non-owner cannot remove adapter — reverts ───────────────────

    function test_removeAdapter_nonOwner_reverts() public {
        MockZkAdapter adapter = _mockAdapter(1);
        router.registerAdapter(1, address(adapter));

        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("OwnableUnauthorizedAccount(address)")), stranger));
        router.removeAdapter(1);
    }

    // ── Test 9: Register adapters for IDs 1, 2, 3 — all succeed ────────────

    function test_registerAdapter_threeIds_allQueryable() public {
        MockZkAdapter a1 = _mockAdapter(1);
        MockZkAdapter a2 = _mockAdapter(2);
        MockZkAdapter a3 = _mockAdapter(3);

        router.registerAdapter(1, address(a1));
        router.registerAdapter(2, address(a2));
        router.registerAdapter(3, address(a3));

        assertTrue(router.isSupported(1));
        assertTrue(router.isSupported(2));
        assertTrue(router.isSupported(3));
        assertFalse(router.isSupported(4));

        assertEq(router.getAdapter(1), address(a1));
        assertEq(router.getAdapter(2), address(a2));
        assertEq(router.getAdapter(3), address(a3));
    }

    // ── Extra: routeProofAggregated — succeeds and returns full tuple ────────

    function test_routeProofAggregated_returnsFullTuple() public {
        MockZkAdapter adapter = _mockAdapter(1);
        router.registerAdapter(1, address(adapter));

        (bool valid, bytes32 stfCommitment, bytes32 programVKey, bytes32 policyHash, bytes32 proverSetDigest) =
            router.routeProofAggregated(1, hex"deadbeef", new bytes(0));

        assertTrue(valid);
        assertEq(stfCommitment, STF);
        assertEq(programVKey, VKEY);
        assertEq(policyHash, POL);
        assertEq(proverSetDigest, DIG);
    }

    // ── Extra: routeProofAggregated with unregistered id — reverts ──────────

    function test_routeProofAggregated_unregistered_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(ProofRouter.AdapterNotRegistered.selector, 5));
        router.routeProofAggregated(5, hex"", new bytes(0));
    }

    // ── Extra: removeAdapter on unregistered id — reverts ───────────────────

    function test_removeAdapter_unregistered_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(ProofRouter.AdapterNotRegistered.selector, 7));
        router.removeAdapter(7);
    }

    // ── Extra: registerAdapter with zero address — reverts ──────────────────

    function test_registerAdapter_zeroAddress_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(ProofRouter.AdapterZero.selector));
        router.registerAdapter(1, address(0));
    }

    // ── H-02 Timelock tests ──────────────────────────────────────────────────

    // Adapter stays active during removal timelock window
    function test_removeAdapter_adapterActiveduringTimelock() public {
        MockZkAdapter adapter = _mockAdapter(1);
        router.registerAdapter(1, address(adapter));
        router.removeAdapter(1);

        // Adapter must still be routable during the timelock window
        bytes memory proof = hex"deadbeef";
        bytes32[] memory inputs = new bytes32[](0);
        bool result = router.routeProof(1, proof, inputs);
        assertTrue(result);
    }

    // activateAdapterRemoval before timelock reverts with TimelockActive
    function test_activateAdapterRemoval_beforeTimelock_reverts() public {
        MockZkAdapter adapter = _mockAdapter(1);
        router.registerAdapter(1, address(adapter));
        router.removeAdapter(1);

        vm.expectRevert(abi.encodeWithSelector(ProofRouter.TimelockActive.selector, block.timestamp + 1 days));
        router.activateAdapterRemoval(1);
    }

    // activateAdapterRemoval with no pending removal reverts
    function test_activateAdapterRemoval_noPending_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(ProofRouter.NoAdapterRemovalScheduled.selector, 3));
        router.activateAdapterRemoval(3);
    }

    // setAdapterChangeDelay below floor reverts
    function test_setAdapterChangeDelay_belowFloor_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(ProofRouter.AdapterChangeTooShort.selector, 1 days, 1 hours));
        router.setAdapterChangeDelay(1 hours);
    }

    // setAdapterChangeDelay at floor succeeds
    function test_setAdapterChangeDelay_atFloor_succeeds() public {
        router.setAdapterChangeDelay(1 days);
        assertEq(router.adapterChangeDelay(), 1 days);
    }

    // setAdapterChangeDelay above floor succeeds and affects new removals
    function test_setAdapterChangeDelay_affectsNewRemovals() public {
        router.setAdapterChangeDelay(2 days);

        MockZkAdapter adapter = _mockAdapter(1);
        router.registerAdapter(1, address(adapter));
        router.removeAdapter(1);

        assertEq(router.getAdapterRemovalActivation(1), block.timestamp + 2 days);
    }

    // Non-owner cannot call activateAdapterRemoval
    function test_activateAdapterRemoval_nonOwner_reverts() public {
        MockZkAdapter adapter = _mockAdapter(1);
        router.registerAdapter(1, address(adapter));
        router.removeAdapter(1);
        vm.warp(block.timestamp + 1 days + 1);

        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("OwnableUnauthorizedAccount(address)")), stranger));
        router.activateAdapterRemoval(1);
    }

    // Non-owner cannot call setAdapterChangeDelay
    function test_setAdapterChangeDelay_nonOwner_reverts() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("OwnableUnauthorizedAccount(address)")), stranger));
        router.setAdapterChangeDelay(2 days);
    }

    // ── Extra: remove then re-register — requires timelock ──────────────────

    function test_removeAndReregister_requiresTimelock() public {
        MockZkAdapter a1 = _mockAdapter(1);
        router.registerAdapter(1, address(a1));

        // Schedule removal
        router.removeAdapter(1);

        // Cannot re-register while a1 is still in the slot
        MockZkAdapter a2 = _mockAdapter(1);
        vm.expectRevert(abi.encodeWithSelector(ProofRouter.AdapterAlreadyRegistered.selector, 1));
        router.registerAdapter(1, address(a2));

        // After timelock and activation, re-registration succeeds
        vm.warp(block.timestamp + 1 days + 1);
        router.activateAdapterRemoval(1);

        router.registerAdapter(1, address(a2));
        assertEq(router.getAdapter(1), address(a2));
        assertTrue(router.isSupported(1));
    }
}
