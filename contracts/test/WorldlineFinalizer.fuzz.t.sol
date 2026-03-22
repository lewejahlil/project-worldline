// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/WorldlineFinalizer.sol";
import "../src/zk/Verifier.sol";
import "../src/zk/Groth16ZkAdapter.sol";

/// @title WorldlineFinalizer Fuzz Tests
/// @notice Property-based / fuzz tests for the WorldlineFinalizer contract.
///         Run with: forge test --match-contract WorldlineFinalizerFuzz -v
contract WorldlineFinalizerFuzzTest is Test {
    WorldlineFinalizer finalizer;
    Verifier verifier;
    Groth16ZkAdapter adapter;

    bytes32 constant DOMAIN = keccak256("worldline-fuzz-domain");
    bytes32 constant PROGRAM_VKEY = keccak256("program-vkey");
    bytes32 constant POLICY_HASH = keccak256("policy-hash");
    bytes32 constant PROVER_DIGEST = keccak256("prover-set");
    uint256 constant MAX_DELAY = 3600;

    function setUp() public {
        // Warp to a timestamp large enough that any uint32 staleness offset cannot
        // underflow the arithmetic in testFuzz_rejectStaleProof:
        //   block.timestamp - MAX_DELAY - uint256(delayPastMax)
        // Needs: block.timestamp >= MAX_DELAY + type(uint32).max + 1
        vm.warp(uint256(type(uint32).max) + MAX_DELAY + 2);

        verifier = new Verifier();
        // isDev=true for all fuzz tests — exercises dev behaviour.
        adapter = new Groth16ZkAdapter(address(verifier), PROGRAM_VKEY, POLICY_HASH, true);
        finalizer = new WorldlineFinalizer(address(adapter), DOMAIN, MAX_DELAY);
        // Enable permissionless mode so the fuzzer address can submit.
        finalizer.setPermissionless(true);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    function encodeValidInputs(
        uint256 l2Start,
        uint256 l2End,
        uint256 windowCloseTimestamp
    ) internal pure returns (bytes memory) {
        bytes32 stf = keccak256("stf");
        return abi.encode(
            stf,
            l2Start,
            l2End,
            bytes32(0), // outputRoot
            bytes32(0), // l1BlockHash
            DOMAIN,
            windowCloseTimestamp
        );
    }

    function encodeValidProof(bytes32 stf) internal pure returns (bytes memory) {
        return abi.encode(stf, PROGRAM_VKEY, POLICY_HASH, PROVER_DIGEST);
    }

    // ── Fuzz tests ────────────────────────────────────────────────────────────

    /// Any publicInputs with length != 224 must revert with BadInputsLen.
    function testFuzz_rejectBadInputLength(bytes calldata randomInputs) public {
        vm.assume(randomInputs.length != 224);
        bytes memory proof = encodeValidProof(keccak256("stf"));
        vm.expectRevert(WorldlineFinalizer.BadInputsLen.selector);
        finalizer.submitZkValidityProof(proof, randomInputs);
    }

    /// A domain separator other than DOMAIN must always revert with DomainMismatch.
    function testFuzz_rejectWrongDomain(bytes32 wrongDomain) public {
        vm.assume(wrongDomain != DOMAIN);
        bytes32 stf = keccak256("stf-domain");
        bytes memory proof = encodeValidProof(stf);
        // Build 224-byte publicInputs with the wrong domain.
        uint256 ts = block.timestamp + 100;
        bytes memory inputs = abi.encode(
            stf,
            uint256(0),
            uint256(100),
            bytes32(0),
            bytes32(0),
            wrongDomain,
            ts
        );
        vm.expectRevert(WorldlineFinalizer.DomainMismatch.selector);
        finalizer.submitZkValidityProof(proof, inputs);
    }

    /// After N successful submissions, nextWindowIndex must equal N.
    /// (Small N to keep the fuzz run fast.)
    function testFuzz_windowIndexOnlyIncrements(uint8 n) public {
        vm.assume(n > 0 && n <= 10);
        uint256 l2End = 100;
        uint256 ts = block.timestamp + 3600;
        bytes32 stf = keccak256("stf-incr");
        for (uint8 i = 0; i < n; i++) {
            bytes memory proof = encodeValidProof(stf);
            bytes memory inputs = abi.encode(
                stf,
                l2End * i, // l2Start: previous end
                l2End * (i + 1), // l2End: next boundary
                bytes32(0),
                bytes32(0),
                DOMAIN,
                ts
            );
            finalizer.submitZkValidityProof(proof, inputs);
        }
        assertEq(finalizer.nextWindowIndex(), uint256(n));
    }

    /// Contiguity invariant: l2Start must equal lastL2EndBlock for non-genesis windows.
    function testFuzz_contiguityEnforced(uint128 l2Start, uint128 l2End) public {
        vm.assume(l2End > l2Start);

        // First submit genesis window: l2Start=0, l2End=100.
        uint256 ts = block.timestamp + 3600;
        bytes32 stf = keccak256("stf-cont");
        bytes memory proof = encodeValidProof(stf);
        bytes memory inputs = abi.encode(stf, uint256(0), uint256(100), bytes32(0), bytes32(0), DOMAIN, ts);
        finalizer.submitZkValidityProof(proof, inputs);
        // lastL2EndBlock is now 100.

        // Now attempt a non-contiguous submission (l2Start != 100) on window 1.
        vm.assume(uint256(l2Start) != 100);
        vm.assume(uint256(l2End) > uint256(l2Start));

        proof = encodeValidProof(stf);
        inputs = abi.encode(stf, uint256(l2Start), uint256(l2End), bytes32(0), bytes32(0), DOMAIN, ts);
        vm.expectRevert(WorldlineFinalizer.NotContiguous.selector);
        finalizer.submitZkValidityProof(proof, inputs);
    }

    /// Any windowCloseTimestamp older than block.timestamp - maxAcceptanceDelay must revert.
    function testFuzz_rejectStaleProof(uint32 delayPastMax) public {
        // windowCloseTimestamp is stale by at least 1 second beyond maxAcceptanceDelay.
        vm.assume(delayPastMax >= 1);
        uint256 windowCloseTimestamp = block.timestamp - MAX_DELAY - uint256(delayPastMax);

        bytes32 stf = keccak256("stf-stale");
        bytes memory proof = encodeValidProof(stf);
        bytes memory inputs = abi.encode(
            stf,
            uint256(0),
            uint256(100),
            bytes32(0),
            bytes32(0),
            DOMAIN,
            windowCloseTimestamp
        );
        vm.expectRevert(WorldlineFinalizer.TooOld.selector);
        finalizer.submitZkValidityProof(proof, inputs);
    }

    /// l2End must be strictly greater than l2Start; equal or reversed must revert.
    function testFuzz_rejectInvalidWindowRange(uint128 l2Start) public {
        // l2End == l2Start (empty window) → revert.
        uint256 ts = block.timestamp + 100;
        bytes32 stf = keccak256("stf-range");
        bytes memory proof = encodeValidProof(stf);
        bytes memory inputs = abi.encode(
            stf,
            uint256(l2Start),
            uint256(l2Start), // l2End == l2Start
            bytes32(0),
            bytes32(0),
            DOMAIN,
            ts
        );
        vm.expectRevert(WorldlineFinalizer.InvalidWindowRange.selector);
        finalizer.submitZkValidityProof(proof, inputs);
    }
}
