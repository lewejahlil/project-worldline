// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./WorldlineTestBase.t.sol";

/// @title WorldlineFinalizer Fuzz Tests
/// @notice Property-based / fuzz tests for the WorldlineFinalizer contract.
///         Run with: forge test --match-contract WorldlineFinalizerFuzz -v
contract WorldlineFinalizerFuzzTest is WorldlineTestBase {
    uint256 constant MAX_DELAY = 3600;

    function setUp() public {
        // Warp to a timestamp large enough that any uint32 staleness offset cannot
        // underflow the arithmetic in testFuzz_rejectStaleProof:
        //   block.timestamp - MAX_DELAY - uint256(delayPastMax)
        // Needs: block.timestamp >= MAX_DELAY + type(uint32).max + 1
        vm.warp(uint256(type(uint32).max) + MAX_DELAY + 2);
        _deployFinalizer(MAX_DELAY, 0);
        finalizer.setPermissionless(true);
    }

    // ── Fuzz tests ────────────────────────────────────────────────────────────

    /// Any publicInputs with length != 224 must revert with BadInputsLen.
    function testFuzz_rejectBadInputLength(bytes calldata randomInputs) public {
        vm.assume(randomInputs.length != 224);
        bytes memory proof = encodeProof(keccak256("stf"));
        vm.expectRevert(WorldlineFinalizer.BadInputsLen.selector);
        finalizer.submitZkValidityProof(proof, randomInputs);
    }

    /// A domain separator other than DOMAIN must always revert with DomainMismatch.
    function testFuzz_rejectWrongDomain(bytes32 wrongDomain) public {
        vm.assume(wrongDomain != DOMAIN);
        uint256 ts = block.timestamp + 100;
        bytes32 stf = computeStfFull(0, 100, bytes32(0), bytes32(0), wrongDomain, ts);
        bytes memory proof = encodeProof(stf);
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
    function testFuzz_windowIndexOnlyIncrements(uint8 n) public {
        vm.assume(n > 0 && n <= 10);
        uint256 l2End = 100;
        uint256 ts = block.timestamp + 3600;
        for (uint8 i = 0; i < n; i++) {
            uint256 start = l2End * i;
            uint256 end = l2End * (i + 1);
            bytes32 stf = computeStfFull(start, end, bytes32(0), bytes32(0), DOMAIN, ts);
            bytes memory proof = encodeProof(stf);
            bytes memory inputs = abi.encode(
                stf,
                start,
                end,
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
        bytes32 stfGenesis = computeStfFull(0, 100, bytes32(0), bytes32(0), DOMAIN, ts);
        bytes memory proof = encodeProof(stfGenesis);
        bytes memory inputs = abi.encode(stfGenesis, uint256(0), uint256(100), bytes32(0), bytes32(0), DOMAIN, ts);
        finalizer.submitZkValidityProof(proof, inputs);

        // Now attempt a non-contiguous submission (l2Start != 100) on window 1.
        vm.assume(uint256(l2Start) != 100);
        vm.assume(uint256(l2End) > uint256(l2Start));

        bytes32 stfBad = computeStfFull(uint256(l2Start), uint256(l2End), bytes32(0), bytes32(0), DOMAIN, ts);
        proof = encodeProof(stfBad);
        inputs = abi.encode(stfBad, uint256(l2Start), uint256(l2End), bytes32(0), bytes32(0), DOMAIN, ts);
        vm.expectRevert(WorldlineFinalizer.NotContiguous.selector);
        finalizer.submitZkValidityProof(proof, inputs);
    }

    /// Any windowCloseTimestamp older than block.timestamp - maxAcceptanceDelay must revert.
    function testFuzz_rejectStaleProof(uint32 delayPastMax) public {
        vm.assume(delayPastMax >= 1);
        uint256 windowCloseTimestamp = block.timestamp - MAX_DELAY - uint256(delayPastMax);

        bytes32 stf = computeStfFull(0, 100, bytes32(0), bytes32(0), DOMAIN, windowCloseTimestamp);
        bytes memory proof = encodeProof(stf);
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
        uint256 ts = block.timestamp + 100;
        bytes32 stf = computeStfFull(uint256(l2Start), uint256(l2Start), bytes32(0), bytes32(0), DOMAIN, ts);
        bytes memory proof = encodeProof(stf);
        bytes memory inputs = abi.encode(
            stf,
            uint256(l2Start),
            uint256(l2Start),
            bytes32(0),
            bytes32(0),
            DOMAIN,
            ts
        );
        vm.expectRevert(WorldlineFinalizer.InvalidWindowRange.selector);
        finalizer.submitZkValidityProof(proof, inputs);
    }
}
