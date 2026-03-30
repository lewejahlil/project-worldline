// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/zk/Halo2Verifier.sol";
import "../src/zk/Halo2ZkAdapter.sol";
import "../src/IZkAdapter.sol";

/// @title Halo2RealVerifierTest
/// @notice Tests the real Halo2Verifier with a genuine KZG proof fixture.
///         The fixture is generated deterministically by:
///         cargo run -p worldline-halo2-circuit --example generate_fixture
///
///         Run with: forge test --match-contract Halo2RealVerifierTest -v
contract Halo2RealVerifierTest is Test {
    bytes32 constant PROGRAM_VKEY = keccak256("halo2-program-vkey");
    bytes32 constant POLICY_HASH = keccak256("halo2-policy-hash");

    Halo2Verifier verifier;
    Halo2ZkAdapter adapter;

    // Fixture data loaded from JSON
    bytes proofBytes;
    uint256 stfCommitment;
    uint256 proverSetDigest;

    function setUp() public {
        // Deploy real verifier and adapter
        verifier = new Halo2Verifier();
        adapter = new Halo2ZkAdapter(address(verifier), PROGRAM_VKEY, POLICY_HASH);

        // Load fixture
        string memory json = vm.readFile("test/fixtures/halo2-proof-fixture.json");
        proofBytes = vm.parseJsonBytes(json, ".proof.rawBytes");
        stfCommitment = vm.parseJsonUint(json, ".publicOutputs.stfCommitment");
        proverSetDigest = vm.parseJsonUint(json, ".publicOutputs.proverSetDigest");
    }

    // ── 1. Real verifier accepts genuine proof ─────────────────────────────

    function test_realVerifierAcceptsValidProof() public view {
        uint256[] memory instances = new uint256[](2);
        instances[0] = stfCommitment;
        instances[1] = proverSetDigest;

        bool valid = verifier.verifyProof(proofBytes, instances);
        assertTrue(valid, "Real Halo2 verifier must accept a valid KZG proof");
    }

    // ── 2. Real verifier rejects proof with wrong stfCommitment ────────────

    function test_realVerifierRejectsWrongStfCommitment() public {
        uint256[] memory instances = new uint256[](2);
        instances[0] = stfCommitment ^ 1; // flip one bit
        instances[1] = proverSetDigest;

        // The real verifier should revert or return false — pairing check fails
        vm.expectRevert();
        verifier.verifyProof(proofBytes, instances);
    }

    // ── 3. Real verifier rejects proof with wrong proverSetDigest ──────────

    function test_realVerifierRejectsWrongDigest() public {
        uint256[] memory instances = new uint256[](2);
        instances[0] = stfCommitment;
        instances[1] = proverSetDigest ^ 1; // flip one bit

        vm.expectRevert();
        verifier.verifyProof(proofBytes, instances);
    }

    // ── 4. Real verifier rejects corrupted proof bytes ─────────────────────

    function test_realVerifierRejectsCorruptedProof() public {
        // Flip a byte in the middle of the proof
        bytes memory corruptedProof = new bytes(proofBytes.length);
        for (uint256 i = 0; i < proofBytes.length; i++) {
            corruptedProof[i] = proofBytes[i];
        }
        corruptedProof[100] = bytes1(uint8(corruptedProof[100]) ^ 0xff);

        uint256[] memory instances = new uint256[](2);
        instances[0] = stfCommitment;
        instances[1] = proverSetDigest;

        vm.expectRevert();
        verifier.verifyProof(corruptedProof, instances);
    }

    // ── 5. Adapter agg path accepts valid proof via real verifier ───────────

    function test_adapterAggPathAcceptsValidProof() public view {
        bytes memory envelope = abi.encode(proofBytes, stfCommitment, proverSetDigest);

        (bool valid, bytes32 stf, bytes32 vkey, bytes32 policy, bytes32 digest) =
            adapter.verify(envelope, new bytes(0));

        assertTrue(valid, "Adapter must accept valid proof through real verifier");
        assertEq(stf, bytes32(stfCommitment), "stfCommitment mismatch");
        assertEq(vkey, PROGRAM_VKEY, "programVKey mismatch");
        assertEq(policy, POLICY_HASH, "policyHash mismatch");
        assertEq(digest, bytes32(proverSetDigest), "proverSetDigest mismatch");
    }

    // ── 6. Adapter thin path accepts valid proof via real verifier ──────────

    function test_adapterThinPathAcceptsValidProof() public view {
        bytes memory envelope = abi.encode(proofBytes, stfCommitment, proverSetDigest);

        bytes32[] memory pubInputs = new bytes32[](0);
        bool valid = IZkAdapter(address(adapter)).verify(envelope, pubInputs);
        assertTrue(valid, "Thin verify path must accept valid proof");
    }

    // ── 7. Adapter rejects corrupted proof via real verifier ───────────────

    function test_adapterRejectsCorruptedProofViaRealVerifier() public {
        bytes memory corruptedProof = new bytes(proofBytes.length);
        for (uint256 i = 0; i < proofBytes.length; i++) {
            corruptedProof[i] = proofBytes[i];
        }
        corruptedProof[100] = bytes1(uint8(corruptedProof[100]) ^ 0xff);

        bytes memory envelope = abi.encode(corruptedProof, stfCommitment, proverSetDigest);

        // Adapter should revert because the real verifier rejects
        vm.expectRevert();
        adapter.verify(envelope, new bytes(0));
    }

    // ── 8. Adapter rejects wrong instances via real verifier ────────────────

    function test_adapterRejectsWrongInstancesViaRealVerifier() public {
        // Valid proof bytes but wrong stfCommitment — pairing check fails
        bytes memory envelope = abi.encode(proofBytes, stfCommitment ^ 1, proverSetDigest);

        vm.expectRevert();
        adapter.verify(envelope, new bytes(0));
    }
}
