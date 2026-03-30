// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/zk/Halo2Verifier.sol";
import "../src/zk/Halo2ZkAdapter.sol";
import "../src/IZkAdapter.sol";

/// @title MockHalo2Verifier
/// @notice Mock verifier that returns a pre-set result for testing adapter logic.
contract MockHalo2Verifier {
    bool private immutable _result;

    constructor(bool result_) {
        _result = result_;
    }

    function verifyProof(
        bytes calldata,
        uint256[] calldata instances
    ) external view returns (bool) {
        // Require correct instance count
        require(instances.length == 2, "bad instance count");
        return _result;
    }
}

/// @title Halo2VerifierTest
/// @notice Tests for the Halo2Verifier and Halo2ZkAdapter contracts.
///         Run with: forge test --match-contract Halo2VerifierTest -v
contract Halo2VerifierTest is Test {
    bytes32 constant PROGRAM_VKEY = keccak256("halo2-program-vkey");
    bytes32 constant POLICY_HASH = keccak256("halo2-policy-hash");

    /// @dev Helper: create a valid-format Halo2 proof envelope (adapter format).
    function _makeProofEnvelope(
        uint256 proofLen,
        uint256 stfCommitment,
        uint256 proverSetDigest
    ) internal pure returns (bytes memory) {
        // Create fake proof bytes of the given length
        bytes memory proofBytes = new bytes(proofLen);
        for (uint256 i = 0; i < proofLen; i++) {
            proofBytes[i] = bytes1(uint8(i % 256));
        }
        return abi.encode(proofBytes, stfCommitment, proverSetDigest);
    }

    // ── 1. Deploy Halo2Verifier — succeeds ──────────────────────────────────

    function test_deployHalo2Verifier() public {
        Halo2Verifier verifier = new Halo2Verifier();
        // The generated verifier has no constructor args and exposes verifyProof.
        // Verify deployment succeeded by checking code exists.
        assertTrue(address(verifier).code.length > 0, "Verifier should have code");
    }

    // ── 2. Deploy Halo2ZkAdapter with verifier address — succeeds ───────────

    function test_deployHalo2ZkAdapter() public {
        Halo2Verifier verifier = new Halo2Verifier();
        Halo2ZkAdapter adapter = new Halo2ZkAdapter(
            address(verifier), PROGRAM_VKEY, POLICY_HASH
        );

        assertEq(adapter.verifierAddress(), address(verifier));
        assertEq(adapter.programVKeyPinned(), PROGRAM_VKEY);
        assertEq(adapter.policyHashPinned(), POLICY_HASH);
    }

    // ── 3. Adapter reports proofSystemId=3 ──────────────────────────────────

    function test_adapterReportsProofSystemId3() public {
        MockHalo2Verifier mock = new MockHalo2Verifier(true);
        Halo2ZkAdapter adapter = new Halo2ZkAdapter(
            address(mock), PROGRAM_VKEY, POLICY_HASH
        );
        assertEq(adapter.proofSystemId(), 3);
    }

    // ── 4. Adapter reports correct expectedProofLength ──────────────────────

    function test_adapterReportsExpectedProofLength() public {
        MockHalo2Verifier mock = new MockHalo2Verifier(true);
        Halo2ZkAdapter adapter = new Halo2ZkAdapter(
            address(mock), PROGRAM_VKEY, POLICY_HASH
        );
        assertEq(adapter.expectedProofLength(), 2144);
        assertEq(adapter.HALO2_PROOF_MIN_LEN(), 2144);
    }

    // ── 5. Adapter rejects proof with wrong length ──────────────────────────

    function test_adapterRejectsShortProof() public {
        MockHalo2Verifier mock = new MockHalo2Verifier(true);
        Halo2ZkAdapter adapter = new Halo2ZkAdapter(
            address(mock), PROGRAM_VKEY, POLICY_HASH
        );

        // Create a short proof (less than HALO2_PROOF_MIN_LEN)
        bytes memory shortProof = abi.encode(uint256(1), uint256(2));

        vm.expectRevert(
            abi.encodeWithSelector(
                Halo2ZkAdapter.ProofTooShort.selector,
                2144,
                shortProof.length
            )
        );
        adapter.verify(shortProof, new bytes(0));
    }

    // ── 6. Adapter conforms to IZkAdapter interface ─────────────────────────

    function test_adapterConformsToIZkAdapter() public {
        MockHalo2Verifier mock = new MockHalo2Verifier(true);
        Halo2ZkAdapter adapter = new Halo2ZkAdapter(
            address(mock), PROGRAM_VKEY, POLICY_HASH
        );

        // Test through the IZkAdapter interface
        IZkAdapter iAdapter = IZkAdapter(address(adapter));
        assertEq(iAdapter.proofSystemId(), 3);
        assertEq(iAdapter.expectedProofLength(), 2144);
    }

    // ── 7. Valid proof envelope — succeeds via IZkAggregatorVerifier ────────

    function test_validProofEnvelope() public {
        MockHalo2Verifier mock = new MockHalo2Verifier(true);
        Halo2ZkAdapter adapter = new Halo2ZkAdapter(
            address(mock), PROGRAM_VKEY, POLICY_HASH
        );

        uint256 stfVal = uint256(keccak256("stf-halo2"));
        uint256 digestVal = uint256(keccak256("digest-halo2"));
        bytes memory envelope = _makeProofEnvelope(2016, stfVal, digestVal);

        (bool valid, bytes32 stf, bytes32 vkey, bytes32 policy, bytes32 digest) =
            adapter.verify(envelope, new bytes(0));

        assertTrue(valid);
        assertEq(stf, bytes32(stfVal));
        assertEq(vkey, PROGRAM_VKEY);
        assertEq(policy, POLICY_HASH);
        assertEq(digest, bytes32(digestVal));
    }

    // ── 8. Adapter reverts when verifier returns false ──────────────────────

    function test_adapterRevertsOnInvalidProof() public {
        MockHalo2Verifier mock = new MockHalo2Verifier(false);
        Halo2ZkAdapter adapter = new Halo2ZkAdapter(
            address(mock), PROGRAM_VKEY, POLICY_HASH
        );

        uint256 stfVal = uint256(keccak256("stf"));
        uint256 digestVal = uint256(keccak256("digest"));
        bytes memory envelope = _makeProofEnvelope(2016, stfVal, digestVal);

        vm.expectRevert(Halo2ZkAdapter.ProofInvalid.selector);
        adapter.verify(envelope, new bytes(0));
    }

    // ── 9. IZkAdapter thin verify path works ────────────────────────────────

    function test_thinVerifyPath() public {
        MockHalo2Verifier mock = new MockHalo2Verifier(true);
        Halo2ZkAdapter adapter = new Halo2ZkAdapter(
            address(mock), PROGRAM_VKEY, POLICY_HASH
        );

        uint256 stfVal = uint256(keccak256("stf-thin"));
        uint256 digestVal = uint256(keccak256("digest-thin"));
        bytes memory envelope = _makeProofEnvelope(2016, stfVal, digestVal);

        bytes32[] memory pubInputs = new bytes32[](0);
        bool valid = IZkAdapter(address(adapter)).verify(envelope, pubInputs);
        assertTrue(valid);
    }

    // ── 10. Real Halo2Verifier rejects invalid proof data ───────────────────
    // Note: The real verifier performs full KZG pairing verification.
    // Submitting random bytes will cause the pairing check to fail (revert).
    // This is correct behavior — a real valid proof is needed.
    // The hardening session will add tests with real proofs.

    function test_realVerifierRejectsInvalidProof() public {
        Halo2Verifier verifier = new Halo2Verifier();

        bytes memory proof = new bytes(2016);
        uint256[] memory instances = new uint256[](2);
        instances[0] = 1;
        instances[1] = 2;

        // The real verifier will revert on invalid proof data
        vm.expectRevert();
        verifier.verifyProof(proof, instances);
    }

    // ── 11. Adapter with real verifier rejects invalid proof envelope ───────

    function test_adapterWithRealVerifierRejectsInvalid() public {
        Halo2Verifier verifier = new Halo2Verifier();
        Halo2ZkAdapter adapter = new Halo2ZkAdapter(
            address(verifier), PROGRAM_VKEY, POLICY_HASH
        );

        uint256 stfVal = uint256(keccak256("stf"));
        uint256 digestVal = uint256(keccak256("digest"));
        bytes memory envelope = _makeProofEnvelope(2016, stfVal, digestVal);

        // The real verifier will reject invalid proof data via the adapter
        vm.expectRevert();
        adapter.verify(envelope, new bytes(0));
    }

    // ── 12. Adapter with real verifier via IZkAdapter rejects invalid ───────

    function test_thinVerifyWithRealVerifierRejectsInvalid() public {
        Halo2Verifier verifier = new Halo2Verifier();
        Halo2ZkAdapter adapter = new Halo2ZkAdapter(
            address(verifier), PROGRAM_VKEY, POLICY_HASH
        );

        uint256 stfVal = uint256(keccak256("stf-thin"));
        uint256 digestVal = uint256(keccak256("digest-thin"));
        bytes memory envelope = _makeProofEnvelope(2016, stfVal, digestVal);

        bytes32[] memory pubInputs = new bytes32[](0);
        // The real verifier will reject — no valid proof
        vm.expectRevert();
        IZkAdapter(address(adapter)).verify(envelope, pubInputs);
    }
}
