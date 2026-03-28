// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/zk/PlonkZkAdapter.sol";
import "../src/test/MockPlonkVerifier.sol";

/// @title ViewMockPlonkVerifier
/// @notice View-compatible mock that always returns a pre-set result.
///         Since the adapter's verify() is view, it uses STATICCALL — so the mock
///         cannot write state. We verify the decoded values via the adapter's return values.
contract ViewMockPlonkVerifier {
    bool private immutable _result;

    constructor(bool result_) {
        _result = result_;
    }

    function verifyProof(
        uint256[24] calldata,
        uint256[2] calldata
    ) external view returns (bool) {
        return _result;
    }
}

/// @title PubSignalsCheckingPlonkMock
/// @notice View-compatible mock that reverts if pubSignals don't match expected values.
///         Used to verify that the adapter passes the correct pubSignals to the verifier.
contract PubSignalsCheckingPlonkMock {
    uint256 private immutable _expectedSig0;
    uint256 private immutable _expectedSig1;

    constructor(uint256 sig0, uint256 sig1) {
        _expectedSig0 = sig0;
        _expectedSig1 = sig1;
    }

    function verifyProof(
        uint256[24] calldata,
        uint256[2] calldata pubSignals
    ) external view returns (bool) {
        require(pubSignals[0] == _expectedSig0, "pubSignals[0] mismatch");
        require(pubSignals[1] == _expectedSig1, "pubSignals[1] mismatch");
        return true;
    }
}

/// @title PlonkVerifierTest
/// @notice Tests for the PlonkZkAdapter.
///         Run with: forge test --match-path "contracts/test/PlonkVerifier.t.sol" -v
contract PlonkVerifierTest is Test {
    bytes32 constant PROGRAM_VKEY = keccak256("program-vkey-plonk");
    bytes32 constant POLICY_HASH = keccak256("policy-hash-plonk");

    // ── Helper: build a valid 832-byte proof ─────────────────────────────────

    function _buildProof(uint256 stfCommitment, uint256 proverSetDigest)
        internal
        pure
        returns (bytes memory)
    {
        uint256[24] memory proofWords;
        // Fill with dummy non-zero values
        for (uint256 i = 0; i < 24; i++) {
            proofWords[i] = i + 1;
        }
        return abi.encode(proofWords, stfCommitment, proverSetDigest);
    }

    // ── 1. Deploy MockPlonkVerifier succeeds ─────────────────────────────────

    function test_deployMockPlonkVerifier() public {
        MockPlonkVerifier mock = new MockPlonkVerifier();
        // Sanity: mock always returns true
        uint256[24] memory dummyProof;
        uint256[2] memory dummySignals;
        assertTrue(mock.verifyProof(dummyProof, dummySignals));
    }

    // ── 2. Deploy PlonkZkAdapter with mock verifier succeeds ─────────────────

    function test_deployPlonkZkAdapter() public {
        ViewMockPlonkVerifier mock = new ViewMockPlonkVerifier(true);
        PlonkZkAdapter adapter = new PlonkZkAdapter(
            address(mock), PROGRAM_VKEY, POLICY_HASH
        );
        assertEq(adapter.verifierAddress(), address(mock));
        assertEq(adapter.programVKeyPinned(), PROGRAM_VKEY);
        assertEq(adapter.policyHashPinned(), POLICY_HASH);
    }

    // ── 3. proofSystemId() returns 2 ─────────────────────────────────────────

    function test_proofSystemId_is_2() public {
        ViewMockPlonkVerifier mock = new ViewMockPlonkVerifier(true);
        PlonkZkAdapter adapter = new PlonkZkAdapter(
            address(mock), PROGRAM_VKEY, POLICY_HASH
        );
        assertEq(adapter.proofSystemId(), 2);
    }

    // ── 4. expectedProofLength() returns 832 ─────────────────────────────────

    function test_expectedProofLength_is_832() public {
        ViewMockPlonkVerifier mock = new ViewMockPlonkVerifier(true);
        PlonkZkAdapter adapter = new PlonkZkAdapter(
            address(mock), PROGRAM_VKEY, POLICY_HASH
        );
        assertEq(adapter.expectedProofLength(), 832);
    }

    // ── 5. PROD_PROOF_MIN_LEN constant is 832 ────────────────────────────────

    function test_PROD_PROOF_MIN_LEN_is_832() public {
        ViewMockPlonkVerifier mock = new ViewMockPlonkVerifier(true);
        PlonkZkAdapter adapter = new PlonkZkAdapter(
            address(mock), PROGRAM_VKEY, POLICY_HASH
        );
        assertEq(adapter.PROD_PROOF_MIN_LEN(), 832);
    }

    // ── 6. Reject proof shorter than 832 bytes (thin path) ───────────────────

    function test_thinVerify_revertsOnShortProof() public {
        ViewMockPlonkVerifier mock = new ViewMockPlonkVerifier(true);
        PlonkZkAdapter adapter = new PlonkZkAdapter(
            address(mock), PROGRAM_VKEY, POLICY_HASH
        );

        // 128 bytes < 832 byte minimum
        bytes memory shortProof = abi.encode(
            keccak256("a"), keccak256("b"), keccak256("c"), keccak256("d")
        );

        bytes32[] memory emptyInputs = new bytes32[](0);
        vm.expectRevert(
            abi.encodeWithSelector(
                PlonkZkAdapter.ProofTooShort.selector,
                832,
                shortProof.length
            )
        );
        adapter.verify(shortProof, emptyInputs);
    }

    // ── 7. Accept valid-length proof — thin path returns true ─────────────────

    function test_thinVerify_acceptsValidLengthProof() public {
        ViewMockPlonkVerifier mock = new ViewMockPlonkVerifier(true);
        PlonkZkAdapter adapter = new PlonkZkAdapter(
            address(mock), PROGRAM_VKEY, POLICY_HASH
        );

        bytes memory proof = _buildProof(999, 888);
        assertEq(proof.length, 832);

        bytes32[] memory emptyInputs = new bytes32[](0);
        bool valid = adapter.verify(proof, emptyInputs);
        assertTrue(valid);
    }

    // ── 8. Aggregated verify — decodes proof layout correctly ─────────────────

    function test_aggVerify_decodesProofLayout() public {
        ViewMockPlonkVerifier mock = new ViewMockPlonkVerifier(true);
        PlonkZkAdapter adapter = new PlonkZkAdapter(
            address(mock), PROGRAM_VKEY, POLICY_HASH
        );

        uint256 stfCommitment = uint256(keccak256("stf-plonk-prod"));
        uint256 proverSetDigest = uint256(keccak256("digest-plonk-prod"));
        bytes memory proof = _buildProof(stfCommitment, proverSetDigest);
        bytes memory publicInputs = new bytes(0);

        (bool valid, bytes32 stf, bytes32 vkey, bytes32 policy, bytes32 digest) =
            adapter.verify(proof, publicInputs);

        assertTrue(valid);
        assertEq(stf, bytes32(stfCommitment));
        assertEq(vkey, PROGRAM_VKEY);
        assertEq(policy, POLICY_HASH);
        assertEq(digest, bytes32(proverSetDigest));
    }

    // ── 9. Aggregated verify — rejects short proof ────────────────────────────

    function test_aggVerify_revertsOnShortProof() public {
        ViewMockPlonkVerifier mock = new ViewMockPlonkVerifier(true);
        PlonkZkAdapter adapter = new PlonkZkAdapter(
            address(mock), PROGRAM_VKEY, POLICY_HASH
        );

        bytes memory shortProof = abi.encode(keccak256("a"), keccak256("b"), keccak256("c"), keccak256("d"));

        vm.expectRevert(
            abi.encodeWithSelector(
                PlonkZkAdapter.ProofTooShort.selector,
                832,
                shortProof.length
            )
        );
        adapter.verify(shortProof, new bytes(0));
    }

    // ── 10. Aggregated verify — reverts when verifier returns false ───────────

    function test_aggVerify_revertsWhenVerifierReturnsFalse() public {
        ViewMockPlonkVerifier mock = new ViewMockPlonkVerifier(false);
        PlonkZkAdapter adapter = new PlonkZkAdapter(
            address(mock), PROGRAM_VKEY, POLICY_HASH
        );

        uint256 stfCommitment = uint256(keccak256("stf"));
        uint256 proverSetDigest = uint256(keccak256("digest"));
        bytes memory proof = _buildProof(stfCommitment, proverSetDigest);

        vm.expectRevert(PlonkZkAdapter.ProofInvalid.selector);
        adapter.verify(proof, new bytes(0));
    }

    // ── 11. pubSignals bound to the proof values ──────────────────────────────

    function test_pubSignals_matchDecodedValues() public {
        uint256 stf = 0xABCD;
        uint256 digest = 0xEF01;
        PubSignalsCheckingPlonkMock mock = new PubSignalsCheckingPlonkMock(stf, digest);
        PlonkZkAdapter adapter = new PlonkZkAdapter(
            address(mock), PROGRAM_VKEY, POLICY_HASH
        );

        bytes memory proof = _buildProof(stf, digest);

        // If pubSignals don't match, the checking mock reverts — so success proves binding.
        (bool valid,,,, ) = adapter.verify(proof, new bytes(0));
        assertTrue(valid, "verify must succeed when pubSignals match");
    }

    // ── 12. Proof length is exactly 832 bytes ────────────────────────────────

    function test_proofEncodingLength_is_832() public pure {
        uint256[24] memory proofWords;
        for (uint256 i = 0; i < 24; i++) {
            proofWords[i] = i + 1;
        }
        uint256 stfCommit = 999;
        uint256 proverDigest = 888;
        bytes memory proof = abi.encode(proofWords, stfCommit, proverDigest);
        assertEq(proof.length, 832);
    }
}
