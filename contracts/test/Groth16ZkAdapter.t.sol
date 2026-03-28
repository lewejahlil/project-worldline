// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/zk/Groth16ZkAdapter.sol";
import "../src/zk/Groth16Verifier.sol";
import "../src/zk/Verifier.sol";

/// @title ViewMockGroth16Verifier
/// @notice View-compatible mock that always returns a pre-set result.
///         Since the adapter's verify() is view, it uses STATICCALL — so the mock
///         cannot write state. We verify the decoded values via the adapter's return values.
contract ViewMockGroth16Verifier {
    bool private immutable _result;

    constructor(bool result_) {
        _result = result_;
    }

    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[2] calldata
    ) external view returns (bool) {
        return _result;
    }
}

/// @title PubSignalsCheckingMock
/// @notice View-compatible mock that reverts if pubSignals don't match expected values.
///         Used to verify that the adapter passes the correct pubSignals to the verifier.
contract PubSignalsCheckingMock {
    uint256 private immutable _expectedSig0;
    uint256 private immutable _expectedSig1;

    constructor(uint256 sig0, uint256 sig1) {
        _expectedSig0 = sig0;
        _expectedSig1 = sig1;
    }

    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[2] calldata pubSignals
    ) external view returns (bool) {
        require(pubSignals[0] == _expectedSig0, "pubSignals[0] mismatch");
        require(pubSignals[1] == _expectedSig1, "pubSignals[1] mismatch");
        return true;
    }
}

/// @title Groth16ZkAdapterTest
/// @notice Tests for the Groth16ZkAdapter, covering both dev and production branches.
///         Run with: forge test --match-contract Groth16ZkAdapter -v
contract Groth16ZkAdapterTest is Test {
    bytes32 constant PROGRAM_VKEY = keccak256("program-vkey");
    bytes32 constant POLICY_HASH = keccak256("policy-hash");

    // ── Dev mode tests ──────────────────────────────────────────────────────

    function test_devMode_decodesDevProofLayout() public {
        Verifier verifier = new Verifier();
        Groth16ZkAdapter adapter = new Groth16ZkAdapter(
            address(verifier), PROGRAM_VKEY, POLICY_HASH, true
        );

        bytes32 stfCommitment = keccak256("stf");
        bytes32 proverDigest = keccak256("digest");
        bytes memory proof = abi.encode(stfCommitment, PROGRAM_VKEY, POLICY_HASH, proverDigest);
        bytes memory publicInputs = new bytes(0);

        (bool valid, bytes32 stf, bytes32 vkey, bytes32 policy, bytes32 digest) =
            adapter.verify(proof, publicInputs);

        assertTrue(valid);
        assertEq(stf, stfCommitment);
        assertEq(vkey, PROGRAM_VKEY);
        assertEq(policy, POLICY_HASH);
        assertEq(digest, proverDigest);
    }

    function test_devMode_revertsOnProgramVKeyMismatch() public {
        Verifier verifier = new Verifier();
        Groth16ZkAdapter adapter = new Groth16ZkAdapter(
            address(verifier), PROGRAM_VKEY, POLICY_HASH, true
        );

        bytes memory proof = abi.encode(
            keccak256("stf"), keccak256("wrong-vkey"), POLICY_HASH, keccak256("digest")
        );
        vm.expectRevert(Groth16ZkAdapter.ProgramVKeyMismatch.selector);
        adapter.verify(proof, new bytes(0));
    }

    // ── Production mode tests ───────────────────────────────────────────────

    function test_prodMode_decodesProductionProofLayout() public {
        ViewMockGroth16Verifier mock = new ViewMockGroth16Verifier(true);
        Groth16ZkAdapter adapter = new Groth16ZkAdapter(
            address(mock), PROGRAM_VKEY, POLICY_HASH, false
        );

        // Construct a production-format proof.
        uint256[2] memory pA = [uint256(1), uint256(2)];
        uint256[2][2] memory pB = [[uint256(3), uint256(4)], [uint256(5), uint256(6)]];
        uint256[2] memory pC = [uint256(7), uint256(8)];
        uint256 stfCommitment = uint256(keccak256("stf-prod"));
        uint256 proverSetDigest = uint256(keccak256("digest-prod"));

        bytes memory proof = abi.encode(pA, pB, pC, stfCommitment, proverSetDigest);
        bytes memory publicInputs = new bytes(0);

        (bool valid, bytes32 stf, bytes32 vkey, bytes32 policy, bytes32 digest) =
            adapter.verify(proof, publicInputs);

        // Verify returned signals.
        assertTrue(valid);
        assertEq(stf, bytes32(stfCommitment));
        assertEq(vkey, PROGRAM_VKEY);
        assertEq(policy, POLICY_HASH);
        assertEq(digest, bytes32(proverSetDigest));
    }

    function test_prodMode_revertsOnUndersizedProof() public {
        ViewMockGroth16Verifier mock = new ViewMockGroth16Verifier(true);
        Groth16ZkAdapter adapter = new Groth16ZkAdapter(
            address(mock), PROGRAM_VKEY, POLICY_HASH, false
        );

        // 128 bytes < 320 byte minimum.
        bytes memory shortProof = abi.encode(
            keccak256("a"), keccak256("b"), keccak256("c"), keccak256("d")
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                Groth16ZkAdapter.ProofTooShort.selector,
                320,
                shortProof.length
            )
        );
        adapter.verify(shortProof, new bytes(0));
    }

    function test_prodMode_revertsWhenVerifierReturnsFalse() public {
        ViewMockGroth16Verifier mock = new ViewMockGroth16Verifier(false);
        Groth16ZkAdapter adapter = new Groth16ZkAdapter(
            address(mock), PROGRAM_VKEY, POLICY_HASH, false
        );

        uint256[2] memory pA = [uint256(1), uint256(2)];
        uint256[2][2] memory pB = [[uint256(3), uint256(4)], [uint256(5), uint256(6)]];
        uint256[2] memory pC = [uint256(7), uint256(8)];
        uint256 stfCommitment = uint256(keccak256("stf"));
        uint256 proverSetDigest = uint256(keccak256("digest"));

        bytes memory proof = abi.encode(pA, pB, pC, stfCommitment, proverSetDigest);

        vm.expectRevert(Groth16ZkAdapter.ProofInvalid.selector);
        adapter.verify(proof, new bytes(0));
    }

    function test_prodMode_pubSignalsMatchDecodedValues() public {
        // Use a checking mock that validates pubSignals inline and reverts on mismatch.
        uint256 stf = 0x1234;
        uint256 digest = 0x5678;
        PubSignalsCheckingMock mock = new PubSignalsCheckingMock(stf, digest);
        Groth16ZkAdapter adapter = new Groth16ZkAdapter(
            address(mock), PROGRAM_VKEY, POLICY_HASH, false
        );

        uint256[2] memory pA = [uint256(10), uint256(20)];
        uint256[2][2] memory pB = [[uint256(30), uint256(40)], [uint256(50), uint256(60)]];
        uint256[2] memory pC = [uint256(70), uint256(80)];

        bytes memory proof = abi.encode(pA, pB, pC, stf, digest);

        // If pubSignals don't match, the checking mock reverts — so success proves binding.
        (bool valid,,,, ) = adapter.verify(proof, new bytes(0));
        assertTrue(valid, "verify must succeed when pubSignals match");
    }

    function test_PROD_PROOF_MIN_LEN_is_320() public {
        ViewMockGroth16Verifier mock = new ViewMockGroth16Verifier(true);
        Groth16ZkAdapter adapter = new Groth16ZkAdapter(
            address(mock), PROGRAM_VKEY, POLICY_HASH, false
        );
        assertEq(adapter.PROD_PROOF_MIN_LEN(), 320);
    }
}
