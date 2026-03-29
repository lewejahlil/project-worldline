// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../src/WorldlineFinalizer.sol";
import "../src/zk/Groth16ZkAdapter.sol";

/// @notice View-compatible mock that always returns true for Groth16 verification.
///         Shared across all Forge test suites that need a finalizer with a mock adapter.
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

/// @title Shared base contract for WorldlineFinalizer Forge tests.
/// @notice Provides common setup, constants, and proof encoding helpers.
///         Subclasses override setUp() to customize genesis block, warp time, etc.
abstract contract WorldlineTestBase is Test {
    WorldlineFinalizer finalizer;
    Groth16ZkAdapter adapter;

    bytes32 constant DOMAIN = keccak256("finalizer-test-domain");
    bytes32 constant PROGRAM_VKEY = keccak256("program-vkey");
    bytes32 constant POLICY_HASH = keccak256("policy-hash");
    bytes32 constant PROVER_DIGEST = keccak256("prover-set");

    /// @dev Deploy finalizer behind a UUPS proxy with a ViewMockGroth16Verifier.
    function _deployFinalizer(
        uint256 maxAcceptanceDelay,
        uint256 genesisL2Block
    ) internal {
        ViewMockGroth16Verifier mock = new ViewMockGroth16Verifier();
        adapter = new Groth16ZkAdapter(address(mock), PROGRAM_VKEY, POLICY_HASH);
        WorldlineFinalizer finImpl = new WorldlineFinalizer();
        ERC1967Proxy finProxy = new ERC1967Proxy(
            address(finImpl),
            abi.encodeCall(
                WorldlineFinalizer.initialize,
                (address(adapter), DOMAIN, maxAcceptanceDelay, genesisL2Block, address(0))
            )
        );
        finalizer = WorldlineFinalizer(address(finProxy));
    }

    /// @dev Compute stfCommitment = keccak256(abi.encode(l2Start, l2End, outputRoot, l1BlockHash, domain, windowCloseTimestamp))
    function computeStf(
        uint256 l2Start,
        uint256 l2End,
        uint256 windowCloseTimestamp
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(l2Start, l2End, bytes32(0), bytes32(0), DOMAIN, windowCloseTimestamp));
    }

    /// @dev Full-parameter stfCommitment computation.
    function computeStfFull(
        uint256 l2Start,
        uint256 l2End,
        bytes32 outputRoot,
        bytes32 l1BlockHash,
        bytes32 domain,
        uint256 windowCloseTimestamp
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(l2Start, l2End, outputRoot, l1BlockHash, domain, windowCloseTimestamp));
    }

    /// @dev Encode 224-byte public inputs for submitZkValidityProof.
    function encodeInputs(
        uint256 l2Start,
        uint256 l2End,
        uint256 windowCloseTimestamp
    ) internal pure returns (bytes memory) {
        bytes32 stf = computeStf(l2Start, l2End, windowCloseTimestamp);
        return abi.encode(stf, l2Start, l2End, bytes32(0), bytes32(0), DOMAIN, windowCloseTimestamp);
    }

    /// @dev Encode a 320-byte Groth16 proof embedding the given stfCommitment.
    function encodeProof(bytes32 stf) internal pure returns (bytes memory) {
        uint256[2] memory pA = [uint256(1), uint256(2)];
        uint256[2][2] memory pB = [[uint256(3), uint256(4)], [uint256(5), uint256(6)]];
        uint256[2] memory pC = [uint256(7), uint256(8)];
        return abi.encode(pA, pB, pC, uint256(stf), uint256(PROVER_DIGEST));
    }
}
