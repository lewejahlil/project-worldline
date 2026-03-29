// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../src/zk/Groth16Verifier.sol";
import "../src/zk/Groth16ZkAdapter.sol";
import "../src/WorldlineRegistry.sol";
import "../src/WorldlineFinalizer.sol";
import "../src/test/MockGroth16Verifier.sol";
import "../src/interfaces/IZkAggregatorVerifier.sol";

/// @notice Local mock adapter that echoes stfCommitment from the first 32 bytes of publicInputs.
contract EchoMockAdapter is IZkAggregatorVerifier {
    function verify(
        bytes calldata, /*proof*/
        bytes calldata publicInputs
    )
        external
        pure
        override
        returns (
            bool valid,
            bytes32 stfCommitment,
            bytes32 programVKey,
            bytes32 policyHash,
            bytes32 proverSetDigest
        )
    {
        stfCommitment = abi.decode(publicInputs, (bytes32));
        valid = true;
        programVKey = bytes32(0);
        policyHash = bytes32(0);
        proverSetDigest = bytes32(0);
    }
}

contract GasBenchmarkTest is Test {
    function setUp() public {
        vm.warp(1_000_000);
    }

    /// @notice Benchmark raw Groth16 BN254 pairing verification (returns false — invalid proof, gas measured).
    function test_gas_groth16_verify() public {
        Groth16Verifier verifier = new Groth16Verifier();
        bool result = verifier.verifyProof(
            [uint256(1), uint256(2)],
            [[uint256(3), uint256(4)], [uint256(5), uint256(6)]],
            [uint256(7), uint256(8)],
            [uint256(0), uint256(0)]
        );
        // result is false for invalid proof — assignment prevents compiler optimisation
        assertFalse(result);
    }

    /// @notice Benchmark Groth16ZkAdapter wrapping a MockGroth16Verifier (always-true).
    function test_gas_adapter_verify() public {
        MockGroth16Verifier mockVerifier = new MockGroth16Verifier();
        Groth16ZkAdapter adapter = new Groth16ZkAdapter(
            address(mockVerifier),
            keccak256("vkey"),
            keccak256("policy")
        );

        // 320-byte proof: pA[2], pB[2][2], pC[2], stfCommitment, proverSetDigest
        bytes memory proof = abi.encode(
            [uint256(1), uint256(2)],
            [[uint256(3), uint256(4)], [uint256(5), uint256(6)]],
            [uint256(7), uint256(8)],
            uint256(1),
            uint256(2)
        );

        (bool valid,,,,) = adapter.verify(proof, "");
        assertTrue(valid);
    }

    /// @notice Benchmark WorldlineRegistry circuit registration.
    function test_gas_registry_register() public {
        WorldlineRegistry regImpl = new WorldlineRegistry();
        ERC1967Proxy regProxy = new ERC1967Proxy(
            address(regImpl),
            abi.encodeCall(WorldlineRegistry.initialize, (address(1)))
        );
        WorldlineRegistry registry = WorldlineRegistry(address(regProxy));
        registry.registerCircuit(
            keccak256("circuit-1"),
            "Benchmark Circuit",
            address(1),
            "ipfs://bench"
        );
    }

    /// @notice Benchmark WorldlineRegistry plugin deprecation (setup: register circuit + plugin, measure deprecatePlugin).
    function test_gas_registry_deregister() public {
        WorldlineRegistry regImpl2 = new WorldlineRegistry();
        ERC1967Proxy regProxy2 = new ERC1967Proxy(
            address(regImpl2),
            abi.encodeCall(WorldlineRegistry.initialize, (address(1)))
        );
        WorldlineRegistry registry = WorldlineRegistry(address(regProxy2));

        bytes32 circuitId = keccak256("circuit-deregister");
        bytes32 pluginId = keccak256("plugin-deregister");

        registry.registerCircuit(circuitId, "c", address(1), "u");
        registry.registerPlugin(pluginId, "1.0", address(2), circuitId);

        // Measured operation
        registry.deprecatePlugin(pluginId);
    }

    /// @notice Benchmark WorldlineFinalizer.submitZkValidityProof using EchoMockAdapter.
    function test_gas_submit_proof() public {
        EchoMockAdapter mockAdapter = new EchoMockAdapter();

        bytes32 domainSep = keccak256("bench-domain");
        WorldlineFinalizer finImpl1 = new WorldlineFinalizer();
        ERC1967Proxy finProxy1 = new ERC1967Proxy(
            address(finImpl1),
            abi.encodeCall(WorldlineFinalizer.initialize, (address(mockAdapter), domainSep, 7 days, 1, address(0)))
        );
        WorldlineFinalizer finalizer = WorldlineFinalizer(address(finProxy1));
        finalizer.setPermissionless(true);

        uint256 l2Start = 1;
        uint256 l2End = 100;
        bytes32 outputRoot = keccak256("output");
        bytes32 l1Hash = keccak256("l1");
        uint256 closeTs = block.timestamp;
        bytes32 stf = keccak256(abi.encode(l2Start, l2End, outputRoot, l1Hash, domainSep, closeTs));

        bytes memory publicInputs = abi.encode(stf, l2Start, l2End, outputRoot, l1Hash, domainSep, closeTs);
        bytes memory proof = abi.encode(uint256(1), uint256(2));

        finalizer.submitZkValidityProof(proof, publicInputs);
    }

    /// @notice Benchmark full on-chain quorum validation: Groth16ZkAdapter wrapping MockGroth16Verifier.
    function test_gas_quorum_check() public {
        MockGroth16Verifier mockVerifier = new MockGroth16Verifier();
        Groth16ZkAdapter zkAdapter = new Groth16ZkAdapter(
            address(mockVerifier),
            keccak256("vkey"),
            keccak256("policy")
        );

        bytes32 domainSep = keccak256("bench-domain");
        WorldlineFinalizer finImpl2 = new WorldlineFinalizer();
        ERC1967Proxy finProxy2 = new ERC1967Proxy(
            address(finImpl2),
            abi.encodeCall(WorldlineFinalizer.initialize, (address(zkAdapter), domainSep, 7 days, 1, address(0)))
        );
        WorldlineFinalizer finalizer = WorldlineFinalizer(address(finProxy2));
        finalizer.setPermissionless(true);

        uint256 l2Start = 1;
        uint256 l2End = 100;
        bytes32 outputRoot = keccak256("output");
        bytes32 l1Hash = keccak256("l1");
        uint256 closeTs = block.timestamp;
        bytes32 stf = keccak256(abi.encode(l2Start, l2End, outputRoot, l1Hash, domainSep, closeTs));

        bytes memory publicInputs = abi.encode(stf, l2Start, l2End, outputRoot, l1Hash, domainSep, closeTs);

        // Proof embeds stf at position 8 (index 8 of 10 uint256 words) for Groth16ZkAdapter
        bytes memory proof = abi.encode(
            [uint256(1), uint256(2)],
            [[uint256(3), uint256(4)], [uint256(5), uint256(6)]],
            [uint256(7), uint256(8)],
            uint256(stf),
            uint256(keccak256("digest"))
        );

        finalizer.submitZkValidityProof(proof, publicInputs);
    }
}
