// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Groth16Adapter
/// @notice Lightweight adapter that prepares Wordline public inputs for
///         on-chain verification. It pins the expected program verification
///         key and policy hash so the registry can rely on a stable ABI while
///         proofs are generated off-chain.
contract Groth16Adapter {
    bytes32 public constant PROGRAM_VKEY =
        0x00000000000000000000000000000000000000000000000000000000000A11CE;
    bytes32 public constant POLICY_HASH =
        0x0000000000000000000000000000000000000000000000000000000000000B0B;

    struct PublicInputs {
        bytes32 stfCommitment;
        bytes32 programVKey;
        bytes32 policyHash;
        bytes32 proverSetDigest;
    }

    /// @notice Decode the ABI packed public inputs emitted by the off-chain
    ///         prover and reshape them for on-chain Groth16 verification.
    /// @param publicInputsRaw ABI-encoded bytes representing the circuit
    ///        metadata expected by the Wordline circuit (160 bytes).
    function decodeWordlinePublicInputs(bytes calldata publicInputsRaw)
        external
        pure
        returns (PublicInputs memory)
    {
        require(publicInputsRaw.length == 160, "invalid public inputs length");

        bytes32 stfCommitment;
        assembly {
            stfCommitment := calldataload(publicInputsRaw.offset)
        }

        PublicInputs memory inputs;
        inputs.stfCommitment = stfCommitment;
        inputs.programVKey = PROGRAM_VKEY;
        inputs.policyHash = POLICY_HASH;
        // For v1.0 we bind proverSetDigest to the ABI (keccak256(publicInputsRaw))
        // so the on-chain adapter and circuit remain consistent without extra calldata.
        inputs.proverSetDigest = keccak256(publicInputsRaw);
        return inputs;
    }
}
