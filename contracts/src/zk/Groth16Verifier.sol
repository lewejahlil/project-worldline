// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Groth16Verifier (Placeholder)
/// @notice Placeholder verifier with the same external interface as a snarkjs-generated
///         Groth16/BN254 verifier. Drop-in replacement once the circuit is compiled.
///
/// @dev TODO: Replace with snarkjs-generated verifier after circuit compilation:
///      1. npm run c:ptau       (download Powers of Tau ceremony file)
///      2. npm run c:compile    (circom → .r1cs + .wasm in circuits/artifacts/)
///      3. npm run c:setup      (generate proving key)
///      4. npm run c:export     (export this contract from the zkey)
///      5. npx snarkjs r1cs info circuits/artifacts/worldline.r1cs   (verify metrics)
///
/// @dev GAS NOTE: A real BN254 Groth16 verifier calls the pairing precompiles at
///      addresses 0x06 (bn256Add), 0x07 (bn256ScalarMul), and 0x08 (bn256Pairing).
///      Expected verification cost: ~207,700 gas base + ~7,160 gas per public signal
///      ≈ 230,000 gas for four public signals. This placeholder does NOT call those
///      precompiles; it is purely a dev/test safety guard.
///
/// @dev SAFETY GUARD: Returns `true` ONLY on Hardhat network (chainid 31337).
///      On any other network this contract reverts, preventing accidental use in
///      production before the real verifier is wired in.
contract Groth16Verifier {
    error NotProductionVerifier();

    /// @notice Verify a Groth16/BN254 proof.
    /// @param _pA        Proof element A: G1 point encoded as [x, y] (2 × uint256).
    /// @param _pB        Proof element B: G2 point encoded as [[x0,x1],[y0,y1]] (2×2 uint256).
    /// @param _pC        Proof element C: G1 point encoded as [x, y] (2 × uint256).
    /// @param _pubSignals Public inputs for the circuit (2 × uint256 for SquareHash).
    /// @return Whether the proof is cryptographically valid.
    ///
    /// @dev TODO: Replace this function body with snarkjs-generated BN254 pairing checks.
    ///      The real implementation calls ecAdd/ecMul/ecPairing precompiles and verifies
    ///      the Groth16 verification equation:
    ///        e(A, B) == e(α, β) · e(vk_input, γ) · e(C, δ)
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[2] calldata _pubSignals
    ) public view returns (bool) {
        // SAFETY GUARD: Only operates on Hardhat network (chainid 31337).
        // In production this must be replaced with real BN254 pairing verification
        // (~230k gas). The guard prevents accidental deployment to live networks.
        if (block.chainid != 31337) {
            revert NotProductionVerifier();
        }

        // Suppress unused variable warnings for the placeholder implementation.
        // A real verifier would consume these values in the pairing check.
        _pA;
        _pB;
        _pC;
        _pubSignals;

        return true;
    }
}
