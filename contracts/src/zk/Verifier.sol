// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Worldline Demo Verifier
/// @author Worldline Contributors
/// @notice Lightweight verifier that mirrors the behaviour of the Circom
///         `SquareHash` circuit. It is intentionally simple so the Solidity
///         integration tests and devnet can exercise the call flow without a
///         heavy proving setup.
/// @dev DEV-ONLY — This contract is a placeholder for development and testing.
///      In production, replace this with a fully fledged SNARK verifier
///      generated from the circuit artifacts via `snarkjs`.
contract Verifier {
    error InvalidProof();
    error SecretTooLarge();

    /// @notice Validates a proof-of-presence by recomputing the commitment
    ///         on-chain. In production this would be replaced by a fully fledged
    ///         SNARK verifier generated from the circuit artifacts.
    /// @param secret The private secret revealed for development purposes.
    /// @param publicHash The expected commitment that should equal `secret^2`.
    /// @dev MED-004 remediation: rejects `secret >= 2^128` to prevent checked-arithmetic
    ///      overflow panic (which would mask the error as a generic revert instead of
    ///      `InvalidProof`). This keeps the dev verifier consistent with Circom field
    ///      arithmetic within the safe multiplication range.
    function verifyProof(uint256 secret, uint256 publicHash) public pure {
        if (secret >= (1 << 128)) revert SecretTooLarge();
        if (secret * secret != publicHash) {
            revert InvalidProof();
        }
    }
}
