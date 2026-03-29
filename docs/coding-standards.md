# Coding Standards — Project Worldline

## Circom

- `pragma circom 2.1.6` — no exceptions
- BN254 curve only (bn-128)
- All signals must be constrained — zero unconstrained signals policy
- Poseidon hash from `circomlib/circuits/poseidon.circom`
- circomlib LessThan bit-decomposition warnings are expected; not soundness issues

## Solidity

- Solidity ^0.8.24
- Hardhat + ethers v6 for integration tests
- Forge for unit tests and fuzz tests
- Gas benchmarks via `hardhat-gas-reporter`
- All verifier contracts must match the circuit's vkey
- Production proof format: 320 bytes (BN254 pairing, ecAdd/ecScalarMul/ecPairing precompiles)
- MockGroth16Verifier.sol for test suites only — never deployed to mainnet

## Rust

- Edition 2021, stable toolchain
- `#[deny(clippy::all)]` enforced
- No `unwrap()` in non-test code — use `?` or explicit error handling
- Crates are workspace members under root `Cargo.toml`
- Criterion for benchmarks

## General

- No floating point in circuit or contract math
- All PRs must pass CI before merge
- Commit messages: `scope: description` (e.g., `circuits: add Poseidon constraint tests`)
- Branch naming: `scope-short-description` (e.g., `contracts-plonk-adapter`)
