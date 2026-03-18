# Worldline v1.0

Worldline is a multi-ZK-prover architecture for rollups on EVM L1s. An
off-chain aggregator selects provers via a signed directory, optionally
performs recursion over inner proofs, and produces a single Groth16/BN254
proof per window that the on-chain finalizer verifies. This repository
bundles the circuits, contracts, Rust driver, and pluggable SDKs needed to
run the full stack locally.

## Packages

- `circuits/` – Circom circuits and tooling used to generate zk-SNARK artifacts.
- `contracts/` – Solidity smart contracts plus Hardhat configuration and tests.
- `crates/` – Rust workspace containing the driver, registry, and compatibility façade.
- `devnet/` – Node.js orchestration script that deploys the stack against a local Anvil network.
- `plugins/` – Reference plugin implementation showcasing the SDK surface area.
- `schemas/` – JSON schemas defining configuration formats shared across components.
- `tests/` – Cross-language integration tests.

## Quick start

```bash
npm ci
npm run contracts:build
cargo test
npm run devnet
```

Refer to the documentation in each package for details on advanced usage.
