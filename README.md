# Worldline v1.0

Worldline is a modular proof-of-presence stack that combines zero-knowledge
circuits, Ethereum smart contracts, a Rust driver, and pluggable SDKs. This
repository bundles all components necessary to run the protocol locally.

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
