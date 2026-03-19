# Worldline v1.0

Worldline is a multi-ZK-prover architecture for rollups on EVM L1s. An
off-chain aggregator selects provers via a signed directory, optionally
performs recursion over inner proofs, and produces a single Groth16/BN254
proof per window that the on-chain finalizer verifies. This repository
bundles the circuits, contracts, Rust driver, and pluggable SDKs needed to
run the full stack locally.

## Packages

| Directory     | Description                                                   |
|---------------|---------------------------------------------------------------|
| `circuits/`   | Circom circuits and tooling for generating zk-SNARK artifacts |
| `contracts/`  | Solidity smart contracts plus Hardhat configuration and tests |
| `crates/`     | Rust workspace: driver, registry, compat facade, devnet utils |
| `devnet/`     | Node.js orchestration script for local Anvil deployments      |
| `docs/`       | Design docs, technical specification, and threat model        |
| `plugins/`    | Reference plugin implementation showcasing the SDK surface    |
| `schemas/`    | JSON schemas defining configuration formats                   |
| `test/`       | Solidity integration and E2E tests                            |

## Quick start

```bash
npm ci
npm run contracts:build
cargo test
npx hardhat test
npm run devnet
```

## Architecture

See `docs/design/system-design.md` for the full architecture and
`docs/specs/technical-specification.md` for the protocol specification.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards,
and the PR process.
