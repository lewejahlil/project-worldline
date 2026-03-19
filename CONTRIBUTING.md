# Contributing to Worldline

Thank you for your interest in contributing to Worldline! This document covers
the development workflow, coding standards, and PR process.

## Prerequisites

- **Node.js** >= 18
- **Rust** stable toolchain (with `clippy` and `rustfmt` components)
- **Anvil** (from Foundry) for local devnet
- **Circom** 2.1.6 for circuit compilation

## Getting Started

```bash
# Install JS dependencies
npm ci

# Compile contracts
npm run contracts:build

# Run all tests
npm test          # Solidity + Rust
cargo test        # Rust only
npx hardhat test  # Solidity only

# Start local devnet
npm run devnet
```

## Project Structure

| Directory    | Description                                       |
| ------------ | ------------------------------------------------- |
| `circuits/`  | Circom circuits and ZK tooling                    |
| `contracts/` | Solidity smart contracts (Hardhat + Foundry)      |
| `crates/`    | Rust workspace (driver, registry, compat, devnet) |
| `devnet/`    | Local Anvil orchestration script                  |
| `docs/`      | Design docs, specs, and threat model              |
| `plugins/`   | Reference prover plugin implementations           |
| `schemas/`   | JSON schemas for configuration formats            |
| `test/`      | Solidity integration tests                        |

## Coding Standards

### Rust

- Run `cargo fmt` before committing
- Run `cargo clippy -- -D warnings` — no warnings allowed
- Write tests for all public functions

### TypeScript / Solidity

- Run `npm run lint` (ESLint) and `npm run format:check` (Prettier)
- Follow the existing test patterns in `test/`
- Use NatSpec comments for all public Solidity functions

## Pull Request Process

1. Create a feature branch from `main`
2. Make your changes with clear, atomic commits
3. Ensure all tests pass: `npm test && cargo test`
4. Ensure linting passes: `npm run lint && cargo clippy -- -D warnings`
5. Open a PR with a clear description of what and why
6. Address review feedback

## Architecture

See `docs/design/system-design.md` for the full architecture and
`docs/specs/technical-specification.md` for the protocol specification.

## Security

If you discover a security vulnerability, please report it responsibly.
See `docs/security/threat-model.md` for the threat model.
