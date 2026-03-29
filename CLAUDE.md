# Project Worldline

Multi-ZK-prover verification architecture. Groth16/Plonk/Halo2 provers submit validity proofs for state transitions, aggregated via quorum-based verification.

## Architecture

- **ProofRouter** — UUPS-upgradeable on-chain router that dispatches proofs to registered ZK adapters by proof system ID
- **Proof systems** — Groth16 (ID=1), Plonk (ID=2), Halo2 (ID=3), each with a dedicated verifier contract and ZkAdapter
- **WorldlineFinalizer** — UUPS-upgradeable contract that accepts validity proofs per window, verifies via the router, and finalizes state transitions
- **WorldlineRegistry** — UUPS-upgradeable registry with timelocked compat facade changes
- **Multi-prover quorum** — Up to 3 provers per window; quorum threshold configurable (1–3)
- **Proof aggregation** — Off-chain Rust aggregator collects and verifies proofs from multiple systems
- **Proof recursion** — Recursive verification over inner proofs before on-chain submission
- **Circom circuits** — BN254 STF circuit with circomlib-compatible Poseidon, independent Plonk circuit (Path B)

## Repo Layout

```
circuits/src/          → Circom circuits (BN254, pragma 2.1.6)
circuits/stf/          → STF and prover set binding circuits
circuits/zkeys/        → Trusted setup artifacts (dev ceremony)
circuits/test/         → Mocha/Chai circuit tests
contracts/src/         → Solidity verifier + registry (^0.8.24)
contracts/src/zk/      → ZK verifiers and adapters (Groth16, Plonk, Halo2)
contracts/src/blob/    → EIP-4844 blob verification
contracts/test/        → Forge unit + fuzz tests
crates/registry/       → Rust prover registry
crates/aggregation/    → Proof aggregation module
crates/recursion/      → Proof recursion module
crates/halo2-circuit/  → Halo2 STF circuit (KZG/BN254, circomlib-compatible Poseidon)
crates/worldline-driver/ → CLI driver for aggregation, recursion, blob encoding
crates/worldline-registry/ → Extended registry with directory, selection, canonical hashing
crates/worldline-compat/   → Compatibility facade
crates/worldline-devnet/   → Devnet utilities
crates/benches/        → Criterion benchmarks
devnet/                → Docker local devnet
scripts/               → Deploy, simulation, CI
test/                  → Hardhat integration tests
test/integration/      → Multi-prover integration tests
.github/workflows/     → CI pipeline
```

## Domain Quick-Ref

- Proof systems: Groth16=1, Plonk=2, Halo2=3
- Quorum: 1–3 (N=3 max provers)
- Batch size: 1–1024
- Public outputs: stfCommitment, proverSetDigest
- stfCommitment = Poseidon(preStateRoot, postStateRoot, batchCommitment)
- proverSetDigest = Poseidon(proverIds[], proofSystemIds[], quorumCount)
- Proof sizes: Groth16=320 bytes, Plonk=832 bytes, Halo2=192 bytes (BN254 pairing format)
- Powers of Tau: 2^11 ptau, 1867 constraints, 1859 wires

## RPC Endpoints

- Mainnet (fork sim): `https://ethereum-rpc.publicnode.com` (free, no key) — fallback: `https://eth.llamarpc.com`
- Testnet (deploy): Sepolia (chain ID 11155111) — active, sunsetting Sept 2026
- Sepolia RPC: `https://sepolia-rpc.publicnode.com`

## Commands

```bash
cd circuits && npx mocha test/ --timeout 10000   # circuit tests
npx hardhat test                                   # solidity tests
REPORT_GAS=true npx hardhat test                   # gas report
cargo test --workspace                             # rust tests
cargo bench                                        # criterion benchmarks
```

## Standards

See `docs/coding-standards.md` for full conventions. Key rules:

- Circom: pragma 2.1.6, BN254 only, zero unconstrained signals
- Solidity: ^0.8.24, Hardhat + ethers v6, Forge for fuzz tests
- Rust: edition 2021, stable, `#[deny(clippy::all)]`, no `unwrap()` outside tests
- Commits: `scope: description` (e.g., `contracts: add Plonk adapter`)

## Sub-Agent Rules

1. Each sub-agent gets explicit file ownership — no overlapping writes
2. Define interfaces before spawning dependent agents
3. Each agent runs only its scoped tests
4. Only the designated owner modifies shared configs (Cargo.toml, hardhat.config.ts, package.json)
