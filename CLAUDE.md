# Project Worldline

Multi-ZK-prover verification architecture. Groth16/Plonk/Halo2 provers submit validity proofs for state transitions, aggregated via quorum-based verification.

## Repo Layout

```
circuits/src/          → Circom circuits (BN254, pragma 2.1.6)
circuits/zkeys/        → Trusted setup artifacts (dev ceremony)
circuits/test/         → Mocha/Chai circuit tests
contracts/src/         → Solidity verifier + registry (^0.8.20)
contracts/test/        → Forge + Hardhat tests
crates/registry/       → Rust prover registry
crates/aggregation/    → Proof aggregation module
crates/recursion/      → Proof recursion module
crates/benches/        → Criterion benchmarks
devnet/                → Docker local devnet
scripts/               → Deploy, simulation, CI
.github/workflows/     → CI pipeline
```

## Chunk Status

| #   | Scope                                        | Status |
| --- | -------------------------------------------- | ------ |
| 1   | Circuit design + Poseidon constraints        | ✅     |
| 2   | Trusted setup + circuit tests (8/8 pass)     | ✅     |
| 3   | Solidity verifier contracts (175 tests pass) | ✅     |
| 4   | Rust registry crate                          | ✅     |
| 5   | Proof aggregation + recursion                | ✅     |
| 6   | Benchmarks (Solidity gas + Criterion)        | ✅     |
| 7   | Devnet hardening + integration tests         | ✅     |
| 8   | Mainnet fork simulation                      | ✅     |
| 9   | Testnet deploy + CI pipeline                 | ✅     |
| A   | Proof routing layer                          | ✅     |

## Dependencies

```
1 → 2 → 3 ─┬→ 6 ─┐
             │     ├→ 7 → 8 → 9
   2 → 5 ───┤     │
        4 ──┴→ 6 ─┘
```

## Domain Quick-Ref

- Proof systems: Groth16=1, Plonk=2, Halo2=3
- Quorum: 1–3 (N=3 max provers)
- Batch size: 1–1024
- Public outputs: stfCommitment, proverSetDigest
- stfCommitment = Poseidon(preStateRoot, postStateRoot, batchCommitment)
- proverSetDigest = Poseidon(proverIds[], proofSystemIds[], quorumCount)
- Proof format: 320-byte production (BN254 pairing)
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
- Solidity: ^0.8.20, Hardhat + ethers v6, Forge for fuzz tests
- Rust: edition 2021, stable, `#[deny(clippy::all)]`, no `unwrap()` outside tests
- Commits: `chunk-N: description`

## Sub-Agent Rules

1. Each sub-agent gets explicit file ownership — no overlapping writes
2. Define interfaces before spawning dependent agents
3. Each agent runs only its scoped tests
4. Only the designated owner modifies shared configs (Cargo.toml, hardhat.config.ts, package.json)
