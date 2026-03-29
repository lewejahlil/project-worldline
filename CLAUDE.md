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
contracts/src/         → Solidity verifier + registry (^0.8.24, compiled with 0.8.34)
contracts/src/zk/      → ZK verifiers and adapters (Groth16, Plonk, Halo2)
contracts/src/blob/    → EIP-4844 blob verification
contracts/test/        → Forge unit + fuzz tests (WorldlineTestBase.t.sol is shared base)
crates/registry/       → Rust prover registry
crates/aggregation/    → Proof aggregation module
crates/recursion/      → Proof recursion module
crates/halo2-circuit/  → Halo2 STF circuit (KZG/BN254, circomlib-compatible Poseidon)
crates/worldline-driver/ → CLI driver for aggregation, recursion, blob encoding (binary crate, uses anyhow)
crates/worldline-registry/ → Extended registry with directory, selection, canonical hashing
crates/worldline-compat/   → Compatibility facade
crates/worldline-devnet/   → Devnet utilities
crates/benches/        → Criterion benchmarks
devnet/                → Docker local devnet
scripts/               → Deploy, simulation, CI
test/                  → Hardhat integration tests
test/integration/      → Multi-prover integration tests (deployment-fixtures.ts has shared helpers)
docs/                  → Specs, security audits, refactor analysis, feature gap analysis
.github/workflows/     → CI pipeline
remappings.txt         → Forge import remappings (@openzeppelin → node_modules)
```

## Domain Quick-Ref

- Proof systems: Groth16=1, Plonk=2, Halo2=3
- Quorum: 1–3 (N=3 max provers)
- Batch size: 1–1024
- Public outputs: stfCommitment, proverSetDigest
- stfCommitment = Poseidon(preStateRoot, postStateRoot, batchCommitment)
- proverSetDigest = Poseidon(proverIds[], proofSystemIds[], quorumCount)
- Proof sizes: Groth16=320 bytes, Plonk=832 bytes, Halo2=1536 bytes (BN254 KZG)
- Groth16 circuit: 2^11 ptau, 773 constraints, 775 wires (circomlib 2.0.5)
- Plonk circuit: 2^14 ptau, 731 R1CS constraints / 12,217 Plonk gates, 736 wires (circomlib 2.0.5)
- Halo2 circuit: k=8, 256 rows (BN254 KZG)
- Quorum digest asymmetry: the circuit's proverSetDigest is always computed over all 3 prover slots (zero-padded), while the aggregation layer's prover_set_digest is computed only from submitted proofs — these may differ when fewer than 3 provers are active

## RPC Endpoints

- Mainnet (fork sim): `https://ethereum-rpc.publicnode.com` (free, no key) — fallback: `https://eth.llamarpc.com`
- Testnet (deploy): Sepolia (chain ID 11155111) — active, sunsetting Sept 2026
- Sepolia RPC: `https://sepolia-rpc.publicnode.com`

## Test Counts

- Hardhat: 220 tests
- Forge: 114 tests (10 suites, includes fuzz tests at 256 runs each)
- Rust: 238 tests (12 ignored — require snarkjs/halo2-verify binaries)

## Commands

```bash
cd circuits && npx mocha test/ --timeout 10000   # circuit tests
npx hardhat test                                   # solidity tests (219 tests)
REPORT_GAS=true npx hardhat test                   # gas report
forge test                                         # forge unit + fuzz tests (113 tests)
cargo test --workspace                             # rust tests (238 tests)
cargo bench                                        # criterion benchmarks
```

## Standards

See `docs/coding-standards.md` for full conventions. Key rules:

- Circom: pragma 2.1.6, BN254 only, zero unconstrained signals
- Solidity: ^0.8.24, compiled with 0.8.34 (Hardhat + Forge aligned), custom errors only (no revert strings)
- Rust: edition 2021, stable, `#[deny(clippy::all)]`, no `unwrap()` outside tests; library crates use `thiserror`, binary crates use `anyhow`
- TypeScript tests: use shared helpers from `test/integration/deployment-fixtures.ts` (`enablePermissionless()`, `computeStfCommitment()`, `encodeProof()`, `findEventLog()`)
- Forge tests: inherit from `WorldlineTestBase.t.sol` when testing finalizer + Groth16 adapter setup
- Commits: `scope: description` (e.g., `contracts: add Plonk adapter`)

## UUPS Proxy Architecture

**Proxied contracts** (ERC-1967 UUPS, upgradeable):

- `WorldlineFinalizer` — accepts ZK proofs, enforces domain/contiguity/staleness
- `ProofRouter` — dispatches proofs to registered adapters by proof system ID
- `WorldlineRegistry` — stores circuit/driver/plugin metadata with timelocked facade
- `WorldlineOutputsRegistry` — timelocked registry for programVKey/policyHash/oracle tuples

All four proxied contracts:

- Use `_disableInitializers()` in constructors
- Have `__gap` storage reservations sized to 50 total slots per contract
- Emit `UpgradeAuthorized(newImpl, authorizer)` from `_authorizeUpgrade()`
- Enforce `onlyOwner` on `_authorizeUpgrade()`
- Store ownership via OZ v5 EIP-7201 namespaced storage (no sequential slot conflicts)

**Non-proxied contracts** (immutable, not upgradeable):

- `Groth16ZkAdapter`, `PlonkAdapter`, `Halo2ZkAdapter` — ZK adapters (constructor-set params)
- `BlobVerifier`, `BlobKzgVerifier` — EIP-4844 blob verification utilities
- All verifier contracts under `contracts/src/zk/`

## Key Internal Patterns

- **WorldlineFinalizer** uses `_validateAndPrepare()` for shared submission validation (auth, decode, domain binding, contiguity, staleness, STF binding, CEI state update) — both `_submit()` and `_submitRouted()` call it, then diverge only for their verification path
- **typechain-types/** is gitignored and NOT tracked — regenerated by `npx hardhat compile`
- All contracts use `NotAuthorized` (US spelling) — `WorldlineRegistry` and `WorldlineFinalizer` are consistent

## Sub-Agent Rules

1. Each sub-agent gets explicit file ownership — no overlapping writes
2. Define interfaces before spawning dependent agents
3. Each agent runs only its scoped tests
4. Only the designated owner modifies shared configs (Cargo.toml, hardhat.config.ts, package.json)
