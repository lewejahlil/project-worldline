# Project Worldline — Post-Audit Optimization Changelog

## Security Remediations

- [R-1] `bytes` crate — defense-in-depth: added `overflow-checks = true` to `[profile.release]` in workspace `Cargo.toml` to prevent integer overflow exploitation in `BytesMut::reserve` (CVE-2026-25541)
- [R-2] `bincode` — confirmed not present in dependency tree; no migration needed (RUSTSEC-2025-0141)
- [R-3] `evm-units` — confirmed absent from dependency tree; no remediation needed
- [R-4] `sha-rust` — confirmed absent from dependency tree; no remediation needed
- [R-5] Malicious time-utility crates (`chrono_anchor` et al.) — confirmed absent from dependency tree
- [DEAD-1] Removed unused `url` dependency from `worldline-registry/Cargo.toml`

## TypeScript / npm Security

- [T-1] Confirmed clean `package-lock.json` — no compromised `chalk`/`debug` versions
- [T-2] npm audit shows 46 vulnerabilities from `undici` (hardhat transitive) — pre-existing, not actionable without hardhat major version upgrade
- [T-3] ESLint baseline established; Prettier formatting enforced for `**/*.{ts,js,json,md}`

## Codebase Inconsistencies Fixed

- [REG-1] Documented intentional registry schema divergence (Solidity bytes32 IDs vs Rust string IDs) in `docs/audit-analysis-post-remediation.md`
- [DEAD-2] Documented unreachable `Ok(false)` branch in `verify_directory_signature()` (aggregator.rs)
- [DEAD-3] Documented silently dropped `endpoints`/`attestations` fields in directory fixture JSON
- [TEST-3] Documented missing `setFacadeChangeDelay` test coverage gap
- [TEST-5] Expanded Criterion benchmarks to cover 1000/10000 entry snapshots, circuit lookup, and save/load roundtrip
- Fixed aggregation bench panic at sizes 16/32 by capping `min_count` to `MAX_MANIFEST_ENTRIES`
- Fixed clippy `manual_clamp` warning

## Prover Performance Optimizations

### Chunk 2A — Solidity Verifier Optimization

- Reordered `_submit()` validation: cheap checks (domain binding, window range, contiguity, staleness) before expensive keccak256 STF binding verification
- Inlined `pubSignals` array in `Groth16ZkAdapter.verifyProof()` to avoid extra memory allocation
- Upgraded Solidity from 0.8.20 to 0.8.24 with `evmVersion: "cancun"` for EIP-4844 support

### Chunk 2B — Rust Registry & Off-Chain Prover Optimization

- Removed unused `url` dependency from `worldline-registry`
- Expanded Criterion benchmarks: `bench_circuit_lookup`, `bench_snapshot_save_load_roundtrip`, `bench_serialization_roundtrip` at 100/1000/10000 entries
- Fixed bench_aggregation to respect `MAX_MANIFEST_ENTRIES = 8`

### Chunk 2C — Circuit-Level Optimization

- Compiled SquareHash circuit: 1 constraint on BN-128 (already minimal after INF-005 fix)
- Documented constraint counts in `docs/circuit-constraint-counts.txt`
- Assessed witness async queue (N/A), Halo2 lookup tables (N/A), aggregation inner verifiers (N/A — recursion not implemented)

## Production Features Completed

### P1 — Nullifier Double-Spend Prevention (2 new Hardhat tests)

- Added `ProofConsumed(uint256 indexed windowIndex, bytes32 proofHash)` event to `WorldlineFinalizer._submit()` for on-chain proof hash audit trail
- Added test: `ProofConsumed` event emits correct proof hash
- Added test: identical proof bytes submitted twice reverts with `NotContiguous`

### P2 — EIP-4844 Blob Submission (5 new Hardhat tests)

- Created `BlobVerifier` library with native `blobhash()` opcode (Solidity 0.8.24)
- Created `IBlobSubmission` interface for blob-carrying proof submissions
- Created `BlobVerifierHarness` test contract
- 5 tests: getBlobHash, verifyBlobHash (NoBlobAtIndex), validateVersionByte (valid 0x01, invalid 0x00, invalid 0x02)

### P3 — Multi-Prover Fallback Routing (5 new Rust tests)

- Added `SelectionEvent` enum: `PrimarySelected`, `FallbackTriggered`, `ProverExcluded`
- Added `ExclusionReason` enum: `Offline`, `Degraded`, `NotInAllowlist`, `HealthCheckFailed`
- Added `default_fallback_tiers()`: canonical halo2 > plonk > groth16 fallback chain
- Added event emission to `select()` and `run_aggregator()` (warn-level for fallback/exclusion)
- 5 tests: halo2 offline falls back to plonk, fallback emits event, offline prover emits exclusion, default tiers structure, primary emits event

### P4 — Aggregation Edge Cases (5 new Rust tests)

- Single-proof batch produces valid manifest
- Zero-proof batch returns `NoValidSelection` (structured error)
- Max-size batch at limit (8) succeeds
- Max-size batch exceeded returns `ManifestTooLarge`
- Mixed proof systems (groth16 + plonk + halo2) in one batch

### P5 — Deployment Script Hardening

- Added 7 post-deploy verification checks to `scripts/deploy.ts`:
  - WorldlineRegistry owner matches deployer
  - WorldlineFinalizer adapter matches deployed adapter
  - WorldlineFinalizer domainSeparator matches config
  - WorldlineFinalizer is not paused
  - WorldlineFinalizer nextWindowIndex is 0
  - WorldlineOutputsRegistry owner matches deployer
  - WorldlineRegistry compatFacade matches deployed WorldlineCompat

### P6 — Observability Hooks

- Added structured `tracing::info!` to `export_compat()` and `check_plugin()`
- Added `tracing::warn!` for plugin-not-found cases
- Added sync completion log with byte count
- Added event-level logging in aggregator for `SelectionEvent` variants (fallback triggers, prover exclusions)

## Files Modified

| File                                                  | Change                                          | Reason                 |
| ----------------------------------------------------- | ----------------------------------------------- | ---------------------- |
| `Cargo.toml`                                          | Added `overflow-checks = true`                  | R-1 defense-in-depth   |
| `hardhat.config.ts`                                   | Solidity 0.8.24, evmVersion cancun              | EIP-4844 support       |
| `contracts/src/WorldlineFinalizer.sol`                | Added ProofConsumed event                       | P1 nullifier hardening |
| `contracts/src/blob/BlobVerifier.sol`                 | New file                                        | P2 EIP-4844            |
| `contracts/src/blob/IBlobSubmission.sol`              | New file                                        | P2 EIP-4844            |
| `contracts/src/blob/BlobVerifierHarness.sol`          | New file                                        | P2 test harness        |
| `contracts/src/zk/Groth16ZkAdapter.sol`               | Inline pubSignals                               | Chunk 2A gas opt       |
| `crates/worldline-registry/src/selection.rs`          | SelectionEvent, fallback chain, edge case tests | P3, P4                 |
| `crates/worldline-registry/Cargo.toml`                | Removed `url` dep                               | DEAD-1                 |
| `crates/worldline-registry/benches/registry_bench.rs` | Expanded benchmarks                             | Chunk 2B               |
| `crates/worldline-driver/src/aggregator.rs`           | Event logging                                   | P3, P6                 |
| `crates/worldline-driver/src/lib.rs`                  | Structured logging                              | P6                     |
| `crates/benches/src/bench_aggregation.rs`             | Fixed panic, capped policy                      | Chunk 2B               |
| `scripts/deploy.ts`                                   | Post-deploy verification                        | P5                     |
| `test/WorldlineFinalizer.test.ts`                     | +2 tests (ProofConsumed, duplicate)             | P1                     |
| `test/BlobVerifier.test.ts`                           | New file, +5 tests                              | P2                     |
| `.gitignore`                                          | Added `circuits/artifacts/*_js/`                | Chunk 2C               |
| `docs/audit-analysis-post-remediation.md`             | Chunk 1 full analysis                           | Chunk 1                |
| `docs/chunk-2c-circuit-optimization.md`               | Circuit analysis                                | Chunk 2C               |
| `docs/circuit-constraint-counts.txt`                  | Constraint counts                               | Chunk 2C               |
| `docs/gas-report-post-optimization.md`                | Before/after gas comparison                     | Chunk 4                |

## Test Suite Delta

- Rust: 91 → 101 (+10 tests)
- Hardhat: 119 → 126 (+7 tests)
- Total: 210 → 227 (+17 tests)

---

## Addendum v1.1 — Solidity Upgrade & EIP-4844 Full Implementation

### Solidity Compiler
- Upgraded from 0.8.20 → 0.8.34 (latest stable as of Feb 2026)
- Set evmVersion to "cancun" — enables blobhash(), block.blobbasefee, MCOPY, TLOAD/TSTORE
- Updated all pragma statements to ^0.8.24 minimum
- Patched: high-severity IR pipeline bug (affected 0.8.28–0.8.33)

### EIP-4844 — On-Chain
- Implemented BlobKzgVerifier.sol with blobhash() + KZG point evaluation precompile (0x0A)
- Preserved existing BlobVerifier library (replaced assembly blobhash with native call)
- Wired BlobKzgVerifier into WorldlineFinalizer with dual-mode verification:
  KZG mode (verifier set + 48-byte commitment) or hash-only fallback
- block.blobbasefee fee gating with caller-specified maximum
- Created BlobSubmission.sol implementing IBlobSubmission interface

### EIP-4844 — Off-Chain
- scripts/blob-helpers.ts: blob encoding, KZG commitment/proof via c-kzg, SHA256 versioned hash
- scripts/blob-tx-sender.ts: type-3 BlobTx construction helpers
- crates/worldline-driver/src/blob.rs: encode_as_blob, decode_blob, validate_blob_field_elements

### Test Suite Delta (v1.1)
- Rust: 101 → 106 (+5 blob encoding tests)
- Hardhat: 126 → 139 (+13 tests: 8 BlobKzgVerifier + 5 blob encoding)
