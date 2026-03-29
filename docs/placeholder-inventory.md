# Placeholder Inventory — Phase 1 Audit

> **All placeholders listed below have been resolved.**

This document catalogs all placeholder or stub implementations found during the
Phase 1 circuit audit. Each entry lists the file, line number, current behavior,
intended behavior, and the feature phase that replaced it.

---

## Rust Crate Placeholders

### 1. `crates/worldline-driver/src/recursion.rs:111`

**Current behavior:** Returns empty proof bytes `vec![]` for each inner prover slot.

```rust
let inner_proofs: Vec<Vec<u8>> = (0..k).map(|_| vec![]).collect();
```

**What it should do:** Contact each of the first `k_in_proof` prover endpoints,
request a proof for the current window's witness, collect and validate each proof
against the prover's `vkey_commitment`.

**Replaced in:** Rust prover wiring phase. The empty proof bytes were
replaced with real Groth16 proof generation via `prove_stf_groth16()`.

---

### 2. `crates/worldline-driver/src/recursion.rs:76-78` (TODO comment)

**Current behavior:** Function docstring documents that actual inner proof collection
is not yet implemented.

**What it should do:** Implement live prover connections and real proof collection.

**Replaced in:** Rust prover wiring phase — inner proof collection now produces real
Groth16 proof bytes from the WorldlineSTF circuit.

---

### 3. `crates/worldline-driver/src/recursion.rs:105-110` (TODO comment)

**Current behavior:** Comment block describing the planned production flow for
inner proof collection, followed by structured placeholder construction.

**What it should do:** Implement the three steps described in the comment:

1. Contact prover endpoints
2. Request proofs for the current window
3. Validate proofs against `vkey_commitment`

**Replaced in:** Rust prover wiring phase.

---

### 4. `crates/benches/src/bench_recursion.rs:26`

**Current behavior:** Benchmark measures latency of structured placeholder
construction (`build_recursion_witness`), which currently constructs empty vectors.

**What it should do:** Benchmark real witness generation and proof generation latency.

**Replaced in:** Rust prover wiring phase — new benchmarks for `build_stf_witness()` and
`prove_stf_groth16()` were added alongside the existing recursion depth benchmark.

---

### 5. `crates/benches/src/bench_verify.rs:10-22`

**Current behavior:** Uses a synthetic JSON payload and measures `canonical_keccak()`
latency as a proxy for "Groth16 BN254 verification". No actual BN254 pairing
verification occurs.

**What it should do:** Benchmark real on-chain verification gas costs or native
Groth16 verification latency.

**Replaced in:** Rust prover wiring phase — real Groth16 proving benchmarks were added.
The existing canonical keccak benchmark remains valid for its specific purpose.

---

## Solidity Contract Placeholders

### 6. `contracts/src/zk/Groth16Verifier.sol` (entire contract)

**Current behavior:** Stub contract that reverts with `NotYetImplemented()` on all
calls. Previously returned `true` unconditionally on Hardhat (chainid 31337).

**What it should do:** Perform real BN254 elliptic curve pairing checks
(`ecAdd`, `ecMul`, `ecPairing` precompiles) to verify Groth16 proofs.

**Replaced in:** Solidity verifier contracts phase — real verifier generated from
`worldline_stf_final.zkey` via `npx snarkjs zkey export solidityverifier`.

---

### 7. `contracts/src/zk/Verifier.sol` (entire contract)

**Current behavior:** Dev-only verifier that checks `secret * secret == publicHash`.
Mirrors the removed SquareHash circuit.

**What it should do:** This is intentionally a development utility. It will remain
available for dev-mode adapter deployments but is not used in production flows.

**Status:** Not a blocker. Dev-mode-only contract; no action required for Phase 1.

---

### 8. `scripts/deploy.ts` — Adapter deployment

**Current behavior:** Deploys `Groth16ZkAdapter` with the demo `Verifier` address
for both dev and production modes. Production mode would call the stub
`Groth16Verifier` which always reverts.

**What it should do:** In production mode, deploy and wire the real `Groth16Verifier`
generated from snarkjs.

**Replaced in:** Solidity verifier contracts phase — deployment script was updated to deploy
the real pairing verifier. A warning guard was added for the interim.

---

## Circuit Placeholders

### 9. `circuits/worldline.circom` (removed)

**Previous behavior:** 2-constraint SquareHash demo (`secret * secret === publicHash`).
No rollup logic, no STF commitment, no prover set binding.

**Replaced with:** Removed during initial circuit design. Replaced by
`circuits/stf/worldline_stf.circom` (trusted setup and circuit tests) and
`circuits/stf/worldline_prover_set.circom` (benchmarks and gas optimization).

---

## Summary

| #   | File                                        | Phase                       | Status         |
| --- | ------------------------------------------- | --------------------------- | -------------- |
| 1   | `recursion.rs:111` — empty proof bytes      | Rust prover wiring          | Resolved       |
| 2   | `recursion.rs:76-78` — TODO docstring       | Rust prover wiring          | Resolved       |
| 3   | `recursion.rs:105-110` — TODO comment       | Rust prover wiring          | Resolved       |
| 4   | `bench_recursion.rs:26` — placeholder bench | Rust prover wiring          | Resolved       |
| 5   | `bench_verify.rs` — synthetic verify bench  | Rust prover wiring          | Resolved       |
| 6   | `Groth16Verifier.sol` — stub verifier       | Solidity verifier contracts | Resolved       |
| 7   | `Verifier.sol` — dev verifier               | N/A                         | Dev-only, keep |
| 8   | `deploy.ts` — production adapter wiring     | Solidity verifier contracts | Resolved       |
| 9   | `worldline.circom` — SquareHash demo        | Initial circuit design      | **Removed**    |
