# Circuit-Level Optimization Report

**Date:** 2026-03-27

---

## 2C-1: Circuit Compilation & Constraint Counts

**Circuit:** `circuits/worldline.circom` (SquareHash)
**Compiler:** circom 2.1.6
**Curve:** BN-128 (BN254)

| Metric         | Value |
| -------------- | ----- |
| Constraints    | 1     |
| Wires          | 3     |
| Private Inputs | 1     |
| Public Inputs  | 1     |
| Labels         | 4     |
| Outputs        | 0     |

**Assessment:** The circuit is already at its minimum (1 non-linear constraint for `secret * secret === publicHash`). The previous INF-005 remediation removed a redundant `isValid` output signal that contributed 1 unnecessary constraint. No further reduction is possible.

Artifacts generated:

- `circuits/artifacts/worldline.r1cs` — R1CS constraint system
- `circuits/artifacts/worldline_js/worldline.wasm` — WASM witness generator

---

## 2C-2: Witness Generation Async Queue Audit

**Status: N/A — No async witness generation queue exists.**

The codebase has no async witness generation pipeline. The only async code in `worldline-driver` is:

- `main.rs:58` — `async fn main()` (tokio entry point)
- `lib.rs:18` — `pub async fn sync_registry()` (registry HTTP fetch)

Witness generation (`build_recursion_witness()` in `recursion.rs`) is synchronous and returns immediately with placeholder data. When production witness generation is implemented (requiring live prover connections), an async queue pattern would be appropriate, but there is nothing to optimize today.

---

## 2C-3: Halo2 Lookup Table Evaluation

**Status: N/A — No Halo2 implementation exists.**

Per the initial circuit analysis (finding PSP-3), no Halo2 verifier, adapter, circuit, or lookup table exists anywhere in the codebase. The Rust registry accepts `BackendMeta.kind = "halo2"` as a string, but no Halo2-specific logic is present. This item is deferred until Halo2 support is implemented.

---

## 2C-4: Aggregation Circuit Inner Verifier Evaluation

**Status: N/A — Recursion circuits not implemented.**

Per the initial circuit analysis (finding PSP-4), the recursion circuits (`accum.circom`, `miniverifier.circom`) documented in `circuits/recursion/README.md` are not yet implemented. The off-chain scaffolding in `recursion.rs` returns empty placeholder proof bytes.

**Recommendations for when recursion circuits are implemented:**

1. **snark-accum mode:** Use batched BN254 pairing checks (multi-Miller loop) to reduce the number of final exponentiations from `k` to 1.
2. **snark-miniverifier mode:** Consider the circomlib `Groth16Verifier` template or a custom inlined verifier. Each inner proof verification adds ~20,000–30,000 constraints.
3. **Both modes:** Ensure the outer circuit's public inputs include the `prover_set_digest` (keccak256 of manifest JSON) to bind the proof to the selected prover set on-chain.

---

## Summary

| Item                        | Status | Action Taken                       |
| --------------------------- | ------ | ---------------------------------- |
| Circuit compilation         | Done   | Compiled, 1 constraint (minimal)   |
| Constraint reduction        | Done   | Already minimal after INF-005 fix  |
| Witness async queue         | N/A    | No async queue exists              |
| Halo2 lookup tables         | N/A    | No Halo2 implementation            |
| Aggregation inner verifiers | N/A    | Recursion circuits not implemented |

**Circuit-level optimization is complete.** Most items are N/A due to the early implementation state (only a demo SquareHash circuit exists). The circuit is already optimized at 1 constraint. Meaningful circuit-level optimization work will begin when production circuits and recursion modes are implemented.
