# Worldline Recursion Modes

This directory will contain Circom circuits for the two Worldline recursion modes.

---

## Overview

The Worldline outer proof optionally aggregates up to `k_in_proof` (0–4) inner proofs from
individual ZK provers. Recursion is controlled by the `recursion.mode` field in the policy JSON.

| Mode                 | Description                                                                                                                                                                             |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `none`               | No recursion. The outer circuit proves STF correctness directly. All prover diversity is enforced off-chain; the outer verifier key commitment (`programVKey`) pins the entire circuit. |
| `snark-accum`        | SNARK accumulator. Inner proofs are folded into an accumulator and a single deferred pairing check verifies all at once. Lower per-proof cost, higher circuit complexity.               |
| `snark-miniverifier` | Mini-verifier circuit. The outer circuit contains an inlined Groth16 verifier sub-circuit that directly checks each inner proof. Higher per-proof cost but simpler circuit structure.   |

---

## Activation Criteria

Recursion is activated by setting `recursion.mode` in the policy to a non-`none` value.
The aggregator reads `k_in_proof` (0–4) and `max_inner` from the policy and passes them
to `build_recursion_witness()` in `crates/worldline-driver/src/recursion.rs`.

### When to use `snark-accum`

- You need to aggregate 3–4 inner proofs efficiently.
- You are willing to pay the one-time cost of a more complex proving ceremony.
- BN254 pairing check batching is available in your proving system.

### When to use `snark-miniverifier`

- Simplicity is preferred over maximal efficiency.
- You need 1–2 inner proofs verified inside the outer circuit.
- Your prover supports recursive SNARKs natively (e.g. Nova, Plonky2, Halo2).

---

## Trade-offs

| Property               | `none`             | `snark-accum`                 | `snark-miniverifier`            |
| ---------------------- | ------------------ | ----------------------------- | ------------------------------- |
| Circuit complexity     | Low                | High                          | Medium                          |
| On-chain gas           | Baseline ~230k     | Baseline ~230k                | Baseline + ~7k/inner            |
| Off-chain proving time | Fastest            | Slowest (accumulator folding) | Medium                          |
| Security assumptions   | Outer circuit only | Outer + accumulator soundness | Outer + mini-verifier soundness |
| `k_in_proof` range     | 0                  | 1–4                           | 1–4                             |

---

## Files (TODO)

- `accum.circom` — SNARK accumulator circuit (not yet implemented)
- `miniverifier.circom` — Mini-verifier circuit (not yet implemented)
- `test/` — Circuit test vectors for both modes

---

## Implementation Status

⚠️ **Not yet implemented.** The recursion circuit files require:

1. A production-grade outer Worldline circuit (currently `circuits/worldline.circom` is a
   minimal SquareHash demo).
2. An audited SNARK accumulator or mini-verifier sub-circuit.
3. A trusted setup ceremony for the recursive circuit.

The off-chain scaffolding in `crates/worldline-driver/src/recursion.rs` is in place and
returns structured placeholder witnesses. The actual prover connections and circuit wiring
are marked as `// TODO`.

---

## References

- [Worldline Technical Specification](../docs/specs/technical-specification.md)
- [System Design](../docs/design/system-design.md)
- [Threat Model](../docs/security/threat-model.md) — T8 (Recursion Witness Forgery)
- [recursion.rs](../../crates/worldline-driver/src/recursion.rs) — off-chain witness builder
