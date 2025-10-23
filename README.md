# Project Wordline

Vendor-neutral, OP-Stack-compatible single-proof L1 finality with off-chain
multi-prover aggregation.

- One proof verified on L1 per window (gas-flat; no on-chain k-of-n).
- Policy-based multi-prover safety (e.g., >=2 distinct families).
- Deterministic subset selection proven in-circuit.
- Hard provenance bound to canonical Ethereum L1 data (deposits + EIP-4844).
- Watcher recomputes from L1 and enforces finality depth.

Licensing mix:
- Code: Apache-2.0 (c) 2025 Lewej Whitelow (lewejahlil)
- Examples/CI/Devnet: MIT-0
- Docs: CC BY 4.0
- Schemas/Fixtures/Benchmarks: CC0

See /docs for Spec, Design, and Threat Model (v1.0).
