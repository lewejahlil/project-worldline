# Feature Completeness Gap Analysis — Project Worldline

_Generated: 2026-03-29. Assessment of what's missing, incomplete, or stubbed for Worldline to operate as a production multi-ZK-prover verification architecture._

---

## Proof Lifecycle — Current State

```
Proof Request → Prover Selection → Proving → Aggregation → Recursion → Blob Encoding → On-Chain Verification → Finalization
     ✗              ✓ (Rust)        ✗         ⚠️ partial      ⚠️ partial    ✓ (Rust+Sol)      ✓ (Solidity)         ✓ (Solidity)
```

---

## Gap Inventory

### 1. Placeholder Poseidon Digest in Aggregation

- **Component:** `crates/aggregation/src/aggregator.rs` lines 46–55
- **Current state:** `simple_digest()` uses XOR-folding (`out[i % 32] ^= byte`) to compute prover set digests. Comment explicitly states: "In production this would be a real Poseidon hash."
- **What complete looks like:** Proper Poseidon hash over BN254 field elements, matching the circomlib-compatible Poseidon used in the circuits and halo2-circuit crate. The on-chain `stfCommitment` and `proverSetDigest` are Poseidon hashes — the off-chain aggregator must produce matching values.
- **Dependencies:** PSE Poseidon crate (already a dependency in halo2-circuit). Needs a shared Poseidon utility across crates.
- **Category:** **Critical path** — aggregated proofs with XOR-folded digests will not match on-chain verification.

### 2. Incomplete Batch Size Upper-Bound Constraint in Halo2 Circuit

- **Component:** `crates/halo2-circuit/src/stf_circuit.rs` lines 325–351
- **Current state:** Comment says "For full soundness, we decompose (batchSize - 1) into 10 bits" but only implements a nonzero check: `(1025 - batchSize) != 0`. The actual 10-bit lookup table decomposition is not implemented.
- **What complete looks like:** Range constraint via bit decomposition proving `batchSize ∈ [1, 1024]`. Without this, a malicious prover could claim an out-of-range batch size.
- **Dependencies:** None — halo2 range check gadgets are available in the current dependency tree.
- **Category:** **Critical path** — soundness gap in the halo2 circuit.

### 3. Recursion Witness Collection Stubbed

- **Component:** `crates/worldline-driver/src/recursion.rs` lines 105–111
- **Current state:** `build_recursion_witness()` returns empty proof bytes (`inner_proofs: vec![]`). TODO comment: "Actual inner proof collection requires live prover connections."
- **What complete looks like:** Function connects to prover endpoints (via HTTP/gRPC), collects inner proofs for a given window, validates them locally, and assembles the recursion witness.
- **Dependencies:** Prover API definition (doesn't exist yet), network client, proof format serialization.
- **Category:** **Critical path** — cannot perform proof recursion without inner proofs.

### 4. Subprocess-Based Proof Verification (Not Integrated)

- **Component:** `crates/aggregation/src/verifiers/groth16.rs`, `plonk.rs`, `halo2.rs`
- **Current state:** Verification shells out to `snarkjs verify` (Groth16, Plonk) or `cargo run --bin halo2-verify` (Halo2). Tests are marked `#[ignore]` when binaries aren't available. Hardcoded temp file paths risk collision under concurrency.
- **What complete looks like:** Native Rust verification using bellman/snarkjs-rs for Groth16/Plonk and halo2_proofs for Halo2. No subprocess dependency, no temp files, concurrent-safe.
- **Dependencies:** Rust bindings for snarkjs verification OR native BN254 pairing verification. Halo2 verifier is already available via `halo2_proofs::plonk::verify_proof`.
- **Category:** **Required before mainnet** — subprocess approach works for testing but is too fragile and slow for production.

### 5. No Prover API / RPC Interface

- **Component:** Does not exist
- **Current state:** No API definition for provers to receive proving requests or submit completed proofs. The aggregator assumes proofs are available locally.
- **What complete looks like:** gRPC or REST API service definition with endpoints: `RequestProof(windowId, inputs) → jobId`, `GetProofStatus(jobId) → status`, `GetProof(jobId) → proof`. Authentication, rate limiting, proof format validation.
- **Dependencies:** API framework choice (tonic for gRPC, axum for REST), authentication scheme.
- **Category:** **Critical path** — external provers cannot integrate without an API.

### 6. No Prover Orchestration / Job Queue

- **Component:** Does not exist
- **Current state:** No mechanism to assign proving jobs to provers, track job status, handle timeouts, or retry failed proofs. The driver assumes proofs are pre-computed.
- **What complete looks like:** Job queue (Redis/PostgreSQL-backed) that: assigns windows to provers based on policy, tracks proof generation progress, enforces SLA timeouts, triggers fallback to alternative provers on failure, publishes metrics.
- **Dependencies:** Prover API (#5), database/queue backend, monitoring integration.
- **Category:** **Required before mainnet** — manual proof coordination doesn't scale.

### 7. No Key Management Infrastructure

- **Component:** Does not exist
- **Current state:** Proving keys (zkeys) are stored as files. Directory signing keys are referenced but no key lifecycle management exists. Deploy scripts accept private keys via environment variables.
- **What complete looks like:** HSM integration or KMS (AWS KMS, GCP KMS) for: prover signing keys, directory authority keys, deployer keys. Key rotation procedures. Ceremony tooling for trusted setup key generation (currently uses dev ceremony artifacts).
- **Dependencies:** Cloud provider SDK or HSM driver, ceremony coordination tooling.
- **Category:** **Required before mainnet** — bare private keys in env vars are unacceptable for production.

### 8. No Health Monitoring / Metrics

- **Component:** Does not exist
- **Current state:** No metrics emission, health endpoints, or alerting. The Rust crates define a `HealthStatus` enum and selection logic considers prover health, but nothing produces or updates health signals.
- **What complete looks like:** Prometheus metrics for: proof generation latency, verification pass/fail rates, aggregation throughput, on-chain gas costs, window finalization lag. Health check endpoint for aggregator service. Alerting on: missed windows, prover failures, quorum not met.
- **Dependencies:** metrics/prometheus crate, HTTP server for health endpoint.
- **Category:** **Required before mainnet** — operating blind is unacceptable.

### 9. No Indexer / Event Consumer

- **Component:** Does not exist
- **Current state:** On-chain events (`OutputProposed`, `ZkProofAccepted`, `ManifestAnnounced`, `ProofConsumed`) are emitted but nothing indexes or consumes them off-chain.
- **What complete looks like:** Event indexer (subgraph or custom) that: tracks all finalized windows, maintains a queryable history of proofs and provers, provides an API for external consumers to query finalization status, powers a dashboard.
- **Dependencies:** Indexing infrastructure (The Graph, custom Rust indexer with ethers-rs).
- **Category:** **Enhancement** — system functions without indexing but is opaque to operators and integrators.

### 10. No SDK / Integration Library for External Teams

- **Component:** Does not exist
- **Current state:** No client library, no integration guide, no reference implementation for an L2 team wanting to use Worldline as their verification layer.
- **What complete looks like:** TypeScript and Rust SDKs that: construct submission payloads, interact with the Prover API, query finalization status. Integration guide covering: contract deployment, prover registration, policy configuration, monitoring setup.
- **Dependencies:** Stable Prover API (#5), stable contract ABIs, documentation.
- **Category:** **Enhancement** — not blocking core functionality but blocking adoption.

### 11. No Production Trusted Setup Ceremony Tooling

- **Component:** `circuits/zkeys/` contains dev ceremony artifacts
- **Current state:** Powers of Tau files and phase-2 contributions exist for development. No tooling for coordinating a production multi-party ceremony.
- **What complete looks like:** Ceremony coordinator (similar to Hermez/PSE ceremony tools): participant registration, contribution ordering, verification of each contribution, final beacon randomness, publication of transcript.
- **Dependencies:** Circom circuit finalization, participant coordination infrastructure.
- **Category:** **Required before mainnet** — dev ceremony keys are not secure for production.

### 12. Devnet Partially Implemented

- **Component:** `crates/worldline-devnet/`, `devnet/`
- **Current state:** Docker compose exists for local devnet. Devnet crate has basic utilities. Scripts exist for deploy and smoke test.
- **What complete looks like:** One-command devnet that: deploys all contracts, registers all three proof systems, seeds sample proofs, runs the aggregator, and provides a UI dashboard showing finalization progress.
- **Dependencies:** Working aggregator (#3, #4), prover mocks.
- **Category:** **Enhancement** — current devnet works for development; fuller version aids onboarding.

---

## Dependency Chain

```
                    ┌─────────────────────┐
                    │ 1. Fix Poseidon      │
                    │    digest            │
                    └────────┬────────────┘
                             │
                    ┌────────▼────────────┐
                    │ 2. Fix batch size    │
                    │    constraint        │
                    └────────┬────────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
    ┌─────────▼──────┐ ┌────▼──────┐ ┌─────▼─────────┐
    │ 5. Prover API  │ │ 4. Native │ │ 11. Ceremony  │
    │    definition   │ │ verifiers │ │     tooling    │
    └────────┬───────┘ └───────────┘ └───────────────┘
             │
    ┌────────▼───────┐
    │ 3. Recursion   │
    │    witness      │
    └────────┬───────┘
             │
    ┌────────▼───────┐
    │ 6. Job queue   │
    │ orchestration   │
    └────────┬───────┘
             │
    ┌────────┼────────────┐
    │        │            │
    ▼        ▼            ▼
  7. Key   8. Health   9. Indexer
  mgmt     monitoring
             │
             ▼
        10. SDK
```

---

## Summary by Category

| Category | Gaps |
|----------|------|
| **Critical path** | #1 Poseidon digest, #2 batch size constraint, #3 recursion witness, #5 prover API |
| **Required before mainnet** | #4 native verifiers, #6 job queue, #7 key management, #8 monitoring, #11 ceremony |
| **Enhancement** | #9 indexer, #10 SDK, #12 devnet |
