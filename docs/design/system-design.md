# Project Worldline — System Design

## Purpose
Define the architecture, dataflow, and component responsibilities for Worldline’s multi-ZK-prover validity pipeline. The design is stack-neutral for EVM environments that expose BN254 pairing precompiles and requires no L1 protocol changes.

## Architectural Overview

### Finality Plane (Onchain)
- **WorldlineFinalizer**: Accepts exactly one ZK proof per window; enforces contiguity, domain binding, and staleness; emits canonical events. Gas-minimized defaults: immutable domain separator, zero-copy ABI decode, single indexed topic per event, optional telemetry compiled out.
- **Groth16ZkAdapter**: Verifier wrapper that pins `programVKey` and `policyHash` and exposes the four fixed public signals in order. Returns `(valid, stfCommitment, programVKey, policyHash, proverSetDigest)`.
- **WorldlineOutputsRegistry** (timelocked): Schedules and activates `{programVKey, policyHash, oracle}` per domain; enables safe VK/policy rotations and adapter swaps.

### Proof And Provenance Plane (Offchain)
- **Aggregator/Driver**: Snapshots the ZK Prover Directory, applies the selection policy, constructs the canonical manifest and digest, optionally prepares a recursion witness, generates the outer proof, and submits to the finalizer.
- **ZK Prover Plugins**: Pluggable families/implementations (e.g., Groth16, Halo2/KZG, SNARK-wrapped STARKs). STARKs count toward in-proof checks only when SNARK-wrapped.
- **ZK Prover Directory**: Signed, content-addressed registry of available provers with `vkey_commitment`, `image_digest`, SLO/health, and optional attestations.
- **Policy**: Canonical JSON that sets diversity/minimum counts, allowlists, inclusion ratio, and recursion parameters (`mode`, `k_in_proof`, `max_inner`).

### Governance
- VK/policy changes and adapter swaps are gated by the timelocked registry. Finalizer operational toggles (`permissionless`, proposer/submitter sets, pause, `l1FinalityMinDepth`, `maxAcceptanceDelay`) are local and non-governance-critical.

## Data And Control Flow

1. **Window Assembly**
   - Watcher prepares the 224-byte ABI payload:
     - `stfCommitment` = Keccak of the seven ABI words (EVM Keccak-256), including `domainSeparator`.
     - `l2Start`, `l2End`, `outputRoot`, `l1BlockHash`, `domainSeparator`, `windowCloseTimestamp`.
   - `domainSeparator = keccak256(abi.encode(chainId, finalizerAddress, domainTag))`.

2. **Directory Snapshot And Eligibility**
   - Aggregator snapshots and verifies the signed directory.
   - Apply SLO filters (latency/health) to get the eligible set for this window.

3. **Deterministic Selection**
   - Deterministically select the lexicographically smallest prefix by key `family || 0x00 || prover_id || version` satisfying:
     - `min_count`, `min_distinct_families`, `required_families`.
     - allowlist (if present).
     - inclusion ≥ `min_inclusion_ratio` over eligible entries.
   - Tie-breakers: lower `latency_ms`, then lower `cost_usd`.

4. **Manifest And Digest**
   - Build canonical JSON (stable-sorted by `(family, prover_id, version)`).
   - `proverSetDigest = keccak256(canonical_json(manifest))`.

5. **Optional Recursion Witness**
   - If policy enables recursion:
     - **snark-accum**: Prove an accumulator relation for up to `max_inner` SNARKs; enforce mapping to the first `m` manifest entries and `m ≥ k_in_proof`.
     - **snark-miniverifier**: Embed/run mini verifiers for the first `k_in_proof` SNARKs (up to `max_inner`).

6. **Outer Proof Generation**
   - Produce a Groth16/BN254 proof with **four** public signals, in order:
     1. `stfCommitment`
     2. `programVKey`
     3. `policyHash`
     4. `proverSetDigest`

7. **Submission And Finalization**
   - Send via `submitZkValidityProof` (minimal) or `submitZkValidityProofWithMeta` (optional telemetry).
   - Finalizer verifies through the adapter; checks domain equality, contiguity, staleness; emits:
     - `OutputProposed(windowIndex, outputRoot, l2Start, l2End, l1BlockHash)`
     - `ZkProofAccepted(windowIndex, policyHash, programVKey, proverSetDigest)`
     - Optional: `ManifestAnnounced(proverSetDigest, locator)` and `ZkProofMeta(...)`.

## Component Responsibilities

### WorldlineFinalizer
- Inputs: `(proof, publicInputs224[, meta])`.
- Validations: not paused; length=224; permission gate (if enabled); `locator.length ≤ MAX_LOCATOR_BYTES` when compiled; `domainSeparator` equality; strict contiguity; `now - windowCloseTimestamp ≤ maxAcceptanceDelay`.
- Adapter call: require `valid` and `stfFromProof == stfCommitment`.
- State advances: increment `nextWindowIndex`, update `lastL2EndBlock`.
- Gas discipline: immutable domain separator; zero-copy `calldataload`; single indexed topic; optional telemetry compiled out.

### Groth16ZkAdapter
- Pins `programVKey` and `policyHash` immutably; wires to an audited Groth16 verifier.
- Returns the signals read directly from the proof to avoid recomputation errors.

### WorldlineOutputsRegistry
- Timelocked `{programVKey, policyHash, oracle}` per `(chainIdHash, domainTag)`; events `PendingSet`, `Activated`, `MinDelaySet`.
- Safe rotations and outer-circuit swaps by updating the adapter pointer at the finalizer.

### Aggregator/Driver
- Ensures selection determinism and manifest bounds.
- Produces optional recursion witness.
- Generates and submits the outer proof via redundant backends.
- Publishes manifest and policy artifacts; digest is authoritative.

### ZK Prover Plugins
- Provide prover services with reproducible binaries (`image_digest`) and `vkey_commitment`.
- STARKs can be SNARK-wrapped to participate in in-proof checks.

## Circuit Design (Outer; Groth16/BN254)

### Public Signals
1. `stfCommitment` — binds the entire ABI (including `domainSeparator`).
2. `programVKey` — pins the STF verifier.
3. `policyHash` — pins selection/recursion rules.
4. `proverSetDigest` — binds the canonical manifest bytes.

### Keccak Gadget
- EVM Keccak-256 variant for both ABI hashing and manifest hashing.
- Sized for `ceil(MAX_MANIFEST_BYTES/136)` sponge blocks; fixed-capacity, no dynamic loops.

### Recursion Gadgets (Optional, Policy-Driven)
- **Accumulator** mode minimizes constraints by proving an aggregate pairing relation over inner SNARKs.
- **Mini-verifier** mode embeds small verifiers for greater in-proof transparency at higher constraint cost.

### Migration
- Changing recursion mode, `max_inner`, or outer proving system requires a new circuit/zkey and adapter, activated via the timelocked registry. The four-signal interface remains unchanged.

## Determinism And Canonicalization

### Canonical JSON Rules
- UTF-8; no insignificant whitespace; lexicographic key order; stable array order; lowercase field names as specified.
- Reference canonicalizers in multiple languages MUST produce byte-identical outputs. The onchain digest is always `keccak256` of these exact bytes.

### Selection Determinism
- Fully deterministic given `(directory snapshot, policy, SLO filters)` with documented tie-breakers.
- Stable sorts and prefix selection ensure reproducible `proverSetDigest`.

## Gas And Performance

- Groth16 verify gas ≈ `207,700 + 7,160 × signals` ⇒ about **236k** for four signals.
- Typical per-window total (verify + calldata + logs): **~242k–305k gas** with defaults:
  - Immutable domain separator.
  - Zero-copy ABI decode.
  - Permissionless hot path.
  - One indexed topic per event.
  - Telemetry events compiled out by default.
- Recursion off by default for baseline cost; policy can enable it with published benchmarks and gas gates.
- ABI fixed at 224 bytes; public signals fixed at 4 to cap verify costs.

## Security Properties

- **Domain Binding:** Proofs are bound to a deployment via `domainSeparator`.
- **Single-Proof Finality:** Exactly one accepted proof per contiguous window; duplicates and gaps rejected.
- **Policy/Provenance Binding:** Circuit binds `programVKey`, `policyHash`, and `proverSetDigest`; watchers recompute digests from artifacts.
- **Replay Defenses:** Cross-instance and stale-proof replays are rejected (domain and staleness checks).
- **Governance Safety:** VK/policy/adapter changes timelocked; events surface pending/activation steps.
- **DoS Hygiene:** Sender-pays verification; optional allowlists; preflight verification offchain; small bounded calldata.

## Compatibility

- **Target Environment:** EVM chains with BN254 (alt_bn128) pairing precompiles (e.g., Ethereum L1 and most EVM L2s). No L1 changes.
- **Alternative Outer Proof Systems:** Deployments preferring PLONK/FFLONK (BLS12-381/KZG) can swap the outer circuit and adapter via the registry while preserving the four public signals and ABI.
- **Stack Integrations:** Optional facades can mirror another stack’s event shape when useful; correctness does not depend on any facade.
- **Data Availability:** Orthogonal; the rollup’s STF must commit any DA references it relies on, and Worldline finalizes whatever the STF binds.

## Observability And Operations

- **Authoritative Events:** `OutputProposed`, `ZkProofAccepted`.
- **Optional Telemetry (Default Off):** `ManifestAnnounced`, `ZkProofMeta`.
- **Watchers:** Verify `policyHash` via the registry; recompute `proverSetDigest` from the published manifest; treat `locator` as hint only.
- **Runbooks:** To be published post-implementation (deployment, rotation, pause/resume, incident response).

## Upgrade And Rotation Flows

- **VK/Policy Rotation:** Propose in the registry (`PendingSet`), wait timelock, `Activated`, then update adapter pointer at the finalizer if required.
- **Adapter Swap (Outer Circuit Migration):** Deploy new adapter with new verifier/VK/policy pins; schedule and activate via registry; update finalizer’s adapter address.
- **Operational Controls:** Toggle `permissionless`, proposer/submitter sets, `paused`, `l1FinalityMinDepth`, and `maxAcceptanceDelay` without touching governance state.

## Published Artifacts Per Window

- Canonical manifest bytes and `proverSetDigest`.
- Policy JSON and `policyHash`.
- Directory snapshot hash and signatures.
- Proof metadata (optional telemetry).
- Gas snapshots and SLA metrics (for regression detection).

