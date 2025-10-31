# Project Worldline — System Design (Revised)

## Purpose

Define the architecture, dataflow and component responsibilities for Worldline’s multi‑ZK‑prover validity pipeline.  This revised design builds on the initial proposal【961699711512204†L21-L39】 and incorporates feedback from threat modelling and prototype implementations.  It formalises off‑chain data structures, defines deterministic selection with explicit algorithms, expands recursion gadget descriptions, clarifies liveness expectations, and outlines supply‑chain and operational considerations.

Worldline remains stack‑neutral for EVM environments that expose BN254 pairing precompiles and requires no L1 protocol changes.  Alternative outer proving systems (e.g., PLONK/FFLONK over BLS12‑381) can be integrated via the adapter interface without altering the public ABI or signals.

## Architectural Overview

### Finality Plane (On‑chain)

- **WorldlineFinalizer**: Accepts exactly one ZK proof per window; enforces contiguity, domain binding and staleness; emits canonical events.  The contract is gas‑optimised via an immutable domain separator, zero‑copy ABI decode, a single indexed topic per event and compile‑time toggles for telemetry【961699711512204†L65-L70】.
- **Groth16ZkAdapter** (default): Verifier wrapper that pins `programVKey` and `policyHash` and exposes the four fixed public signals in order.  Returns `(valid, stfCommitment, programVKey, policyHash, proverSetDigest)`【961699711512204†L73-L74】.
- **WorldlineOutputsRegistry** (timelocked): Schedules and activates `{programVKey, policyHash, oracle}` per domain; enables safe VK/policy rotations and adapter swaps【961699711512204†L77-L80】.  Governance processes must enforce multisig control and a minimum timelock.

### Proof and Provenance Plane (Off‑chain)

- **Aggregator/Driver**: Snapshots the signed ZK Prover Directory, applies deterministic selection based on the policy, constructs the canonical manifest and digest, optionally prepares a recursion witness, generates the outer proof using ZK prover plugins and submits to the finalizer.  The aggregator MUST verify directory signatures and canonicalisation, apply SLO/health filters deterministically, and publish the directory snapshot hash, manifest bytes and proof metadata for watchers.
- **ZK Prover Plugins**: Pluggable prover families/implementations (e.g., Groth16/BN254, PLONK/FFLONK/BLS12‑381, Halo2/KZG, SNARK‑wrapped STARKs).  STARKs count toward in‑proof checks only when wrapped in a SNARK.  Each plugin must be versioned and deliver reproducible binaries with `vkey_commitment` and `image_digest` in the directory.
- **ZK Prover Directory**: Signed, content‑addressed registry of available provers with detailed fields (ID, family, version, endpoints, `vkey_commitment`, `image_digest`, SLO/health metrics, attestations).  See § Off‑chain Components for the schema.
- **Policy**: Canonical JSON describing diversity and recursion requirements: `min_count`, `min_distinct_families`, `required_families`, optional `allowlist_provers`, `fallback_tiers`, `min_inclusion_ratio` and recursion parameters (`mode`, `k_in_proof`, `max_inner`).

### Governance

VK/policy changes and adapter swaps are gated by the timelocked registry.  Finalizer operational toggles (`permissionless`, proposer/submitter sets, pause, `l1FinalityMinDepth`, `maxAcceptanceDelay`) are local and do not require governance delays; they should nevertheless be recorded in change logs to aid monitoring and audits.

## Data and Control Flow

1. **Window Assembly**
   - Watcher (or aggregator) prepares the 224‑byte ABI payload comprising `stfCommitment`, `l2Start`, `l2End`, `outputRoot`, `l1BlockHash`, `domainSeparator`, `windowCloseTimestamp`【961699711512204†L23-L29】.
   - Compute `domainSeparator = keccak256(abi.encode(chainId, finalizerAddress, domainTag))` to bind the proof to a deployment.
   - Compute `stfCommitment = Keccak(abi_words)` (EVM Keccak‑256) and include it as the first ABI word.

2. **Directory Snapshot and Eligibility**
   - Aggregator fetches the latest signed directory JSON; verify signatures (multisig or TEE attestations) and compute its digest.
   - Apply SLO/health filters (uptime, latency, cost) as deterministic functions to produce the **eligible set**.  Filters MUST NOT include randomness.
   - Publish the directory snapshot hash and signatures with the proof for watcher verification.

3. **Deterministic Selection**
   - Sort `eligible` by `key = family || 0x00 || prover_id || 0x00 || version` (lexicographically)【946157393255609†L160-L167】.
   - Choose the smallest prefix `selected` satisfying: (a) `|selected| ≥ min_count`; (b) `selected` contains at least `min_distinct_families`; (c) `required_families` ⊆ the families of `selected`; (d) `|selected| / |eligible| ≥ min_inclusion_ratio`.  If no prefix satisfies the constraints, apply fallback tiers by gradually relaxing diversity constraints.
   - Resolve ties by comparing `latency_ms`, then `cost_usd`, entry by entry.  Randomness MUST NOT be used; watchers must reproduce the same selection.
   - Ensure `k_in_proof ≤ |selected|` when recursion is enabled.  Publish the selected list as a manifest and compute `proverSetDigest = keccak256(canonical_json(manifest))`.

4. **Manifest and Digest**
   - Build canonical JSON containing exactly the fields needed for circuit checks (`prover_id`, `family`, `version`, `vkey_commitment`, `image_digest`) and optionally other audit fields.  Lexicographically sort entries by `(family, prover_id, version)`; stable sort across fields.
   - Compute `proverSetDigest` and include it in the proof public signals and the `ZkProofAccepted` event.【961699711512204†L41-L42】

5. **Optional Recursion Witness**
   - If policy enables recursion, prepare a witness according to the selected mode:
     - **Accumulator mode:** Aggregate up to `max_inner` inner SNARKs using a pairing accumulator; ensure `m ≥ k_in_proof` and the inner proofs correspond to the first `m` manifest entries.  Publish `m` in proof metadata.
     - **Mini‑verifier mode:** Include each inner proof for the first `k_in_proof` manifest entries; the outer circuit embeds minimal verifiers for each inner proof.  Benchmark and publish constraint costs and gas impacts per `k_in_proof`.
   - The recursion witness MUST be deterministic and verifiable off‑chain.  Watchers should recompute or verify the witness using reference tools.

6. **Outer Proof Generation**
   - Produce a Groth16/BN254 proof with the four public signals: `stfCommitment`, `programVKey`, `policyHash`, `proverSetDigest`【961699711512204†L50-L54】.  If using an alternative proof system (e.g., PLONK/KZG), produce a proof compatible with the new adapter; the signals stay unchanged.
   - Ensure the prover’s verifying key commitment matches `programVKey` and the on‑chain pin; mismatches must abort the aggregation.

7. **Submission and Finalization**
   - Submit the proof via `submitZkValidityProof` (minimal) or `submitZkValidityProofWithMeta` (if including recursion metadata or locator).
   - Finalizer verifies via the adapter; checks domain equality, contiguity and staleness; ensures exactly one proof per window; emits `OutputProposed` and `ZkProofAccepted` events【961699711512204†L56-L62】.

## Component Responsibilities

### WorldlineFinalizer

As described in the technical specification, the finalizer enforces domain binding, contiguity and staleness, calls the adapter’s `verify` function, and emits canonical events.  It must remain agnostic to off‑chain selection; it simply trusts the proof and signals if valid.  Permissionless submission can be toggled; in permissioned mode, only designated submitters may call the finalizer.

### Groth16ZkAdapter / Alternative Adapters

Adapters encapsulate the outer verifying key and provide the `verify` interface.  The default Groth16 adapter pins the VK and `policyHash`.  Deployments may introduce new adapters for PLONK/FFLONK, Halo2 or other proof systems without changing the finalizer.  New adapters should implement the same four‑signal interface and call a gas‑optimised verifier library.

### WorldlineOutputsRegistry

Timelocked key/value store for `{programVKey, policyHash, oracle}` per `(chainIdHash, domainTag)`.  A pending record can be scheduled with an `eta`; after the timelock expires, `activate` moves it to `active`.  An adapter swap is executed by calling the finalizer’s `setAdapter` function.  The registry MUST be controlled by a multisig; time delays should be enforced by the contract and not rely on social processes.

### Aggregator/Driver

The aggregator MUST:

1. Fetch and verify the directory snapshot(s) and signatures.
2. Apply deterministic SLO filters and policy‑driven selection; publish the selection algorithm and test vectors.
3. Enforce `MAX_MANIFEST_ENTRIES`, `MAX_MANIFEST_BYTES` and recursion bounds; abort if bounds exceeded.
4. Generate the canonical manifest, compute `proverSetDigest`, and (optionally) produce a recursion witness.
5. Use redundant prover plugins to generate the outer proof; cross‑check `programVKey` and `policyHash` pins; abort on mismatch.
6. Submit the proof to the finalizer; publish directory snapshot, manifest, policy, recursion witness and proof metadata for watchers.
7. Operate multiple aggregator instances for liveness; coordinate to avoid race conditions (only one proof is accepted per window).  Aggregators should monitor each other and prepare fallback proofs if one fails.

### ZK Prover Plugins

Each plugin must provide reproducible binaries (`image_digest`) and the verifying key commitment (`vkey_commitment`).  The aggregator should prefer plugins with audited verifiers and soundness proofs.  STARK outputs may be SNARK‑wrapped to participate in recursion.  Plugins must be deterministic; SLO metrics must be measured and published to support tie‑breakers.

## Circuit Design (Outer; Groth16/BN254)

See the technical specification for details.  In summary:

- Four public signals: `stfCommitment`, `programVKey`, `policyHash`, `proverSetDigest`【961699711512204†L90-L97】.
- Keccak gadget sized for `ceil(MAX_MANIFEST_BYTES/136)` blocks to hash the manifest【961699711512204†L98-L100】.
- Optional recursion gadgets: accumulator and mini‑verifier modes【961699711512204†L102-L105】.  Soundness proofs for each gadget must be provided; parameter changes require a new circuit and adapter.

Performance benchmarks should be published for each supported recursion mode, including proving time, proof size and gas cost.  Policy may disable recursion by default and enable it only after performance is validated.

## Determinism and Canonicalisation

### Canonical JSON Rules

Canonical JSON MUST be UTF‑8, with no insignificant whitespace, lexicographic key order, stable array order and lowercase field names.  Cross‑language canonicalisation libraries with identical outputs (Rust, TypeScript, etc.) must be provided; watchers and auditors must use these libraries to recompute `policyHash` and `proverSetDigest`.  Conformance tests across languages are required to avoid canonicalisation bugs (see Threat T7【440116836263521†L38-L48】).

### Selection Determinism

Selection MUST be deterministic given the directory snapshot, policy and SLO filters.  The algorithm described above must be implemented identically across languages; watchers should run the same algorithm to verify the manifest.  Test vectors and pseudocode should be included in the repository to prevent drift.

## Gas and Performance

See the technical specification for baseline gas costs (~242k–305k gas per window with Groth16 verification【351724319320624†L79-L84】).  Recursion adds complexity: accumulator mode adds ~O(k) constraints and proof size; mini‑verifier mode adds a full verifying circuit per inner SNARK.  Operators should benchmark both modes and publish expected gas/latency.  Outer proof size stays constant (8 × `uint256`) for Groth16; other proof systems may differ.

## Security Properties

Security goals include domain binding, single‑proof finality, policy/provenance binding, replay defences, governance safety and DoS hygiene【961699711512204†L131-L139】.  The design emphasises deterministic selection, canonical JSON, pinned verifiers and timelocked governance.  New in this revision: explicit directory signatures and reproducible builds; cross‑language canonicalisation; aggregator redundancy for liveness; and reference watcher tools.  Residual risks include verifier/circuit bugs and supply‑chain attacks; continuous audits and monitoring are required.

## Compatibility

Worldline is compatible with any EVM chain supporting BN254 pairing precompiles; alternative outer proof systems may be integrated by adding new adapters without altering the finalizer【961699711512204†L141-L146】.  Optional facades can emit stack‑specific events for integrations (e.g., OP stack) without affecting correctness.  Data availability remains out of scope; the rollup STF must bind any DA references in `stfCommitment`.

## Observability and Operations

Authoritative events are `OutputProposed` and `ZkProofAccepted`; optional telemetry (`ManifestAnnounced`, `ZkProofMeta`) can aid monitoring.  Watchers MUST verify `policyHash` and recompute `proverSetDigest`【961699711512204†L149-L152】.  Operators should publish runbooks for deployment, rotation, pause/resume and incident response; cross‑language watcher scripts should be open sourced.  Liveness metrics (latency, SLO adherence) and selection logs should be recorded to detect anomalies.

## Upgrade and Rotation Flows

VK/policy rotation: schedule a new record in the registry (`PendingSet`); wait timelock; activate; update adapter pointer on the finalizer.  Adapter swap (outer circuit migration) follows the same flow.  Operational controls (permissionless mode, proposer/submitter sets, pause/resume, `l1FinalityMinDepth`, `maxAcceptanceDelay`) can be toggled without timelock but must be logged.  Emergency pause/resume may be used to mitigate incidents; restart procedures must ensure no window is missed.

## Published Artifacts per Window

- Canonical manifest bytes and `proverSetDigest`.
- Policy JSON and `policyHash`.
- Directory snapshot hash, signatures and snapshot block height.
- Recursion witness (if applicable) and proof metadata (e.g., recursion mode, `k_in_proof`, selected count).
- Aggregator logs: SLO metrics, selection parameters, tie‑break decisions.

Publishing these artifacts ensures auditability and enables independent re‑derivation of the digest and selection.
