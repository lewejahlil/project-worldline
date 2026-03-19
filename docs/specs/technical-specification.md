# Project Worldline — Technical Specification (Revised)

## Abstract

Worldline is a multi‑ZK‑prover architecture for rollups on EVM L1s. An off‑chain aggregator applies a policy defined in canonical JSON, constructs a canonical manifest of selected provers from a signed directory, optionally performs recursion/aggregation over a subset of inner proofs, and produces one Groth16/BN254 proof that binds: (a) the window’s public inputs, (b) the STF program verifying key, (c) the governing policy hash, and (d) the canonical prover‑set digest. On‑chain, the `WorldlineFinalizer` verifies that proof and accepts exactly one output per contiguous window. There is no on‑chain k‑of‑n, and non‑ZK evidence is not accepted.

This revised specification incorporates lessons from early prototypes and a security review. It formalises the off‑chain directory format and deterministic selection algorithm, elaborates the recursion gadgets, clarifies liveness and redundancy expectations, expands supply‑chain protections, defines cross‑language canonicalisation libraries, and outlines governance and operational processes.

## Scope

Stack‑agnostic for any EVM chain that supports BN254 (`alt_bn128`) pairing precompiles (e.g., Ethereum L1 and most EVM L2s). Data‑availability choices remain the rollup’s concern; Worldline binds whatever the STF commits. Alternative outer proving systems (e.g., PLONK/FFLONK over BLS12‑381) can be plugged in via the adapter interface without changing the four public signals.

## Goals

- **Single‑proof finality:** Finalise each window with a single ZK proof at predictable, low gas.
- **Auditable provenance:** Make selected ZK provers auditable via an in‑proof manifest digest and signed directory attestations.
- **Recursion/aggregation capability:** Ship recursion gadgets; activation is policy‑driven.
- **Deterministic multi‑prover selection:** Define precise, deterministic selection over a signed directory using lexicographic keys and explicit tie‑breakers.
- **Governed parameters:** Govern the STF verifying key and the selection policy via a timelocked registry; support safe rotations and circuit swaps.

## Non‑Goals

- Accepting fraud/optimistic proofs or signatures on‑chain.
- Implementing DA logic or changing a rollup’s STF.
- Providing randomised prover selection; selection is deterministic.

## Terminology

- **Proof**: succinct zero‑knowledge proof of computational integrity (Groth16/BN254 by default; other systems pluggable via adapters).
- **Multi‑ZK‑Prover**: selection across multiple SNARK families/implementations (e.g., Groth16, PLONK/FFLONK, Halo2/KZG, SNARK‑wrapped STARKs).
- **Directory entry**: signed record describing a prover (see § Off‑chain Components).
- **Policy**: canonical JSON describing selection requirements and recursion parameters.
- **Manifest**: canonical JSON array of the selected provers for a window.

## Public Interfaces (Summary)

| Surface   | Name                       | Purpose                                                                                                          |
| --------- | -------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Contract  | `WorldlineFinalizer`       | Accept exactly one ZK proof per window; enforce contiguity, domain binding and staleness; emit canonical events. |
| Interface | `IZkAggregatorVerifier`    | Adapter API exposing verification and the four fixed public signals.                                             |
| Contract  | `Groth16ZkAdapter`         | Pins the verifying key and policy; verifies Groth16 proofs with fixed signal order.                              |
| Registry  | `WorldlineOutputsRegistry` | Timelocked activation of `{programVKey, policyHash, oracle}` per domain; governs rotations and adapter swaps.    |

## Public Inputs ABI (224 bytes, big‑endian `uint256`)

| Offset | Field                  | Type      | Description                                                                                  |
| -----: | ---------------------- | --------- | -------------------------------------------------------------------------------------------- |
|   0x00 | `stfCommitment`        | `bytes32` | Keccak of the seven ABI words below (EVM Keccak‑256), including `domainSeparator`.           |
|   0x20 | `l2Start`              | `uint256` | First L2 block in the window.                                                                |
|   0x40 | `l2End`                | `uint256` | Last L2 block in the window.                                                                 |
|   0x60 | `outputRoot`           | `bytes32` | Rollup output root over `[l2Start,l2End]`.                                                   |
|   0x80 | `l1BlockHash`          | `bytes32` | Reference L1 block hash (integration‑specific).                                              |
|   0xA0 | `domainSeparator`      | `bytes32` | `keccak256(abi.encode(chainId, finalizerAddress, domainTag))`; binds proofs to a deployment. |
|   0xC0 | `windowCloseTimestamp` | `uint256` | Window close time; bounds acceptance staleness.                                              |

Outer proof encoding uses Groth16/BN254 as 8 × `uint256` (256 bytes). The system can support alternative outer proof systems (e.g., PLONK) by deploying a new adapter and outer circuit via the registry; the four public signals and ABI remain fixed.

Other commitments:

- `programVKey` = `bytes32` commitment to the STF verifying key.
- `policyHash` = `keccak256(canonical_json(policy))`.
- `proverSetDigest` = `keccak256(canonical_json(manifest))`.

Canonical JSON rules: UTF‑8; no insignificant whitespace; lexicographic key order; stable array order; lowercase field names where specified. A **reference canonicaliser** must be published in at least two languages (e.g., Rust and TypeScript) with test vectors; cross‑language conformance is critical to avoid digest mismatches.

## Parameters and Bounds

| Name                   | Value | Notes                                                                                         |
| ---------------------- | ----: | --------------------------------------------------------------------------------------------- |
| `MAX_MANIFEST_ENTRIES` |     8 | Hard bound for selection set size; protects gas and selection determinism.                    |
| `MAX_MANIFEST_BYTES`   |  1536 | Canonical manifest byte length (pre‑padding) cap; enforced off‑chain and in‑circuit.          |
| `MAX_IN_PROOF`         |     4 | Upper bound on inner SNARKs proven recursively.                                               |
| `MAX_LOCATOR_BYTES`    |    96 | Optional locator emission cap.                                                                |
| `k_in_proof`           |   0…4 | Number of manifest entries proven in‑proof; must be ≤ selected entries. Policy controls this. |

The aggregator MUST refuse to build if any bound is exceeded【351724319320624†L63-L64】.

## Events

Only `windowIndex` is indexed to minimize gas usage.

- `OutputProposed(uint256 indexed windowIndex, bytes32 outputRoot, uint256 l2Start, uint256 l2End, bytes32 l1BlockHash)`
- `ZkProofAccepted(uint256 indexed windowIndex, bytes32 policyHash, bytes32 programVKey, bytes32 proverSetDigest)`
- `ManifestAnnounced(bytes32 proverSetDigest, bytes locator)` (optional; default disabled)
- `ZkProofMeta(uint256 indexed windowIndex, uint8 recursionMode, uint8 kInProof, uint8 selectedCount)` (optional; default disabled)

Watcher requirements:

- Recompute `keccak256(canonical_json(manifest))` and match `proverSetDigest`.
- Verify `policyHash` against the timelocked registry.
- Verify that published directory snapshots and signatures match the manifest entries (see § Off‑chain Components).
- Treat `locator` as a hint; the digest is authoritative.

## Gas and Cost

For Groth16/BN254, verify gas is ~207,700 + 7,160 × (public signals) ≈ 236k for four signals【351724319320624†L79-L80】. Typical per‑window L1 cost (verify + calldata + logs) is ~242k–305k gas with defaults【351724319320624†L79-L83】. Optional telemetry events (`ManifestAnnounced`, `ZkProofMeta`) are compiled out by default and can save ~1k–2k gas/window【351724319320624†L84-L87】. Recursion off by default; enabling recursion increases proving time and in‑circuit constraints (see § Recursion and Aggregation).

## Contracts

### WorldlineFinalizer (on‑chain)

Constructor: `(address adapter, uint64 l1FinalityMinDepth, bytes32 domainSeparator, uint64 maxAcceptanceDelay)`.

State: adapter; permissionless (boolean); proposers; submitters; `nextWindowIndex` (0); `lastL2EndBlock` (0); paused; `l1FinalityMinDepth`; `DOMAIN_SEPARATOR` (immutable); `maxAcceptanceDelay`.

Errors: `Paused()`, `BadInputsLen()`, `NotAuthorized()`, `NotContiguous()`, `AdapterZero()`, `LocatorTooLong()`, `DomainMismatch()`, `TooOld()`.

`submitZkValidityProofWithMeta(bytes proof, bytes publicInputs224, uint8 recursionMode, uint8 kInProof, uint8 selectedCount, bytes locator)`

- Checks: not paused; length = 224; permission (if enabled); `locator.length ≤ MAX_LOCATOR_BYTES` if locator compiled; decode ABI; enforce domain equality; enforce contiguity; enforce staleness (`now - windowCloseTimestamp ≤ maxAcceptanceDelay`); call adapter; require valid proof and matching `stfCommitment`; emit events; advance window.

`submitZkValidityProof(bytes proof, bytes publicInputs224)`

- Minimal variant; emits only `OutputProposed` and `ZkProofAccepted`.

Invariants: one accepted proof per window; windows strictly contiguous; ABI word 0 equals `stfCommitment`; domain enforced.

### IZkAggregatorVerifier (adapter interface)

```
interface IZkAggregatorVerifier {
  function verify(bytes calldata proof, bytes calldata publicInputsRaw /* 224 B */)
    external
    view
    returns (
      bool valid,
      bytes32 stfCommitment,
      bytes32 programVKey,
      bytes32 policyHash,
      bytes32 proverSetDigest
    );
}
```

### Groth16ZkAdapter

Pins `verifier`, `programVKeyPinned`, and `policyHashPinned` as immutables. Verifies Groth16 with four public signals in order: `[stfCommitment, programVKey, policyHash, proverSetDigest]`. Returns the pins and the digest read directly from the proof.

### Worldline Outputs Registry (timelocked)

Keyed by `keccak256(chainIdHash, domainTag)`. State maps `active[key] = {oracle, programVKey, policyHash}` and `pending[key] = {record, eta}`. Functions:

- `schedule(record, eta)`; `eta` must be ≥ `block.timestamp + minDelay`.
- `activate(key)` after timelock; moves pending to active. An adapter swap is performed by updating the finalizer’s adapter to the new contract.
- Events: `PendingSet`, `Activated`, `MinDelaySet`.

Governance processes must define multisig and timelock parameters; at a minimum the administrator keys should be held in a 2‑of‑3 or higher threshold multisig and published timelocks (e.g., 24–72 hours) must be honoured. Emergency pause/resume functions should be accessible via a separate governance path with shorter timelocks.

## Circuit (Outer; Groth16/BN254)

### Public signals

1. `stfCommitment` — binds the entire ABI (including `domainSeparator`).
2. `programVKey` — pins the STF verifier.
3. `policyHash` — pins selection and recursion rules.[... ELLIPSIZATION ...]d.

## Off‑chain Components

### ZK Prover Directory (signed, content‑addressed)

The directory is a canonical JSON object whose keys are prover identifiers; the value for each key is a record describing one prover implementation. The directory MUST be signed by a recognised authority (e.g., a multisig of provers and the rollup operator). The directory snapshot digest (e.g., SHA‑256) and the set of signatures are published with each window.

Each directory **entry** has the following fields (all mandatory unless stated optional):

| Field             | Type      | Description                                                                                                   |
| ----------------- | --------- | ------------------------------------------------------------------------------------------------------------- |
| `prover_id`       | `string`  | Human‑readable identifier unique within its family.                                                           |
| `family`          | `string`  | Proving system family (e.g., `groth16_bn254`, `plonk_bls12_381`, `halo2_kzg`).                                |
| `version`         | `string`  | Semantic version (e.g., `1.2.0`); used in sorting and compatibility checks.                                   |
| `endpoints`       | `object`  | Map of service endpoints (e.g., REST URLs, IPFS locators). At least one endpoint MUST be provided.            |
| `vkey_commitment` | `bytes32` | Commitment to the prover’s verifying key; watchers must cross‑check this with `programVKey` for inner proofs. |
| `image_digest`    | `string`  | Digest of the prover container/binary (e.g., OCI‑digest); ensures reproducible builds.                        |
| `attestations`    | `array`   | Optional attestations (e.g., TEE measurements, audits) signed by third parties.                               |
| `latency_ms`      | `integer` | Observed round‑trip latency in milliseconds (for tie‑breakers).                                               |
| `cost_usd`        | `integer` | Observed cost per proof in USD (for tie‑breakers).                                                            |
| `health`          | `object`  | SLO/health metrics (uptime, error rate); used to filter eligible entries.                                     |

The aggregator MUST verify the directory signatures and ensure the JSON adheres to the canonicalisation rules. Directory updates are asynchronous; the snapshot hash and signatures included per window provide auditability. Provers must supply reproducible binaries; the `image_digest` should refer to an OCI‑compliant image or reproducible build root. Attestations should be signed by independent auditors or secure enclaves (e.g., SGX); policy can require attestations from specific families or TEEs.

### Policy (canonical JSON)

The policy drives selection diversity and recursion parameters. It is a canonical JSON object with the following fields:

| Field                   | Type                | Description                                                                                            |
| ----------------------- | ------------------- | ------------------------------------------------------------------------------------------------------ |
| `version`               | `integer`           | Policy version; increments on changes.                                                                 |
| `min_count`             | `integer`           | Minimum number of provers to select.                                                                   |
| `min_distinct_families` | `integer`           | Minimum number of distinct families.                                                                   |
| `required_families`     | `array`             | List of families that MUST be included.                                                                |
| `allowlist_provers`     | `array` (optional)  | List of prover identifiers allowed; if omitted all provers are allowed.                                |
| `fallback_tiers`        | `array` (optional)  | List of fallback family‑mix strategies to apply if the main selection fails.                           |
| `min_inclusion_ratio`   | `number`            | Ratio (0–1) of eligible entries that must be selected (post SLO filter).                               |
| `recursion`             | `object` (optional) | Specifies recursion mode (`none`, `snark‑accum`, `snark‑miniverifier`), `k_in_proof`, and `max_inner`. |

`policyHash = keccak256(canonical_json(policy))`. Any change to the policy requires an adapter swap via the registry, as the policy is pinned in the contract. Policies should be auditable and version‑controlled; test vectors and watchers should verify that the on‑chain policy matches off‑chain expectations.

### Manifest and Digest

Per window, the aggregator constructs a manifest: a canonical JSON array of the selected directory entries, stable‑sorted by `(family, prover_id, version)`. Each manifest entry must contain exactly the directory fields used in circuit checks (`prover_id`, `family`, `version`, `vkey_commitment`, `image_digest`); additional fields may be included for audit but MUST NOT affect sorting or digest. The digest is `proverSetDigest = keccak256(canonical_json(manifest))`.

### Deterministic Selection

Given `(directory snapshot, policy, SLO filter)`, selection MUST be deterministic. Let `eligible` be the list of directory entries passing SLO filters and (if present) `allowlist_provers`. Let `key = family || 0x00 || prover_id || 0x00 || version`. Sort `eligible` lexicographically by `key`. Choose the smallest prefix (in sorted order) satisfying:

1. `selected.length ≥ min_count`.
2. `selected` contains at least `min_distinct_families` distinct `family` values.
3. `required_families ⊆ selected_families`.
4. `selected.length / eligible.length ≥ min_inclusion_ratio`.

If multiple prefixes satisfy the above, apply tie‑breakers: prefer lower `latency_ms`, then lower `cost_usd`, comparing entry by entry. If selection still fails, apply `fallback_tiers` (if defined) by progressively lowering `min_distinct_families` or adjusting `required_families`. Selection MUST NOT be randomised; watchers must be able to recompute `selected` given the same inputs. When recursion is enabled, ensure `k_in_proof ≤ selected.length` and `max_inner` is respected. A reference implementation of the selection algorithm, with pseudocode and test vectors, should be published in the repository【946157393255609†L160-L167】.

### Publication

Deployments may emit `ManifestAnnounced(proverSetDigest, locator)` once per window. The `locator` is a hint (e.g., IPFS CID or HTTPS URL) pointing to the published directory snapshot, policy, manifest, and optional recursion witness. The digest is authoritative; watchers MUST recompute `proverSetDigest` and `policyHash` from the bytes.

## Recursion and Aggregation (capability; policy‑driven)

Recursion is optional and controlled via policy. When disabled, the aggregator must set `recursionMode = 0` and `kInProof = 0`. When enabled, it must prepare a recursion witness according to the selected mode:

- **snark‑accum (accumulator mode):** Use an accumulator proof to aggregate up to `max_inner` inner SNARKs. The witness includes accumulation inputs and compressed commitments. The circuit enforces that the number of aggregated inner proofs `m` satisfies `m ≥ k_in_proof` and that the aggregated proofs correspond to the first `m` manifest entries.
- **snark‑miniverifier (mini‑verifier mode):** Embed minimal verifiers for each of the first `k_in_proof` inner proofs. The witness includes each inner proof; the circuit replays the inner verifications. The cost scales roughly with `k_in_proof` and the complexity of the inner verifiers; careful benchmarking is required. Soundness requires the mini‑verifiers to be consistent with the pinned `vkey_commitment` in the manifest.

Operators should publish performance metrics for both modes (e.g., proving time, proof size, gas for outer verification) to inform policy choices. Migration to alternative recursion gadgets (e.g., PLONK accumulators) requires a new circuit and adapter via the registry; the public signals remain unchanged.

## Compatibility

Worldline is stack‑neutral: it relies only on EVM BN254 precompiles and does not depend on any specific rollup stack. Deployments may integrate optional facades to mirror other stacks’ event shapes (e.g., OP‑stack `OutputProposed`/`StateBatchAppended` events) without affecting correctness【961699711512204†L80-L83】. Alternative outer proof systems (e.g., PLONK/FFLONK on BLS12‑381) can be integrated by deploying a new outer circuit and adapter; the four public signals and ABI stay fixed【961699711512204†L142-L145】.

## Observability

Authoritative on‑chain events are `OutputProposed` and `ZkProofAccepted`. Optional telemetry (`ManifestAnnounced`, `ZkProofMeta`) can assist monitoring but are off by default. Watchers MUST verify `policyHash` via the registry and recompute `proverSetDigest` from the manifest【351724319320624†L73-L76】. Cross‑language canonicalisation libraries with test vectors must be provided to avoid canonicalisation bugs (see Threat T7【440116836263521†L38-L48】). Reference watcher scripts should be published with the repository.

## Governance and Upgrades

`programVKey` and `policyHash` are pinned immutably in the adapter; changes flow through the timelocked `WorldlineOutputsRegistry` and an adapter update on the finalizer【351724319320624†L190-L191】. This requires two governance actions: (1) schedule and activate the new record in the registry; (2) update the finalizer’s adapter pointer. The registry must be controlled by a multisig subject to a minimum timelock (e.g., 24–72 hours). Emergency pause/resume functions should be accessible through a separate governance path; changes to `maxAcceptanceDelay`, `l1FinalityMinDepth`, and permissionless mode can be enacted without crossing the timelock.

## Liveness and Redundancy

The design allows multiple independent aggregators to produce proofs for the same window; only the first valid proof accepted by the finalizer finalises the window. To avoid single points of failure, deployments SHOULD operate at least two aggregators using the same directory snapshot and policy. Aggregators MUST publish directory snapshots and manifests so watchers can audit selection and reconstruct the same digest. In case of aggregator compromise, a fallback aggregator can submit a proof before `maxAcceptanceDelay` expires.

## Security Considerations

Worldline’s threat model (see `docs/security/threat-model.md`) enumerates threats such as invalid proofs, cross‑domain replay, stale proofs, malicious policies, canonicalisation bugs, recursion witness forgery, supply‑chain attacks and DoS【440116836263521†L38-L54】. Mitigations include pinned verifiers, timelocked governance, deterministic selection, canonical JSON with conformance tests, soundness proofs for recursion gadgets, reproducible provers with `image_digest` and attestations, bounded calldata and off‑chain checks, multisig keys and monitoring, and cross‑language watcher tools. Residual risks remain in circuit/verifier correctness and supply‑chain; continuous audits and monitoring are required.
