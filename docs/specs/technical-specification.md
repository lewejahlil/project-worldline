# Project Worldline — Technical Specification

## Abstract
Worldline is a multi-ZK-prover architecture for rollups on EVM L1s. An offchain aggregator applies a multi-ZK-prover policy, constructs a canonical manifest of selected ZK provers, optionally performs recursion/aggregation over a subset of inner ZK proofs, and produces one Groth16 (BN254) outer ZK proof that binds: (a) the window’s public inputs, (b) the STF program verifying key, (c) the governing policy hash, and (d) the canonical ZK-prover-set digest. Onchain, the WorldlineFinalizer verifies that ZK proof and accepts exactly one output per contiguous window. There is no onchain k-of-n, and non-ZK evidence is not accepted.

## Scope
Stack-agnostic for any EVM chain that supports BN254 (alt_bn128) precompiles (e.g., Ethereum L1 and most EVM L2s). Data-availability choices remain the rollup’s concern; Worldline binds whatever the STF commits.

## Goals
- Finalize each window with a single ZK proof at predictable, low gas.
- Make selected ZK provers auditable via an in-proof manifest digest.
- Ship recursion/aggregation capability; activation is policy-driven.
- Govern the STF verifying key and the selection policy via a timelocked registry.
- Keep interfaces stack-neutral; optional facades can mirror ecosystem events.

## Non-Goals
- Accepting fraud/optimistic proofs or signatures onchain.
- Implementing DA logic or changing a rollup’s STF.

## Terminology
- Proof: succinct zero-knowledge proof of computational integrity.
- Multi-ZK-Prover: selection across multiple ZK families/implementations (e.g., Groth16, PLONK/FFLONK, Halo2/KZG, SNARK-wrapped STARKs).

## Public Interfaces (Summary)

| Surface | Name | Purpose |
|---|---|---|
| Contract | WorldlineFinalizer | Accept exactly one ZK proof per window; enforce contiguity, domain, and staleness; emit canonical events. |
| Interface | IZkAggregatorVerifier | Adapter API exposing verification and the four fixed public signals. |
| Contract | Groth16ZkAdapter | Pins VK and policy; verifies Groth16 with fixed signal order. |
| Registry | WorldlineOutputsRegistry | Timelocked activation of {programVKey, policyHash, oracle} per domain. |

## Public Inputs ABI (224 bytes, big-endian `uint256`)

| Offset | Field | Type | Description |
|---:|---|---|---|
| 0x00 | stfCommitment | bytes32 | Keccak of the seven ABI words below (EVM Keccak-256), includes domainSeparator. |
| 0x20 | l2Start | uint256 | First L2 block in window. |
| 0x40 | l2End | uint256 | Last L2 block in window. |
| 0x60 | outputRoot | bytes32 | Rollup output root over [l2Start,l2End]. |
| 0x80 | l1BlockHash | bytes32 | Reference L1 block hash (integration-specific). |
| 0xA0 | domainSeparator | bytes32 | keccak256(abi.encode(chainId, finalizerAddress, domainTag)). |
| 0xC0 | windowCloseTimestamp | uint256 | Window close time; bounds acceptance staleness. |

Outer Proof Encoding: Groth16/BN254 as 8×`uint256` (256 bytes).

Other Commitments:
- programVKey = `bytes32` commitment to the STF verifying key.
- policyHash  = `keccak256(canonical_json(policy))`.
- proverSetDigest = `keccak256(canonical_json(manifest))`.

Canonical JSON: UTF-8; no insignificant whitespace; lexicographic key order; stable array order; lowercase field names where specified.

## Parameters and Bounds

| Name | Value | Notes |
|---|---:|---|
| MAX_MANIFEST_ENTRIES | 8 | Hard bound for selection set size. |
| MAX_MANIFEST_BYTES | 1536 | Canonical JSON size cap (pre-padding). |
| MAX_IN_PROOF | 4 | Upper bound for in-proof inner SNARKs. |
| MAX_LOCATOR_BYTES | 96 | Optional locator emission cap. |
| k_in_proof | 0..4 | Must be ≤ selected entries. |

The aggregator refuses to build if any bound is exceeded.

## Events
(only `windowIndex` is indexed to minimize gas)

- OutputProposed(uint256 indexed windowIndex, bytes32 outputRoot, uint256 l2Start, uint256 l2End, bytes32 l1BlockHash)
- ZkProofAccepted(uint256 indexed windowIndex, bytes32 policyHash, bytes32 programVKey, bytes32 proverSetDigest)
- ManifestAnnounced(bytes32 proverSetDigest, bytes locator) (optional; default disabled)
- ZkProofMeta(uint256 indexed windowIndex, uint8 recursionMode, uint8 kInProof, uint8 selectedCount) (optional; default disabled)

Watcher requirements:
- Recompute `keccak256(canonical_json(manifest))` and match `proverSetDigest`.
- Verify `policyHash` against the timelocked registry.
- Treat `locator` as a hint; the digest is authoritative.

## Gas and Cost
- Groth16 verify gas: ~207,700 + ~7,160 × (public_signals) ⇒ ~236k for four signals.
- Typical per-window L1 cost (verify + calldata + logs): ~242k–305k gas with defaults:
  - Domain separator as `immutable` (no `SLOAD`).
  - Zero-copy ABI decode (pure `calldataload`).
  - Permissionless hot path (no mapping reads).
  - One indexed topic per event (the index).
  - Optional telemetry compiled out by default:
    - `ManifestAnnounced` off saves ~1.0k–1.8k gas/window.
    - `ZkProofMeta` off saves ~0.7k–1.0k gas/window.

## Contracts

### WorldlineFinalizer (onchain)
Constructor: (address adapter, uint64 l1FinalityMinDepth, bytes32 domainSeparator, uint64 maxAcceptanceDelay)

State: adapter; permissionless (true); proposers; submitters; nextWindowIndex (0); lastL2EndBlock (0); paused; l1FinalityMinDepth; DOMAIN_SEPARATOR (immutable); maxAcceptanceDelay.

Errors: Paused(), BadInputsLen(), NotAuthorized(), NotContiguous(), AdapterZero(), LocatorTooLong(), DomainMismatch(), TooOld().

submitZkValidityProofWithMeta(bytes proof, bytes publicInputs224, uint8 recursionMode, uint8 kInProof, uint8 selectedCount, bytes locator)
- Checks: not paused; len=224; permission (if enabled); `locator.length ≤ MAX_LOCATOR_BYTES` if locator compiled; decode ABI; enforce domain, contiguity, staleness; call adapter; require `valid` and matching `stfCommitment`; emit events; advance window.

submitZkValidityProof(bytes proof, bytes publicInputs224)
- Minimal variant: emits only OutputProposed and ZkProofAccepted.

Invariants: one accepted proof per window; windows strictly contiguous; ABI word 0 equals `stfCommitment`; domain enforced.

### IZkAggregatorVerifier (adapter interface)
    interface IZkAggregatorVerifier {
      function verify(bytes calldata proof, bytes calldata publicInputsRaw /*224B*/)
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

### Groth16ZkAdapter
Pins `verifier`, `programVKeyPinned`, `policyHashPinned` as immutables. Verifies Groth16 with four public signals in order: [stfCommitment, programVKey, policyHash, proverSetDigest]. Returns the pins and the digest as read from the proof.

### Worldline Outputs Registry (timelocked)
Keyed by `keccak256(chainIdHash, domainTag)`.
`active[key] = {oracle, programVKey, policyHash}`; `pending[key] = {record, eta}`.
`schedule(record, eta)`; `activate(key)` after timelock.
Events: PendingSet, Activated, MinDelaySet.

## Circuit (Outer; Groth16/BN254)
Public signals (fixed at four): `stfCommitment`, `programVKey`, `policyHash`, `proverSetDigest`.

Private inputs: `abi0..abi6`, `programVKey_in`, `policyHash_in`, `manifest_bytes`, optional `recursion_witness`.

Constraints:
- `stfCommitment == Keccak(abi_words)` (EVM Keccak-256), including `domainSeparator`.
- `programVKey == programVKey_in`; `policyHash == policyHash_in`.
- `proverSetDigest == keccak256(manifest_bytes)` using a fixed-capacity Keccak gadget sized to `ceil(MAX_MANIFEST_BYTES/136)` sponge blocks.
- If recursion is enabled and `k_in_proof > 0`, validate the first `k` manifest entries (accumulator or mini-verifier).

Changing recursion mode or `max_inner` requires a new circuit/zkey and adapter via the registry.

## Offchain Components

### ZK Prover Directory (signed, content-addressed)
Entry: {prover_id, family, version, endpoints, vkey_commitment, image_digest, attestations[]}.
The aggregator snapshots the directory hash per window.

### Policy (canonical JSON)
Fields: `version`, `min_count`, `min_distinct_families`, `required_families`, optional `allowlist_provers`, `fallback_tiers`, `min_inclusion_ratio` (0–1) over eligible directory entries (post-SLO filter), and `recursion = { mode: "none" | "snark-accum" | "snark-miniverifier", k_in_proof, max_inner }`.

`policyHash = keccak256(canonical_json(policy))`. Any change requires a timelocked adapter swap.

Example (canonical JSON):
    {"min_count":3,"min_distinct_families":2,"min_inclusion_ratio":0.5,"recursion":{"k_in_proof":2,"max_inner":4,"mode":"snark-accum"},"required_families":["groth16_bn254"],"version":1}

### Manifest and Digest
Per window, canonical JSON array of selected ZK provers (stable-sorted by `(family, prover_id, version)`).  
`proverSetDigest = keccak256(canonical_json(manifest))`.

### Deterministic Selection
Pick the lexicographically smallest prefix by key `family || 0x00 || prover_id || version` satisfying:
- `count ≥ min_count`
- `distinct_families ≥ min_distinct_families`
- `required_families ⊆ selected_families`
- allowlist respected (if present)
- inclusion ≥ `min_inclusion_ratio` of eligible entries (after SLO filters)

Tie-breakers: lower `latency_ms`, then lower `cost_usd`.

### Publication
Deployments may emit `ManifestAnnounced(proverSetDigest, locator)` once. Locator is a hint (IPFS/HTTPS). Digest is authoritative.

## Recursion and Aggregation (capability; policy-driven)
- Mapping: first `k_in_proof` manifest entries are proven in-proof. STARKs count toward `k_in_proof` only if `wrap:"snark"`.
- Modes:
  - snark-accum: prove an accumulator relation for `m ≤ max_inner` inner SNARKs; enforce mapping to first `m` entries and `m ≥ k_in_proof`.
  - snark-miniverifier: embed verifiers for the first `k_in_proof` inner SNARKs, up to `max_inner`.

## Compatibility
- Target environment: EVM chains with BN254 (alt_bn128) pairing precompiles (e.g., Ethereum L1 and most EVM L2s). No L1 protocol changes; no stack-specific semantics.
- Alternative outer proof systems: deployments preferring PLONK/FFLONK (BLS12-381/KZG) can introduce a replacement outer circuit and adapter via the timelocked registry, preserving the same four public signals and ABI.
- Stack integrations: Worldline is stack-neutral. Optional facades can mirror another stack’s event shape (e.g., OP) without altering guarantees. No facade is required for correctness.
- Data availability: orthogonal. The STF should bind any DA references (e.g., blob roots, certificates) it relies on; Worldline finalizes whatever the STF commits.

## Observability
Authoritative onchain events: OutputProposed, ZkProofAccepted.
Optional telemetry (default off): ManifestAnnounced, ZkProofMeta.
Watchers: verify `policyHash` via the registry; recompute `proverSetDigest` from the manifest; treat `locator` as hint only.

## Governance and Upgrades
`programVKey` and `policyHash` are pinned in the adapter; changes flow through the timelocked WorldlineOutputsRegistry and an adapter update on the finalizer. Operational toggles: `permissionless`, proposer/submitter sets, `paused`, `l1FinalityMinDepth`, `maxAcceptanceDelay`.
