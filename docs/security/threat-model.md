# Project Worldline — Threat Model & Risk Analysis

## 1. Scope & Trust Boundaries
Worldline finalizes rollup windows on EVM L1s using a single outer Groth16/BN254 proof produced by an offchain aggregator under a **multi-ZK-prover policy**. The onchain plane verifies that proof via an adapter, enforces window contiguity and domain binding, and emits canonical events. Worldline does **not** alter the rollup’s STF or DA; it only binds what the STF commits.

**In-scope components**
- Onchain: `WorldlineFinalizer`, `Groth16ZkAdapter`, `WorldlineOutputsRegistry` (timelocked).
- Offchain: Aggregator/driver, ZK prover plugins, signed ZK Prover Directory, canonical JSON policy and manifest, optional recursion witness.
- Interfaces/artifacts: 224-byte public inputs ABI; four fixed public signals; canonical JSON and Keccak digests.

**Trust boundaries**
- L1 contract boundary: all untrusted calldata; proofs are untrusted until verified.
- Offchain boundary: directory, policy, and manifest are public artifacts; watchers recompute digests.
- Governance boundary: registry timelock for `{programVKey, policyHash, oracle}` rotation and adapter swaps.

## 2. Assets To Protect
- **Finality correctness:** exactly one valid proof per contiguous window.
- **State binding:** `(stfCommitment, programVKey, policyHash, proverSetDigest)` must match what was proven.
- **Domain separation:** proofs cannot be replayed across deployments or domains.
- **Governance integrity:** VK/policy/adapter changes respect timelock; no unauthorized activation.
- **Availability:** honest submitters can finalize; DoS is bounded and costly to the attacker.
- **Auditability:** external parties can recompute policy and manifest digests from published bytes.

## 3. Attacker Model
- **External adversary:** crafts invalid proofs, malformed ABI inputs, replays proofs across domains or stale windows, spams submissions to raise costs.
- **Malicious prover(s):** returns incorrect proofs or attempts equivocation across windows.
- **Compromised aggregator:** selects a biased manifest, drops honest provers, or forges offchain artifacts.
- **Operator/governance compromise:** attempts fast-track of malicious VK/policy or adapter swap.
- **Supply-chain adversary:** tampered prover images/verifiers, dependency poisoning.

## 4. Architecture Recap (For Threat Context)
- **Onchain:** `WorldlineFinalizer` accepts `(proof, publicInputs224[, meta])`, calls `Groth16ZkAdapter.verify`, enforces contiguity/staleness/domain, emits `OutputProposed` and `ZkProofAccepted`. Optional telemetry events are compiled out by default.
- **Four public signals (fixed):** `stfCommitment`, `programVKey`, `policyHash`, `proverSetDigest`.
- **ABI (224 bytes):** `{stfCommitment, l2Start, l2End, outputRoot, l1BlockHash, domainSeparator, windowCloseTimestamp}`; `stfCommitment = Keccak(ABI words)`.
- **Offchain:** deterministic selection of provers from a signed directory per policy → canonical manifest → `proverSetDigest = keccak256(manifest bytes)` → optional recursion witness → outer proof.

## 5. Threats, Impacts, Mitigations

| ID | Vector | Impact | Primary Mitigations | Residual Risk / Status |
|---|---|---|---|---|
| T1 | Invalid proof accepted | Finality corruption | Audited Groth16 verifier; adapter pins VK & policy; four fixed public signals; exact `stfCommitment` equality; strict ABI length | Low, requires verifier or adapter bug. Include formal tests/fuzzing. |
| T2 | Cross-domain replay | Cross-chain/state confusion | `domainSeparator = keccak256(chainId, finalizer, domainTag)` inside ABI and proven; checked equality onchain | Low. Add integration tests across multiple deployments. |
| T3 | Stale proof accepted | Time rollback or reorg abuse | `windowCloseTimestamp` in ABI; `maxAcceptanceDelay` enforced by finalizer | Low if delay tuned. Monitor acceptance latency. |
| T4 | Window non-contiguity | State gaps/overlaps | Finalizer stores `lastL2EndBlock`; enforces strict contiguity | Low. Unit tests on edge transitions. |
| T5 | Malicious policy or VK swap | Undercuts security rules | Timelocked `WorldlineOutputsRegistry`; two-step `PendingSet`→`Activated`; adapter swap gated | Medium→Low with governance hygiene. Require out-of-band notice. |
| T6 | Biased/forged manifest | Reduces prover diversity | Circuit binds `proverSetDigest`; watchers recompute from canonical manifest; deterministic selection algo & published policy | Low if watchers active. Provide reference watcher. |
| T7 | Canonicalization bugs | Digest mismatch (DoS) | Single reference canonicalizer; cross-lang test vectors; size bounds (`MAX_MANIFEST_BYTES`) | Medium→Low with conformance tests. |
| T8 | Recursion witness forgery | Fake inner-proof claims | If policy enables recursion, circuit enforces mapping to first `k_in_proof`; accumulator/mini-verifier soundness proofs; size caps | Low with audited recursion gadget. |
| T9 | Prover supply-chain | Backdoored binaries/verifiers | `image_digest` & `vkey_commitment` in directory; attestations; optional SNARK-wrapping for STARK outputs | Medium; require signatures and periodic audits. |
| T10 | Calldata/parsing bugs | Unexpected acceptance/DoS | Fixed-length ABI (224B); zero-copy `calldataload`; explicit `BadInputsLen` | Low. Fuzz decode paths. |
| T11 | Gas griefing/DoS | Liveness degradation | Sender-pays; permissionless hot path; telemetry off by default; one indexed topic | Low. Optional allowlists/submitter caps. |
| T12 | Registry replay/mis-key | Incorrect activation | Keyed by `(chainIdHash, domainTag)`; typed structs; events `PendingSet/Activated` | Low. Add invariant tests. |
| T13 | RNG/clock skew offchain | Divergent selection | Deterministic selection; no RNG; SLO filters must be deterministic; publish snapshot hash | Low. Test with adversarial directories. |
| T14 | Side-channel in circuit | Info leakage/unsoundness | No private L2 state as public inputs; fixed Keccak gadget; constraint audits | Low. Circuit reviews required. |
| T15 | Reorg handling | Conflicting `l1BlockHash` | ABI binds `l1BlockHash`; deployments set `l1FinalityMinDepth` | Low if depth ≥ target reorg risk. |

## 6. Abuse & DoS Cases
- **Submission spam:** mitigated by sender-pays gas and minimal parsing; optional allowlist for emergencies.  
- **Telemetry bloat:** optional events are compiled out by default; `MAX_LOCATOR_BYTES` caps size if enabled.  
- **Manifest churn:** `MAX_MANIFEST_ENTRIES` and `MAX_MANIFEST_BYTES` bound costs; watchers rely on digests, not locators.

## 7. Operational Risks & Safeguards
- **Key management:** multisig/hardware custody for registry admin; timelock not bypassable.  
- **Rollout:** canary on testnets; staged activation via registry; publish VK/policy/manifests with hashes.  
- **Monitoring:** index `OutputProposed`/`ZkProofAccepted`; cross-check digests; alert on missed windows or digest mismatches.  
- **Upgrades:** adapter swaps for outer circuit migrations; unchanged four-signal ABI.

## 8. Validation & Test Plan (Security-Focused)
- **Solidity:** Foundry fuzz for ABI parsing, contiguity, domain checks; echidna invariants; differential tests on events.  
- **Circuit:** constraint coverage; negative tests (tampered ABI words, VK/policy/manifest mismatches); recursion gadget unit tests; reproducible proving.  
- **End-to-end:** golden vectors for `(ABI, policy, manifest, proof)`; multi-deployment replay tests; gas ceilings.  
- **Offchain:** canonicalizer cross-lang conformance; directory signature verification; deterministic selection under adversarial inputs.

## 9. Residual Risk & Monitoring
Residual risks remain in circuit/verifier correctness and offchain supply-chain. Continuous monitoring (alerts on digest mismatches, acceptance latency, unexpected adapter changes) and periodic audits reduce exposure.

## 10. Incident Response (High-Level)
1. **Detect:** alerts from watchers/indexers; user reports.  
2. **Triage:** freeze submissions by pausing finalizer (break-glass), if needed.  
3. **Contain/Eradicate:** rotate VK/policy or adapter via timelock; redeploy patched contracts; revoke compromised keys.  
4. **Recover:** resume permissionless submissions; backfill windows if required.  
5. **Postmortem:** publish RCA, patches, test vectors; add regression tests.

## 11. Appendix — STRIDE Mapping (Selected)
- **Spoofing:** cross-domain replay → domain binding with `domainSeparator`.  
- **Tampering:** manifest/policy tamper → canonical JSON + onchain digest match.  
- **Repudiation:** signed directory + event logs.  
- **Information Disclosure:** none beyond public artifacts; no sensitive private inputs.  
- **Denial of Service:** spam/large calldata → bounded ABI, sender-pays, telemetry off.  
- **Elevation of Privilege:** registry admin misuse → timelock, events, multisig discipline.

## 12. Explicit Assumptions
- BN254 pairing precompiles are correct on target L1/L2.  
- Groth16 verifier is correct and audited; circuit proving keys are generated with secure ceremonies.  
- Watchers and indexers exist and recompute digests independently.  
- The rollup STF commits correct `outputRoot` and any DA references it relies on.

## 13. References (Internal)
- Technical Specification (`docs/specs/technical-specification.md`)  
- System Design (`docs/design/system-design.md`)
