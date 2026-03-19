# Project Worldline — Threat Model & Risk Analysis (Revised)

## 1. Scope & Trust Boundaries

Worldline finalises rollup windows on EVM L1s using a single outer Groth16/BN254 proof produced by an off‑chain aggregator under a **multi‑ZK‑prover policy**. The on‑chain plane verifies that proof via an adapter, enforces window contiguity and domain binding, and emits canonical events. Worldline does **not** alter the rollup’s STF or data availability; it only binds whatever the STF commits【550409739156115†L15-L21】.

This revised threat model incorporates feedback from security reviews and prototype implementations. It explicitly models supply‑chain threats, directory tampering, aggregator compromise and canonicalisation bugs, and outlines additional mitigations including multisig directory signatures, reproducible builds, aggregator redundancy, cross‑language canonicalisers and reference watchers.

**In‑scope components**

- On‑chain: `WorldlineFinalizer`, `Groth16ZkAdapter` or alternative adapters, `WorldlineOutputsRegistry` (timelocked).
- Off‑chain: Aggregator/driver, ZK prover plugins, signed ZK Prover Directory, canonical JSON policy and manifest, optional recursion witness.
- Interfaces/artifacts: 224‑byte public inputs ABI; four fixed public signals; canonical JSON and Keccak digests; directory snapshots and signatures.

**Trust boundaries**

- **L1 contract boundary**: all calldata is untrusted; proofs are untrusted until verified.
- **Off‑chain boundary**: directory, policy and manifest are public artifacts; watchers must recompute digests and verify signatures.
- **Directory signing boundary**: the directory must be signed by a recognised multisig or TEE; the aggregator and watchers must verify these signatures.
- **Governance boundary**: registry timelock for `{programVKey, policyHash, oracle}` rotation and adapter swaps; multisig keys enforce delays and approvals.

## 2. Assets to Protect

- **Finality correctness**: exactly one valid proof per contiguous window.
- **State binding**: `(stfCommitment, programVKey, policyHash, proverSetDigest)` must match what was proven.
- **Domain separation**: proofs cannot be replayed across deployments or domains.
- **Directory integrity**: directory entries and signatures must be authentic; forged entries must not be accepted.
- **Supply‑chain integrity**: prover binaries/verifiers must be reproducible; `vkey_commitment` and `image_digest` must match published audits.
- **Governance integrity**: VK/policy/adapter changes must respect timelock and multisig; no unauthorized activation.
- **Availability and liveness**: honest aggregators can finalise; aggregator failures or DoS must not stall rollup finality.
- **Auditability**: external parties can recompute policy, manifest and directory digests from published bytes; watchers can verify directory signatures.

## 3. Attacker Model

- **External adversary**: crafts invalid proofs, malformed ABI inputs, cross‑domain or stale proofs, spams submissions to raise costs.
- **Malicious prover(s)**: returns incorrect proofs, attempts equivocation across windows or misreports SLO metrics.
- **Compromised aggregator**: selects a biased manifest, omits honest provers, forges off‑chain artifacts, or colludes with provers.
- **Operator/governance compromise**: attempts fast‑track of malicious VK/policy or adapter swap; misuses pause/resume or acceptance delay settings.
- **Supply‑chain adversary**: tampered prover images/verifiers, directory signing key compromise, dependency poisoning.
- **Canonicalisation adversary**: exploits differences in JSON canonicalisation across languages to cause digest mismatches (DoS).

## 4. Architecture Recap (for Threat Context)

- **On‑chain**: `WorldlineFinalizer` accepts `(proof, publicInputs224[, meta])`, calls `IZkAggregatorVerifier.verify`, enforces contiguity, staleness and domain equality, and emits `OutputProposed` and `ZkProofAccepted`【550409739156115†L30-L34】. Optional telemetry events are compiled out by default.
- **Four public signals (fixed)**: `stfCommitment`, `programVKey`, `policyHash`, `proverSetDigest`【550409739156115†L30-L34】.
- **ABI (224 bytes)**: `{stfCommitment, l2Start, l2End, outputRoot, l1BlockHash, domainSeparator, windowCloseTimestamp}`; `stfCommitment = Keccak(ABI words)`.
- **Off‑chain**: deterministic selection of provers from a signed directory per policy → canonical manifest → `proverSetDigest` = Keccak(manifest bytes) → optional recursion witness → outer proof.
- **Directory**: canonical JSON; must be signed by multisig/TEE; includes `prover_id`, `family`, `version`, `endpoints`, `vkey_commitment`, `image_digest`, `attestations`, SLO metrics.
- **Policy**: canonical JSON with diversity thresholds, allowlists, inclusion ratio, recursion parameters.
- **Manifest**: canonical JSON array of selected directory entries; sorted by `(family, prover_id, version)`; digest computed via Keccak.
- **Selection**: deterministic algorithm with explicit tie‑breakers; watchers recompute selection given directory snapshot, policy and SLO filters.

## 5. Threats, Impacts, Mitigations (Updated)

| ID      | Vector                         | Impact                                              | Primary Mitigations                                                                                                                                                                                                           | Residual Risk / Status                                                                                 |
| ------- | ------------------------------ | --------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| **T1**  | Invalid proof accepted         | Finality corruption                                 | Audited Groth16 (or alternative) verifier; adapter pins VK and policy; four fixed public signals; exact `stfCommitment` equality; strict ABI length and parsing; recursion gadgets proven sound                               | Low if verifier and circuit sound. Formal proofs and audits required.                                  |
| **T2**  | Cross‑domain replay            | Cross‑chain/state confusion                         | `domainSeparator = keccak256(chainId, finalizerAddress, domainTag)` inside ABI and proven; equality check on‑chain                                                                                                            | Low; integration tests across deployments recommended.                                                 |
| **T3**  | Stale proof accepted           | Time rollback or reorg abuse                        | `windowCloseTimestamp` in ABI; `maxAcceptanceDelay` enforced; aggregator publishes directory snapshot block height                                                                                                            | Low if delay tuned and watchers monitor acceptance latency.                                            |
| **T4**  | Window non‑contiguity          | State gaps/overlaps                                 | Finalizer stores `lastL2EndBlock`; enforces strict contiguity                                                                                                                                                                 | Low. Unit tests on edge transitions.                                                                   |
| **T5**  | Malicious policy or VK swap    | Undercuts security rules                            | Timelocked registry; two‑step `PendingSet`→`Activated`; adapter swap gated; multisig control; public announcements                                                                                                            | Medium→Low with governance hygiene; publish rotations early and monitor chain events.                  |
| **T6**  | Biased/forged manifest         | Reduces prover diversity or excludes honest provers | Deterministic selection algorithm with explicit thresholds and tie‑breakers; circuit binds `proverSetDigest`; watchers recompute manifest and verify directory signatures                                                     | Low if watchers active and algorithm deterministic. Publish reference implementation and test vectors. |
| **T7**  | Canonicalisation bugs          | Digest mismatch → DoS                               | Canonical JSON rules defined; reference canonicalisers in multiple languages; cross‑language test vectors; `MAX_MANIFEST_BYTES` bound【440116836263521†L38-L48】                                                              | Medium→Low if conformance tests run across languages; watchers must detect mismatches and alert.       |
| **T8**  | Recursion witness forgery      | Fake inner‑proof claims                             | Circuit enforces mapping of recursion witness to first `k_in_proof` manifest entries; soundness proofs of accumulator/mini‑verifier; size caps                                                                                | Low with audited recursion gadgets and policy gating.                                                  |
| **T9**  | Prover supply‑chain compromise | Backdoored binaries/verifiers                       | Directory entries include `image_digest` & `vkey_commitment`; reproducing builds and attestations; directory signed by multisig/TEE; policy may require attestations; ability to revoke provers                               | Medium; requires continuous audits and ability to rotate out compromised provers.                      |
| **T10** | Directory tampering            | Forged directory entries or signatures              | Directory snapshot must be signed by a multisig or TEE; aggregator verifies signatures; watchers verify snapshot hash and signatures; policy allows require attestations                                                      | Low if signing keys secure. Need key rotation and hardware security modules.                           |
| **T11** | Calldata/parsing bugs          | Unexpected acceptance/DoS                           | Fixed‑length ABI (224 B); zero‑copy `calldataload`; explicit `BadInputsLen` error【440116836263521†L38-L54】; foundry fuzzing                                                                                                 | Low. Fuzz decode paths; unit tests.                                                                    |
| **T12** | Gas griefing/DoS               | Liveness degradation                                | Sender‑pays; permissionless hot path; optional allowlists/submitter caps; `MAX_MANIFEST_ENTRIES` and `MAX_MANIFEST_BYTES` bound calldata【440116836263521†L38-L54】                                                           | Low. Gas ceilings and liveness monitors recommended.                                                   |
| **T13** | Registry replay/mis‑key        | Incorrect activation or keying errors               | Registry keyed by `(chainIdHash, domainTag)`; typed structs; events `PendingSet`, `Activated`【440116836263521†L51-L53】                                                                                                      | Low. Add invariant tests; watchers monitor registry events.                                            |
| **T14** | RNG/clock skew off‑chain       | Divergent selection                                 | Selection algorithm is deterministic; SLO filters must be deterministic; publish directory snapshot time and block number                                                                                                     | Low. Test with adversarial directories; watchers replicate selection.                                  |
| **T15** | Side‑channel in circuit        | Info leakage/unsoundness                            | No private L2 state as public inputs; fixed Keccak gadget; independent audits                                                                                                                                                 | Low. Circuit audits required.                                                                          |
| **T16** | Reorg handling                 | Conflicting `l1BlockHash`                           | ABI binds `l1BlockHash`; `l1FinalityMinDepth` set on finalizer【440116836263521†L50-L54】                                                                                                                                     | Low if depth ≥ expected reorg risk.                                                                    |
| **T17** | Aggregator compromise          | Liveness failure; biased selection                  | Operate multiple aggregators; publish directory snapshot and manifest for watchers; watchers can derive manifest and compute digest; alternative aggregator can submit proof if one fails before `maxAcceptanceDelay` expires | Medium→Low with redundancy and monitoring.                                                             |

## 6. Abuse & DoS Cases

- **Submission spam**: mitigated by sender‑pays gas and minimal parsing; optional allowlist for emergencies【440116836263521†L56-L59】.
- **Telemetry bloat**: optional events are compiled out by default; `MAX_LOCATOR_BYTES` caps locator size【440116836263521†L56-L59】.
- **Manifest churn**: `MAX_MANIFEST_ENTRIES` and `MAX_MANIFEST_BYTES` bound costs; deterministic selection and watchers rely on digest, not locators【440116836263521†L56-L60】.
- **Directory churn**: directory updates are asynchronous; aggregator includes snapshot hash and signatures; watchers verify the snapshot before recomputing selection.
- **Aggregator crash**: multiple aggregators mitigate single point of failure; liveness monitors detect delayed proofs; fallback aggregator can submit before `maxAcceptanceDelay`.

## 7. Operational Risks & Safeguards

- **Key management**: multisig/hardware custody for registry admin and directory signing keys; use threshold signatures; rotate keys periodically; hardware security modules (HSMs) or TEEs recommended【440116836263521†L62-L64】.
- **Rollout**: canary deployments on testnets; staged activation via registry; publish verifying key, policy and manifest with hashes; watchers and auditors test canonicalisation across languages.
- **Monitoring**: index `OutputProposed`/`ZkProofAccepted` events; cross‑check digests; verify directory signatures; alert on missed windows, digest mismatches or unexpected adapter changes【440116836263521†L64-L65】. Monitor aggregator liveness and SLO metrics.
- **Upgrades**: adapter swaps for outer circuit migrations; unchanged four‑signal ABI; require timelock and multisig【440116836263521†L65-L66】.
- **Prover rotation and revocation**: policy updates and directory snapshots can remove compromised provers; watchers and aggregators must enforce new policies promptly; publish revocation announcements.
- **Reference watcher tools**: maintain open‑source scripts that verify directory signatures, recompute selection and digests and monitor on‑chain events; test across languages (Rust, JS, Python) to detect canonicalisation drift.

## 8. Validation & Test Plan (Security‑Focused)

- **Solidity**: foundry fuzzing for ABI parsing, contiguity and domain checks; echidna invariants; differential tests on event emission. Validate rejection of bad lengths, old windows and wrong domain.【440116836263521†L67-L71】
- **Circuit**: constraint coverage; negative tests (tampered ABI words, mismatched VK/policy/manifest digests); recursion gadget unit tests; reproducible proving. Provide test vectors for mini‑verifier and accumulator gadgets.
- **Directory**: test verification of multisig signatures; canonicalisation across languages; detection of tampered entries; revocation flows.
- **Selection**: implement reference selection in at least two languages; test with adversarial directories and policies; cross‑check tie‑breaker logic.
- **End‑to‑end**: golden vectors for `(ABI, policy, manifest, directory snapshot, proof)`; multi‑deployment replay tests; gas ceilings; aggregator failure scenarios.
- **Off‑chain**: canonicaliser cross‑lang conformance; directory signature verification; deterministic selection under adversarial inputs【440116836263521†L67-L71】.

## 9. Residual Risk & Monitoring

Residual risks remain in circuit/verifier correctness, directory signing key compromise, and supply‑chain (prover code and dependencies). Continuous monitoring is required: alerts on digest mismatches, acceptance latency, unexpected adapter changes, aggregator liveness and directory signature failures【440116836263521†L73-L74】. Periodic audits of the circuit, verifier, directory signing process and prover binaries must be planned.

## 10. Incident Response (High‑Level)

1. **Detect**: watchers/indexers and liveness monitors detect anomalies (digest mismatch, missed window, unexpected directory signature); user reports may trigger investigation【440116836263521†L77-L80】.
2. **Triage**: freeze submissions by pausing the finalizer (break‑glass) if needed; block compromised aggregator endpoints.
3. **Contain/Eradicate**: rotate `programVKey`, `policyHash` or adapter via timelock; issue new directory with compromised provers removed; revoke or rotate directory signing keys; redeploy patched contracts; coordinate with prover maintainers.
4. **Recover**: resume permissionless submissions; backfill windows if required; re‑enable telemetry; restore aggregator redundancy; inform users.
5. **Postmortem**: publish root cause analysis (RCA), patches and test vectors; update threat model and runbooks; add regression tests to avoid recurrence【440116836263521†L79-L81】.

## 11. Appendix — STRIDE Mapping (Selected)

- **Spoofing**: cross‑domain replay → mitigated by domain binding with `domainSeparator`【550409739156115†L30-L34】.
- **Tampering**: manifest/policy/directory tamper → canonical JSON + on‑chain digest match; multisig signatures on directory; watchers verify digests and signatures.
- **Repudiation**: signed directory + event logs + multisig governance events.
- **Information Disclosure**: none beyond public artifacts; no sensitive private inputs.
- **Denial of Service**: spam/large calldata → bounded ABI, sender‑pays, telemetry off; aggregator redundancy; gas/griefing mitigations.
- **Elevation of Privilege**: registry admin misuse → timelock, multisig, events, and cross‑checker watchers; directory signing key misuse → multisig, key rotation.

## 12. Explicit Assumptions (Updated)

- BN254 pairing precompiles are correct on target L1/L2.
- Groth16 verifier is correct and audited; proving keys are generated via secure ceremonies; alternative proof systems are similarly audited.
- Canonical JSON libraries and selection implementations across languages are equivalent; test vectors catch discrepancies.
- Directory entries are signed by a trusted multisig/TEE; signers protect their keys and rotate them securely.
- Watchers and indexers exist and recompute digests, verify signatures, monitor aggregator liveness and directory updates.
- Rollup STF commits correct `outputRoot` and any DA references it relies on.

## 13. References (Internal)

- Technical Specification (revised)
- System Design (revised)
