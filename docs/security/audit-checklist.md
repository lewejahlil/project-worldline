# Worldline Security Audit Checklist

**Version:** 1.0
**Date:** 2026-03-22
**Scope:** Worldline v1.0 — on-chain contracts + off-chain aggregator/registry

---

## 1. Threat Mitigations

| ID      | Threat                                      | Mitigation                                                                                                                                                                                         | Contract / Module                                                                                                                       | Test Coverage                                                                                                                                                                                           |
| ------- | ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **T1**  | Invalid proof accepted                      | Groth16 verifier + adapter pins VK and policy; four fixed public signals; exact `stfCommitment` equality check; strict ABI length; recursion gadgets (when active) proven sound                    | `Groth16ZkAdapter.verify()` (L:91–136); `Groth16Verifier.verifyProof()`                                                                 | `Groth16ZkAdapter.test.ts`: "reverts when underlying proof is invalid"; `WorldlineFinalizer.test.ts`: "reverts on wrong input length"; `WorldlineFinalizer.fuzz.t.sol`: `testFuzz_rejectBadInputLength` |
| **T2**  | Cross-domain replay                         | `domainSeparator` inside 224-byte ABI and equality-checked on-chain in `_submit()`                                                                                                                 | `WorldlineFinalizer._submit()` (L:182)                                                                                                  | `WorldlineFinalizer.test.ts`: "reverts on domain mismatch"; `WorldlineFinalizer.fuzz.t.sol`: `testFuzz_rejectWrongDomain`                                                                               |
| **T3**  | Stale proof accepted                        | `windowCloseTimestamp` in ABI; `maxAcceptanceDelay` enforced in `_submit()`                                                                                                                        | `WorldlineFinalizer._submit()` (L:191–193)                                                                                              | `WorldlineFinalizer.test.ts`: "reverts when proof is too old (TooOld)"; `WorldlineFinalizer.fuzz.t.sol`: `testFuzz_rejectStaleProof`                                                                    |
| **T4**  | Window non-contiguity                       | `lastL2EndBlock` stored; strict `l2Start == lastL2EndBlock` enforced on non-genesis windows                                                                                                        | `WorldlineFinalizer._submit()` (L:188)                                                                                                  | `WorldlineFinalizer.test.ts`: "enforces contiguous windows"; `WorldlineFinalizer.fuzz.t.sol`: `testFuzz_contiguityEnforced`                                                                             |
| **T5**  | Malicious policy or VK swap                 | Timelocked `WorldlineOutputsRegistry` with two-step `schedule`/`activate`; adapter swap gated by `onlyOwner`; `minTimelock` ≥ 24 h by default                                                      | `WorldlineOutputsRegistry.schedule()`, `WorldlineOutputsRegistry.activate()` (L:108–156); `WorldlineFinalizer.setAdapter()` (L:122–126) | `WorldlineOutputsRegistry.test.ts`; `GovernanceRotation.test.ts` (full rotation end-to-end)                                                                                                             |
| **T6**  | Biased / forged manifest                    | Deterministic selection algorithm in `crates/worldline-registry/src/selection.rs` with explicit tie-breakers; `proverSetDigest` bound in outer proof; watchers recompute manifest                  | `crates/worldline-registry/src/selection.rs`; `schemas/selection-test-vectors.json`                                                     | `selection.rs` unit tests (determinism, allowlist, required families, fallback tiers); `schemas/selection-test-vectors.json` (5 vectors)                                                                |
| **T7**  | Canonicalisation bugs / digest mismatch DoS | Canonical JSON rules defined in spec and implemented in Rust + TypeScript; cross-language test vectors in `schemas/canonical-test-vectors.json`; `MAX_MANIFEST_BYTES` bound                        | `crates/worldline-registry/src/canonical.rs`; `scripts/canonical-json.ts`                                                               | `canonical.rs` unit tests (10+ cases); shared test vectors loaded in both Rust (`shared_test_vectors_*` tests) and TypeScript (conformance suite)                                                       |
| **T8**  | Recursion witness forgery                   | Circuit enforces mapping of recursion witness to first `k_in_proof` manifest entries; size caps; accumulator/mini-verifier gadgets proven sound (pending circuit audit)                            | `crates/worldline-driver/src/recursion.rs`; `circuits/recursion/README.md`                                                              | `recursion.rs`: `k_in_proof_gt_manifest_returns_error`, `k_in_proof_gt_max_inner_returns_error`                                                                                                         |
| **T9**  | Prover supply-chain compromise              | Directory entries include `image_digest` + `vkey_commitment`; directory must be signed by multisig/TEE; selection cross-checks against policy; `allowlist_provers` can restrict to audited provers | `crates/worldline-registry/src/directory.rs`; `crates/worldline-registry/src/selection.rs`                                              | `directory.rs`: `verify_signature_does_not_panic`; ⚠️ real secp256k1 recovery not yet implemented — see `directory.rs` TODO                                                                             |
| **T10** | Directory tampering                         | Directory signed by multisig/TEE; `verify_directory_signature()` checks signature before using entries; aggregator warns on verification failure                                                   | `crates/worldline-registry/src/directory.rs`                                                                                            | `directory.rs`: `verify_signature_does_not_panic` ⚠️ real recovery pending                                                                                                                              |
| **T11** | Calldata / parsing bugs                     | Fixed-length ABI (224 B); explicit `BadInputsLen` revert; `abi.decode` reverts on malformed input                                                                                                  | `WorldlineFinalizer._submit()` (L:165)                                                                                                  | `WorldlineFinalizer.test.ts`: "reverts on wrong input length"; `WorldlineFinalizer.fuzz.t.sol`: `testFuzz_rejectBadInputLength`                                                                         |
| **T12** | Gas griefing / DoS                          | Sender-pays; permissionless hot path; optional `allowlist`; `locatorTooLong` caps extra calldata                                                                                                   | `WorldlineFinalizer._submit()` (L:149)                                                                                                  | `WorldlineFinalizer.test.ts`: "reverts when metaLocator exceeds 96 bytes"                                                                                                                               |
| **T13** | Registry replay / mis-keying                | Registry keyed by `keccak256(abi.encodePacked(chainIdHash, domainTag))`; typed structs; events emitted on schedule + activate                                                                      | `WorldlineOutputsRegistry.domainKey()` (L:94–98)                                                                                        | `WorldlineOutputsRegistry.test.ts`                                                                                                                                                                      |
| **T14** | RNG / clock skew off-chain                  | Selection algorithm is fully deterministic (no RNG); sort + tie-break is byte-level lexicographic; test vectors validate identical output                                                          | `crates/worldline-registry/src/selection.rs`                                                                                            | `selection.rs`: `selection_is_deterministic` (100 runs)                                                                                                                                                 |
| **T15** | Side-channel in circuit                     | No private L2 state in public inputs; fixed Keccak gadget; circuit is minimal SquareHash demo — production circuit requires independent audit                                                      | `circuits/worldline.circom`                                                                                                             | Circuit tests in `circuits/test/worldline.test.ts`; ⚠️ production circuit audit required                                                                                                                |
| **T16** | Reorg handling                              | ABI binds `l1BlockHash` (word 5 of 224-byte payload); `maxAcceptanceDelay` limits post-close window; watchers can detect conflicting hashes                                                        | `WorldlineFinalizer._submit()` (L:168–178)                                                                                              | `WorldlineFinalizer.test.ts`: "emits OutputProposed and ZkProofAccepted on success"                                                                                                                     |
| **T17** | Aggregator compromise / liveness failure    | Multiple aggregators recommended; directory + manifest published for watcher recomputation; `maxAcceptanceDelay` limits window for alternative submission                                          | `scripts/watcher.ts`; `crates/worldline-driver/src/aggregator.rs`                                                                       | `GovernanceRotation.test.ts` exercises adapter rotation; `watcher.ts` validates on-chain events                                                                                                         |

---

## 2. Custom vs. Standard Implementations

| Component            | Implementation                                                          | Notes                                                                                                                                             |
| -------------------- | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Ownable`            | Custom (`contracts/src/utils/Ownable.sol`)                              | Minimal implementation; no `renounceOwnership`. Auditors should compare with OpenZeppelin's.                                                      |
| `Verifier`           | Dev stub (`contracts/src/zk/Verifier.sol`)                              | ⚠️ Must be replaced with snarkjs-generated Groth16 verifier before production. Only checks `secret² == publicHash`.                               |
| `Groth16Verifier`    | Placeholder (`contracts/src/zk/Groth16Verifier.sol`)                    | ⚠️ Placeholder only. Returns `true` on chainid 31337. Must be replaced with real snarkjs-generated verifier (~230k gas).                          |
| `Groth16ZkAdapter`   | Custom (`contracts/src/zk/Groth16ZkAdapter.sol`)                        | Pins VK + policy; supports `isDev` mode. ⚠️ `IS_DEV_MODE=true` bypasses Groth16 verification. Must deploy with `IS_DEV_MODE=false` in production. |
| Canonical JSON       | Custom Rust (`canonical.rs`) + TypeScript (`scripts/canonical-json.ts`) | Cross-validated against 10 shared test vectors in `schemas/canonical-test-vectors.json`.                                                          |
| Selection algorithm  | Custom Rust (`selection.rs`)                                            | Deterministic; validated against 5 test vectors in `schemas/selection-test-vectors.json`.                                                         |
| Directory signatures | Stub (`crates/worldline-registry/src/directory.rs`)                     | ⚠️ `k256` secp256k1 recovery not yet implemented. Function returns `Ok(true)` always. Must be completed before production.                        |
| Keccak-256           | `tiny-keccak` crate (off-chain); EVM native (on-chain)                  | On-chain keccak via Solidity `keccak256()`. Off-chain via `tiny-keccak::Keccak::v256()`.                                                          |

---

## 3. Known TODOs / Production Readiness Gaps

| Priority    | Area                             | TODO                                                                                                                      |
| ----------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| 🔴 CRITICAL | `Groth16Verifier.sol`            | Replace placeholder with snarkjs-generated verifier. Run `npm run c:compile && npm run c:setup && npm run c:export`.      |
| 🔴 CRITICAL | `Groth16ZkAdapter.sol` prod path | Implement real Groth16 proof decoding in the `!IS_DEV_MODE` branch. Define proof byte format (pA + pB + pC + pubSignals). |
| 🔴 CRITICAL | `directory.rs`                   | Implement secp256k1 signature recovery using `k256` crate.                                                                |
| 🟠 HIGH     | `IS_DEV_MODE` in adapter         | Ensure all production deployments use `isDev=false`. Add deployment check.                                                |
| 🟠 HIGH     | Recursion witness                | Implement live prover connections in `recursion.rs`.                                                                      |
| 🟡 MEDIUM   | Circuit audit                    | Commission independent audit of production Groth16 circuit and its verification key.                                      |
| 🟡 MEDIUM   | Directory signing                | Implement multisig / TEE signing for the prover directory.                                                                |
| 🟢 LOW      | Benchmarks                       | Populate `docs/benchmarks.md` Section 4 after circom compilation.                                                         |
| 🟢 LOW      | Reference watcher                | Deploy `scripts/watcher.ts` as a long-running service for production monitoring.                                          |

---

## 4. Audit Scope

Contracts in scope (all in `contracts/src/`):

- `WorldlineFinalizer.sol`
- `WorldlineRegistry.sol`
- `WorldlineCompat.sol`
- `WorldlineOutputsRegistry.sol`
- `zk/Groth16ZkAdapter.sol`
- `zk/Groth16Verifier.sol` ⚠️ placeholder — review after real verifier is generated
- `zk/Verifier.sol` (dev only)
- `utils/Ownable.sol`
- `interfaces/IZkAggregatorVerifier.sol`

Off-chain modules in scope:

- `crates/worldline-registry/src/canonical.rs`
- `crates/worldline-registry/src/selection.rs`
- `crates/worldline-registry/src/directory.rs`
- `crates/worldline-driver/src/aggregator.rs`
- `crates/worldline-driver/src/recursion.rs`
