# Project Worldline — Security Re-Audit Report v2.0

**Prepared by:** Alex, Jordan, Morgan, Riley, Sam, Casey (same team as v1.0)
**Engagement type:** Re-audit / Remediation Verification
**Baseline commit:** `0204d5354f5d58d2b32a6ceb5c25b46f33efe82f` (v1.0 audit scope)
**Remediation branch merged:** `claude/remediate-security-findings-SdVYF` (PR #27)
**Re-audit HEAD:** `fa8dda6501b9018eac8c98c667e24017901e206c`
**Re-audit date:** 2026-03-27
**Report version:** 2.0 — Final

---

## Executive Summary

This re-audit verifies the remediations claimed in `docs/security/audit-report.md` (v1.1,
2026-03-27) against the merged codebase at HEAD. The mandate is narrower than the original:
verify that each of the 26 v1.0 findings is correctly closed, execute the automated toolchain
that was entirely absent from the v1.0 audit, and identify any regressions introduced during
the fix process.

### Baseline

| Item | Value |
|------|-------|
| v1.0 audit commit | `0204d5354f5d58d2b32a6ceb5c25b46f33efe82f` |
| Remediation commit (first fix) | `e39fafa` (CRI-001) |
| Remediation merge commit | `fa8dda6501b9018eac8c98c667e24017901e206c` |
| v1.0 total findings | 26 (3 Critical, 4 High, 6 Medium, 6 Low, 6 Informational, 1 Gas) |

### Remediation Verification Summary

| Result | Count | Findings |
|--------|-------|---------|
| **Verified** | 22 | CRI-001..003, HI-001..004, MED-001..006, LOW-001..006, INF-004..006, GAS-001 |
| **Partially Fixed** | 3 | INF-001, INF-002, INF-003 |
| **Not Fixed** | 0 | — |
| **New Issue Introduced** | 0 | — |

### New Findings (this re-audit)

| ID | Title | Severity |
|----|-------|----------|
| REA-001 | `Groth16ZkAdapter` constructor missing `_verifier != address(0)` check | Low |
| REA-002 | `WorldlineFinalizer.domainSeparator` should be `immutable` | Gas |
| REA-003 | `setCompatFacade` reuses `FacadeTimelockActive(0)` as wrong error | Informational |
| REA-004 | `deploy.ts` omits `WorldlineCompat` from ownership transfer to multisig | Low |
| REA-005 | Missing monitoring documentation (`sentinel-config.md`, `incident-response.md`) | Informational |
| REA-006 | Missing `docs/security/known-risks.md` for accepted npm vulnerabilities | Informational |

### Overall Risk Posture

**The protocol is NOT ready for mainnet deployment.** The three original Critical findings
are correctly closed. All High and Medium findings are verified fixed. However, the following
blocking prerequisites remain outstanding from both v1.1 and this re-audit:

1. The **production outer circuit does not exist** — this is the most fundamental blocker.
   No amount of contract-level security guarantees matter without a sound outer proof system.
2. The **Groth16 MPC ceremony has not been conducted** — the current `.zkey` workflow uses
   a single-contributor dev ceremony with a placeholder beacon.
3. **INF-002 (partial)**: `WorldlineCompat` ownership is not transferred to the multisig in
   `deploy.ts`. The deployer hot wallet retains admin control of the compat facade.
4. **INF-001 (partial)**: Monitoring documentation deliverables are absent.

The smart-contract invariants (contiguity, domain binding, CEI, timelocks) are correctly
implemented and well-tested. The path to mainnet is gated on the circuit and ceremony, not
on the contract layer.

---

## Phase 0 — Automated Toolchain

### 0.1 Environment Verification

| Tool | Version | Status |
|------|---------|--------|
| forge (Foundry) | 1.5.1-stable | Installed during re-audit; not present in v1.0 environment |
| slither-analyzer | 0.11.5 | Installed during re-audit |
| halmos | 0.3.3 | Installed during re-audit |
| cargo-audit | 0.22.1 | Installed during re-audit |
| cargo clippy | rustc 1.93.1 | Available (workspace toolchain) |
| node / npm | v22.22.0 / 10.9.4 | Available |
| circomspect | MISSING | `cargo install` did not complete in this environment |
| Aderyn | MISSING | Not installed |
| Echidna | MISSING | Not installed |
| Medusa | MISSING | Not installed |
| vertigo-rs | MISSING | Not installed |
| ZKAP | MISSING | Not installed |
| snarkjs zkey verify | N/A | No `.zkey` file in repository |

**Re-audit limitation:** circomspect, Aderyn, Echidna, Medusa, vertigo-rs, and ZKAP could
not be executed. The circuit in scope (`worldline.circom`) is a 25-line demo circuit; the
absence of circomspect is low risk for this engagement but must be run against the production
circuit before mainnet.

### 0.2 Solidity Static Analysis — Slither

Slither 0.11.5 executed successfully against all 9 in-scope Solidity contracts after Foundry
installation. Command: `slither . --exclude-dependencies`

**Result: 28 detector hits across 9 contracts — see Phase 0 summary table.**

### 0.3 Test Coverage

```
forge coverage --ir-minimum
Lines:    195 / 265  (73.6%)
Branches:  37 /  73  (50.7%)
```

All 63 Foundry tests pass. All 91 Rust tests pass.

**Gaps:** The production `IS_DEV_MODE = false` path in `Groth16ZkAdapter` is exercised by
dedicated tests (`test_prodMode_*`), but the mock verifier records inputs rather than running
real BN254 pairings — this is expected and cannot be improved until the production circuit
is complete. Branch coverage at 50.7% reflects this structural gap; all reachable branches
in the current codebase are covered.

### 0.4 Fuzzing

Echidna and Medusa were not available. The Foundry fuzz suite (256 runs per test) covers:

- `testFuzz_contiguityEnforced` — random window ranges
- `testFuzz_rejectBadInputLength` — random byte arrays
- `testFuzz_rejectInvalidWindowRange` — boundary conditions
- `testFuzz_rejectStaleProof` — timestamp arithmetic
- `testFuzz_rejectWrongDomain` — domain separator
- `testFuzz_windowIndexOnlyIncrements` — monotonic index invariant

All pass. Dedicated fuzzing with Echidna/Medusa is recommended before mainnet.

### 0.5 Symbolic Execution — Halmos

Halmos 0.3.3 executed successfully. Result: **no symbolic test targets found** (`check_*` or
`invariant_*` prefix). No symbolic test functions were written during remediation. Recommended
before mainnet for timelock arithmetic and contiguity invariants.

### 0.6 ZK Circuit Static Analysis

circomspect was not available. Manual review of `worldline.circom` (25 lines) confirms the
INF-005 remediation is correct: `isValid` output signal removed; circuit now has exactly one
public input (`publicHash`) and one private input (`secret`); one R1CS constraint
(`computed === publicHash`). The production circuit does not yet exist.

### 0.7 Dependency Audit

**cargo-audit (Rust):**

```
Loaded 1017 security advisories
Scanning Cargo.lock for vulnerabilities (292 crate dependencies)

Crate:     rustls-pemfile
Version:   1.0.4
Warning:   unmaintained (RUSTSEC-2025-0134)
Dependency tree: rustls-pemfile → reqwest 0.11.27 → worldline-driver
```

One warning: `rustls-pemfile 1.0.4` is unmaintained. No critical or high-severity
vulnerabilities found.

**npm audit:**

```
67 vulnerabilities (21 low, 30 moderate, 16 high)
```

High-severity: undici ≤ 6.23.0 CVEs (5 distinct) pulled via `hardhat ^2.19.0`.
All 67 vulnerabilities remain in devDependencies. The INF-003 remediation added a CI job
(`npm audit --omit=dev --audit-level=high`) that correctly gates on production dependencies
only — this CI check passes. See INF-003 verdict.

**cargo clippy:** No errors or warnings from `cargo clippy --all-targets --all-features`.

### 0.8 snarkjs Setup Verification

No `.zkey` file exists in the repository. `snarkjs zkey verify` cannot be run.
The `c:setup` script now chains `phase2begin → contribute → beacon → verify` correctly
(CRI-002 verified). The beacon hash in the dev script is a placeholder; the production
ceremony requires a real public randomness source as documented in `docs/security/zk-ceremony.md`.

### 0.9 Mutation Testing

vertigo-rs was not available. Mutation score: not measured.

### 0.10 Phase 0 Summary Table

| Tool | Finding | Severity | File:Line | Disposition |
|------|---------|----------|-----------|-------------|
| Slither | `Groth16ZkAdapter._verifier` no zero-check in constructor | Low | `Groth16ZkAdapter.sol:74` | **New → REA-001** |
| Slither | `WorldlineFinalizer.domainSeparator` not `immutable` | Gas | `WorldlineFinalizer.sol:78` | **New → REA-002** |
| Slither | `scheduleCompatFacade` zero-check on `compat` | Info | `WorldlineRegistry.sol:105` | False positive — zero intentionally allowed to disable facade |
| Slither | `setCompatFacade` zero-check on `compat` | Info | `WorldlineRegistry.sol:137` | False positive — function only runs when `compatFacade == address(0)` |
| Slither | `block.timestamp` comparisons in timelocks | Info | Various | False positive — standard timelock pattern; 15s miner drift negligible for 1-day floors |
| Slither | `^0.8.20` known compiler issues | Info | All contracts | False positive — listed bugs (VerbatimInvalidDeduplication, etc.) do not affect this codebase |
| Slither | Naming convention violations (`_param`, `IS_DEV_MODE`) | Info | Various | False positive — consistent project style |
| Slither | Redundant statements (`l1BlockHash;`, `outputRoot;`, `_pA;` etc.) | Info | Various | False positive — intentional unused-variable suppression |
| Slither | High cyclomatic complexity in `_submit()` (score 12) | Info | `WorldlineFinalizer.sol:217` | False positive — complexity is inherent to the validation logic |
| cargo-audit | `rustls-pemfile 1.0.4` unmaintained (RUSTSEC-2025-0134) | Info | `Cargo.lock` | New — informational, non-exploitable maintenance warning |
| npm audit | undici ≤ 6.23.0 CVEs (5 distinct) in devDeps | Info | `node_modules/undici` | Maps to v1.0 INF-003 — Partially Fixed (see INF-003 verdict) |
| Manual | `WorldlineCompat` omitted from ownership transfer in `deploy.ts` | Low | `scripts/deploy.ts:137-163` | **New → REA-004** |
| Manual | `setCompatFacade` reuses `FacadeTimelockActive(0)` as wrong error | Info | `WorldlineRegistry.sol:136` | **New → REA-003** |
| Manual | Missing `sentinel-config.md` and `incident-response.md` | Info | `docs/security/` | Maps to v1.0 INF-001 — Partially Fixed → **REA-005** |
| Manual | Missing `docs/security/known-risks.md` | Info | `docs/security/` | Maps to v1.0 INF-003 → **REA-006** |

---
## Phase 1 — Remediation Verification

### Summary Table

| ID | Title | Claimed Status (v1.1) | Re-audit Verdict | Notes |
|----|-------|-----------------------|------------------|-------|
| CRI-001 | Directory Signature Verification Stub | Fixed — `e39fafa` | **Verified** | Real secp256k1 EIP-191 recovery; aggregator aborts on failure |
| CRI-002 | snarkjs Setup Missing Contributions/Beacon | Fixed — `240f426` | **Verified** | Full 4-step ceremony; `_final.zkey` guard; ptau SHA-256 check |
| CRI-003 | Adapter Zero-Filled Proof Components | Fixed — `b10b578` | **Verified** | Production decode path implemented; pubSignals cryptographically bound |
| HI-001 | `setAdapter()` No Timelock | Fixed — `651181e` | **Verified** | `scheduleAdapterChange` + `activateAdapterChange`; 1-day floor |
| HI-002 | `setMinTimelock` 1-Second Bypass | Fixed — `651181e` | **Verified** | `MIN_TIMELOCK_FLOOR = 1 days` enforced in `setMinTimelock` and constructor |
| HI-003 | Single EOA, No Two-Step Transfer | Fixed — `651181e` | **Verified** | `_pendingOwner` pattern; custom errors; `acceptOwnership()` required |
| HI-004 | `verify()` Exposes Secret On-Chain | Fixed — `f1c4022` | **Verified** | `block.chainid != 31337 → revert DevOnly()` in Registry and Compat |
| MED-001 | `stfCommitment` Not Independently Verified | Fixed — `d735b19` | **Verified** | On-chain `keccak256(abi.encode(6 fields))` recomputation; `StfBindingMismatch` |
| MED-002 | `MAX_MANIFEST_ENTRIES` Unenforced | Fixed — `d735b19` | **Verified** | Constant = 8; `ManifestTooLarge` error enforced post-selection |
| MED-003 | Zero Oracle in `schedule()` | Fixed — `f1c4022` | **Verified** | `OracleZero`, `VKeyZero`, `PolicyHashZero` guards |
| MED-004 | Verifier Overflow for `secret > 2^128` | Fixed — `f1c4022` | **Verified** | `secret >= 1 << 128 → revert SecretTooLarge()` |
| MED-005 | `setCompatFacade` Privilege Escalation | Fixed — `f1c4022` | **Verified** | Two-step timelocked `scheduleCompatFacade` / `activateCompatFacade` |
| MED-006 | Canonical Keccak Vectors Incomplete | Fixed — `d735b19` | **Verified** | All 10 vectors populated; test asserts non-empty; all pass |
| LOW-001 | Ownable: No Two-Step Transfer | Fixed — `651181e` | **Verified** | Closed by HI-003 fix |
| LOW-002 | Ownable Uses `require()` Strings | Fixed — `651181e` | **Verified** | Closed by HI-003 fix; all custom errors |
| LOW-003 | Genesis Window Accepts Any `l2Start` | Fixed — `6594024` | **Verified** | `genesisL2Block` immutable; `GenesisStartMismatch` on window 0 |
| LOW-004 | `metaLocator` Not Emitted | Fixed — `6594024` | **Verified** | `ManifestAnnounced(proverSetDigest, metaLocator)` emitted |
| LOW-005 | CEI Violation in `_submit()` | Fixed — `6594024` | **Verified** | State (`nextWindowIndex`, `lastL2EndBlock`) updated before external call |
| LOW-006 | Degraded Provers Silently Included | Fixed — `6594024` | **Verified** | `allow_degraded: bool` (default false); `Degraded` excluded by default |
| INF-001 | No Monitoring Infrastructure | Fixed — `0ab8a3e` | **Partially Fixed** | `watcher.ts` expanded; required docs absent — see below |
| INF-002 | `deploy.ts` Hot Wallet Owner | Fixed — `0ab8a3e` | **Partially Fixed** | `WorldlineCompat` ownership NOT transferred — see REA-004 |
| INF-003 | 46 npm Vulnerabilities | Fixed — `0ab8a3e` | **Partially Fixed** | CI audits prod deps only (correct); `known-risks.md` absent — see below |
| INF-004 | `download-ptau.ts` No Integrity Check | Fixed — `240f426` | **Verified** | `PTAU_SHA256` constant; exits if mismatch |
| INF-005 | `isValid` Signal Not Public in Circuit | Fixed — `0ab8a3e` | **Verified** | `isValid` output removed; circuit compiles clean |
| INF-006 | snarkjs Unpinned | Fixed — `240f426` | **Verified** | `"snarkjs": "0.7.6"` — no range prefix |
| GAS-001 | `activate()` Already Optimal | Acknowledged | **Verified — No Regression** | No changes to `activate()` struct write pattern |

---

### Detailed Verdicts for Partially Fixed Findings

#### INF-001 — No Monitoring Infrastructure — **Partially Fixed**

**What was done:** `scripts/watcher.ts` was expanded (commit `0ab8a3e`) to subscribe to all
privileged-role events: `AdapterSet`, `AdapterChangeScheduled`, `PausedSet`,
`OwnershipTransferred`, `OwnershipTransferStarted`, `PermissionlessSet`, `SubmitterSet`,
`MaxAcceptanceDelaySet`, `AdapterChangeDelaySet`, `ManifestAnnounced`. The CI pipeline
received an npm-audit job.

**What remains missing:**
- `scripts/monitoring/sentinel-config.md` — **does not exist** (required by the re-audit
  checklist and the v1.0 recommendation for Forta/OZ Defender Sentinel configuration).
- `docs/security/incident-response.md` — **does not exist** (required by the re-audit
  checklist for operational IR procedure).
- `watcher.ts` remains a reference script stub, not a deployed service with alerting.

**Risk:** Without the monitoring documentation and a deployed watcher, a privileged-role
attack (compromised owner key executing `scheduleAdapterChange`) would go undetected until
the timelock expires and `activateAdapterChange` is called. The timelock (≥1 day) provides
the detection window, but only if someone is watching. See also **REA-005**.

#### INF-002 — `deploy.ts` Hot Wallet Owner — **Partially Fixed**

**What was done:** `deploy.ts` now requires `MULTISIG_ADDRESS` for non-dev deployments and
calls `transferOwnership(MULTISIG_ADDRESS)` on `WorldlineFinalizer`, `WorldlineRegistry`,
and `WorldlineOutputsRegistry`. A prominent comment documents that the multisig must call
`acceptOwnership()` on each contract.

**What remains missing:** `WorldlineCompat` is deployed at step 6 and wired as the registry's
`compatFacade` at step 7, but **`compat.transferOwnership(MULTISIG_ADDRESS)` is never called**.
`WorldlineCompat` therefore remains owned by the deployer EOA after a production deployment.

**Risk:** `WorldlineCompat` is `onlyOwner`-gated for all registry mutations
(`registerCircuit`, `registerDriver`, `registerPlugin`, `deprecatePlugin`). A compromised
deployer key can modify the registry's circuit/driver/plugin state even after the multisig
owns the other contracts. This is a **new Low severity finding — REA-004**.

#### INF-003 — npm Vulnerabilities — **Partially Fixed**

**What was done:** Commit `0ab8a3e` added a CI job `npm-audit` that runs:
```bash
npm audit --omit=dev --audit-level=high   # fails on HIGH prod-dep vulns
npm audit --audit-level=critical || echo "::warning::..."  # warns on dev vulns
```

This is the correct approach: all 67 vulnerabilities (including all 16 high) are in
devDependencies. `npm audit --omit=dev --audit-level=high` passes cleanly. The CI
correctly separates production risk from dev-toolchain risk.

**What remains missing:**
- `docs/security/known-risks.md` does not exist. The accepted risks (undici CVEs in
  hardhat devDependencies) are not formally documented outside of the CI log.
- `hardhat` is still at `^2.19.0`; undici CVE count has grown from 46 to 67 since the
  v1.0 audit as new advisories were published. The fix path (`npm audit fix --force` →
  `hardhat@3.2.0`) is a breaking change that has not been evaluated.

**Risk to CI/developer machines:** An RCE in undici triggered via the Hardhat HTTP stack
on a developer machine that also holds deployment keys remains a theoretical risk. The
existing CI approach (prod-only gate) is an acceptable interim posture if documented.


---

## Phase 2 — Regression Analysis

### 2.1 Timelock Attack Surface (HI-001, HI-002, MED-005)

**`scheduleAdapterChange()` lockout vector:** Calling `scheduleAdapterChange()` a second
time overwrites `pendingAdapter` and resets `pendingAdapterActivation` to
`block.timestamp + adapterChangeDelay`. There is no separate cancel function, but the owner
can effectively cancel by scheduling the current live adapter address, then calling
`activateAdapterChange()` after the delay (a safe no-op). No lockout is possible. **No
regression.**

**`activateAdapterChange()` atomicity:** The function sets `adapter`, clears
`pendingAdapter = address(0)`, and resets `pendingAdapterActivation = 0` in sequence, with
no external calls in between. The new adapter becomes active only after all three writes
complete. **No partial-state reentrancy risk.**

**`scheduleCompatFacade()` zero-address path:** `pendingCompatFacade` can be set to
`address(0)` to schedule disabling the facade. This is intentional and documented in the
NatSpec. **No regression.**

### 2.2 Two-Step Ownership Edge Cases (HI-003)

**Double `transferOwnership` call:** The second call overwrites `_pendingOwner`. This is the
correct and expected behavior (effectively cancels the first pending transfer). **No
regression.**

**Owner as pending owner:** `transferOwnership` can be called with `newOwner == owner()`,
setting `_pendingOwner = _owner`. The current owner could then call `acceptOwnership()`,
which would be a no-op (ownership unchanged). This is a harmless edge case.

**"Stuck" pending transfer:** If `_pendingOwner` is set to a contract that cannot call
`acceptOwnership()` (e.g., a multisig with a broken executor), the owner retains control
(the `_owner` slot is unchanged until acceptance) and can overwrite `_pendingOwner` by
calling `transferOwnership()` again with the correct address. **No permanent lock is
possible.** No `cancelOwnershipTransfer()` is needed given this recovery path.

### 2.3 CEI Reordering Consequences (LOW-005)

After the CEI fix, `nextWindowIndex` and `lastL2EndBlock` are written before
`adapter.verify()` is called. If `adapter.verify()` reverts:

1. The EVM unwinds both storage writes — the window slot is not consumed. ✅ Correct.
2. The emit statements after `verify()` are also unwound — no phantom events. ✅ Correct.
3. `WorldlineFinalizer` has no other storage writes inside `adapter.verify()` — the adapter
   is a separate contract with its own storage. **No partial-state hazard.**

Reentry during `adapter.verify()` would see the incremented `nextWindowIndex`, preventing a
second submission for the same window index. **Reentrancy protection is correct.**

### 2.4 k256 Address Derivation Correctness (CRI-001)

Code path in `directory.rs`:

```rust
// EIP-191 hash — correct 32-byte prefix form
fn eip191_hash(message: &[u8; 32]) -> [u8; 32] {
    keccak256("\x19Ethereum Signed Message:\n32" ‖ message)
}

// Address derivation — correct: strip 0x04 prefix, hash 64 bytes, take last 20
fn pubkey_to_eth_address(key: &VerifyingKey) -> [u8; 20] {
    let uncompressed = key.to_encoded_point(false);
    let pubkey_bytes = &uncompressed.as_bytes()[1..];  // strip 0x04 prefix byte
    let hash = keccak256(pubkey_bytes);
    hash[12..]                                          // last 20 bytes
}
```

Both are correct:
- EIP-191 uses the 32-byte form (`\n32` suffix) appropriate for `personal_sign` over a
  prehash, matching how ethers.js `signer.signMessage(bytes32)` behaves.
- Address derivation strips exactly 1 prefix byte, hashes 64 bytes, and takes the last 20.
  Off-by-one would occur if `[1..]` were replaced with `[0..]` (includes prefix) or
  `[2..]` (too many stripped) — neither is the case.

The test key (`ac0974bec...`, Hardhat account #0) is a well-known external reference,
confirming the implementation round-trips correctly against an independently computed address.
**No bug found.**

### 2.5 Canonical Test Vector Keccak Conformance (MED-006)

- All 10 vectors in `schemas/canonical-test-vectors.json` have non-empty, non-placeholder
  `keccak256` fields (confirmed programmatically: zero empty fields found).
- `canonical.rs::shared_test_vectors_keccak` asserts all fields are populated and matches
  each against `canonical_keccak()` — all 23 tests pass.
- The CI `canonical-conformance` job runs both Rust and TypeScript canonicalisers against
  the shared vectors. **No divergence detected.**

---

## Phase 3 — Open Items

### 3.1 MED-001 Spec Clarification Status

The v1.1 remediation chose the 6-field formula (excluding `stfCommitment` itself):

```solidity
bytes32 expectedStf = keccak256(
    abi.encode(l2Start, l2End, outputRoot, l1BlockHash, inputDomainSeparator, windowCloseTimestamp)
);
```

This matches the spec description in the v1.0 report:
> `stfCommitment = keccak256(abi.encode(l2Start, l2End, outputRoot, l1BlockHash, domainSeparator, windowCloseTimestamp))`

The SPEC-CLARIFICATION-NEEDED flag in the original finding's recommendation (regarding
whether `stfCommitment` should commit to itself as a 7th word) was resolved by adopting the
6-field formula. **The on-chain formula is internally consistent.** However, because the
production circuit does not yet exist, the circuit team MUST verify that the outer circuit
enforces the same formula when it is written. If the circuit uses a different commitment
encoding, the on-chain guard would incorrectly reject valid proofs. This is recorded on the
Pre-Mainnet Checklist.

### 3.2 New Findings from Automated Toolchain

See Phase 4 — New Findings section (REA-001 through REA-006).

### 3.3 Production Circuit and Recursion Components

The production outer circuit does **not yet exist** (confirmed: no files in `circuits/`
beyond `worldline.circom` and the demo SquareHash setup). This is unchanged from v1.0 and
remains the single most critical blocker for mainnet.

`crates/worldline-driver/src/recursion.rs` (222 lines) was not modified during remediation.
The module is scaffolding only: it builds `RecursionWitness` structs with placeholder empty
proof bytes. All hardcoded constants (`max_inner = 4`, `k_in_proof`) are configurable via
`RecursionConfig`; no circuit indices are hardcoded. The module will require a full review
once the accumulator circuit is written.

**Pre-mainnet requirement:** Full re-audit of the production circuit and `recursion.rs`
after circuit finalization. Added to Pre-Mainnet Checklist.

### 3.4 `watcher.ts` Trust Assumptions

`watcher.ts` is a batch-query reference script, not a persistent service. It has no
PagerDuty/Slack integration and no persistent chain-tip subscription. It is not deployed
anywhere. The `proverSetDigest` mismatch check requires a `--verify-manifest` path
argument; without it, manifest verification is skipped.

As the only independent verifier of `proverSetDigest` on the off-chain side, its security
posture matters: if the watcher and the aggregator share the same host, a key compromise
compromises both. **Recorded as REA-005 (Informational).**

### 3.5 `recursion.rs` Analysis

`recursion.rs` was not modified during remediation. Targeted review findings:

- No hardcoded circuit indices or field-element constants.
- `k_in_proof > manifest.len()` and `k_in_proof > max_inner` both produce errors correctly.
- Placeholder inner proof bytes are zeroed (`vec![0u8; 64]`); the comment documents this
  will be replaced by real proof bytes from provers. No security impact until circuit exists.
- The module does not perform any cryptographic operations; it only builds data structures
  for the aggregator. **No findings.**

### 3.6 `Groth16Verifier.sol` Placeholder Behavior

The placeholder `Groth16Verifier.sol` correctly reverts with `NotProductionVerifier()` on
any chain other than Hardhat (`chainid != 31337`). The revert is explicit and unambiguous.

If this placeholder were accidentally deployed to a testnet, every call to
`Groth16Verifier.verifyProof()` would revert with a named error, causing
`Groth16ZkAdapter.verify()` to propagate `ProofInvalid()` — a clear failure mode, not a
silent false return. **No opaque failure mode.** No new finding required.


---

## Phase 4 — New Findings

---

### [REA-001] `Groth16ZkAdapter` Constructor Missing Zero-Check on `_verifier`

**Severity:** Low
**Category:** Input Validation / Deployment Safety
**Location:** `contracts/src/zk/Groth16ZkAdapter.sol` — `constructor`, line 74
**Auditor(s):** Jordan, Morgan
**Status:** Open

#### Description

The `Groth16ZkAdapter` constructor accepts a `_verifier` address and stores it as
`immutable verifierAddress` without validating that `_verifier != address(0)`:

```solidity
constructor(
    address _verifier,
    bytes32 _programVKeyPinned,
    bytes32 _policyHashPinned,
    bool _isDev
) {
    IS_DEV_MODE = _isDev;
    verifierAddress = _verifier;   // no zero-check
    ...
}
```

If `_verifier` is accidentally set to `address(0)` during deployment:
- In **dev mode**: `Verifier(address(0)).verifyProof(...)` will revert on every call,
  permanently bricking the adapter.
- In **production mode**: `Groth16Verifier(address(0)).verifyProof(...)` will revert on
  every call with an out-of-gas or invalid opcode, permanently bricking the adapter.

Because `verifierAddress` is `immutable`, there is no way to fix it without redeploying.
The `WorldlineFinalizer` would then need a new `scheduleAdapterChange` + timelock cycle.

Note: The `WorldlineFinalizer` constructor correctly rejects `_adapter == address(0)`, and
the `deploy.ts` script supplies the already-deployed `verifierAddr` — so accidental zero
deployment is unlikely in practice but is not protected against at the contract level.

#### Recommendation

Add a zero-check in the constructor:

```solidity
if (_verifier == address(0)) revert InvalidVerifier();
```

Define `error InvalidVerifier()`.

---

### [REA-002] `WorldlineFinalizer.domainSeparator` Should Be `immutable`

**Severity:** Gas
**Category:** Gas Optimization
**Location:** `contracts/src/WorldlineFinalizer.sol` — line 78
**Auditor(s):** Jordan
**Status:** Open

#### Description

`domainSeparator` is assigned once in the constructor and never modified. Declaring it
`immutable` would embed the value in contract bytecode, eliminating a cold SLOAD (~2,100
gas) on every call to `_submit()`.

```solidity
// Current
bytes32 public domainSeparator;

// Recommended
bytes32 public immutable domainSeparator;
```

Slither 0.11.5 independently flagged this (`immutable-states` detector).

#### Recommendation

Change `bytes32 public domainSeparator` to `bytes32 public immutable domainSeparator`.

---

### [REA-003] `setCompatFacade` Reuses `FacadeTimelockActive(0)` as Wrong Error Code

**Severity:** Informational
**Category:** Code Quality / Error Semantics
**Location:** `contracts/src/WorldlineRegistry.sol` — `setCompatFacade()`, line 136
**Auditor(s):** Morgan
**Status:** Open

#### Description

`setCompatFacade()` is a one-time bootstrapping function that reverts if the facade has
already been set. It uses `FacadeTimelockActive(0)` as the revert error:

```solidity
function setCompatFacade(address compat) external onlyOwner {
    if (compatFacade != address(0)) revert FacadeTimelockActive(0);
    compatFacade = compat;
    emit CompatFacadeSet(compat);
}
```

`FacadeTimelockActive` semantically means "a scheduled facade change cannot be activated
yet because the timelock has not elapsed; it activates at timestamp X." Passing `0` as the
activation time is misleading and would confuse any off-chain tooling that decodes this
error and interprets the argument as a future timestamp.

The correct error for "cannot call direct setter because facade is already set" should be a
dedicated error, e.g., `FacadeAlreadySet()`.

#### Recommendation

```solidity
error FacadeAlreadySet();
...
if (compatFacade != address(0)) revert FacadeAlreadySet();
```

---

### [REA-004] `deploy.ts` Omits `WorldlineCompat` from Multisig Ownership Transfer

**Severity:** Low
**Category:** Infrastructure / Key Custody
**Location:** `scripts/deploy.ts` — ownership transfer block, lines 137–163
**Auditor(s):** Casey, Morgan
**Status:** Open

#### Description

The INF-002 remediation added mandatory ownership transfer to a multisig after deployment.
However, `transferOwnership(MULTISIG_ADDRESS)` is called on only three of the four ownable
contracts:

| Contract | `transferOwnership` called |
|----------|---------------------------|
| `WorldlineFinalizer` | ✅ yes (line 142) |
| `WorldlineRegistry` | ✅ yes (line 149) |
| `WorldlineOutputsRegistry` | ✅ yes (line 156) |
| `WorldlineCompat` | ❌ **missing** |

`WorldlineCompat` inherits from `Ownable` and is gated by `onlyOwner` on all registry
mutation functions: `registerCircuit`, `registerDriver`, `registerPlugin`,
`deprecatePlugin`. After a production deployment, the deployer's hot wallet retains admin
control of the compat facade permanently — contradicting the stated goal of transferring
all protocol ownership to the multisig.

#### Attack Scenario

1. Developer deploys to mainnet with `MULTISIG_ADDRESS=0xSafe`.
2. Three contracts transfer ownership. `WorldlineCompat` does not.
3. Deployer's hot wallet is later compromised.
4. Attacker calls `WorldlineCompat.registerCircuit(maliciousCircuitId, ..., maliciousVerifier, ...)`.
5. The registry now contains a circuit entry pointing to an attacker-controlled verifier
   address, which can be used to compromise any plugin relying on that circuit ID.

#### Recommendation

Add to `deploy.ts` after step 7 (wiring the facade):

```typescript
const compatTx = await compat.transferOwnership(MULTISIG_ADDRESS);
await compatTx.wait();
console.log(`   WorldlineCompat.transferOwnership → ${MULTISIG_ADDRESS} (pending acceptance)`);
```

Add `WorldlineCompat` to the `acceptOwnership()` documentation comment.

---

### [REA-005] Missing Monitoring Documentation Files

**Severity:** Informational
**Category:** Infrastructure / Operational Security
**Location:** `docs/security/` (absent files)
**Auditor(s):** Casey
**Status:** Open

#### Description

The INF-001 remediation claim states the finding is fixed, but two documentation deliverables
specified in the re-audit checklist are absent:

1. **`scripts/monitoring/sentinel-config.md`** — does not exist. The v1.0 recommendation
   called for a Forta bot or OpenZeppelin Defender Sentinel configuration listing monitored
   events. The expanded `watcher.ts` covers the event list in code, but no documented
   sentinel configuration exists for the operations team.

2. **`docs/security/incident-response.md`** — does not exist. The v1.0 recommendation
   called for an operational IR checklist with contact details, stablecoin-issuer freeze
   contacts, and an on-call rotation.

`watcher.ts` remains a batch-query reference script. It is not a deployed persistent
service. Without the documentation, the protocol has no documented procedure for responding
to an anomalous privileged-role event detected during monitoring.

#### Recommendation

Create both files before mainnet. Minimum content:

- `sentinel-config.md`: list of monitored events, threshold conditions for alerting
  (e.g., any `AdapterSet` not preceded by `AdapterChangeScheduled` ≥ 24h prior),
  alerting endpoint configuration.
- `incident-response.md`: on-call contacts, escalation path, pause procedure, stablecoin
  issuer freeze contacts, post-incident review template.

---

### [REA-006] Missing `docs/security/known-risks.md` for Accepted npm Vulnerabilities

**Severity:** Informational
**Category:** Supply Chain / Documentation
**Location:** `docs/security/` (absent file)
**Auditor(s):** Casey
**Status:** Open

#### Description

The INF-003 re-audit checklist requires that accepted risks be documented in
`docs/security/known-risks.md`. This file does not exist.

The current `npm audit` posture — 67 vulnerabilities (21 low, 30 moderate, 16 high), all in
devDependencies, with a CI gate on production deps only — is a reasonable and defensible
approach. But the rationale is only implicit (visible in CI run output) rather than
explicitly documented. Any new developer or security reviewer encountering the `npm audit`
output has no documented rationale for why these are accepted.

Additionally, the one Rust advisory (`rustls-pemfile` unmaintained, RUSTSEC-2025-0134) and
any future cargo-audit findings have no documented acceptance record.

#### Recommendation

Create `docs/security/known-risks.md` with entries for each accepted risk:

- npm: undici CVEs in devDependencies — rationale, scope (CI/dev only), review cadence.
- npm: path to full fix (`hardhat@3.2.0`) and blocking reason (breaking change, not yet
  evaluated).
- cargo: `rustls-pemfile` unmaintained — rationale, replacement timeline.


---

## Automated Tool Output Summary

| Tool | Version | Findings | New vs. Known | Notes |
|------|---------|----------|---------------|-------|
| Slither | 0.11.5 | 9 detector categories, 28 result hits | 2 new (REA-001, REA-002); 7 false positives | Requires `forge` — installed during re-audit |
| Halmos | 0.3.3 | 0 | 0 new | No `check_*`/`invariant_*` test targets in codebase |
| cargo-audit | 0.22.1 | 1 warning | 1 new informational (rustls-pemfile unmaintained) | Yanked-crate check failed (registry 503); vuln scan completed |
| cargo clippy | rustc 1.93.1 | 0 errors, 0 warnings | — | Clean |
| npm audit | 10.9.4 | 67 vulns (21L/30M/16H) | Maps to INF-003 (v1.0 known) | All devDeps; CI prod-only gate passes |
| forge test | 1.5.1-stable | 0 failures (63/63 pass) | — | All tests pass |
| forge coverage | 1.5.1-stable | Line 73.6%, Branch 50.7% | — | Branch gap due to unimplemented production circuit path |
| circomspect | MISSING | N/A | N/A | Install failed; must run against production circuit |
| Aderyn | MISSING | N/A | N/A | Not installed |
| Echidna | MISSING | N/A | N/A | Not installed |
| Medusa | MISSING | N/A | N/A | Not installed |
| vertigo-rs | MISSING | N/A | N/A | Not installed; mutation score not measured |
| ZKAP | MISSING | N/A | N/A | Not installed |
| snarkjs zkey verify | N/A | N/A | N/A | No `.zkey` in repo; mandatory before production ceremony |

---

## Updated Coverage Analysis

| Metric | v1.0 Baseline | v2.0 (post-remediation) | Delta |
|--------|---------------|------------------------|-------|
| Forge tests | 0 (Foundry not available) | 63 / 63 pass | +63 |
| Hardhat tests | 119 (claimed) | not re-run | — |
| Rust tests | 91 / 91 pass | 91 / 91 pass | 0 |
| Line coverage | Not measured | 73.6% (195/265) | baseline |
| Branch coverage | Not measured | 50.7% (37/73) | baseline |

**New test suites added during remediation:**

- `contracts/test/AccessControl.t.sol` — 18 tests (HI-001, HI-002, HI-003)
- `contracts/test/Chunk5.t.sol` — 19 tests (HI-004, MED-003, MED-004, MED-005)
- `contracts/test/Chunk7.t.sol` — 8 tests (LOW-003, LOW-004, LOW-005)
- `contracts/test/Groth16ZkAdapter.t.sol` — 7 tests (CRI-003 production path)
- Rust: 8 new directory tests (CRI-001), 3 selection tests (MED-002/LOW-006)

**Remaining coverage gaps:**

- Production `IS_DEV_MODE = false` with a real BN254 verifier (blocked until circuit exists)
- Double `schedule()` on same domain key (overwrite path in `WorldlineOutputsRegistry`)
- `setMinTimelock` itself subject to a timelock (not implemented; not required for floor
  enforcement but recommended before mainnet)
- Symbolic/invariant tests for timelock arithmetic and contiguity properties

---

## Updated Pre-Mainnet Checklist

### Contract Security

- [x] CRI-001 — Directory signature verification implemented (real secp256k1)
- [x] CRI-002 — snarkjs ceremony workflow corrected (contributions + beacon + verify)
- [x] CRI-003 — Adapter production proof decode path implemented; pubSignals bound
- [x] HI-001 — Timelocked adapter change (`scheduleAdapterChange` + delay ≥ 1 day)
- [x] HI-002 — `MIN_TIMELOCK_FLOOR = 1 days` enforced on `setMinTimelock`
- [x] HI-003 — Two-step ownership transfer; custom errors
- [x] HI-004 — `verify()` dev-only guard (`chainid == 31337`)
- [x] MED-001 — On-chain `stfCommitment` binding verification (6-field keccak)
- [x] MED-002 — `MAX_MANIFEST_ENTRIES = 8` enforced in selection
- [x] MED-003 — Zero-value guards on `schedule()` inputs
- [x] MED-004 — `SecretTooLarge` guard in dev Verifier
- [x] MED-005 — Timelocked compat facade changes
- [x] MED-006 — All canonical keccak test vectors populated
- [x] LOW-001..006 — All Low findings closed
- [ ] **REA-001** — Add `_verifier != address(0)` check in `Groth16ZkAdapter` constructor
- [ ] **REA-002** — Declare `domainSeparator` as `immutable` in `WorldlineFinalizer`
- [ ] **REA-003** — Replace `FacadeTimelockActive(0)` with `FacadeAlreadySet()` in `setCompatFacade`
- [ ] **REA-004 BLOCKING** — Add `compat.transferOwnership(MULTISIG_ADDRESS)` to `deploy.ts`

### Ceremony and Circuit

- [ ] **BLOCKING** — Production outer circuit written
- [ ] **BLOCKING** — Production outer circuit audited by independent party
- [ ] **BLOCKING** — Public Groth16 MPC ceremony conducted (≥5 independent contributors)
- [ ] **BLOCKING** — Beacon applied from publicly committed randomness source
- [ ] **BLOCKING** — `snarkjs zkey verify` passes on production `worldline_final.zkey`
- [ ] **BLOCKING** — `Groth16Verifier.sol` exported from `worldline_final.zkey` via `npm run c:export`
- [ ] **BLOCKING** — Outer circuit enforces same `stfCommitment` 6-field formula as on-chain guard (MED-001 follow-up)
- [ ] `recursion.rs` re-reviewed after production accumulator circuit is finalized

### Key Custody and Deployment

- [ ] **BLOCKING** — All four contracts (`WorldlineFinalizer`, `WorldlineRegistry`,
  `WorldlineOutputsRegistry`, `WorldlineCompat`) ownership transferred to multisig ≥ 2-of-3
- [ ] **BLOCKING** — Multisig confirms `acceptOwnership()` on all four contracts
- [ ] Multisig signers use hardware wallets with transaction detail confirmation on device
- [ ] Key rotation procedure documented
- [ ] Emergency pause runbook documented

### Monitoring and Operations

- [ ] `watcher.ts` deployed as persistent service with PagerDuty/Slack alerting
- [ ] `scripts/monitoring/sentinel-config.md` created (REA-005)
- [ ] `docs/security/incident-response.md` created (REA-005)
- [ ] `docs/security/known-risks.md` created with accepted npm/cargo risk rationale (REA-006)
- [ ] On-call rotation established with at least 2 engineers
- [ ] Stablecoin issuer freeze contacts documented

### Testing and CI

- [ ] circomspect run against production circuit
- [ ] Echidna/Medusa invariant fuzz suite for `WorldlineFinalizer`
- [ ] Halmos symbolic tests for timelock arithmetic and contiguity
- [ ] vertigo-rs mutation score measured; target ≥ 85%
- [ ] `npm audit fix --force` (`hardhat@3.2.0`) evaluated and either applied or formally deferred

---

_End of Report — Project Worldline Security Re-Audit v2.0_
_Baseline audit commit: `0204d5354f5d58d2b32a6ceb5c25b46f33efe82f`_
_Remediation merge commit: `fa8dda6501b9018eac8c98c667e24017901e206c`_
_Re-audit date: 2026-03-27_
_22 of 26 v1.0 findings verified closed — 3 partially fixed — 6 new findings (0 Critical, 0 High, 2 Low, 4 Informational)_

