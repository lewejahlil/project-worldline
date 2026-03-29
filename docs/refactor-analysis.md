# Refactoring Analysis — Project Worldline

_Generated: 2026-03-29. Read-only structural analysis of the full codebase._

---

## Methodology

Every production source file was read across Solidity (`contracts/src/`, `contracts/test/`), Rust (`crates/`), and TypeScript (`test/`, `scripts/`). Automated tools run: `cargo machete` (0 unused deps), `cargo clippy --pedantic` (30 warnings, 25 auto-fixable), `depcheck` (4 potentially unused npm deps). Manual analysis follows.

---

## Refactoring Targets (Ranked by Impact-to-Risk Ratio)

### 1. Extract shared submission validation in WorldlineFinalizer

- **File:** `contracts/src/WorldlineFinalizer.sol` lines 429–591
- **Problem:** `_submit()` (lines 429–511) and `_submitRouted()` (lines 516–591) contain ~160 lines of near-identical validation logic: domain binding, window range, contiguity, staleness, STF commitment binding, state updates, and event emissions. Only the "Interactions" phase differs (adapter.verify vs proofRouter.routeProofAggregated).
- **Approach:** Extract `_validateAndUpdateState(bytes calldata publicInputs)` internal function returning the decoded tuple. Both `_submit` and `_submitRouted` call validation, then diverge only for verification.
- **Risk:** LOW — internal refactoring, no ABI change. Forge + Hardhat tests cover both paths extensively.
- **Impact:** HIGH — eliminates largest duplication in the codebase (~160 lines), reduces audit surface.

### 2. Centralize Forge test setup into a shared base contract

- **Files:** `contracts/test/AccessControl.t.sol`, `FinalizerGenesisAndEvents.t.sol`, `WorldlineFinalizer.fuzz.t.sol`, `GasBenchmark.t.sol`
- **Problem:** Each test contract deploys WorldlineFinalizer + adapter + proxy with identical setUp() boilerplate (~20–30 lines per file). ViewMockGroth16Verifier is redefined inline in multiple test files instead of importing from `contracts/src/test/`.
- **Approach:** Create `contracts/test/WorldlineTestBase.t.sol` with shared setUp, constants, and proof encoding helpers. Individual test contracts inherit and override only what differs.
- **Risk:** LOW — test-only change.
- **Impact:** MEDIUM — reduces ~100 lines of test duplication, makes adding new Forge tests faster.

### 3. Centralize TypeScript test helpers and reduce `setPermissionless` duplication

- **Files:** 14 test files across `test/`, `test/integration/`, `test/fork/`, `test/gas/`
- **Problem:** `setPermissionless(true)` called inline 25 times across 14 files. `computeStf`, `encodePublicInputs`, `encodeProof` helpers are redefined locally in unit test files instead of importing from `test/integration/deployment-fixtures.ts`. Event parsing helper `findZkProofAccepted` duplicated across 3+ integration test files. 245 instances of `as any` type casts throughout tests.
- **Approach:** Export shared helpers from `deployment-fixtures.ts` (or a new `test/helpers.ts`). Replace inline definitions with imports. Address `as any` selectively where typechain types are available.
- **Risk:** LOW — test-only changes.
- **Impact:** MEDIUM — reduces ~200 lines of test duplication, improves type safety.

### 4. Fix error naming inconsistency (NotAuthorised vs NotAuthorized) — DEFERRED

- **Files:** `contracts/src/WorldlineRegistry.sol` line 15, `contracts/src/WorldlineFinalizer.sol` line 22
- **Problem:** `WorldlineRegistry` uses `NotAuthorised` (British spelling), `WorldlineFinalizer` uses `NotAuthorized` (US spelling). Inconsistent across the project.
- **Status:** **Deferred as a future coordinated change.** Renaming a custom error changes its 4-byte selector, which affects any off-chain code, subgraph, or monitoring that matches on the selector. This should be done as a coordinated change with all consumers updated simultaneously, not as an incidental refactoring fix.
- **Risk:** MEDIUM if done without coordination — changes error selector ABI.
- **Impact:** LOW — cosmetic consistency fix.

### 5. Fix `require()` string in MockHalo2Verifier

- **File:** `contracts/src/test/MockHalo2Verifier.sol` line 11
- **Problem:** Uses `require(instances.length == 2, "bad instance count")` while all other contracts and mocks use custom errors exclusively.
- **Approach:** Add `error BadInstanceCount()` and replace the require with `if (instances.length != 2) revert BadInstanceCount()`.
- **Risk:** NEGLIGIBLE — test mock only.
- **Impact:** LOW — error pattern consistency.

### 6. Remove `typechain-types/` from git tracking

- **File:** `typechain-types/` directory (182 tracked files)
- **Problem:** `.gitignore` excludes `typechain-types/` but 182 files are already committed. CI regenerates them via `npx hardhat compile`. No import depends on them being committed vs generated.
- **Approach:** `git rm -r --cached typechain-types/` and commit.
- **Risk:** LOW — CI regenerates on compile. Verify no CI step depends on pre-committed types.
- **Impact:** LOW — reduces repo bloat, prevents spurious merge conflicts on generated files.

### 7. Fix Solc version divergence between Foundry and Hardhat

- **Files:** `foundry.toml` (solc = "0.8.24"), `hardhat.config.ts` (version: "0.8.34")
- **Problem:** Forge compiles with solc 0.8.24 while Hardhat compiles with 0.8.34. Since contracts use `pragma solidity ^0.8.24`, both are valid, but compilation behavior may diverge across compiler versions (optimizer differences, new warnings, etc.).
- **Approach:** Align `foundry.toml` to use 0.8.34 (matching Hardhat) or pin both to 0.8.24. Recommendation: use 0.8.24 in both since that's the pragma floor.
- **Risk:** LOW — changing compiler version may surface new warnings but no behavioral change.
- **Impact:** LOW — eliminates subtle compilation divergence.

### 8. Fix stale documentation references

- **Files:** `README.md` line 3, `docs/security/threat-model.md`, `docs/security/audit-report.md`, `docs/specs/technical-specification.md`
- **Problem:** README says "architecture for rollups" — Worldline is a verification architecture, not a rollup. Multiple docs use "rollup" framing. `docs/placeholder-inventory.md` references "no rollup logic." Audit reports use "rollup" extensively but those are historical documents that should not be modified.
- **Approach:** Update README.md and living documentation (threat-model, technical-specification, design docs) to use "verification architecture" framing. Leave audit reports untouched (they're point-in-time artifacts).
- **Risk:** NEGLIGIBLE — documentation only.
- **Impact:** LOW — correctness of project positioning.

### 9. Fix tsconfig.json include path typo

- **File:** `tsconfig.json` line 12
- **Problem:** `"include": ["scripts", "tests", ...]` references `"tests"` but the actual directory is `"test"`.
- **Approach:** Change `"tests"` to `"test"`.
- **Risk:** NEGLIGIBLE.
- **Impact:** LOW — TypeScript compilation may pick up test files correctly for IDE support.

### 10. Standardize Rust error handling in worldline-driver

- **Files:** `crates/worldline-driver/src/aggregator.rs`, `crates/worldline-driver/src/lib.rs`
- **Problem:** Uses bare `anyhow::Result` throughout without a custom error enum. Domain errors (selection failure) are mixed with I/O errors. Other crates (`aggregation`, `registry`, `recursion`) all use typed `thiserror` enums.
- **Approach:** Create `AggregatorError` enum with `thiserror::Error` derive. Keep `anyhow` as the top-level wrapper in CLI main, but use typed errors in library functions.
- **Risk:** LOW — internal Rust change, no ABI impact.
- **Impact:** LOW-MEDIUM — consistency with other crates, better error diagnostics.

### 11. Fix Rust clippy pedantic warnings (25 auto-fixable)

- **File:** `crates/halo2-circuit/src/stf_circuit.rs`
- **Problem:** 30 clippy pedantic warnings, 25 auto-fixable (doc_markdown backticks, must_use attributes). Also: `synthesize()` function is 199 lines (clippy::too_many_lines limit is 100).
- **Approach:** Run `cargo clippy --fix` for the 25 auto-fixable ones. The `synthesize()` function length is inherent to halo2 circuit layout — accept with `#[allow(clippy::too_many_lines)]` and a comment.
- **Risk:** LOW — cosmetic + lint fixes.
- **Impact:** LOW — cleaner clippy output.

### 12. Replace `.to_str().unwrap()` in Rust verifiers

- **Files:** `crates/aggregation/src/verifiers/groth16.rs:90`, `plonk.rs:170`, `halo2.rs:76`
- **Problem:** `PathBuf::to_str().unwrap()` panics on non-UTF-8 paths. Library crates should not panic.
- **Approach:** Return `VerificationError` on path conversion failure via `.ok_or(VerificationError::...)?`.
- **Risk:** LOW — error path only changes on non-UTF-8 paths (rare but possible).
- **Impact:** LOW — correctness for edge cases, no-unwrap rule compliance.

### 13. Use unique temp file names in Rust verifiers

- **Files:** `crates/aggregation/src/verifiers/groth16.rs:77-78`, `plonk.rs:156-158`, `halo2.rs:59-60`
- **Problem:** Hardcoded temp file names (`worldline_groth16_proof.json`) will collide if multiple verifications run concurrently.
- **Approach:** Append UUID or process ID to temp file names. Or use `tempfile::NamedTempFile`.
- **Risk:** LOW — adds a dependency (`tempfile` or `uuid`), straightforward change.
- **Impact:** LOW-MEDIUM — prevents concurrency bugs in production aggregator.

---

## Items Assessed but Not Recommended for This Pass

### Timelocked parameter pattern consolidation (WorldlineFinalizer)
The 4 timelocked parameters (adapter, blobKzgVerifier, domainSeparator, genesisL2Block) follow an identical schedule/activate pattern. A `TimelockManager` library could deduplicate ~300 lines. **Not recommended now** because: (a) high effort — requires generic type handling across address/bytes32/uint256 values, (b) changes contract storage layout interaction, (c) audit reports reference the current pattern. Better as a v2 architectural change.

### Trait extraction for Rust aggregation strategies
`Independent` and `Sequential` strategies duplicate ~40 lines of verification logic. Could extract a `StrategyExecutor` trait. **Deferred** — the duplication is small and the strategies may diverge further as the system matures.

### `as any` elimination in TypeScript tests (245 instances)
Would require properly typing all contract interactions through typechain. **Deferred** — high effort, low risk-of-regression from the current state. Worth doing incrementally.

### Blob verification helper extraction (WorldlineFinalizer)
The KZG vs hash-only routing in `submitZkValidityProofWithBlob()` could be extracted to `_verifyBlob()`. **Deferred** — the function is only 33 lines and the conditional is straightforward.

---

## Automated Analysis Summary

| Tool | Finding |
|------|---------|
| `cargo machete` | 0 unused Rust dependencies |
| `cargo clippy --pedantic` | 30 warnings (25 auto-fixable), mostly doc_markdown in halo2-circuit |
| `depcheck` | 4 potentially unused npm deps: `circomlib`, `@openzeppelin/contracts`, `@openzeppelin/contracts-upgradeable`, `circomlibjs` — these are used by Forge remappings and circuit tests, likely false positives |
| `solhint` | Not configured (no `.solhint.json`) |
