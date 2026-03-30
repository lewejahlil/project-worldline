# Coverage Gap Analysis — Project Worldline

_Generated: 2026-03-29. Counterpart to `docs/feature-completeness-gap-analysis.md`. Characterizes the full test coverage picture for the multi-ZK-prover verification pipeline: what is exercised, what is tested only against mocks, and what is not tested at all._

---

## Baseline

| Test suite        | Count   | Notes                                                          |
| ----------------- | ------- | -------------------------------------------------------------- |
| Hardhat (TS)      | 239     | Includes 8 prover-api-e2e + 11 real-verifier integration tests |
| Forge (Solidity)  | 138     | 13 test suites, fuzz at 256 runs, +24 real-verifier tests      |
| Rust (cargo test) | 275     | 2 ignored (require snarkjs / halo2-verify)                     |
| **Total**         | **652** |                                                                |

---

## Proving Pipeline — Coverage by Stage

The full proving lifecycle is:

```
Proof request → Prover selection → Proving (Groth16 / Plonk / Halo2)
    → Aggregation → Recursion → Blob encoding → On-chain verification → Finalization
```

### Stage 1 — Proof generation (Groth16 · Plonk)

**Source:** `crates/worldline-api/src/service.rs` (ProvingService), subprocess calls to snarkjs via `crates/aggregation/src/verifiers/groth16.rs` and `plonk.rs`.

| Path                                          | Tested? | How                                                                                   |
| --------------------------------------------- | ------- | ------------------------------------------------------------------------------------- |
| Groth16 proof generation (snarkjs subprocess) | No      | `ServiceConfig.groth16` is `None` in all tests; snarkjs artifacts not present in CI   |
| Plonk proof generation (snarkjs subprocess)   | No      | Same; `ServiceConfig.plonk` is always `None` in test fixtures                         |
| ProvingService.prove() — Groth16 path         | No      | None of the 8 `e2e_encoding.rs` tests request system ID=1 or ID=2                     |
| ProvingService.prove() — Plonk path           | No      | Same                                                                                  |
| ProvingService.prove() — Halo2 path           | **Yes** | `e2e_encoding.rs` (8 tests): full native-Rust prove, calldata encode, serde roundtrip |

The ProvingService's partial-success fallback logic is unit-tested in `service.rs` (12 tests) but only with mocked `InnerProver` outcomes — not real provers.

### Stage 1 — Proof generation (Halo2)

**Source:** `crates/halo2-circuit/`, `crates/recursion/src/halo2_prover.rs`.

| Path                                           | Tested? | How                                                                                                                             |
| ---------------------------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `WorldlineStfCircuit` constraints (MockProver) | **Yes** | `stf_tests.rs` (9 MockProver tests): quorum bounds, batch size bounds, prover ID non-zero, proofSystemId range, Poseidon output |
| Real KZG proof generation + `verify_proof`     | **Yes** | `stf_tests.rs::real_proof_generation_and_verification`: full `create_proof` / `verify_proof` cycle using KZG/BN254              |
| Halo2Prover unit tests (recursion crate)       | **Yes** | `crates/recursion/src/halo2_prover.rs` (5 tests)                                                                                |

### Stage 1 — Circuit constraint tests (Circom)

**Source:** `circuits/test/`.

| Path                                                                   | Tested?     | How                                                                                                                                                                       |
| ---------------------------------------------------------------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Groth16 circuit (worldline_stf.circom) — snarkjs fullProve/verify      | Conditional | `worldline_stf.test.ts` (8 tests): real snarkjs proof gen + verify; **skips entirely** if build artifacts missing — not gated into standard CI                            |
| Plonk circuit (worldline_stf_plonk.circom) — conformance + constraints | Conditional | `worldline_stf_plonk.test.js` (12 tests): constraint tests always run; cross-circuit conformance and on-chain E2E skip if original artifacts or local Hardhat node absent |

Circuit tests are not part of `npx hardhat test` or `cargo test`. They require a pre-built ceremony output and are run via `npx mocha`.

### Stage 2 — Aggregation

**Source:** `crates/aggregation/`.

| Path                                                             | Tested?                 | How                                                                                                                                    |
| ---------------------------------------------------------------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| ProofAggregator: quorum validation, proof-add errors, strategies | **Yes**                 | `aggregation_tests.rs` (13 tests)                                                                                                      |
| Multi-system aggregation (Groth16 + Plonk + Halo2 mixed)         | **Yes**                 | `multi_system_tests.rs` (15 tests, MockVerifier)                                                                                       |
| Real Groth16 proof verification (snarkjs subprocess)             | **No — ignored**        | `test_real_groth16_verification_ignored` (#[ignore = "requires snarkjs"])                                                              |
| Real Halo2 proof verification (subprocess binary)                | **No — ignored**        | `test_real_halo2_verification_ignored` (#[ignore = "requires halo2-verify helper binary"])                                             |
| Real Plonk proof verification (snarkjs subprocess)               | **Not tested at all**   | PlonkVerifier has no integration test                                                                                                  |
| Poseidon digest (aggregator → Halo2 circuit)                     | **Yes — internal only** | `poseidon_cross_system_tests.rs` (4 tests): aggregator digest matches Halo2 circuit `compute_public_outputs`; both use PSE sponge mode |
| Poseidon digest (aggregator/Halo2 → circomlib Groth16/Plonk)     | **Documented mismatch** | `poseidon_conformance.rs` (4 tests): documents that PSE sponge ≠ circomlib compression function; see gap #1 below                      |

### Stage 3 — Recursion

**Source:** `crates/recursion/`.

| Path                                                          | Tested? | How                                                                                                  |
| ------------------------------------------------------------- | ------- | ---------------------------------------------------------------------------------------------------- |
| RecursiveVerifier: wrap, recurse, max_depth, verify_structure | **Yes** | `recursion_tests.rs` (10 tests)                                                                      |
| MultiProverPipeline (all 3 provers)                           | **Yes** | `pipeline.rs` (8 unit tests), `groth16_prover.rs` (14), `plonk_prover.rs` (6), `halo2_prover.rs` (5) |
| RecursionWitness collection in driver                         | **Yes** | `crates/worldline-driver/src/recursion.rs` (9 unit tests)                                            |
| Real inner proof recursion (actual ZK wrap)                   | **No**  | All RecursiveVerifier tests operate on mock aggregated proofs with dummy proof bytes                 |

### Stage 4 — Blob encoding

**Source:** `crates/worldline-driver/src/blob.rs`, `contracts/src/blob/`.

| Path                                                            | Tested?               | How                                                                                                  |
| --------------------------------------------------------------- | --------------------- | ---------------------------------------------------------------------------------------------------- |
| Blob encoding (Rust)                                            | **Yes**               | `blob.rs` (5 unit tests): chunking, padding, sidecar construction                                    |
| BlobVerifier.getBlobHash / verifyBlobHash / validateVersionByte | **Yes (error paths)** | `BlobVerifier.test.ts` (Hardhat): `NoBlobAtIndex` and `InvalidVersionedHash` reverts                 |
| BlobVerifier full round-trip (real EIP-4844 blob)               | **No**                | Local Hardhat EVM returns `bytes32(0)` for `blobhash(0)`; test file explicitly notes this limitation |
| BlobKzgVerifier                                                 | **Not tested**        | No Hardhat or Forge test deploys or calls it                                                         |

### Stage 5 — On-chain proof verification

This is the most significant coverage gap in the codebase.

#### Groth16Verifier

| Path                                                 | Tested? | How                                                                                                                                                                    |
| ---------------------------------------------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| BN254 pairing check (real circuit proof)             | **Yes** | `Groth16RealVerifier.t.sol` (8 tests): real verifier accepts valid proof, rejects corrupted proof/wrong stf/wrong digest; adapter agg+thin paths; `GasBenchmark.t.sol` |
| End-to-end: snarkjs proof → Groth16Verifier on-chain | **Yes** | `groth16-real-verifier.test.ts` (3 tests): adapter round-trip, corrupted proof rejection, full stack through finalizer with `submitZkValidityProof`                    |

#### PlonkVerifierV2

| Path                                        | Tested? | How                                                                                                                                                  |
| ------------------------------------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| PlonkVerifierV2 real pairing check          | **Yes** | `PlonkRealVerifier.t.sol` (8 tests): real verifier accepts valid proof, rejects corrupted proof/wrong stf/wrong digest; adapter agg+thin paths       |
| End-to-end: snarkjs proof → PlonkVerifierV2 | **Yes** | `plonk-real-verifier.test.ts` (3 tests): adapter round-trip, corrupted proof rejection, full stack through router + finalizer with routed submission |

#### Halo2Verifier

| Path                                  | Tested? | How                                                                                                                                                  |
| ------------------------------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| Halo2Verifier (real, production mode) | **Yes** | `Halo2RealVerifier.t.sol` (8 tests): real verifier accepts valid SHPLONK proof, rejects corrupted proof/wrong stf/wrong digest; adapter agg+thin     |
| Halo2ZkAdapter with real verifier     | **Yes** | `halo2-real-verifier.test.ts` (5 tests): adapter round-trip, corrupted proof rejection, full stack through router + finalizer with routed submission |

### Stage 5 — Adapter and router layers

| Path                                                      | Tested? | How                                                                                            |
| --------------------------------------------------------- | ------- | ---------------------------------------------------------------------------------------------- |
| Groth16ZkAdapter proof decode + dispatch                  | **Yes** | `Groth16ZkAdapter.t.sol` (5 tests), mock verifier                                              |
| PlonkZkAdapter proof decode + dispatch (thin + agg paths) | **Yes** | `PlonkVerifier.t.sol` (12 tests), mock verifier                                                |
| Halo2ZkAdapter proof decode + dispatch                    | **Yes** | `Halo2Verifier.t.sol` (12 tests), mock mode verifier                                           |
| ProofRouter: registration, timelock, routing              | **Yes** | `ProofRouter.t.sol` (21 tests), mock adapters; `routing.test.ts` (8 tests)                     |
| ProofRouter → Finalizer integration                       | **Yes** | `routing.test.ts`, `multiprover-quorum.test.ts`, `prover-api-e2e.test.ts` — all mock verifiers |

### Stage 6 — WorldlineFinalizer

| Path                                                                        | Tested?     | How                                                                                     |
| --------------------------------------------------------------------------- | ----------- | --------------------------------------------------------------------------------------- |
| Input validation (domain, contiguity, staleness, STF binding, window range) | **Yes**     | `WorldlineFinalizer.fuzz.t.sol` (7 fuzz tests), `prover-api-e2e.test.ts`                |
| Genesis L2 block validation                                                 | **Yes**     | `FinalizerGenesisAndEvents.t.sol` (4 tests)                                             |
| CEI ordering, event emission                                                | **Yes**     | `FinalizerGenesisAndEvents.t.sol`                                                       |
| Permissionless toggle                                                       | **Yes**     | Integration tests; `enablePermissionless()` used throughout                             |
| Permissioned submission (non-permissionless)                                | **Partial** | Tested in some top-level Hardhat tests; not systematically covered in integration suite |
| `submitZkValidityProof` (direct adapter)                                    | **Yes**     | Multiple test files                                                                     |
| `submitZkValidityProofRouted` (router path)                                 | **Yes**     | `routing.test.ts`, `prover-api-e2e.test.ts`, `multiprover-quorum.test.ts`               |
| Timelocked adapter/router changes                                           | **Yes**     | `AccessControl.t.sol`                                                                   |

---

## Contract Surface — Coverage by Contract

### WorldlineFinalizer

Comprehensively tested for state machine logic, validation invariants, access control, and UUPS upgrade correctness. All tests use mock verifiers — the cryptographic verification layer is not exercised.

### ProofRouter

Well-tested: registration, timelocking, routing to registered adapters, error paths. All through mock adapters.

### WorldlineRegistry and WorldlineOutputsRegistry

Both well-covered: circuit/driver/plugin registration, timelocked compat facade, zero-value guards, two-step ownership, UUPS upgrades.

### Groth16ZkAdapter / PlonkZkAdapter / Halo2ZkAdapter

Proof format decoding, length validation, public signal binding, proofSystemId constants — all covered. No test exercises the real verifier contracts through these adapters.

### Verifier contracts (Groth16Verifier, PlonkVerifierV2, Halo2Verifier)

| Contract        | Forge coverage                                                                                | Hardhat coverage                                                                            |
| --------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| Groth16Verifier | **Real proof tests** (`Groth16RealVerifier.t.sol`, 8 tests) + gas (`GasBenchmark.t.sol`)      | **Real proof tests** (`groth16-real-verifier.test.ts`, 3 tests) + conditional circuit tests |
| PlonkVerifierV2 | **Real proof tests** (`PlonkRealVerifier.t.sol`, 8 tests)                                     | **Real proof tests** (`plonk-real-verifier.test.ts`, 3 tests) + conditional circuit tests   |
| Halo2Verifier   | **Real proof tests** (`Halo2RealVerifier.t.sol`, 8 tests) + mock mode (`Halo2Verifier.t.sol`) | **Real proof tests** (`halo2-real-verifier.test.ts`, 5 tests)                               |

---

## Gap Inventory

### Critical path — blocks re-audit or external integrator confidence

#### Gap 1 — Poseidon cross-system conformance unresolved

- **Location:** `crates/halo2-circuit/tests/poseidon_conformance.rs`
- **Finding:** The Halo2 circuit's `poseidon_compress_3` / `poseidon_compress_7` use PSE Poseidon in sponge mode. The circomlib Poseidon used in the Groth16 and Plonk Circom circuits uses a compression-function mode with different initial state and output extraction. Both produce distinct outputs for identical inputs:
  - PSE stfCommitment: `0x06a3ec151a5931765cbe6a5c50aef89ca0b13c21432dff8ab5a2bdfc58c906e1`
  - circomlib stfCommitment: `0x2e1de696850f25d0594670ee7fd253af5893e313da0d8a161d63fa9994baf9e4`
- **Scope:** 4 tests in `poseidon_conformance.rs` document this divergence. The tests are labeled "should be #[ignore]" in prose but their actual `#[ignore]` attribute status is inconsistent with the CLAUDE.md "5 ignored" count — they may be running and failing silently or skipped by an undocumented mechanism.
- **Impact:** A Halo2 proof and a Groth16/Plonk proof submitted for the same window will produce different `stfCommitment` and `proverSetDigest` values. Multi-prover quorum scenarios that mix proof systems are currently non-conformant at the digest level. The aggregator's `poseidon_cross_system_tests.rs` confirms internal consistency between the aggregator and the Halo2 circuit, but this consistency does not extend to the Circom-based provers.
- **Blocking test:** No test validates that a proof generated by the Groth16 or Plonk circuit produces the same `stfCommitment` as the Halo2 circuit for the same inputs.
- **Category: Critical path**

#### Gap 2 — Real verifier pairing untested end-to-end — CLOSED

- **Location:** `contracts/src/zk/Groth16Verifier.sol`, `PlonkVerifierV2.sol`, `Halo2Verifier.sol`
- **Status: CLOSED** (2026-03-30, branch `claude/crypto-hardening-U52T7`)
- **Resolution:** All three proof systems now have real verifier round-trip tests using genuine BN254 proof fixtures:
  - **Groth16:** `Groth16RealVerifier.t.sol` (8 Forge tests) + `groth16-real-verifier.test.ts` (3 Hardhat tests) — real `Groth16Verifier` accepts valid proof, rejects corrupted proof/wrong instances, full stack through finalizer
  - **Plonk:** `PlonkRealVerifier.t.sol` (8 Forge tests) + `plonk-real-verifier.test.ts` (3 Hardhat tests) — real `PlonkVerifierV2` with genuine pairing check, full stack through router + finalizer
  - **Halo2:** `Halo2RealVerifier.t.sol` (8 Forge tests) + `halo2-real-verifier.test.ts` (5 Hardhat tests) — real `Halo2Verifier` with SHPLONK KZG verification, full stack through router + finalizer
  - Fixture generators committed: `scripts/generate-groth16-fixture.mjs`, `scripts/generate-plonk-fixture.mjs`, `crates/halo2-circuit/examples/generate_fixture.rs`
  - Verifier contracts regenerated from current zkeys to fix stale VK constants discovered during this work
  - Total new tests: +24 Forge, +11 Hardhat
- **Original finding:** No test in any suite exercised real on-chain pairing verification in a correctness context. `GasBenchmark.t.sol` deployed the real `Groth16Verifier` but only measured gas on an invalid proof. `PlonkVerifierV2` was never instantiated in Forge. `Halo2Verifier` was always deployed with `mockMode=true`.
- **Category: Critical path — RESOLVED**

#### Gap 3 — Subprocess verifiers not exercised in CI

- **Location:** `crates/aggregation/src/verifiers/groth16.rs`, `plonk.rs`, `halo2.rs`
- **Finding:** All three aggregation verifiers shell out to external binaries (`snarkjs verify` for Groth16/Plonk, `cargo run --bin halo2-verify` for Halo2). Real-proof tests are either:
  - Ignored (`test_real_groth16_verification_ignored`, `test_real_halo2_verification_ignored`)
  - Absent entirely (Plonk subprocess verifier has zero tests — not even an ignored one)
- **Impact:** The aggregation layer's ability to reject invalid proofs is untested. The `ProofAggregator` test suite confirms structural logic (quorum counting, deduplication, proof-length validation) but not cryptographic verification.
- **Category: Critical path**

### Required — should close before re-audit

#### Gap 4 — ProvingService Groth16 and Plonk paths untested

- **Location:** `crates/worldline-api/src/service.rs`, `e2e_encoding.rs`
- **Finding:** The `ProvingService::prove()` e2e tests (8 tests in `e2e_encoding.rs`) only request `system_id=3` (Halo2). The Groth16 and Plonk paths both depend on `SubprocessArtifacts` (snarkjs WASM + zkey), which are never provided in the test configuration. The service's partial-success logic, health tracking, and `encode_proof` for Groth16 and Plonk are exercised only through unit mocks.
- **Impact:** The API surface for Groth16 and Plonk has no end-to-end path test. Encoding bugs or API type mismatches would not be caught.
- **Category: Required**

#### Gap 5 — Circuit tests artifact-gated, absent from CI

- **Location:** `circuits/test/worldline_stf.test.ts`, `worldline_stf_plonk.test.js`
- **Finding:** Both circuit test suites check for compiled artifacts (`.wasm`, `.zkey`) at startup and call `describe.skip` if absent. The Groth16 circuit suite (8 tests) skips entirely; the Plonk suite (12 tests) skips conformance and on-chain E2E tests. These are run via `npx mocha`, not `npx hardhat test`, and are not part of CI.
- **Impact:** Constraint changes in the Circom circuits are not caught by CI. The critical `batchSize ∈ [1,1024]` range constraint — already identified as an incomplete bit-decomposition in `docs/feature-completeness-gap-analysis.md` — cannot be regression-tested without artifacts.
- **Category: Required**

#### Gap 6 — BlobVerifier E2E structurally deferred

- **Location:** `contracts/src/blob/BlobVerifier.sol`, `BlobKzgVerifier.sol`; `test/BlobVerifier.test.ts`
- **Finding:** The local Hardhat EVM returns `bytes32(0)` for `blobhash(0)` (pre-Cancun behavior). The `BlobVerifier.test.ts` tests only the error paths: `NoBlobAtIndex` and `InvalidVersionedHash`. `BlobKzgVerifier` has no tests in either Hardhat or Forge. Full round-trip verification requires a Cancun-enabled environment.
- **Impact:** The blob submission path is untested at the on-chain level. Integrators using EIP-4844 have no test evidence of correctness.
- **Category: Required**

#### Gap 7 — Driver proof submission subcommand not tested

- **Location:** `crates/worldline-driver/` (binary + library crate)
- **Finding:** The `cli.rs` integration tests cover `export`, `check`, `sync`, and `--help`. There is no test for a `submit` or `prove` subcommand (the actual proof submission path through the driver to an on-chain contract). The driver library's `recursion.rs` (9 tests), `blob.rs` (5 tests), and `aggregator.rs` (2 tests) are unit-tested, but the end-to-end driver → RPC → contract call path is absent.
- **Category: Required**

### Enhancement — useful before external integrators or wider adoption

#### Gap 8 — Multi-proof-system quorum at single-window level

- **Location:** `test/integration/multiprover-quorum.test.ts`, `WorldlineFinalizer.sol`
- **Finding:** WorldlineFinalizer advances `nextWindowIndex` on each accepted proof (one proof per window). The multi-prover quorum demo in `multiprover-quorum.test.ts` submits sequential windows from different proof systems. There is no test where multiple provers submit proofs for the same window and quorum acceptance is enforced at the window level — the architecture does not yet expose this as a contract-level primitive, and there is no test that verifies the expected behavior when it is.
- **Category: Enhancement**

#### Gap 9 — Registry → Finalizer domain binding not tested end-to-end

- **Location:** `WorldlineOutputsRegistry.sol`, `WorldlineFinalizer.sol`
- **Finding:** `WorldlineOutputsRegistry` and `WorldlineFinalizer` are tested independently. No integration test validates the flow: schedule a domain key in `WorldlineOutputsRegistry` → activate after timelock → submit a proof with that `programVKey`/`policyHash` through `WorldlineFinalizer` and confirm acceptance.
- **Category: Enhancement**

#### Gap 10 — Permissioned submission path under-covered

- **Location:** `WorldlineFinalizer.sol`
- **Finding:** Most Hardhat integration tests call `enablePermissionless(finalizer)` as part of setup. The permissioned path (non-permissionless, prover whitelist enforcement) is tested in some top-level Hardhat files but not systematically across the integration suite.
- **Category: Enhancement**

#### Gap 11 — UUPS implementation contract storage gap not verified

- **Location:** `contracts/src/` (all four UUPS contracts)
- **Finding:** Upgrade tests verify that V1 state is preserved after upgrading to V2. They do not test storage layout compatibility directly — no slot-level assertion confirms that the `__gap` reservations in V1 and the new storage slots in V2 do not collide. Storage collision would be a silent failure.
- **Category: Enhancement**

---

## Summary by Priority

| #   | Gap                                                                                                                                  | Category                       |
| --- | ------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------ |
| 1   | Poseidon cross-system conformance unresolved (PSE sponge ≠ circomlib compression)                                                    | **Critical path**              |
| 2   | ~~Real verifier pairing untested end-to-end~~ — **CLOSED** (all 3 systems have real proof round-trip tests, +24 Forge / +11 Hardhat) | ~~Critical path~~ **Resolved** |
| 3   | Subprocess verifiers not exercised in CI (Groth16/Halo2 ignored; Plonk absent)                                                       | **Critical path**              |
| 4   | ProvingService Groth16 and Plonk paths untested (snarkjs dependency, no e2e)                                                         | Required                       |
| 5   | Circuit tests artifact-gated, not in CI (Circom Groth16 + Plonk suites)                                                              | Required                       |
| 6   | BlobVerifier E2E structurally deferred (no Cancun-enabled test environment)                                                          | Required                       |
| 7   | Driver proof submission subcommand not tested                                                                                        | Required                       |
| 8   | Multi-proof-system quorum at single-window level not tested                                                                          | Enhancement                    |
| 9   | Registry → Finalizer domain binding flow not tested end-to-end                                                                       | Enhancement                    |
| 10  | Permissioned submission path under-covered in integration suite                                                                      | Enhancement                    |
| 11  | UUPS storage gap not verified at slot level                                                                                          | Enhancement                    |

---

## What Is Well-Covered

The following areas have strong test depth and are not gaps:

- **State machine invariants** in `WorldlineFinalizer`: domain, contiguity, staleness, STF binding, window range, genesis block — fuzz-tested and property-tested
- **Proof format decoding** in all three adapters: length checks, public signal extraction, proof envelope structure
- **Access control and timelocking** across all contracts: two-step ownership, minimum delay floors, adapter/router/facade timelocking
- **UUPS upgrade mechanics**: V1→V2 state preservation, double-init prevention, implementation lock (`_disableInitializers`)
- **ProofRouter routing logic**: registration, deduplication, mismatched ID rejection, adapter active during removal window
- **Registry operations**: circuit/driver/plugin registration, fuzz-tested roundtrips
- **Aggregation structural logic**: quorum counting, proof deduplication, strategy variants, error conditions
- **Halo2 circuit constraints**: MockProver tests cover all constraint boundaries; real KZG proof generation and verification tested natively in Rust
- **Poseidon internal consistency**: aggregator ↔ Halo2 circuit confirmed matching; cross-system Rust tests pass
- **Calldata encoding** for all three proof systems: verified structurally via `prover-api-e2e.test.ts` and `e2e_encoding.rs`
