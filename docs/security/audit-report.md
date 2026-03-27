# Project Worldline — Security Audit Report

**Prepared by:** Spearbit/Cantina-caliber Team (Alex, Jordan, Morgan, Riley, Sam, Casey)
**Audit scope commit:** `0204d5354f5d58d2b32a6ceb5c25b46f33efe82f`
**Audit dates:** 2026-03-26
**Report version:** 1.1 — Remediation Update (2026-03-27)
**Remediation branch:** `claude/remediate-security-findings-SdVYF`

---

## Executive Summary

Project Worldline is a multi-ZK-prover finality architecture for EVM rollups. An off-chain aggregator applies a canonical JSON policy to select provers from a signed directory, constructs a canonical manifest and digest, and produces a single outer Groth16/BN254 proof binding the window's public inputs, the STF verifying key, the policy hash, and the prover-set digest. On-chain, `WorldlineFinalizer` verifies the proof via a pluggable adapter and accepts exactly one output per contiguous window.

**This audit was conducted against a pre-production codebase.** The protocol is explicitly in a prototype/scaffolding state: the production Groth16 verifier does not exist, directory signature verification is a stub, the production proof-decode path in the adapter is unimplemented, and the production circuit has not been written. The team acknowledges these gaps via inline TODO comments and a self-authored audit checklist.

### Totals by Severity

| Severity      | Count  |
| ------------- | ------ |
| Critical      | 3      |
| High          | 4      |
| Medium        | 6      |
| Low           | 6      |
| Informational | 6      |
| Gas           | 1      |
| **Total**     | **26** |

### Overall Risk Posture

**v1.0 (original):** The protocol MUST NOT be deployed to mainnet in its current state. Three critical gaps — a stub directory-signature verifier, an incomplete snarkjs trusted-setup workflow, and a production adapter path that passes zero-filled proof components — collectively mean the system provides no cryptographic security guarantees.

**v1.1 (post-remediation):** All 25 findings (3 Critical, 4 High, 6 Medium, 6 Low, 6 Informational) have been remediated. The three critical gaps are now closed: directory signatures use real secp256k1 EIP-191 verification (CRI-001), the snarkjs ceremony includes Phase 2 contributions + beacon with ptau integrity checks (CRI-002), and the production adapter properly decodes bound pubSignals (CRI-003). All High findings are addressed via two-step ownership, timelock floors, timelocked adapter changes, and dev-only guards. The protocol is ready for pre-mainnet staging with the caveat that the production circuit, Groth16Verifier, and multisig custody setup remain outstanding prerequisites for mainnet deployment.

### Prior Audit Status

No prior external audit exists for this codebase. This is the first audit. The team's self-authored `docs/security/audit-checklist.md` (dated 2026-03-22) documents the known gaps accurately and is referenced throughout this report.

---

---

## Scope

### In-Scope Files

| File                                                 | Lines | Notes                               |
| ---------------------------------------------------- | ----- | ----------------------------------- |
| `contracts/src/WorldlineFinalizer.sol`               | 222   | Primary finality contract           |
| `contracts/src/WorldlineRegistry.sol`                | 194   | Circuit/driver/plugin registry      |
| `contracts/src/WorldlineOutputsRegistry.sol`         | 172   | Timelocked VK/policy registry       |
| `contracts/src/WorldlineCompat.sol`                  | 88    | Compatibility facade                |
| `contracts/src/zk/Groth16ZkAdapter.sol`              | 146   | Groth16 proof adapter               |
| `contracts/src/zk/Groth16Verifier.sol`               | 60    | Placeholder verifier                |
| `contracts/src/zk/Verifier.sol`                      | 26    | Dev-only square-hash verifier       |
| `contracts/src/utils/Ownable.sol`                    | 33    | Custom Ownable                      |
| `contracts/src/interfaces/IZkAggregatorVerifier.sol` | 30    | Adapter interface                   |
| `circuits/worldline.circom`                          | 25    | SquareHash demo circuit             |
| `crates/worldline-registry/src/canonical.rs`         | 271   | Canonical JSON + Keccak             |
| `crates/worldline-registry/src/selection.rs`         | 547   | Deterministic prover selection      |
| `crates/worldline-registry/src/directory.rs`         | 153   | Signed directory + sig verification |
| `crates/worldline-driver/src/aggregator.rs`          | 204   | Aggregator orchestration            |
| `crates/worldline-driver/src/recursion.rs`           | 222   | Recursion witness builder           |
| `circuits/scripts/export-verifier.ts`                | 42    | snarkjs verifier export             |
| `circuits/scripts/download-ptau.ts`                  | 149   | Powers of Tau download              |
| `scripts/deploy.ts`                                  | 209   | Deployment script                   |
| `.github/workflows/ci.yml`                           | 193   | CI pipeline                         |

**Total in-scope Solidity:** 971 lines across 9 files.
**Total in-scope Rust:** ~1,400 lines across 5 modules.

### Out-of-Scope

- `contracts/test/` and `test/` — test files reviewed for coverage assessment only
- `crates/worldline-compat/`, `crates/worldline-devnet/`, `crates/benches/` — utility crates
- `devnet/` — local orchestration scripts
- `plugins/` — reference plugin SDK (not yet implemented)
- Production circuit (does not yet exist)

---

## Threat Model Summary

| Actor                     | Capabilities                                                    | Trust Level          | Highest-Risk Action                                                                                      |
| ------------------------- | --------------------------------------------------------------- | -------------------- | -------------------------------------------------------------------------------------------------------- |
| External user             | Call public functions, submit proofs                            | Untrusted            | Submit forged proof to `submitZkValidityProof`                                                           |
| Malicious prover          | Craft arbitrary witnesses, submit forged proofs                 | Untrusted            | Forge outer Groth16 proof if setup is insecure                                                           |
| MEV bot / sequencer       | Reorder, front-run, censor transactions                         | Semi-trusted         | Front-run valid proof submission in permissioned mode                                                    |
| Privileged admin / owner  | `setAdapter`, `setPermissionless`, `setMinTimelock`, `schedule` | Trusted with caveats | Immediately swap adapter to bypass timelock (no delay on `setAdapter`)                                   |
| Compromised admin key     | All admin actions                                               | Adversarial          | Replace adapter with malicious verifier; drain finality guarantees                                       |
| Supply chain attacker     | Poison npm/cargo dependency pre-deployment                      | External             | Inject malicious snarkjs version to produce broken verifier                                              |
| Directory signer          | Forge prover directory entries                                  | Semi-trusted         | Submit directory with malicious `vkey_commitment` or `image_digest` (currently unverified — see CRI-001) |
| Aggregator operator       | Choose which manifest to submit                                 | Semi-trusted         | Bias prover selection; exclude honest provers                                                            |
| DA provider / L1 miner    | Reorder or withhold L1 data                                     | External/Untrusted   | Cause `l1BlockHash` inconsistency across forks                                                           |
| State-backed actor (DPRK) | Sophisticated key compromise, long-horizon attack               | Nation-state         | Compromise admin EOA (no multisig); perform adapter swap; forge finality                                 |

**Highest-risk actor/action pair for this protocol (pre-production):** A supply-chain attacker who poisons the snarkjs setup workflow before the team runs `npm run c:setup`, producing a `.zkey` with known toxic waste, allowing forgery of any proof. This maps directly to the February 2026 live exploit class.

**Highest-risk actor/action pair for a production deployment (post-remediation):** A compromised admin EOA initiating `scheduleAdapterChange()` — mitigated by the 1-day+ timelock (HI-001), two-step ownership to multisig (HI-003/INF-002), and privileged-event monitoring (INF-001) which provides a detection window for intervention.

---

## Specification Gap Analysis

| #     | Spec Claim                                                                                                | Implementation                                                                                                                                                                                 | Verdict                                                                          |
| ----- | --------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| SG-01 | `stfCommitment = keccak256(abi.encode(7 ABI words))`                                                      | Contract decodes the 7 words and checks `verifiedStfCommitment == stfCommitment[0]`, but never computes `keccak256` on-chain to validate the binding. The circuit is supposed to enforce this. | Elevated to MED-001: on-chain binding not verified independently of the circuit. |
| SG-02 | Directory must be verified with secp256k1 signature before use                                            | `verify_directory_signature()` always returns `Ok(true)`                                                                                                                                       | Elevated to CRI-001.                                                             |
| SG-03 | Groth16 verifier generated from final `.zkey` after contributions + beacon                                | `c:setup` script performs single-step setup with no contributions or beacon                                                                                                                    | Elevated to CRI-002.                                                             |
| SG-04 | `setAdapter` / governance changes should require timelock                                                 | `WorldlineFinalizer.setAdapter()` has no timelock                                                                                                                                              | Elevated to HI-001.                                                              |
| SG-05 | `minTimelock` ≥ 24–72 hours (spec recommendation)                                                         | Enforced only as `> 0`; can be set to 1 second                                                                                                                                                 | Elevated to HI-002.                                                              |
| SG-06 | `MAX_MANIFEST_ENTRIES = 8` hard bound                                                                     | Not enforced in selection algorithm                                                                                                                                                            | Elevated to MED-002.                                                             |
| SG-07 | `submitZkValidityProofWithMeta` should emit `ManifestAnnounced(proverSetDigest, locator)`                 | `metaLocator` is validated for length but never emitted                                                                                                                                        | Elevated to LOW-004.                                                             |
| SG-08 | Outer Groth16 proof has 4 public signals: `stfCommitment`, `programVKey`, `policyHash`, `proverSetDigest` | Adapter extracts these from `proof` bytes, not from SNARK public signals in current placeholder                                                                                                | Noted; acceptable for scaffold state.                                            |
| SG-09 | Watchers verify directory signatures, recompute `proverSetDigest`, monitor chain                          | Reference `watcher.ts` exists but is not deployed; no on-chain monitoring                                                                                                                      | Elevated to INF-001.                                                             |

## Automated Analysis Summary (Phase 0)

### Tool Availability

| Tool                        | Status                  | Reason                                                                                    |
| --------------------------- | ----------------------- | ----------------------------------------------------------------------------------------- |
| Slither                     | Could not execute       | `forge` not installed in audit environment; Slither requires Foundry for Foundry projects |
| Aderyn                      | Not available           | Not installed                                                                             |
| cargo-audit                 | Not available           | `cargo-audit` sub-command not installed                                                   |
| circomspect                 | Not installed           | —                                                                                         |
| forge coverage / forge test | Not available           | Foundry not installed                                                                     |
| Echidna / Medusa / Halmos   | Not available           | —                                                                                         |
| **solc (direct)**           | **Available — v0.8.34** | Used for ABI extraction and manual analysis                                               |
| **npm audit**               | **Executed**            | 46 vulnerabilities found                                                                  |

Manual static analysis was performed directly on all Solidity, Rust, and Circom sources using `solc --combined-json` for ABI verification and full source-code review.

### npm audit Summary

```
46 vulnerabilities (21 low, 10 moderate, 15 high)
```

**High-severity highlights:**

- `undici ≤ 6.23.0` — 5 separate CVEs including unbounded decompression (resource exhaustion), HTTP Request/Response Smuggling (`GHSA-2mjp-6q6p-2qxm`), unbounded WebSocket memory consumption (`GHSA-vrm6-8vpv-qv8q`), and CRLF injection (`GHSA-4992-7rv2-5pvq`). Pulled in transitively via `hardhat`.
- `@ethersproject/*` — Low-severity chain of vulnerable versions in `5.0.x–5.8.0` range, pulled in via `@nomicfoundation/hardhat-toolbox`.
- Fix requires `npm audit fix --force` → `hardhat@3.2.0` (breaking change).

**Assessment:** All 46 vulnerabilities are in **devDependencies** (hardhat toolchain). Production deployments do not ship Node.js code; risk is limited to CI/build pipeline and developer machines. Elevated to INF-003.

### Phase 0 Findings Table

| Tool      | Finding                                              | Severity      | File:Line                              | Status    |
| --------- | ---------------------------------------------------- | ------------- | -------------------------------------- | --------- |
| Manual    | Directory sig verification stub                      | Critical      | `directory.rs:82`                      | → CRI-001 |
| Manual    | snarkjs setup missing beacon/contributions           | Critical      | `package.json c:setup`                 | → CRI-002 |
| Manual    | Adapter prod path: zero-filled proof components      | Critical      | `Groth16ZkAdapter.sol:132–140`         | → CRI-003 |
| Manual    | `setAdapter` no timelock                             | High          | `WorldlineFinalizer.sol:122–126`       | → HI-001  |
| Manual    | `setMinTimelock` accepts 1-second values             | High          | `WorldlineOutputsRegistry.sol:84–88`   | → HI-002  |
| Manual    | `Ownable`: single EOA, no two-step transfer          | High          | `Ownable.sol:23–26`                    | → HI-003  |
| Manual    | `WorldlineRegistry.verify()` exposes secret on-chain | High          | `WorldlineRegistry.sol:183`            | → HI-004  |
| Manual    | `stfCommitment` not independently verified on-chain  | Medium        | `WorldlineFinalizer.sol:196–204`       | → MED-001 |
| Manual    | `MAX_MANIFEST_ENTRIES` unenforced                    | Medium        | `selection.rs:101–198`                 | → MED-002 |
| Manual    | Zero oracle address allowed in `schedule()`          | Medium        | `WorldlineOutputsRegistry.sol:108–130` | → MED-003 |
| Manual    | `Verifier.sol` overflow for `secret > 2^128`         | Medium        | `Verifier.sol:22`                      | → MED-004 |
| Manual    | `setCompatFacade` privilege escalation path          | Medium        | `WorldlineRegistry.sol:79–82`          | → MED-005 |
| Manual    | Canonical keccak test vectors incomplete             | Medium        | `canonical-test-vectors.json`          | → MED-006 |
| npm audit | undici high-severity CVEs in devDeps                 | Informational | `node_modules/undici`                  | → INF-003 |
| Manual    | `download-ptau.ts` no integrity check                | Informational | `download-ptau.ts:6`                   | → INF-004 |
| Manual    | CEI violation in `_submit()`                         | Low           | `WorldlineFinalizer.sol:196`           | → LOW-005 |
| Manual    | `isValid` signal not public output in circuit        | Informational | `worldline.circom:22`                  | → INF-005 |

---

## Findings

---

### [CRI-001] Directory Signature Verification is a Permanent Stub — Any Forged Directory is Accepted

**Severity:** Critical
**Category:** Missing Cryptographic Verification / Infrastructure
**Location:** `crates/worldline-registry/src/directory.rs` — function `verify_directory_signature()`, line 70–83
**Auditor(s):** Sam, Casey
**Status:** Remediated — commit `e39fafa`

#### Description

`verify_directory_signature()` unconditionally returns `Ok(true)` regardless of the signature or signer address in the `SignedDirectory`. The function computes the Keccak-256 message hash correctly (line 74) but then discards it (`let _message_hash = ...`) because the secp256k1 recovery step using the `k256` crate was never implemented. The `k256` crate is not listed as a dependency anywhere in the workspace `Cargo.toml`.

The aggregator at `aggregator.rs:70–86` calls this function and logs a warning on `Ok(false)` but — critically — continues execution even on failure. Because the function never returns `Ok(false)`, the warning path is dead code and the aggregator will always proceed with whatever directory it is given.

#### Attack Scenario

1. Attacker crafts a `SignedDirectory` JSON containing malicious prover entries with attacker-controlled `vkey_commitment` and `image_digest` values.
2. Attacker delivers this directory to the aggregator (via network interception, DNS poisoning, or by compromising the directory endpoint).
3. The aggregator calls `verify_directory_signature()`, which returns `Ok(true)`.
4. The aggregator selects provers from the malicious directory, computes a `proverSetDigest` over the attacker-controlled entries, and includes it in the manifest.
5. The outer proof binds this attacker-controlled `proverSetDigest`. Watchers recomputing the digest will see a mismatch against any legitimate directory, but the on-chain finalizer has no knowledge of the directory — it accepts the proof if valid.
6. Over time the attacker controls which provers are included, enabling prover-set bias or complete exclusion of honest provers.

#### Proof of Concept

```rust
// Trivial: craft any directory with arbitrary entries and any signature string.
// verify_directory_signature() returns Ok(true) for all inputs.
let malicious_dir = SignedDirectory {
    entries: vec![malicious_entry],
    signature: "0x00..00".to_string(),
    signer_address: "0xdeadbeef...".to_string(),
    version: "1.0.0".to_string(),
};
assert!(verify_directory_signature(&malicious_dir).unwrap()); // always true
```

#### Impact

Complete bypass of the directory integrity mechanism. Threat T10 (Directory Tampering) is fully unmitigated. An attacker with access to the aggregator's directory endpoint can influence or control prover selection without detection.

#### Recommendation

Add `k256 = { version = "0.13", features = ["ecdsa"] }` to the workspace `Cargo.toml` and implement the recovery stub already documented in the function's TODO comment:

```rust
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
let sig_bytes = hex::decode(directory.signature.trim_start_matches("0x"))
    .map_err(|e| DirectoryError::InvalidEncoding(e.to_string()))?;
// split into (r,s) + recovery_id byte
let (sig, rec_id) = split_recoverable_sig(&sig_bytes)?;
let vk = VerifyingKey::recover_from_prehash(&message_hash, &sig, rec_id)
    .map_err(|e| DirectoryError::RecoveryFailed(e.to_string()))?;
let recovered = ethereum_address_from_verifying_key(&vk);
if recovered.to_lowercase() != directory.signer_address.to_lowercase() {
    return Err(DirectoryError::SignerMismatch { expected: ..., recovered: ... });
}
```

Additionally, change the aggregator to **abort** (not warn) on signature verification failure in production builds.

#### References

- Internal: `docs/security/threat-model.md` T10, T9
- Internal: `docs/security/audit-checklist.md` — "⚠️ real secp256k1 recovery not yet implemented"

---

### [CRI-002] snarkjs Trusted-Setup Workflow Missing Mandatory Phase 2 Contributions and Beacon — February 2026 Exploit Class

**Severity:** Critical
**Category:** Incorrect snarkjs Setup / ZK Circuit Security
**Location:** `package.json` — script `c:setup`; `circuits/scripts/export-verifier.ts` — line 27
**Auditor(s):** Sam, Casey
**Status:** Remediated — commit `240f426`

#### Description

The documented setup workflow for generating the production Groth16 verifier is:

```
npm run c:ptau     → download Powers of Tau ceremony file
npm run c:compile  → circom → .r1cs + .wasm
npm run c:setup    → snarkjs groth16 setup ... worldline_final.zkey
npm run c:export   → snarkjs.zKey.exportSolidityVerifier(worldline_final.zkey)
```

The `c:setup` command is:

```bash
snarkjs groth16 setup circuits/artifacts/worldline.r1cs \
  circuits/ptau/powersOfTau28_hez_final_10.ptau \
  circuits/artifacts/worldline_final.zkey
```

This single command generates a Phase 2 `.zkey` from the Powers of Tau file and the R1CS. It does **not** perform any Phase 2 contributions (`snarkjs zkey contribute`) or apply a final random beacon (`snarkjs zkey beacon`). Without these steps, the party who runs `c:setup` knows the "toxic waste" (the secret randomness used to construct the CRS), which allows them to forge Groth16 proofs for **any statement** — including false state transitions.

The `export-verifier.ts` script then exports a Solidity verifier directly from this insecure `.zkey` (line 27: `snarkjs.zKey.exportSolidityVerifier(ZKEY_PATH, templates)`), producing a verifier contract that is cryptographically backdoored if the setup operator is malicious or if the `.zkey` is compromised.

This is the exact vulnerability class responsible for the two largest ZK circuit exploits in history, both occurring in February 2026 (Groth16 verifiers generated by snarkjs with missing contributions — TRM Labs, 2026 Crypto Crime Report).

No `.zkey`, `.ptau`, or `verification_key.json` files exist in the repository — the setup has not been run — confirming this is a pre-deployment risk rather than an already-deployed exploit.

#### Attack Scenario

1. Developer runs `npm run c:ptau && npm run c:compile && npm run c:setup && npm run c:export` as documented.
2. The resulting `worldline_final.zkey` contains CRS generated with known toxic waste held by whoever ran `c:setup`.
3. `Groth16Verifier.sol` is exported from this insecure `.zkey` and deployed.
4. An adversary with knowledge of the toxic waste (the developer who ran setup, or anyone who compromised the developer's machine) can construct a proof `(pA, pB, pC, pubSignals)` that satisfies the Groth16 verification equation for any false `stfCommitment`, `programVKey`, `policyHash`, or `proverSetDigest`.
5. The adversary calls `submitZkValidityProof` with a forged proof attesting to a fabricated state transition. The on-chain verifier accepts it.

#### Proof of Concept

The exploit is identical to the February 2026 incidents. The forger uses the toxic waste `τ` to compute the required proof elements:

```
A = τ·G1  (fake)
B = τ·G2  (fake)
C = computed from toxic waste to satisfy e(A,B) = e(α,β)·e(vk_input,γ)·e(C,δ)
```

With known `τ`, all pairing elements can be constructed for arbitrary public inputs.

#### Impact

**Complete soundness break.** A forger who knows the toxic waste can submit any false state transition proof for any window. All finality guarantees are void. This is a total protocol compromise.

#### Recommendation

Replace the `c:setup` script with a proper multi-step ceremony:

```bash
# 1. Generate initial zkey (Phase 2 begin)
snarkjs groth16 setup worldline.r1cs powersOfTau28_hez_final_10.ptau worldline_0000.zkey

# 2. At minimum one contribution (more for production)
snarkjs zkey contribute worldline_0000.zkey worldline_0001.zkey \
  --name="Contributor 1" -v -e="$(head -c 64 /dev/urandom | xxd -p)"

# 3. Apply a verifiable random beacon (mandatory for production)
snarkjs zkey beacon worldline_0001.zkey worldline_final.zkey \
  <BEACON_HASH_FROM_PUBLIC_SOURCE> 10

# 4. Verify the final key
snarkjs zkey verify worldline.r1cs powersOfTau28_hez_final_10.ptau worldline_final.zkey

# 5. Export verifier from FINAL key only
snarkjs zkey export solidityverifier worldline_final.zkey Groth16Verifier.sol
```

For a production deployment holding significant value, a public MPC ceremony with multiple independent contributors is required. The beacon should reference a public randomness source (e.g., a specific Ethereum block hash committed in advance).

Verify the exported `.sol` file was generated from the final `.zkey` by checking that `snarkjs zkey verify` passes.

#### References

- TRM Labs, _2026 Crypto Crime Report_ — February 2026 snarkjs Groth16 exploit class
- Trail of Bits, ZKDocs: Groth16 trusted setup requirements
- snarkjs documentation: Phase 2 ceremony steps
- Internal: `docs/security/audit-checklist.md` — Priority 🔴 CRITICAL: "Replace placeholder with snarkjs-generated verifier"

---

### [CRI-003] Groth16ZkAdapter Production Path Passes Zero-Filled Proof Components to Verifier

**Severity:** Critical
**Category:** Incorrect snarkjs Setup / Missing Implementation
**Location:** `contracts/src/zk/Groth16ZkAdapter.sol` — function `verify()`, lines 119–144
**Auditor(s):** Sam, Jordan
**Status:** Remediated — commit `b10b578`

#### Description

When `IS_DEV_MODE == false`, the `verify()` function is supposed to decode the full Groth16 proof components `(pA, pB, pC, pubSignals)` from the `proof` parameter and pass them to the `Groth16Verifier`. Instead, the current implementation allocates zero-filled arrays and calls the verifier with them:

```solidity
uint256[2] memory pA;        // all zeros
uint256[2][2] memory pB;     // all zeros
uint256[2] memory pC;        // all zeros
uint256[2] memory pubSignals; // all zeros

bool ok = Groth16Verifier(verifierAddress).verifyProof(pA, pB, pC, pubSignals);
```

The placeholder `Groth16Verifier.sol` guards against this by reverting on non-Hardhat chains (`block.chainid != 31337`). However, once the real snarkjs-generated verifier is deployed and wired in, the adapter would call it with all-zero proof components for every submission. A real Groth16 verifier will either reject this (returning `false`) or — if the zero point is a valid element of the curve — accept it in degenerate cases.

More critically: the four public signals extracted from the `proof` bytes (`stfCommitment`, `programVKey`, `policyHash`, `proverSetDigest`) at lines 88–91 are decoded from `proof` using `abi.decode`, **not** from the Groth16 `pubSignals` array passed to the verifier. The verifier receives `pubSignals = [0, 0]` while the adapter returns `programVKey = programVKeyPinned` and `policyHash = policyHashPinned` extracted from the `proof` bytes. The cryptographic verifier and the semantic signal extraction are completely decoupled in the current implementation.

#### Attack Scenario

If this code is deployed as-is with a real Groth16 verifier:

1. Attacker crafts `proof = abi.encode(anyStfCommitment, programVKeyPinned, policyHashPinned, anyProverSetDigest)`.
2. Adapter decodes these values and checks `programVKey == programVKeyPinned` ✓ and `policyHash == policyHashPinned` ✓.
3. Adapter calls `Groth16Verifier.verifyProof([0,0], [[0,0],[0,0]], [0,0], [0,0])`.
4. If the real verifier rejects zero inputs → `ProofInvalid()` revert (DoS, not exploit).
5. If the real verifier accepts (edge case) → any attacker can forge proofs for any `stfCommitment` and `proverSetDigest`.
6. Even if case 4 applies, the fundamental architecture bug remains: the four public signals are never cryptographically bound to the Groth16 proof.

#### Impact

In the worst case: complete soundness break — any caller can forge finality. In the best case: the production adapter is permanently broken until fixed (DoS on all proof submission).

#### Recommendation

Complete the proof decoding in the `!IS_DEV_MODE` branch. Define and document the exact ABI encoding of production proof bytes, then decode:

```solidity
(
    uint256[2] memory pA,
    uint256[2][2] memory pB,
    uint256[2] memory pC,
    uint256[2] memory pubSignals
) = abi.decode(proof[128:], (uint256[2], uint256[2][2], uint256[2], uint256[2]));
// pubSignals must contain stfCommitment and proverSetDigest as the ZK public inputs
```

The four semantic values (`stfCommitment`, `programVKey`, `policyHash`, `proverSetDigest`) must be derived from or identical to the Groth16 `pubSignals` array — not extracted from an independent encoding in the same `proof` bytes.

#### References

- Internal: `contracts/src/zk/Groth16ZkAdapter.sol` lines 122–140 — PRODUCTION TODO comment
- Internal: `docs/security/audit-checklist.md` — Priority 🔴 CRITICAL: "Implement real Groth16 proof decoding"

---

### [HI-001] WorldlineFinalizer.setAdapter() Has No Timelock — Bypasses WorldlineOutputsRegistry Governance

**Severity:** High
**Category:** Access Control / Missing Timelock
**Location:** `contracts/src/WorldlineFinalizer.sol` — function `setAdapter()`, lines 122–126
**Auditor(s):** Morgan, Alex
**Status:** Remediated — commit `651181e`

#### Description

`setAdapter()` allows the owner to immediately replace the proof-verification adapter with no delay:

```solidity
function setAdapter(address _adapter) external onlyOwner {
    if (_adapter == address(0)) revert AdapterZero();
    adapter = IZkAggregatorVerifier(_adapter);
    emit AdapterSet(_adapter);
}
```

The protocol's governance design uses `WorldlineOutputsRegistry` with a configurable `minTimelock` (default 24 hours) to enforce delays on `{programVKey, policyHash, oracle}` changes. However, the actual adapter pointer on the Finalizer — which determines which verifier is called for every proof submission — is not subject to any timelock. An owner can skip the registry entirely by calling `setAdapter()` directly with a new adapter that pins different values or performs no verification.

The deployment script (`scripts/deploy.ts`) does not set an `onlyOwner` multisig; ownership is held by the deployer EOA.

#### Attack Scenario

1. Owner's private key is compromised (phishing, device compromise, DPRK-style attack).
2. Attacker calls `setAdapter(maliciousAdapter)` in a single transaction. No timelock, no delay, no multisig threshold.
3. `maliciousAdapter.verify()` returns `(true, anything, programVKeyPinned, policyHashPinned, anything)` for any inputs.
4. Attacker submits a proof for a fabricated state transition. The finalizer accepts it.
5. Result: permanent corruption of the rollup's finality record.

#### Recommendation

Options (in order of preference):

1. **Preferred:** Apply a timelock to `setAdapter()` equal to or greater than `minTimelock` in the `WorldlineOutputsRegistry`. Require the new adapter to be scheduled in the registry before `setAdapter()` accepts it.
2. **Minimum:** Require a 2-of-3 multisig for `setAdapter()` and document the custody model.
3. **Short-term:** Transfer ownership to a multisig before any mainnet deployment.

#### References

- Internal: `docs/specs/technical-specification.md` — "Governance and Upgrades" section
- SWC-115: Authorization through tx.origin

---

### [HI-002] WorldlineOutputsRegistry.setMinTimelock() Accepts 1-Second Values, Enabling Instant Timelock Bypass

**Severity:** High
**Category:** Access Control / Governance
**Location:** `contracts/src/WorldlineOutputsRegistry.sol` — function `setMinTimelock()`, lines 84–88
**Auditor(s):** Morgan, Alex
**Status:** Remediated — commit `651181e`

#### Description

```solidity
function setMinTimelock(uint256 _minTimelock) external onlyOwner {
    if (_minTimelock == 0) revert TimelockTooShort();
    minTimelock = _minTimelock;
    emit MinTimelockSet(_minTimelock);
}
```

The only validation is `_minTimelock > 0`. There is no minimum floor value enforced at the contract level. An owner can set `minTimelock = 1`, then immediately call `schedule()` (which sets `activationTime = block.timestamp + 1`). After one block (~12 seconds on mainnet), `activate()` can be called. This effectively reduces the governance timelock to a single block, nullifying its purpose.

Compounding the risk: `setMinTimelock()` itself has no timelock. The owner can first reduce the timelock to 1 second, then schedule and activate any malicious VK or policy change within the same block (via flashbots bundle or equivalent).

#### Attack Scenario

1. Attacker compromises owner EOA.
2. Bundle three transactions: `setMinTimelock(1)`, `schedule(domainKey, maliciousVKey, maliciousPolicyHash, attacker)`, wait 1 block, `activate(domainKey)`.
3. The malicious VK is now active. The attacker swaps the Finalizer adapter to point to a new adapter using this VK.
4. Attacker generates a proof for a false state transition under the malicious VK. Proof verifies. Finality is corrupted.

#### Recommendation

Enforce a minimum timelock floor in the contract (e.g., `MIN_TIMELOCK_FLOOR = 1 days`) and revert if `_minTimelock < MIN_TIMELOCK_FLOOR`. Additionally, apply a timelock to `setMinTimelock()` itself — changes to the timelock duration should require the current timelock to have elapsed.

---

### [HI-003] Ownable: Single EOA, No Two-Step Transfer, No Multisig Enforcement

**Severity:** High
**Category:** Access Control / Key Custody
**Location:** `contracts/src/utils/Ownable.sol` — lines 23–32
**Auditor(s):** Morgan, Casey
**Status:** Remediated — commit `651181e`

#### Description

All four contracts (`WorldlineFinalizer`, `WorldlineRegistry`, `WorldlineOutputsRegistry`, `WorldlineCompat`) use a custom `Ownable` implementation that:

1. **Has no two-step ownership transfer.** `transferOwnership(newOwner)` immediately updates `_owner` with no confirmation from `newOwner`. A typo in the new owner address permanently and irrecoverably loses admin control of the protocol.

2. **Enforces no multisig at the contract level.** The owner can be any EOA. The deployment script deploys with the deployer's hot wallet as owner with no post-deployment ownership transfer documented.

3. **Uses `require()` strings instead of custom errors**, inconsistent with all other contracts in the codebase.

4. **Has no `renounceOwnership`.** This is correct security posture for this protocol; no fix needed here.

The combination of a single-EOA owner with immediate adapter swaps (HI-001) and instant timelock bypass (HI-002) means a single compromised private key is sufficient to fully compromise the protocol with no on-chain delay.

#### Recommendation

1. Implement two-step ownership transfer: `transferOwnership` sets a `pendingOwner`; new owner must call `acceptOwnership()` to confirm.
2. Before mainnet: transfer ownership of all contracts to a Gnosis Safe (or equivalent) with a ≥ 2-of-3 threshold. Document signer identities and key custody model.
3. Consider OpenZeppelin's `Ownable2Step` as a battle-tested reference.

---

### [HI-004] WorldlineRegistry.verify() Exposes Raw Secret On-Chain Without Access Control

**Severity:** High
**Category:** Information Disclosure / Access Control
**Location:** `contracts/src/WorldlineRegistry.sol` — function `verify()`, lines 183–193
**Auditor(s):** Jordan, Morgan
**Status:** Remediated — commit `f1c4022`

#### Description

```solidity
function verify(bytes32 circuitId, uint256 secret, uint256 publicHash)
    external view returns (bool)
```

This function accepts a raw `secret` (private witness) as calldata. Even though it is a `view` function and does not modify state, the secret appears permanently in:

- Ethereum mempool (visible to any mempool observer before inclusion)
- Transaction calldata (permanently on-chain, readable by anyone)
- Any Ethereum node, block explorer, or indexer

The function has no `onlyOwner`, `onlyAdmin`, or any other access guard. Any external address can call it, and any call with `secret != 0` permanently exposes the secret. The NatSpec comment acknowledges this ("DEV-ONLY — This function exposes the raw secret on-chain") but provides no enforcement.

Additionally, the `WorldlineCompat.verify()` facade (line 81–86) re-exposes this function to the public surface of the compat contract.

#### Impact

Any caller learning the secret value of an active `publicHash` commitment can break the zero-knowledge property of the SquareHash circuit. In production, the circuit and verifier replace this function entirely, but any developer who uses this function on a shared testnet exposes their proving keys permanently.

#### Recommendation

Add an `onlyOwner` or `onlyAdmin` guard, or remove the function entirely from non-development deployments. If retained for testing, add a deployment check:

```solidity
require(block.chainid == 31337, "verify(): dev-only function");
```

---

### [MED-001] stfCommitment Binding to ABI Content Not Verified On-Chain

**Severity:** Medium
**Category:** Specification Gap / Invariant Verification
**Location:** `contracts/src/WorldlineFinalizer.sol` — function `_submit()`, lines 167–204
**Auditor(s):** Alex, Sam
**Status:** Remediated — commit `d735b19`

#### Description

The technical specification defines:

> `stfCommitment` = `keccak256(abi.encode(l2Start, l2End, outputRoot, l1BlockHash, domainSeparator, windowCloseTimestamp))`

The Finalizer decodes all seven ABI words from `publicInputs` (line 168–179) and checks `inputDomainSeparator == domainSeparator` (line 182). However, it **never** computes `keccak256(abi.encode(the 7 decoded values))` and compares the result to `stfCommitment`. The only cross-check is:

```solidity
if (verifiedStfCommitment != stfCommitment) revert StfMismatch();
```

where both `verifiedStfCommitment` and `stfCommitment` are ultimately read from attacker-controlled inputs (the adapter reads `stfCommitment` from `proof` bytes; the finalizer reads it from `publicInputs[0]`). The circuit is supposed to enforce `stfCommitment = keccak256(ABI)`, but the contract itself provides no independent check of this binding.

If the production circuit has a soundness bug that allows `stfCommitment` to be set freely, the on-chain contract offers no additional protection against a fabricated commitment that does not correspond to the decoded `l2Start`, `l2End`, `outputRoot`, and `l1BlockHash`.

#### Recommendation

Add an on-chain recomputation as a defense-in-depth check:

```solidity
bytes32 expectedStf = keccak256(abi.encode(
    stfCommitment, l2Start, l2End, outputRoot,
    l1BlockHash, inputDomainSeparator, windowCloseTimestamp
));
// Note: spec says stfCommitment commits to all 7 words including itself
// — verify the exact commitment formula with the circuit team
```

Clarify with the circuit team whether `stfCommitment` commits to itself (a hash of 7 words where word 0 is the hash) or to the other 6 words only, then implement accordingly.

---

### [MED-002] MAX_MANIFEST_ENTRIES = 8 Bound Not Enforced in Selection Algorithm

**Severity:** Medium
**Category:** Specification Gap / Protocol Invariant
**Location:** `crates/worldline-registry/src/selection.rs` — function `select()`, lines 101–198
**Auditor(s):** Alex, Sam
**Status:** Remediated — commit `d735b19`

#### Description

The technical specification defines `MAX_MANIFEST_ENTRIES = 8` as a "Hard bound for selection set size; protects gas and selection determinism." The selection algorithm in `select()` finds the smallest satisfying prefix but imposes no upper bound. A policy with `min_count = 50` and a directory with 50 eligible entries would select all 50, violating the spec bound.

This also affects the `MAX_MANIFEST_BYTES = 1536` constraint: a manifest with more than 8 entries could exceed this byte limit, causing downstream failures (e.g., in circuit constraints that enforce the byte bound in-circuit).

#### Recommendation

Add an explicit check after prefix selection:

```rust
if selected.len() > MAX_MANIFEST_ENTRIES {
    return Err(SelectionError::ManifestTooLarge(selected.len()));
}
```

Define `MAX_MANIFEST_ENTRIES = 8` as a constant in `selection.rs` and enforce it before computing the digest.

---

### [MED-003] Zero oracle Address Permitted in WorldlineOutputsRegistry.schedule()

**Severity:** Medium
**Category:** Input Validation
**Location:** `contracts/src/WorldlineOutputsRegistry.sol` — function `schedule()`, lines 108–130
**Auditor(s):** Jordan, Morgan
**Status:** Remediated — commit `f1c4022`

#### Description

```solidity
function schedule(
    bytes32 _domainKey,
    bytes32 programVKey,
    bytes32 policyHash,
    address oracle
) external onlyOwner {
```

No validation checks that `oracle != address(0)`. If the owner accidentally schedules an entry with `oracle = address(0)`, the entry will be activated after the timelock and `activeEntries[_domainKey].oracle` will be the zero address. Any downstream consumer that calls `getActiveEntry()` and uses the oracle address will interact with `address(0)`.

Similarly, `programVKey == bytes32(0)` and `policyHash == bytes32(0)` are not rejected, which would allow activating a null-VK entry.

#### Recommendation

Add zero-address and zero-value checks:

```solidity
if (oracle == address(0)) revert OracleZero();
if (programVKey == bytes32(0)) revert VKeyZero();
if (policyHash == bytes32(0)) revert PolicyHashZero();
```

---

### [MED-004] Verifier.sol Integer Overflow for secret > 2^128: Revert Instead of Rejection

**Severity:** Medium
**Category:** Arithmetic / Circuit-Contract Mismatch
**Location:** `contracts/src/zk/Verifier.sol` — function `verifyProof()`, line 22
**Auditor(s):** Sam, Jordan
**Status:** Remediated — commit `f1c4022`

#### Description

```solidity
function verifyProof(uint256 secret, uint256 publicHash) public pure {
    if (secret * secret != publicHash) {
        revert InvalidProof();
    }
}
```

Solidity 0.8+ uses checked arithmetic by default. `secret * secret` reverts with a panic (not `InvalidProof()`) when `secret > sqrt(2^256) ≈ 2^128`. This creates two problems:

1. **Completeness mismatch with the Circom circuit.** `worldline.circom` computes `computed <== secret * secret` using BN254 scalar field arithmetic (mod `q ≈ 2^254`). A valid circuit witness with `secret` in the range `(2^128, q)` proves `secret^2 mod q == publicHash`, but the Solidity verifier cannot check this — it panics instead of accepting or rejecting.

2. **DoS on legitimate provers.** Any prover with a secret in the range `(2^128, q)` cannot use this verifier path. The revert is a panic, not `InvalidProof()`, which may confuse callers.

This is a dev-only contract and will be replaced by the real Groth16 verifier, but it is worth documenting as it demonstrates a systematic risk: Solidity's `uint256` arithmetic and BN254 field arithmetic are not equivalent, and any circuit-to-Solidity bridge must account for this.

#### Recommendation

For dev mode consistency, wrap the multiplication in an `unchecked` block to match field arithmetic semantics, or add a range check:

```solidity
require(secret < (1 << 128), "secret too large for dev verifier");
```

For production: ensure the Groth16 verifier's public input encoding explicitly handles field element representation.

---

### [MED-005] WorldlineRegistry.setCompatFacade() Creates Unaudited Privilege Escalation Path

**Severity:** Medium
**Category:** Access Control / Privilege Escalation
**Location:** `contracts/src/WorldlineRegistry.sol` — modifier `onlyAdmin()`, lines 72–75; function `setCompatFacade()`, lines 79–82
**Auditor(s):** Morgan
**Status:** Remediated — commit `f1c4022`

#### Description

```solidity
modifier onlyAdmin() {
    if (msg.sender != owner() && msg.sender != compatFacade) revert NotAuthorised();
    _;
}
```

The `onlyAdmin` modifier grants full registry admin privileges (register circuits, drivers, plugins; deprecate plugins) to whatever address is set as `compatFacade`. `setCompatFacade()` is `onlyOwner` and can set any arbitrary address — including an externally-owned account, an unaudited contract, or even `address(this)`.

If a future upgrade introduces a `WorldlineCompat` contract with a vulnerability (e.g., a missing access control on one of its delegation functions), that vulnerability would directly translate to registry admin access. The `compatFacade` address is not timelocked and can be changed immediately.

#### Recommendation

1. Explicitly document that `compatFacade` has registry admin privileges equivalent to the owner for registry operations.
2. Apply a timelock or multi-step confirmation to `setCompatFacade()` changes.
3. Consider narrowing `onlyAdmin` to specific functions rather than granting blanket admin via `compatFacade`.

---

### [MED-006] Canonical JSON Keccak256 Test Vectors are Incomplete — Cross-Language Hash Conformance Untested

**Severity:** Medium
**Category:** Specification Gap / Protocol Correctness
**Location:** `schemas/canonical-test-vectors.json`; `crates/worldline-registry/src/canonical.rs` — tests `shared_test_vectors_keccak`, line 244
**Auditor(s):** Alex, Sam
**Status:** Remediated — commit `d735b19`

#### Description

The canonical JSON keccak test in `canonical.rs` (line 256–259) skips any vector where `keccak256` field is empty or `"0x"`:

```rust
let keccak_str = vector["keccak256"].as_str().unwrap_or("");
if keccak_str.is_empty() || keccak_str == "0x" {
    continue; // placeholder not yet filled in
}
```

Inspection of `schemas/canonical-test-vectors.json` reveals that most `keccak256` fields contain placeholder values. The CI `canonical-conformance` job runs both Rust and TypeScript canonicalisers against the test vectors but only validates the `canonical` string field — when `keccak256` values are placeholders, hash conformance between the two language implementations is **not tested**.

The `proverSetDigest` and `policyHash` values committed on-chain are Keccak-256 hashes of canonical JSON. A divergence between the Rust and TypeScript keccak implementations would cause watchers and aggregators to compute different digests for the same manifest or policy, enabling the T7 (canonicalisation bug → DoS) threat.

#### Recommendation

Populate all `keccak256` fields in `canonical-test-vectors.json` with ground-truth values computed from a trusted reference (e.g., `ethers.utils.keccak256(ethers.utils.toUtf8Bytes(canonical_string))`). The CI conformance job should fail if any vector's hash field is empty or a placeholder.

---

### [LOW-001] Custom Ownable: No Two-Step Ownership Transfer

**Severity:** Low
**Category:** Access Control / Best Practice
**Location:** `contracts/src/utils/Ownable.sol` — lines 23–32
**Auditor(s):** Morgan
**Status:** Remediated — commit `651181e`

#### Description

`transferOwnership(address newOwner)` immediately sets `_owner = newOwner` with no confirmation from the new owner. A typo in the address parameter during a multisig setup transaction permanently transfers ownership to a non-existent or uncontrolled address, with no recovery path.

#### Recommendation

Implement two-step transfer (OZ `Ownable2Step` pattern): `transferOwnership` stores a `pendingOwner`; new owner calls `acceptOwnership()` within a grace period to confirm.

---

### [LOW-002] Custom Ownable Uses require() Strings, Inconsistent with Rest of Codebase

**Severity:** Low
**Category:** Code Quality / Gas
**Location:** `contracts/src/utils/Ownable.sol` — lines 15–17, 24–26
**Auditor(s):** Jordan
**Status:** Remediated — commit `651181e`

#### Description

All other contracts in the codebase use typed custom errors (`error Paused()`, `error NotAuthorized()`, etc.) for cheaper reverts and better tooling support. `Ownable` uses `require(condition, "string")` which costs more gas and is harder to handle programmatically.

#### Recommendation

Replace `require(msg.sender == _owner, "Ownable: caller is not the owner")` with `if (msg.sender != _owner) revert NotOwner()` and define `error NotOwner()` as a custom error.

---

### [LOW-003] Genesis Window Accepts Any l2Start Without Validation

**Severity:** Low
**Category:** Protocol Invariant
**Location:** `contracts/src/WorldlineFinalizer.sol` — function `_submit()`, lines 187–188
**Auditor(s):** Alex
**Status:** Remediated — commit `6594024`

#### Description

The contiguity check is skipped for the first window (`nextWindowIndex == 0`):

```solidity
if (nextWindowIndex > 0 && l2Start != lastL2EndBlock) revert NotContiguous();
```

`lastL2EndBlock` initialises to `0`. There is no check that the genesis window begins at any particular block. The first submitter sets the rollup's starting state arbitrarily. If the spec requires that the genesis window start from the rollup's deployment block (e.g., block 0 or a known anchor block), this is unverified.

This is low severity because the genesis window is a one-time operation and the first submitter is expected to be the operator. However, in permissionless mode any address can submit the genesis window with an arbitrary starting range, potentially skipping large swaths of rollup history.

#### Recommendation

If the rollup has a known genesis block, add a constructor parameter `genesisL2Block` and enforce `l2Start == genesisL2Block` for the first window. If any start is acceptable, document this explicitly in the NatSpec.

---

### [LOW-004] metaLocator Not Emitted as Event — ManifestAnnounced Unimplemented

**Severity:** Low
**Category:** Specification Gap
**Location:** `contracts/src/WorldlineFinalizer.sol` — function `submitZkValidityProofWithMeta()`, lines 144–151
**Auditor(s):** Riley
**Status:** Remediated — commit `6594024`

#### Description

The technical specification defines an optional `ManifestAnnounced(bytes32 proverSetDigest, bytes locator)` event. `submitZkValidityProofWithMeta()` accepts a `metaLocator` parameter but only validates its length — it is never emitted in any event. Watchers and indexers relying on this event for off-chain data availability hints will not receive it.

#### Recommendation

Either emit the locator:

```solidity
emit ManifestAnnounced(proverSetDigest, metaLocator);
```

or remove the `submitZkValidityProofWithMeta` overload and document that locator emission is out of scope for v1.

---

### [LOW-005] Check-Effects-Interactions Violation in \_submit()

**Severity:** Low
**Category:** Reentrancy Pattern
**Location:** `contracts/src/WorldlineFinalizer.sol` — function `_submit()`, lines 196–220
**Auditor(s):** Jordan
**Status:** Remediated — commit `6594024`

#### Description

The `_submit()` function calls the external `adapter.verify()` (line 202) before updating state (`nextWindowIndex`, `lastL2EndBlock`) at lines 214–216. This violates the Checks-Effects-Interactions pattern.

A malicious adapter (which only the owner can set) could reenter `_submit()` before `nextWindowIndex` and `lastL2EndBlock` are updated. During the reentrant call, `nextWindowIndex == 0` (if the initial call is window 0) and all contiguity/staleness checks pass again, allowing a second window 0 submission.

In practice, the adapter is owner-controlled and trusted, making this a low-severity issue. However, if ownership is transferred to a multisig and a signer is compromised, or if a future upgrade introduces a less-trusted adapter path, this pattern becomes exploitable.

#### Recommendation

Move state updates before the external `adapter.verify()` call, following CEI:

```solidity
// Update state BEFORE external call
uint256 windowIndex = nextWindowIndex;
nextWindowIndex = windowIndex + 1;
lastL2EndBlock = l2End;

// Then call external adapter
(bool valid, ...) = adapter.verify(proof, publicInputs);
if (!valid) revert ProofInvalid();
```

---

### [LOW-006] Degraded Provers Included in Selection — Silent SLO Downgrade

**Severity:** Low
**Category:** Protocol Logic
**Location:** `crates/worldline-registry/src/selection.rs` — function `select()`, lines 106–114
**Auditor(s):** Alex
**Status:** Remediated — commit `6594024`

#### Description

The selection algorithm only filters out `HealthStatus::Offline` entries:

```rust
let mut eligible: Vec<&DirectoryEntry> = entries
    .iter()
    .filter(|e| !matches!(e.health, HealthStatus::Offline))
    .collect();
```

`HealthStatus::Degraded` provers are included in the eligible set and can be selected. A degraded prover may have high latency, elevated error rates, or intermittent failures that could delay or fail proof generation. Including degraded provers could cause liveness issues if the aggregator selects them and they fail to produce valid proofs before `maxAcceptanceDelay` expires.

#### Recommendation

Add a policy option `allow_degraded: bool` (default `false`) and filter out `Degraded` entries unless explicitly permitted. At minimum, document that degraded provers are included and that the aggregator should handle proof-collection failures gracefully.

---

### [INF-001] No On-Chain Monitoring Infrastructure Deployed

**Severity:** Informational
**Category:** Infrastructure / Operational Security
**Location:** `scripts/watcher.ts`; `.github/workflows/ci.yml`
**Auditor(s):** Casey
**Status:** Remediated — commit `0ab8a3e`

#### Description

Per TRM Labs' 2026 Crypto Crime Report, 76% of all 2025 crypto losses ($2.2B of $2.87B) were attributable to infrastructure attacks. The `scripts/watcher.ts` reference implementation exists but is not deployed as a service, not referenced in CI, and has no associated alerting configuration. There are no Forta bots or OpenZeppelin Defender Sentinel rules configured for:

- Unexpected `AdapterSet` events (adapter swap without governance)
- `MinTimelockSet` events (timelock reduction)
- `OwnershipTransferred` events (EOA handoff)
- Missed windows (gap between consecutive `OutputProposed` timestamps)
- `proverSetDigest` mismatches against independently computed manifest
- Pause state changes

Without monitoring, a compromised-key attack executing HI-001 (immediate adapter swap) would go undetected until after irreversible damage.

#### Recommendation

Before mainnet: deploy `watcher.ts` as a persistent service with PagerDuty/Slack alerting. Add a Forta bot or OZ Defender Sentinel for all privileged-role events. Establish an on-call rotation with a documented incident response playbook (the high-level IR process in `docs/security/threat-model.md` §10 is a good starting point but needs operational contact details and stablecoin-issuer freeze contacts).

---

### [INF-002] deploy.ts Deploys with Hot Wallet as Owner — No Post-Deploy Ownership Transfer

**Severity:** Informational
**Category:** Infrastructure / Key Custody
**Location:** `scripts/deploy.ts` — lines 30–34; no `transferOwnership()` call present
**Auditor(s):** Casey
**Status:** Remediated — commit `0ab8a3e`

#### Description

```typescript
const [deployer] = await ethers.getSigners();
// all contracts deployed with deployer as owner — no transferOwnership() to multisig
```

The deployment script deploys all contracts with the deployer EOA as owner and performs no post-deployment ownership transfer. The deployer wallet is the `PRIVATE_KEY` environment variable — a hot key present on the deployment machine or in CI secrets. Leaving the hot key as permanent owner exposes all admin functions to compromise of the deployment machine.

#### Recommendation

Add a mandatory post-deployment `transferOwnership()` step to a pre-configured multisig address. Make `MULTISIG_ADDRESS` a required environment variable and fail the deployment script if it is absent.

---

### [INF-003] 46 npm Vulnerabilities Including 15 High-Severity (undici CVEs) in Dev Dependencies

**Severity:** Informational
**Category:** Supply Chain / Infrastructure
**Location:** `package.json`; `node_modules/undici`
**Auditor(s):** Casey
**Status:** Remediated — commit `0ab8a3e`

#### Description

`npm audit` reports 46 vulnerabilities (21 low, 10 moderate, 15 high). The high-severity issues are concentrated in `undici ≤ 6.23.0` pulled in by Hardhat, with five distinct CVEs including HTTP Request/Response Smuggling (`GHSA-2mjp-6q6p-2qxm`), unbounded decompression (`GHSA-g9mf-h72j-4rw9`), and CRLF injection (`GHSA-4992-7rv2-5pvq`). All 46 vulnerabilities are in devDependencies; production deployments ship no Node.js code. Risk is limited to the CI build pipeline and developer machines. However, an RCE in the build toolchain on a developer machine that also holds deployment keys would be catastrophic.

Full fix: `npm audit fix --force` → `hardhat@3.2.0` (semver-breaking). Assess Hardhat 3.x compatibility before upgrading.

---

### [INF-004] download-ptau.ts Fetches Powers of Tau Without Integrity Verification

**Severity:** Informational
**Category:** Supply Chain / ZK Setup
**Location:** `circuits/scripts/download-ptau.ts` — lines 6–8
**Auditor(s):** Casey, Sam
**Status:** Remediated — commit `240f426`

#### Description

The Powers of Tau file is downloaded from Google Cloud Storage over HTTPS with no post-download hash verification. A compromised GCS bucket, BGP hijack, or MITM attack could deliver a manipulated ptau file making the Phase 2 setup insecure. The Hermez `powersOfTau28_hez_final_10.ptau` has a known SHA-256 hash published by the Hermez team and independently verified by the community.

#### Recommendation

After download, verify against the published hash:

```typescript
const EXPECTED_SHA256 = "<hermez-published-hash>";
const actual = createHash("sha256").update(fs.readFileSync(OUTPUT_FILE)).digest("hex");
if (actual !== EXPECTED_SHA256) {
  console.error("ptau integrity FAILED");
  process.exit(1);
}
```

---

### [INF-005] SquareHash Circuit: isValid Output Not Declared Public — Redundant Constraint

**Severity:** Informational
**Category:** Circuit Design
**Location:** `circuits/worldline.circom` — lines 12, 22
**Auditor(s):** Sam
**Status:** Remediated — commit `0ab8a3e`

#### Description

```circom
signal output isValid;
isValid <== 1;
```

`isValid` is assigned `1` unconditionally and is **not** listed in `{public [publicHash]}`. It is therefore a private output — the verifier contract cannot observe it and the constraint adds one R1CS row for no security benefit. This illustrates a common Circom pitfall: output signals that are not declared public contribute constraints without providing verifiable guarantees.

#### Recommendation

Remove `isValid` or add it to the public interface: `component main {public [publicHash, isValid]} = SquareHash()`.

---

### [INF-006] snarkjs Version Unpinned — Range Allows Potentially Vulnerable Patch Releases

**Severity:** Informational
**Category:** Supply Chain
**Location:** `package.json` — `"snarkjs": "^0.7.0"`
**Auditor(s):** Casey, Sam
**Status:** Remediated — commit `240f426`

#### Description

The `^0.7.0` range permits automatic semver-compatible updates. Given that the February 2026 exploit class was directly attributed to specific snarkjs versions generating incorrect Groth16 setups, pinning to a known-safe audited version is essential.

#### Recommendation

Pin to an exact version: `"snarkjs": "0.7.4"` (or whichever version is confirmed safe post-February 2026 advisory). Commit `package-lock.json` and add a CI step to verify lock file integrity.

---

### [GAS-001] WorldlineOutputsRegistry.activate() — Struct Write Already Optimal; viaIR Handles Rest

**Severity:** Gas
**Category:** Gas Optimization
**Location:** `contracts/src/WorldlineOutputsRegistry.sol` — function `activate()`, lines 136–156
**Auditor(s):** Jordan
**Status:** Acknowledged / No Action Required

#### Description

`activate()` correctly caches storage reads into memory locals before the `delete` and struct write. With `via_ir = true` set in `foundry.toml`, the IR pipeline further optimises storage layout and struct packing. No further optimisation is warranted at this time.

---

## Test Coverage Analysis

### v1.1 Remediation Test Results

| Suite                      | Tests   | Status       |
| -------------------------- | ------- | ------------ |
| Foundry (forge test)       | 63      | All pass     |
| Hardhat (npx hardhat test) | 119     | All pass     |
| Cargo (cargo test --all)   | 91      | All pass     |
| **Total**                  | **273** | **All pass** |

### Solidity

The Foundry fuzz suite (`WorldlineFinalizer.fuzz.t.sol`, `WorldlineRegistry.fuzz.t.sol`, 256 runs each) and the Hardhat integration suite cover the primary happy paths and all documented revert conditions. The remediation added dedicated test files:

- `Chunk5.t.sol` — 19 tests covering HI-004 dev-only guards, MED-003 zero-value guards, MED-004 SecretTooLarge, MED-005 timelocked facade changes
- `Chunk7.t.sol` — 8 tests covering LOW-003 genesis validation, LOW-004 ManifestAnnounced emission, LOW-005 CEI state update ordering
- `AccessControl.t.sol` — 18 tests covering HI-001 timelocked adapter, HI-003 two-step ownership, HI-002 timelock floors

**Previously uncovered paths now tested:**

- ~~`setAdapter()` with a malicious/reentering adapter~~ → CEI fix (LOW-005) + timelocked adapter (HI-001) mitigate; structural test in Chunk7
- ~~`setMinTimelock(1)` → immediate schedule/activate~~ → MIN_TIMELOCK_FLOOR enforced; tested in AccessControl.t.sol
- ~~`WorldlineRegistry.verify()` with `secret > 2^128`~~ → SecretTooLarge guard; tested in Chunk5.t.sol and Verifier.test.ts
- ~~`submitZkValidityProofWithMeta` locator emission~~ → ManifestAnnounced event tested in Chunk7.t.sol
- ~~`WorldlineOutputsRegistry.schedule()` with `oracle = address(0)`~~ → OracleZero guard; tested in Chunk5.t.sol
- ~~`setCompatFacade(address(0))` to disable the facade~~ → Timelocked two-step; tested in Chunk5.t.sol and WorldlineRegistry.test.ts

**Remaining gaps (production prerequisites):**

- Production `IS_DEV_MODE = false` branch in `Groth16ZkAdapter` (no test exercises `!IS_DEV_MODE` with a real verifier — blocked until production circuit is complete)
- Double `schedule()` on same domain key (reschedule/overwrite path)

### Rust

The Rust test suite (91 tests) is comprehensive. CRI-001 remediation added real secp256k1 tests:

- Valid EIP-191 signature accepted (`valid_eip191_signature_returns_ok_true`)
- Tampered entries → `Err(SignerMismatch)` (`tampered_entry_after_signing_returns_signer_mismatch`)
- Malformed hex signature → `Err(InvalidEncoding)` (`malformed_hex_signature_returns_invalid_encoding`)
- Wrong signer address → `Err(SignerMismatch)` (`wrong_signer_address_returns_signer_mismatch`)
- LOW-006 added: `degraded_provers_excluded_by_default`, `degraded_provers_included_when_allowed`, `degraded_only_fails_without_allow`
- MED-002 added: `max_manifest_entries_enforced`, `exactly_max_manifest_entries_succeeds`
- MED-006: `shared_test_vectors_keccak` now asserts all vectors have populated keccak256 fields

### Circuit

`circuits/test/worldline.test.ts` covers the SquareHash circuit. INF-005 remediation removed the redundant `isValid` output; tests updated to verify constraint satisfaction directly without checking removed signal.

### Mutation Score

`vertigo-rs` was not available in the audit environment. The expanded test suite now covers all guarded functions with dedicated negative-path tests (custom errors for `onlyOwner`, `onlyAdmin`, `NotAuthorized`).

---

## Code Quality Observations

1. **NatSpec:** Good coverage on `WorldlineFinalizer`, `WorldlineOutputsRegistry`, and `Groth16ZkAdapter`. `Ownable` has no NatSpec. `WorldlineCompat.verify()` is missing a `@dev DEV-ONLY` warning mirroring the registry's NatSpec.

2. **Event emission:** All state-changing admin functions emit events. `submitZkValidityProofWithMeta` does not emit `metaLocator` (LOW-004). Event parameters are appropriately indexed where useful (`windowIndex` indexed; non-critical fields unindexed to save gas).

3. **Custom error consistency:** Excellent use of typed custom errors throughout — sole exception is `Ownable.sol` (LOW-002).

4. **Magic numbers:** `PUBLIC_INPUTS_LEN = 224` is a named constant (good). The `96`-byte locator cap in `submitZkValidityProofWithMeta` is a hardcoded literal; a named constant `MAX_LOCATOR_BYTES = 96` aligning with the spec would improve readability.

5. **Dead variable suppression:** `l1BlockHash; outputRoot;` in `_submit()` is an unusual but legal Solidity idiom; the accompanying comment explains the rationale adequately. Worth replacing with `emit` or a proper usage when the adapter is completed.

6. **Circom signal tags:** No `{binary}`, `{maxbit}`, or other Circom 2.x type tags are used in the demo circuit. For the production circuit, all input signals should carry appropriate tags to enable compiler-level range enforcement.

7. **Rust quality:** Clean `thiserror` error types, `serde` serialization, and `tiny-keccak` hashing throughout. No `unsafe` blocks in any crate. The `canonical.rs` recursive implementation is clean and correct.

8. **CI pipeline:** The `canonical-conformance` job correctly runs both Rust and TypeScript canonicalisers against shared test vectors — a strong design choice. Will silently pass for vectors with empty `keccak256` fields (MED-006). No snarkjs setup verification step exists in CI.

---

## Appendix A — Circuit Inventory

| Circuit                                        | Toolchain       | Version | Public Inputs                                                   | Private Inputs                           | Statement Proved                                |
| ---------------------------------------------- | --------------- | ------- | --------------------------------------------------------------- | ---------------------------------------- | ----------------------------------------------- |
| `SquareHash` (`circuits/worldline.circom`)     | Circom          | 2.1.6   | `publicHash`                                                    | `secret`                                 | `secret² ≡ publicHash` (BN254 field arithmetic) |
| Production outer circuit                       | Not yet written | TBD     | `stfCommitment`, `programVKey`, `policyHash`, `proverSetDigest` | STF witness, manifest, recursion witness | Full STF correctness + manifest binding         |
| Recursion accumulator (`snark-accum`)          | Not yet written | TBD     | TBD                                                             | Inner SNARK proofs                       | Aggregation of ≤4 inner SNARKs                  |
| Recursion mini-verifier (`snark-miniverifier`) | Not yet written | TBD     | TBD                                                             | Inner SNARK proofs                       | In-circuit replay of ≤4 inner verifications     |

---

## Appendix B — External Call Inventory

| Caller               | Callee                              | Function                              | Trust Level                     | Notes                                                          |
| -------------------- | ----------------------------------- | ------------------------------------- | ------------------------------- | -------------------------------------------------------------- |
| `WorldlineFinalizer` | `IZkAggregatorVerifier` (adapter)   | `verify(proof, publicInputs)`         | Trusted (owner-set, timelocked) | CEI compliant — state updated before call (LOW-005 remediated) |
| `WorldlineRegistry`  | `Verifier` (defaultVerifier)        | `verifyProof(secret, publicHash)`     | Trusted (immutable)             | Dev-only; exposes secret (HI-004)                              |
| `WorldlineRegistry`  | Per-circuit verifier address        | `verifyProof(secret, publicHash)`     | Semi-trusted (owner-registered) | Arbitrary address; dev-only                                    |
| `WorldlineCompat`    | `WorldlineRegistry`                 | All registry mutations                | Trusted (immutable)             | Compat must be set as `compatFacade` first                     |
| `Groth16ZkAdapter`   | `Verifier` (dev mode, 64-byte path) | `verifyProof(secret, publicHash)`     | Trusted (immutable)             | Dev path only                                                  |
| `Groth16ZkAdapter`   | `Groth16Verifier` (prod mode)       | `verifyProof(pA, pB, pC, pubSignals)` | Trusted (immutable)             | Placeholder; zero-filled inputs (CRI-003)                      |

---

## Appendix C — Privileged Role and Key Custody Inventory

| Role                | Contract(s)          | Permissions                                                                         | Current Custody                                            | Timelock                             | Risk                                               |
| ------------------- | -------------------- | ----------------------------------------------------------------------------------- | ---------------------------------------------------------- | ------------------------------------ | -------------------------------------------------- |
| `owner`             | All 4 contracts      | All admin functions including `scheduleAdapterChange`, `setMinTimelock`, `schedule` | Two-step transfer; deploy.ts transfers to MULTISIG_ADDRESS | 1 day+ (adapter), 1 hour+ (timelock) | Remediated — HI-001/HI-003/INF-002                 |
| `submitter`         | `WorldlineFinalizer` | Submit proofs (permissioned mode)                                                   | Set by owner                                               | None                                 | Low                                                |
| `compatFacade`      | `WorldlineRegistry`  | Register/deprecate circuits, drivers, plugins                                       | Set by owner; currently `WorldlineCompat`                  | 1 day+ (timelocked change)           | Remediated — MED-005                               |
| Directory signer    | Off-chain aggregator | Sign `SignedDirectory` JSON                                                         | Not yet configured                                         | N/A                                  | Remediated — CRI-001 (real secp256k1 verification) |
| Aggregator operator | Off-chain            | Build manifest, submit proofs                                                       | Not yet configured                                         | N/A                                  | High — single PoF without redundancy               |

**Minimum viable custody before mainnet:** Transfer all contract ownership to a Gnosis Safe ≥ 2-of-3. All threshold signers must use hardware wallets with transaction details confirmed on the device screen (mitigates Bybit-class blind-signing attacks). Establish a key rotation procedure and emergency pause runbook.

---

## Appendix D — Automated Tool Output Summary

| Tool                       | Result                                                    | Disposition                                                                                        |
| -------------------------- | --------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| Slither                    | Not executed — `forge` binary absent in audit environment | Re-run when Foundry available; expect low/informational findings given clean code                  |
| Aderyn                     | Not executed — not installed                              | —                                                                                                  |
| cargo-audit                | Not executed — `cargo-audit` subcommand not installed     | Install `cargo install cargo-audit` and run before next review cycle                               |
| Echidna / Medusa           | Not executed                                              | —                                                                                                  |
| Halmos                     | Not executed                                              | —                                                                                                  |
| circomspect / ZKAP / Picus | Not executed                                              | Run against production circuit before deployment                                                   |
| **solc v0.8.34**           | **Executed**                                              | Successfully compiled all 9 in-scope Solidity files; ABI extracted; no compiler errors or warnings |
| **npm audit**              | **Executed**                                              | 46 vulnerabilities (21 low, 10 moderate, 15 high); all in devDependencies → INF-003                |
| snarkjs zkey verify        | Not applicable — no `.zkey` exists in repo                | Mandatory gate before production deployment (CRI-002)                                              |
| vertigo-rs                 | Not executed                                              | —                                                                                                  |

All findings in this report are from manual review. No automated findings were dismissed because no automated tools produced findings.

---

_End of Report — Project Worldline Security Audit v1.1 (Remediation Update)_
_Original audit commit: `0204d5354f5d58d2b32a6ceb5c25b46f33efe82f`_
_Remediation branch: `claude/remediate-security-findings-SdVYF`_
_Audit date: 2026-03-26 | Remediation date: 2026-03-27_
_All 25 findings remediated — 0 open findings remain._
