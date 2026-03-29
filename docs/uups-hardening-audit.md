# UUPS Proxy Hardening Audit

**Date:** 2026-03-29
**Branch:** `claude/uups-proxy-hardening-audit-Owns5`
**Scope:** Four UUPS-proxied contracts — `WorldlineFinalizer`, `WorldlineRegistry`,
`WorldlineOutputsRegistry`, `ProofRouter` — plus their deployment scripts and test
infrastructure.
**Auditor:** Claude Code (Chunk 1 — read-only)

---

## Summary

| Severity  | Count |
| --------- | ----- |
| CRITICAL  | 0     |
| HIGH      | 2     |
| MEDIUM    | 4     |
| LOW       | 2     |
| **Total** | **8** |

The core UUPS pattern is implemented correctly across all four contracts. Constructors
contain only `_disableInitializers()`, all `initialize()` functions carry the
`initializer` modifier and invoke the full OZ init chain, and `_authorizeUpgrade()` is
consistently restricted to `onlyOwner`. The two HIGH findings are a timelock gap in the
routed proof-submission path. The MEDIUM findings are missing initialization hygiene,
missing storage gaps, an incomplete deployment script, and gaps in the upgrade test
suite.

---

## Contract-by-Contract Findings

### WorldlineFinalizer

**File:** `contracts/src/WorldlineFinalizer.sol`

#### 1. Inheritance chain

```
WorldlineFinalizer
  → Initializable
  → Ownable2StepUpgradeable
  → UUPSUpgradeable
```

All three required bases are present. No extraneous upgrade-related inheritance.
**PASS.**

#### 2. Constructor

```solidity
/// @custom:oz-upgrades-unsafe-allow constructor
constructor() {
    _disableInitializers();
}
```

Contains only `_disableInitializers()`. No state-setting logic. **PASS.**

#### 3. `initialize()` function

```solidity
function initialize(
    address _adapter,
    bytes32 _domainSeparator,
    uint256 _maxAcceptanceDelay,
    uint256 _genesisL2Block,
    address _blobKzgVerifier
) external initializer {
    __Ownable_init(msg.sender);
    __Ownable2Step_init();
    ...
}
```

- `initializer` modifier: **PASS.**
- `__Ownable_init(msg.sender)` called: **PASS.**
- `__Ownable2Step_init()` called: **PASS.**
- `__UUPSUpgradeable_init()` called: **MISSING — see M-01.**
- `domainSeparator`, `maxAcceptanceDelay`, `genesisL2Block` are all set inside
  `initialize()` (not the constructor): **PASS.**

#### 4. Reinitializer versioning

No `reinitializer(N)` function exists. Contract is v1. This is **expected**.

#### 5. `_authorizeUpgrade()`

```solidity
function _authorizeUpgrade(address) internal override onlyOwner {}
```

Present and restricted to `onlyOwner`. **PASS.**
No upgrade-authorization event emitted — see **L-01**.

#### 6. Storage layout

No `__gap` array — see **M-02**. No storage collision with OZ bases (OZ v5 internals
use named private slots, not sequential slots).

New storage variables (blob KZG verifier timelock, domain separator timelock, genesis
block timelock) are appended after the original storage — correct append-only pattern.
**PASS.**

#### 7. Timelock consistency

All timelocked paths for adapter, blob KZG verifier, domain separator, and genesis
block are present with `adapterChangeDelay` (floored at `MIN_ADAPTER_DELAY = 1 day`).

`setProofRouter()` is **not timelocked** — see **H-01**.

`setMaxAcceptanceDelay()` changes a staleness-window parameter immediately. This is a
lower-criticality parameter (it only affects how old a window can be), so a timelock is
not required, but note it is immediate.

#### 8. Event emission

Events are emitted for most admin operations. `initialize()` does not emit a
contract-specific initialization event beyond the OZ `Initialized(1)` event that fires
automatically via the `initializer` modifier. **Acceptable.**

---

### WorldlineRegistry

**File:** `contracts/src/WorldlineRegistry.sol`

#### 1. Inheritance chain

```
WorldlineRegistry
  → Initializable
  → Ownable2StepUpgradeable
  → UUPSUpgradeable
```

All three required bases are present. **PASS.**

#### 2. Constructor

```solidity
/// @custom:oz-upgrades-unsafe-allow constructor
constructor() {
    _disableInitializers();
}
```

Contains only `_disableInitializers()`. **PASS.**

#### 3. `initialize()` function

```solidity
function initialize(address verifier) external initializer {
    __Ownable_init(msg.sender);
    __Ownable2Step_init();
    ...
}
```

- `initializer` modifier: **PASS.**
- `__Ownable_init(msg.sender)` called: **PASS.**
- `__Ownable2Step_init()` called: **PASS.**
- `__UUPSUpgradeable_init()` called: **MISSING — see M-01.**

#### 4. Reinitializer versioning

No `reinitializer(N)` function. Contract is v1. **Expected.**

#### 5. `_authorizeUpgrade()`

```solidity
function _authorizeUpgrade(address) internal override onlyOwner {}
```

Present and restricted to `onlyOwner`. **PASS.**

#### 6. Storage layout

No `__gap` array — see **M-02**.

#### 7. Timelock consistency

`scheduleCompatFacade`/`activateCompatFacade` provides a timelocked facade-change path.
`setCompatFacade` bypasses the timelock for first-time wiring only (enforced by the
`compatFacade != address(0)` guard). This is acceptable for initial deployment wiring.

The revert in `setCompatFacade` when the facade is already set uses
`FacadeTimelockActive(0)` — see **L-02**.

#### 8. Event emission

Events are emitted for all admin operations. **PASS.**

---

### WorldlineOutputsRegistry

**File:** `contracts/src/WorldlineOutputsRegistry.sol`

#### 1. Inheritance chain

```
WorldlineOutputsRegistry
  → Initializable
  → Ownable2StepUpgradeable
  → UUPSUpgradeable
```

All three required bases are present. **PASS.**

#### 2. Constructor

```solidity
/// @custom:oz-upgrades-unsafe-allow constructor
constructor() {
    _disableInitializers();
}
```

Contains only `_disableInitializers()`. **PASS.**

#### 3. `initialize()` function

```solidity
function initialize(uint256 _minTimelock) external initializer {
    __Ownable_init(msg.sender);
    __Ownable2Step_init();
    if (_minTimelock < MIN_TIMELOCK_FLOOR) revert TimelockTooShort(...);
    minTimelock = _minTimelock;
}
```

- `initializer` modifier: **PASS.**
- `__Ownable_init(msg.sender)` called: **PASS.**
- `__Ownable2Step_init()` called: **PASS.**
- `__UUPSUpgradeable_init()` called: **MISSING — see M-01.**

#### 4. Reinitializer versioning

No `reinitializer(N)` function. Contract is v1. **Expected.**

#### 5. `_authorizeUpgrade()`

```solidity
function _authorizeUpgrade(address) internal override onlyOwner {}
```

Present and restricted to `onlyOwner`. **PASS.**

#### 6. Storage layout

No `__gap` array — see **M-02**.

#### 7. Timelock consistency

All output-entry mutations flow through `schedule()`/`activate()` with `minTimelock`
enforced. `setMinTimelock()` itself is immediate (no timelock on the timelock setter),
but this is consistent with how other contracts manage their delay parameters (e.g.,
`setAdapterChangeDelay`, `setFacadeChangeDelay`). **Acceptable.**

#### 8. Event emission

Events emitted for all state changes. **PASS.**

---

### ProofRouter

**File:** `contracts/src/ProofRouter.sol`

#### 1. Inheritance chain

```
ProofRouter
  → Initializable
  → Ownable2StepUpgradeable
  → UUPSUpgradeable
```

All three required bases are present. **PASS.**

#### 2. Constructor

```solidity
/// @custom:oz-upgrades-unsafe-allow constructor
constructor() {
    _disableInitializers();
}
```

Contains only `_disableInitializers()`. **PASS.**

#### 3. `initialize()` function

```solidity
function initialize() external initializer {
    __Ownable_init(msg.sender);
    __Ownable2Step_init();
}
```

- `initializer` modifier: **PASS.**
- `__Ownable_init(msg.sender)` called: **PASS.**
- `__Ownable2Step_init()` called: **PASS.**
- `__UUPSUpgradeable_init()` called: **MISSING — see M-01.**

#### 4. Reinitializer versioning

No `reinitializer(N)` function. Contract is v1. **Expected.**

#### 5. `_authorizeUpgrade()`

```solidity
function _authorizeUpgrade(address) internal override onlyOwner {}
```

Present and restricted to `onlyOwner`. **PASS.**

#### 6. Storage layout

Only one storage variable: `mapping(uint8 => address) private _adapters`.
No `__gap` array — see **M-02**.

#### 7. Timelock consistency

`removeAdapter()` is timelocked (H-02 resolved): it schedules a removal delayed by
`adapterChangeDelay` (min 1 day); `activateAdapterRemoval()` completes it.
`registerAdapter()` is intentionally immediate — it is additive-only (can only fill
empty slots); see H-02 resolution notes for rationale.

#### 8. Event emission

`AdapterRegistered` and `AdapterRemoved` events emitted. **PASS.**

---

## Deployment Infrastructure

### 9. Deployment scripts

**File:** `scripts/deploy.ts`

All three proxied contracts that are deployed use `upgrades.deployProxy(..., { kind: "uups"
})` and call `initialize()`. Implementation addresses are retrieved via
`upgrades.erc1967.getImplementationAddress()` and verified non-zero after deployment.
**PASS.**

**ProofRouter is not deployed in `deploy.ts` — see M-03.**

Ownership transfer via `transferOwnership()` (two-step) is handled in the script for
non-dev networks. **PASS.**

### 10. Upgrade scripts

No dedicated upgrade script (`upgradeToAndCall`) exists. The deployment architecture
supports future upgrades through Hardhat's `upgrades.upgradeProxy()` (already used in
tests). Upgrade scripts can be added when a v2 deployment is needed.

This absence is **expected** for a v1 system. No finding raised.

---

## Test Infrastructure

### 11. Proxy-aware tests

**Forge tests (`contracts/test/`):**
`WorldlineTestBase.t.sol` deploys `WorldlineFinalizer` via `ERC1967Proxy` with an
encoded `initialize()` call — proxy-aware. **PASS.**

All test suites inherit `WorldlineTestBase` or perform equivalent proxy deployment.

**Hardhat integration tests (`test/integration/`):**
`deployment-fixtures.ts` uses `upgrades.deployProxy(..., { kind: "uups" })` for all
four contracts. All integration test helpers use the proxy path. **PASS.**

### 12. Upgrade tests

**File:** `test/integration/upgrade.test.ts`

| Contract                 | V1 deploy | State write | Upgrade to V2 | State preserved | Non-owner reverts | Double-init revert | Impl locked |
| ------------------------ | --------- | ----------- | ------------- | --------------- | ----------------- | ------------------ | ----------- |
| WorldlineFinalizer       | ✓         | ✓           | ✓             | ✓               | ✓                 | ✓                  | ✓           |
| ProofRouter              | ✓         | ✓           | ✓             | ✓               | ✓                 | ✓                  | ✓           |
| WorldlineRegistry        | ✓         | ✓           | ✓             | ✓               | ✓                 | ✓                  | ✓           |
| WorldlineOutputsRegistry | ✓         | ✓           | ✓             | ✓               | ✓                 | ✓                  | ✓           |

All gaps resolved — see **M-04** resolution notes.

No test verifies that `initialize()` reverts on a second call for any contract.
No test verifies that the bare implementation contract cannot be directly initialized.

---

## Findings Detail

---

### H-01 — `setProofRouter` in WorldlineFinalizer has no timelock

**Severity:** HIGH
**File:** `contracts/src/WorldlineFinalizer.sol:319`
**Status:** Open

```solidity
function setProofRouter(address _proofRouter) external onlyOwner {
    proofRouter = IProofRouter(_proofRouter);
    emit ProofRouterSet(_proofRouter);
}
```

`proofRouter` is an active security-critical component for any proof submitted via
`submitZkValidityProofRouted`. Replacing it immediately bypasses the `adapterChangeDelay`
(minimum 1 day) that protects the default adapter. A compromised owner key can atomically
reroute all routed submissions to a malicious verifier with no delay window for users to
observe the change. This is inconsistent with the security model for all other
security-sensitive setters on this contract.

**Impact:** Complete proof-routing bypass with no delay. Severity is HIGH because it
creates a gap in the timelock protection that applies to every other security-sensitive
parameter on this contract.

---

### H-02 — `registerAdapter`/`removeAdapter` in ProofRouter have no timelock

**Severity:** HIGH
**File:** `contracts/src/ProofRouter.sol:85,100`
**Status:** RESOLVED — Chunk 2

```solidity
function registerAdapter(uint8 proofSystemId, address adapter) external onlyOwner { ... }
function removeAdapter(uint8 proofSystemId) external onlyOwner { ... }
```

Both functions are immediate. A compromised or rogue owner can `removeAdapter(1)` then
`registerAdapter(1, maliciousAddr)` in two back-to-back transactions, swapping the
Groth16 adapter to a malicious implementation with zero delay. This entirely circumvents
the `adapterChangeDelay` timelock on `WorldlineFinalizer` for any proof submitted via
the routed path.

**Impact:** Same as H-01 — complete bypass of adapter-change delay for the routed
proof-submission path.

**Resolution (Chunk 2):** `removeAdapter()` was converted to a two-step timelocked flow:
`removeAdapter()` schedules the removal at `block.timestamp + adapterChangeDelay` (minimum
1 day); `activateAdapterRemoval()` completes it after the delay elapses. A new
`setAdapterChangeDelay()` function allows the owner to adjust the delay subject to a
`MIN_ADAPTER_CHANGE_DELAY = 1 days` floor. New events `AdapterRemovalScheduled` and
`AdapterChangeDelaySet` are emitted.

**`registerAdapter()` — intentionally left immediate (additive-only):**
`registerAdapter()` can only register into **empty slots** — it reverts with
`AdapterAlreadyRegistered` if the slot is already occupied. Registering into an empty
slot is purely additive: it adds new routing capability without disrupting any existing
routing path. The security-critical operation is _replacing_ an existing adapter (slot A →
slot B), which requires completing the timelocked `removeAdapter` flow first (at least 1
day of observable warning via `AdapterRemovalScheduled`), then re-registering into the
now-empty slot (observable via `AdapterRegistered`). The timelock on removal is the
security control; the subsequent re-registration after removal is both observable and
unambiguous. No timelock on `registerAdapter()` is required.

---

### M-01 — `__UUPSUpgradeable_init()` not called in any `initialize()`

**Severity:** MEDIUM
**Files:** All four contracts
**Status:** CLOSED — Not Applicable (OZ v5)

**Resolution (Chunk 2 investigation):** In OpenZeppelin v5, `UUPSUpgradeable` is
re-exported from `@openzeppelin/contracts` as a stateless contract
(`@custom:stateless`). It has no `__UUPSUpgradeable_init()` function — the function
does not exist in v5. The audit finding was based on OZ v4 conventions. No code change
is required or possible; the init chain is complete as written.

---

### M-02 — Missing `__gap` arrays in all four proxied contracts

**Severity:** MEDIUM
**Files:** All four contracts
**Status:** RESOLVED — Chunk 3

None of the four contracts declare a `uint256[N] private __gap` storage reservation.
Without a gap:

1. Developers upgrading these contracts must manually track the current storage slot
   count and append new variables correctly.
2. There is no compile-time protection against accidentally inserting a variable in the
   middle of the layout (which would shift all downstream slots and corrupt proxy
   storage).

Standard practice for UUPS contracts is `uint256[50] private __gap` at the end of each
contract's storage block, adjusted to leave a fixed total slot count of 50 or more per
inheritance level. The exact size depends on the current slot consumption:

| Contract                 | Current user-defined slots | Suggested gap |
| ------------------------ | -------------------------- | ------------- |
| WorldlineFinalizer       | 22 (slots 0–21)            | 28            |
| WorldlineRegistry        | 12 (slots 0–11)            | 38            |
| WorldlineOutputsRegistry | 3 (slots 0–2)              | 47            |
| ProofRouter              | 3 (slots 0–2)              | 47            |

**Resolution (Chunk 3):** `uint256[N] private __gap` arrays added at the end of
user-defined storage in all four contracts, sized per the table above. Slot counts
verified with `forge inspect <Contract> storageLayout`. Total reserved slots per contract
= 50 (used + gap).

---

### M-03 — ProofRouter missing from production deployment script

**Severity:** MEDIUM
**File:** `scripts/deploy.ts`
**Status:** Open

`deploy.ts` deploys three of the four UUPS-proxied contracts (WorldlineRegistry,
WorldlineFinalizer, WorldlineOutputsRegistry) and wires them correctly. ProofRouter is
not deployed in the script. As a result:

1. A production deployment will not have the multi-proof-system routing capability
   enabled.
2. `WorldlineFinalizer.setProofRouter()` will not be called, leaving `proofRouter`
   unset (zero address).
3. Any attempt to call `submitZkValidityProofRouted()` on the deployed finalizer will
   revert with `ProofRouterZero`.

PlonkZkAdapter, Halo2ZkAdapter, and the full `registerAdapter` wiring are also absent.

---

### M-04 — Incomplete upgrade test suite coverage

**Severity:** MEDIUM
**File:** `test/integration/upgrade.test.ts`
**Status:** RESOLVED — Chunk 3

The following test scenarios are missing:

1. **WorldlineRegistry v1 → v2 upgrade** with state preservation (circuits, default
   verifier, facade wiring). Only proxy deployment and basic ops through proxy are
   tested.
2. **WorldlineOutputsRegistry v1 → v2 upgrade** with state preservation (minTimelock,
   active entries). Only proxy deployment and basic ops through proxy are tested.
3. **Double-initialize reverts** — no test verifies that calling `initialize()` a second
   time on any contract reverts (OZ `InvalidInitialization`).
4. **Implementation contract locked** — no test verifies that calling `initialize()`
   directly on the bare implementation contract reverts (disabled by
   `_disableInitializers()` in the constructor).

WorldlineFinalizerV2 and ProofRouterV2 test contracts exist in
`contracts/src/test/`. No equivalent V2 contracts exist for WorldlineRegistry or
WorldlineOutputsRegistry, so items 1–2 require creating those test contracts.

**Resolution (Chunk 3):**

- Created `contracts/src/test/WorldlineRegistryV2.sol` with `@custom:oz-upgrades-from WorldlineRegistry`
- Created `contracts/src/test/WorldlineOutputsRegistryV2.sol` with `@custom:oz-upgrades-from WorldlineOutputsRegistry`
- Added WorldlineRegistry v1→v2 upgrade test block: deploy, write state, upgrade, version check, state preservation, non-owner revert
- Added WorldlineOutputsRegistry v1→v2 upgrade test block: deploy, write state (schedule+activate entry), upgrade, version check, state preservation, non-owner revert
- Added "double-initialize reverts" test block covering all 4 contracts
- Added "implementation contract locked" test block covering all 4 contracts

---

### L-01 — `_authorizeUpgrade()` does not emit a bespoke event

**Severity:** LOW
**Files:** All four contracts
**Status:** RESOLVED — Chunk 4

`_authorizeUpgrade(address)` is the internal hook called immediately before
`upgradeTo`/`upgradeToAndCall` executes. The ERC1967 proxy mechanism does emit an
`Upgraded(address indexed implementation)` event, so upgrade traceability exists at the
proxy level. However, there is no application-layer event (e.g.
`UpgradeAuthorized(address newImpl, address authorizer)`) that logs who authorized the
upgrade. This makes forensic attribution harder when reviewing contract history.

This is LOW because the `Upgraded` event from the proxy is sufficient for most indexers.

**Resolution (Chunk 4):** Added `event UpgradeAuthorized(address indexed newImplementation, address indexed authorizer)` to all four contracts. `_authorizeUpgrade(address newImpl)` now emits `UpgradeAuthorized(newImpl, msg.sender)` before returning. This provides explicit authorizer attribution at the application layer, complementing the ERC1967 `Upgraded` event.

---

### L-02 — `setCompatFacade` uses `FacadeTimelockActive(0)` as a "already set" guard

**Severity:** LOW
**File:** `contracts/src/WorldlineRegistry.sol:155`
**Status:** RESOLVED — Chunk 4

```solidity
function setCompatFacade(address compat) external onlyOwner {
    if (compatFacade != address(0)) revert FacadeTimelockActive(0);
    ...
}
```

`FacadeTimelockActive(uint256 activationTime)` semantically means "a timelock is
active; wait until `activationTime`". Using it with `activationTime = 0` when the
facade is already set is misleading — there is no timelock here; the function is simply
guarding against re-use. The revert reason should be a dedicated error like
`FacadeAlreadySet()`.

**Resolution (Chunk 4):** Added `error FacadeAlreadySet()` to `WorldlineRegistry` and updated `setCompatFacade()` to `revert FacadeAlreadySet()` when a facade is already configured.

---

## Appendix: Items Verified and Confirmed Correct

The following audit checklist items were examined and found to have no issues:

- All four constructors contain only `_disableInitializers()` with no state-setting
  logic.
- All four `initialize()` functions carry the `initializer` modifier.
- All four `initialize()` functions call `__Ownable_init(msg.sender)` and
  `__Ownable2Step_init()`.
- All previously constructor-locked parameters (`domainSeparator`, `maxAcceptanceDelay`,
  `genesisL2Block` on Finalizer; `verifier` on Registry; `minTimelock` on
  OutputsRegistry) are now set in `initialize()`.
- No reinitializer functions exist (correct for v1).
- All four `_authorizeUpgrade()` functions are restricted to `onlyOwner` and are not
  empty (they carry the modifier).
- Storage variables do not conflict with OZ v5 internal storage (OZ v5 uses named
  private slots via `StorageSlot`, not sequential slots, for its upgradeable internals).
- `deploy.ts` deploys WorldlineRegistry, WorldlineFinalizer, and WorldlineOutputsRegistry
  through UUPS proxies with correct `initialize()` calls and implementation address
  verification.
- All integration tests in `test/integration/` deploy contracts through proxies, not
  bare implementations.
- `WorldlineFinalizer` upgrade test (V1→V2) and `ProofRouter` upgrade test (V1→V2)
  both pass state preservation and non-owner revert checks.
- `WorldlineFinalizerV2` and `ProofRouterV2` test contracts exist in
  `contracts/src/test/` with correct `@custom:oz-upgrades-from` annotations and
  `_disableInitializers()` constructors.

---

## Resolution Plan

| ID   | Severity | Status               | Description                                                     |
| ---- | -------- | -------------------- | --------------------------------------------------------------- |
| H-01 | HIGH     | RESOLVED — Chunk 2   | Add timelock for `setProofRouter`                               |
| H-02 | HIGH     | RESOLVED — Chunk 2   | Add timelock for `removeAdapter` in ProofRouter                 |
| M-01 | MEDIUM   | CLOSED — N/A (OZ v5) | `__UUPSUpgradeable_init()` does not exist in OZ v5              |
| M-02 | MEDIUM   | RESOLVED — Chunk 3   | Add `__gap` arrays to all four contracts                        |
| M-03 | MEDIUM   | RESOLVED — Chunk 2   | Add ProofRouter deployment to `deploy.ts`                       |
| M-04 | MEDIUM   | RESOLVED — Chunk 3   | Expand upgrade test suite                                       |
| L-01 | LOW      | RESOLVED — Chunk 4   | Add upgrade-authorization event (or document deferral)          |
| L-02 | LOW      | RESOLVED — Chunk 4   | Replace `FacadeTimelockActive(0)` with `FacadeAlreadySet` error |
