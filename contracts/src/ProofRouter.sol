// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {IZkAdapter} from "./IZkAdapter.sol";
import {IZkAggregatorVerifier} from "./interfaces/IZkAggregatorVerifier.sol";

/// @title ProofRouter
/// @notice Routes ZK proofs to the correct verifier adapter based on proof system ID.
///         Maintains an owner-controlled registry of (proofSystemId → adapter address).
///
/// @dev Two routing paths are provided:
///      1. routeProof()           — thin path; calls IZkAdapter.verify(), returns bool,
///                                  emits ProofRouted. For external callers and testing.
///      2. routeProofAggregated() — rich path; calls IZkAggregatorVerifier.verify(),
///                                  returns the full (valid, stfCommitment, programVKey,
///                                  policyHash, proverSetDigest) tuple consumed by
///                                  WorldlineFinalizer._submitRouted().
///
///      Adapters registered here must implement IZkAdapter (for registration validation
///      and the thin path). Adapters used via routeProofAggregated must additionally
///      implement IZkAggregatorVerifier — this is enforced at call-time, not at
///      registration time, to keep the registration interface minimal.
/// @custom:oz-upgrades-from ProofRouter
contract ProofRouter is Initializable, Ownable2StepUpgradeable, UUPSUpgradeable {
    // ── Errors ──────────────────────────────────────────────────────────────────

    /// @notice Adapter address must be non-zero.
    error AdapterZero();

    /// @notice The adapter's self-reported proofSystemId does not match the requested ID.
    error ProofSystemIdMismatch(uint8 expected, uint8 given);

    /// @notice An adapter is already registered for this proofSystemId.
    ///         Call removeAdapter() first to replace it.
    error AdapterAlreadyRegistered(uint8 proofSystemId);

    /// @notice No adapter is registered for the requested proofSystemId.
    error AdapterNotRegistered(uint8 proofSystemId);

    /// @notice No adapter removal has been scheduled for this proofSystemId.
    error NoAdapterRemovalScheduled(uint8 proofSystemId);

    /// @notice The adapter removal timelock has not elapsed yet.
    error TimelockActive(uint256 activationTime);

    /// @notice The requested adapter change delay is below the minimum floor.
    error AdapterChangeTooShort(uint256 required, uint256 given);

    // ── Events ──────────────────────────────────────────────────────────────────

    /// @notice Emitted when a new adapter is registered.
    event AdapterRegistered(uint8 indexed proofSystemId, address adapter);

    /// @notice Emitted when an adapter is removed.
    event AdapterRemoved(uint8 indexed proofSystemId);

    /// @notice Emitted when a proof is successfully routed via routeProof().
    event ProofRouted(uint8 indexed proofSystemId, bool result);

    /// @notice Emitted when an adapter removal is scheduled.
    event AdapterRemovalScheduled(uint8 indexed proofSystemId, uint256 activationTime);

    /// @notice Emitted when the adapter change delay is updated.
    event AdapterChangeDelaySet(uint256 delay);

    // ── Storage ─────────────────────────────────────────────────────────────────

    /// @dev Maps proofSystemId to the registered adapter address.
    mapping(uint8 => address) private _adapters;

    /// @notice Minimum floor for `adapterChangeDelay`.
    uint256 public constant MIN_ADAPTER_CHANGE_DELAY = 1 days;

    /// @notice Delay (seconds) before a scheduled adapter removal can be activated.
    ///         Initialized to 1 day; configurable by owner with a floor of MIN_ADAPTER_CHANGE_DELAY.
    uint256 public adapterChangeDelay;

    /// @dev Maps proofSystemId to the timestamp at which a pending removal can be activated.
    ///      Zero means no removal is scheduled.
    mapping(uint8 => uint256) private _pendingRemovalActivations;

    // ── Constructor ─────────────────────────────────────────────────────────────

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // ── Initializer ─────────────────────────────────────────────────────────────

    function initialize() external initializer {
        __Ownable_init(msg.sender);
        __Ownable2Step_init();
        adapterChangeDelay = 1 days;
    }

    // ── UUPS ────────────────────────────────────────────────────────────────────

    function _authorizeUpgrade(address) internal override onlyOwner {}

    // ── Admin ───────────────────────────────────────────────────────────────────

    /// @notice Register an adapter for a given proof system ID.
    ///         Validates that the adapter's self-reported proofSystemId matches the
    ///         supplied proofSystemId. Reverts if an adapter is already registered
    ///         for that ID (use removeAdapter() first to replace).
    /// @param proofSystemId Numeric proof system identifier (1=Groth16, 2=Plonk, 3=Halo2).
    /// @param adapter       Address of the adapter implementing IZkAdapter.
    function registerAdapter(uint8 proofSystemId, address adapter) external onlyOwner {
        if (adapter == address(0)) revert AdapterZero();
        if (_adapters[proofSystemId] != address(0)) revert AdapterAlreadyRegistered(proofSystemId);

        // Validate adapter's self-reported ID matches the registration request.
        uint8 reportedId = IZkAdapter(adapter).proofSystemId();
        if (reportedId != proofSystemId) revert ProofSystemIdMismatch(proofSystemId, reportedId);

        _adapters[proofSystemId] = adapter;
        emit AdapterRegistered(proofSystemId, adapter);
    }

    /// @notice Schedule a timelocked adapter removal.
    ///         The adapter remains active until `activateAdapterRemoval()` is called after the delay.
    /// @param proofSystemId Numeric proof system identifier to schedule for removal.
    function removeAdapter(uint8 proofSystemId) external onlyOwner {
        if (_adapters[proofSystemId] == address(0)) revert AdapterNotRegistered(proofSystemId);
        uint256 activationTime = block.timestamp + adapterChangeDelay;
        _pendingRemovalActivations[proofSystemId] = activationTime;
        emit AdapterRemovalScheduled(proofSystemId, activationTime);
    }

    /// @notice Activate a previously scheduled adapter removal after the timelock has elapsed.
    ///         Clears the adapter slot and emits AdapterRemoved.
    /// @param proofSystemId Numeric proof system identifier to remove.
    function activateAdapterRemoval(uint8 proofSystemId) external onlyOwner {
        uint256 activationTime = _pendingRemovalActivations[proofSystemId];
        if (activationTime == 0) revert NoAdapterRemovalScheduled(proofSystemId);
        if (block.timestamp < activationTime) revert TimelockActive(activationTime);
        delete _adapters[proofSystemId];
        delete _pendingRemovalActivations[proofSystemId];
        emit AdapterRemoved(proofSystemId);
    }

    /// @notice Update the adapter change delay. Subject to a minimum floor of MIN_ADAPTER_CHANGE_DELAY.
    /// @param _delay New delay in seconds (must be >= MIN_ADAPTER_CHANGE_DELAY).
    function setAdapterChangeDelay(uint256 _delay) external onlyOwner {
        if (_delay < MIN_ADAPTER_CHANGE_DELAY) revert AdapterChangeTooShort(MIN_ADAPTER_CHANGE_DELAY, _delay);
        adapterChangeDelay = _delay;
        emit AdapterChangeDelaySet(_delay);
    }

    // ── Views ───────────────────────────────────────────────────────────────────

    /// @notice Return the adapter address registered for a proof system ID (zero if none).
    function getAdapter(uint8 proofSystemId) external view returns (address) {
        return _adapters[proofSystemId];
    }

    /// @notice Return true if an adapter is registered for the given proof system ID.
    function isSupported(uint8 proofSystemId) external view returns (bool) {
        return _adapters[proofSystemId] != address(0);
    }

    /// @notice Return the timestamp at which a pending adapter removal can be activated.
    ///         Returns 0 if no removal is scheduled for this proofSystemId.
    function getAdapterRemovalActivation(uint8 proofSystemId) external view returns (uint256) {
        return _pendingRemovalActivations[proofSystemId];
    }

    // ── Routing ─────────────────────────────────────────────────────────────────

    /// @notice Thin routing path. Forwards the proof to the registered IZkAdapter and
    ///         returns a simple boolean result. Emits ProofRouted.
    /// @param proofSystemId  Proof system to route to.
    /// @param proof          Encoded proof bytes.
    /// @param publicInputs   Pre-decoded public input words.
    /// @return result        Whether the proof is valid.
    function routeProof(uint8 proofSystemId, bytes calldata proof, bytes32[] calldata publicInputs)
        external
        returns (bool result)
    {
        address adapterAddr = _adapters[proofSystemId];
        if (adapterAddr == address(0)) revert AdapterNotRegistered(proofSystemId);

        result = IZkAdapter(adapterAddr).verify(proof, publicInputs);
        emit ProofRouted(proofSystemId, result);
    }

    /// @notice Rich aggregated routing path. Forwards the proof to the registered
    ///         IZkAggregatorVerifier and returns the full verification tuple consumed
    ///         by WorldlineFinalizer._submitRouted(). Emits ProofRouted.
    /// @dev The adapter at _adapters[proofSystemId] must implement IZkAggregatorVerifier
    ///      in addition to IZkAdapter. A revert with an EvmError will occur otherwise.
    /// @param proofSystemId  Proof system to route to.
    /// @param proof          Encoded proof bytes (format depends on adapter).
    /// @param publicInputs   224-byte ABI-encoded public inputs (WorldlineFinalizer format).
    /// @return valid              Whether the proof is valid.
    /// @return stfCommitment      STF commitment extracted from the proof.
    /// @return programVKey        Program verifying key pinned by the adapter.
    /// @return policyHash         Policy hash pinned by the adapter.
    /// @return proverSetDigest    Prover-set digest extracted from the proof.
    function routeProofAggregated(uint8 proofSystemId, bytes calldata proof, bytes calldata publicInputs)
        external
        returns (bool valid, bytes32 stfCommitment, bytes32 programVKey, bytes32 policyHash, bytes32 proverSetDigest)
    {
        address adapterAddr = _adapters[proofSystemId];
        if (adapterAddr == address(0)) revert AdapterNotRegistered(proofSystemId);

        (valid, stfCommitment, programVKey, policyHash, proverSetDigest) =
            IZkAggregatorVerifier(adapterAddr).verify(proof, publicInputs);

        emit ProofRouted(proofSystemId, valid);
    }
}
