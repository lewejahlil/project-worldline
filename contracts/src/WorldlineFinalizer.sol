// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "./utils/Ownable.sol";
import {IZkAggregatorVerifier} from "./interfaces/IZkAggregatorVerifier.sol";

/// @title WorldlineFinalizer
/// @notice Accepts one ZK proof per contiguous window, verifies it via an adapter,
///         and emits canonical finality events. Enforces domain binding, contiguity,
///         and staleness constraints as specified in the Worldline technical spec.
contract WorldlineFinalizer is Ownable {
    // ── Errors ──────────────────────────────────────────────────────────────────

    error Paused();
    error BadInputsLen();
    error NotAuthorized();
    error NotContiguous();
    error AdapterZero();
    error DomainMismatch();
    error TooOld();
    error InvalidWindowRange();
    error MaxAcceptanceDelayZero();
    error LocatorTooLong();
    error ProofInvalid();
    error StfMismatch();
    error StfBindingMismatch();
    error NoPendingAdapter();
    error TimelockActive(uint256 activationTime);
    error AdapterDelayTooShort(uint256 required, uint256 given);
    error GenesisStartMismatch(uint256 expected, uint256 actual);

    // ── Events ──────────────────────────────────────────────────────────────────

    /// @notice Emitted when a window output is finalized.
    event OutputProposed(
        uint256 indexed windowIndex,
        bytes32 outputRoot,
        uint256 l2Start,
        uint256 l2End,
        bytes32 stfCommitment
    );

    /// @notice Emitted when a ZK proof is accepted for a window.
    event ZkProofAccepted(
        uint256 indexed windowIndex,
        bytes32 programVKey,
        bytes32 policyHash,
        bytes32 proverSetDigest
    );

    event PausedSet(bool paused);
    event PermissionlessSet(bool permissionless);
    event SubmitterSet(address indexed account, bool allowed);
    event MaxAcceptanceDelaySet(uint256 delay);
    event AdapterSet(address indexed adapter);
    event AdapterChangeScheduled(address indexed adapter, uint256 activationTime);
    event AdapterChangeDelaySet(uint256 delay);

    /// @notice Emitted when a proof submission includes a manifest locator hint (LOW-004 remediation).
    /// @param proverSetDigest The keccak256 digest of the canonical prover manifest.
    /// @param metaLocator     Off-chain locator for the manifest data.
    event ManifestAnnounced(bytes32 indexed proverSetDigest, bytes metaLocator);

    // ── Constants ───────────────────────────────────────────────────────────────

    /// @dev Expected length of the public inputs ABI payload (7 × 32 = 224 bytes).
    uint256 private constant PUBLIC_INPUTS_LEN = 224;

    // ── Constants ───────────────────────────────────────────────────────────────

    /// @notice Minimum floor for `adapterChangeDelay`. Prevents setting a zero delay
    ///         which would allow instant adapter swaps (HI-001 remediation).
    uint256 public constant MIN_ADAPTER_DELAY = 1 days;

    // ── Storage ─────────────────────────────────────────────────────────────────

    IZkAggregatorVerifier public adapter;
    bytes32 public domainSeparator;
    uint256 public maxAcceptanceDelay;
    bool public permissionless;
    bool public paused;

    uint256 public nextWindowIndex;
    uint256 public lastL2EndBlock;

    /// @notice The expected l2Start for the genesis window (LOW-003 remediation).
    uint256 public immutable genesisL2Block;

    mapping(address => bool) public submitters;

    /// @notice Delay (seconds) before a scheduled adapter change can be activated.
    ///         Initialized to 1 day; configurable by owner with a floor of MIN_ADAPTER_DELAY.
    uint256 public adapterChangeDelay;

    /// @notice Address of the pending adapter (zero if no change is scheduled).
    address public pendingAdapter;

    /// @notice Timestamp at which the pending adapter change can be activated.
    uint256 public pendingAdapterActivation;

    // ── Constructor ─────────────────────────────────────────────────────────────

    /// @param _adapter            Address of the ZK adapter (must be non-zero).
    /// @param _domainSeparator    Domain separator binding proofs to this chain/deployment.
    /// @param _maxAcceptanceDelay Maximum age (seconds) of a window before it is rejected.
    /// @param _genesisL2Block     Expected l2Start for the genesis window (LOW-003 remediation).
    constructor(
        address _adapter,
        bytes32 _domainSeparator,
        uint256 _maxAcceptanceDelay,
        uint256 _genesisL2Block
    ) {
        if (_adapter == address(0)) revert AdapterZero();
        if (_maxAcceptanceDelay == 0) revert MaxAcceptanceDelayZero();
        adapter = IZkAggregatorVerifier(_adapter);
        domainSeparator = _domainSeparator;
        maxAcceptanceDelay = _maxAcceptanceDelay;
        adapterChangeDelay = 1 days;
        genesisL2Block = _genesisL2Block;
    }

    // ── Modifiers ───────────────────────────────────────────────────────────────

    modifier whenNotPaused() {
        if (paused) revert Paused();
        _;
    }

    // ── Admin ───────────────────────────────────────────────────────────────────

    /// @notice Pause or unpause the finalizer.
    function setPaused(bool _paused) external onlyOwner {
        paused = _paused;
        emit PausedSet(_paused);
    }

    /// @notice Toggle permissionless mode (anyone can submit).
    function setPermissionless(bool _permissionless) external onlyOwner {
        permissionless = _permissionless;
        emit PermissionlessSet(_permissionless);
    }

    /// @notice Grant or revoke submitter role.
    function setSubmitter(address account, bool allowed) external onlyOwner {
        submitters[account] = allowed;
        emit SubmitterSet(account, allowed);
    }

    /// @notice Update the maximum acceptance delay.
    function setMaxAcceptanceDelay(uint256 _delay) external onlyOwner {
        if (_delay == 0) revert MaxAcceptanceDelayZero();
        maxAcceptanceDelay = _delay;
        emit MaxAcceptanceDelaySet(_delay);
    }

    /// @notice Schedule a timelocked adapter change. The new adapter cannot be activated
    ///         until `adapterChangeDelay` seconds have passed. HI-001 remediation.
    /// @param _adapter The address of the new adapter to schedule.
    function scheduleAdapterChange(address _adapter) external onlyOwner {
        if (_adapter == address(0)) revert AdapterZero();
        pendingAdapter = _adapter;
        pendingAdapterActivation = block.timestamp + adapterChangeDelay;
        emit AdapterChangeScheduled(_adapter, pendingAdapterActivation);
    }

    /// @notice Activate a previously scheduled adapter change after the timelock.
    function activateAdapterChange() external onlyOwner {
        if (pendingAdapter == address(0)) revert NoPendingAdapter();
        if (block.timestamp < pendingAdapterActivation) revert TimelockActive(pendingAdapterActivation);
        adapter = IZkAggregatorVerifier(pendingAdapter);
        emit AdapterSet(pendingAdapter);
        pendingAdapter = address(0);
        pendingAdapterActivation = 0;
    }

    /// @notice Update the adapter change delay. Subject to a minimum floor of MIN_ADAPTER_DELAY.
    /// @param _delay New delay in seconds (must be >= MIN_ADAPTER_DELAY).
    function setAdapterChangeDelay(uint256 _delay) external onlyOwner {
        if (_delay < MIN_ADAPTER_DELAY) revert AdapterDelayTooShort(MIN_ADAPTER_DELAY, _delay);
        adapterChangeDelay = _delay;
        emit AdapterChangeDelaySet(_delay);
    }

    // ── Submission ──────────────────────────────────────────────────────────────

    /// @notice Submit a ZK validity proof for the next contiguous window.
    /// @param proof         Encoded proof bytes (format depends on the adapter).
    /// @param publicInputs  224-byte ABI-encoded public inputs.
    function submitZkValidityProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external whenNotPaused {
        _submit(proof, publicInputs);
    }

    /// @notice Submit with optional metadata locator (for indexers/watchers).
    ///         LOW-004 remediation: emits ManifestAnnounced with the proverSetDigest
    ///         decoded from the proof and the caller-supplied metaLocator.
    /// @param proof         Encoded proof bytes.
    /// @param publicInputs  224-byte ABI-encoded public inputs.
    /// @param metaLocator   Optional off-chain locator (capped at 96 bytes).
    function submitZkValidityProofWithMeta(
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes calldata metaLocator
    ) external whenNotPaused {
        if (metaLocator.length > 96) revert LocatorTooLong();
        bytes32 proverSetDigest = _submit(proof, publicInputs);
        emit ManifestAnnounced(proverSetDigest, metaLocator);
    }

    // ── Internal ────────────────────────────────────────────────────────────────

    /// @dev Core submission logic. Returns the proverSetDigest for optional event emission.
    ///      LOW-005 remediation: state updates occur before the external adapter.verify() call
    ///      to follow the Checks-Effects-Interactions pattern and prevent reentrancy.
    function _submit(
        bytes calldata proof,
        bytes calldata publicInputs
    ) internal returns (bytes32) {
        // Auth check
        if (!permissionless && !submitters[msg.sender] && msg.sender != owner()) {
            revert NotAuthorized();
        }

        // ABI length check (cheapest possible — pure calldata length comparison)
        if (publicInputs.length != PUBLIC_INPUTS_LEN) revert BadInputsLen();

        // Decode the seven public input words
        (
            bytes32 stfCommitment,
            uint256 l2Start,
            uint256 l2End,
            bytes32 outputRoot,
            bytes32 l1BlockHash,
            bytes32 inputDomainSeparator,
            uint256 windowCloseTimestamp
        ) = abi.decode(
            publicInputs,
            (bytes32, uint256, uint256, bytes32, bytes32, bytes32, uint256)
        );

        // ── Cheap validation first (comparisons before keccak/SLOAD) ────────
        // Domain binding — single SLOAD + comparison
        if (inputDomainSeparator != domainSeparator) revert DomainMismatch();

        // Window range — pure arithmetic comparison, no storage reads
        if (l2End <= l2Start) revert InvalidWindowRange();

        // Contiguity — single SLOAD + comparison
        // LOW-003 remediation: genesis window l2Start is validated against the constructor anchor.
        if (nextWindowIndex == 0) {
            if (l2Start != genesisL2Block) revert GenesisStartMismatch(genesisL2Block, l2Start);
        } else {
            if (l2Start != lastL2EndBlock) revert NotContiguous();
        }

        // Staleness — SLOAD + arithmetic
        if (maxAcceptanceDelay > 0 && block.timestamp > windowCloseTimestamp + maxAcceptanceDelay) {
            revert TooOld();
        }

        // ── Expensive validation (keccak256) after all cheap checks pass ────
        // MED-001: Defense-in-depth — verify stfCommitment binds to the decoded ABI content.
        // stfCommitment must equal keccak256(abi.encode(l2Start, l2End, outputRoot,
        // l1BlockHash, domainSeparator, windowCloseTimestamp)). This prevents a circuit
        // soundness bug from allowing fabricated commitments that don't match the payload.
        {
            bytes32 expectedStf = keccak256(
                abi.encode(l2Start, l2End, outputRoot, l1BlockHash, inputDomainSeparator, windowCloseTimestamp)
            );
            if (stfCommitment != expectedStf) revert StfBindingMismatch();
        }

        // ── Effects (LOW-005 CEI remediation) ─────────────────────────────────
        // Update state BEFORE the external adapter.verify() call to prevent
        // reentrancy from replaying the same window index.
        uint256 windowIndex = nextWindowIndex;
        nextWindowIndex = windowIndex + 1;
        lastL2EndBlock = l2End;

        // ── Interactions ──────────────────────────────────────────────────────
        (
            bool valid,
            bytes32 verifiedStfCommitment,
            bytes32 programVKey,
            bytes32 policyHash,
            bytes32 proverSetDigest
        ) = adapter.verify(proof, publicInputs);
        if (!valid) revert ProofInvalid();
        if (verifiedStfCommitment != stfCommitment) revert StfMismatch();

        // Emit events
        emit OutputProposed(windowIndex, outputRoot, l2Start, l2End, stfCommitment);
        emit ZkProofAccepted(windowIndex, programVKey, policyHash, proverSetDigest);

        return proverSetDigest;
    }
}
