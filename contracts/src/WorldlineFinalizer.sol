// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {IZkAggregatorVerifier} from "./interfaces/IZkAggregatorVerifier.sol";
import {IProofRouter} from "./interfaces/IProofRouter.sol";
import {BlobVerifier} from "./blob/BlobVerifier.sol";
import {BlobKzgVerifier} from "./blob/BlobKzgVerifier.sol";

/// @title WorldlineFinalizer
/// @notice Accepts one ZK proof per contiguous window, verifies it via an adapter,
///         and emits canonical finality events. Enforces domain binding, contiguity,
///         and staleness constraints as specified in the Worldline technical spec.
/// @custom:oz-upgrades-from WorldlineFinalizer
contract WorldlineFinalizer is Initializable, Ownable2StepUpgradeable, UUPSUpgradeable {
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
    error BlobKzgVerifierZero();
    error ProofRouterZero();
    error UnsupportedProofSystem(uint8 proofSystemId);
    error NoPendingBlobKzgVerifier();
    error NoPendingDomainSeparator();
    error NoPendingGenesisL2Block();
    error ProofRouterAlreadySet();
    error NoPendingProofRouter();

    // ── Events ──────────────────────────────────────────────────────────────────

    /// @notice Emitted when a window output is finalized.
    event OutputProposed(
        uint256 indexed windowIndex, bytes32 outputRoot, uint256 l2Start, uint256 l2End, bytes32 stfCommitment
    );

    /// @notice Emitted when a ZK proof is accepted for a window.
    event ZkProofAccepted(
        uint256 indexed windowIndex, bytes32 programVKey, bytes32 policyHash, bytes32 proverSetDigest
    );

    event PausedSet(bool paused);
    event PermissionlessSet(bool permissionless);
    event SubmitterSet(address indexed account, bool allowed);
    event MaxAcceptanceDelaySet(uint256 delay);
    event AdapterSet(address indexed adapter);
    event AdapterChangeScheduled(address indexed adapter, uint256 activationTime);
    event AdapterChangeDelaySet(uint256 delay);

    /// @notice Emitted when a proof is consumed for a window, providing an explicit
    ///         on-chain audit trail for proof deduplication (NUL-1 hardening).
    /// @param windowIndex The sequential window index this proof was consumed for.
    /// @param proofHash   keccak256 of the raw proof bytes.
    event ProofConsumed(uint256 indexed windowIndex, bytes32 proofHash);

    /// @notice Emitted when a proof submission includes a manifest locator hint (LOW-004 remediation).
    /// @param proverSetDigest The keccak256 digest of the canonical prover manifest.
    /// @param metaLocator     Off-chain locator for the manifest data.
    event ManifestAnnounced(bytes32 indexed proverSetDigest, bytes metaLocator);
    event BlobKzgVerifierSet(address indexed verifier);
    event BlobProofSubmitted(uint256 indexed windowIndex, bytes32 versionedHash, bytes32 blobDataHash);
    event ProofRouterSet(address indexed proofRouter);
    event BlobKzgVerifierChangeScheduled(address indexed verifier, uint256 activationTime);
    event DomainSeparatorChangeScheduled(bytes32 domainSeparator, uint256 activationTime);
    event DomainSeparatorSet(bytes32 domainSeparator);
    event GenesisL2BlockChangeScheduled(uint256 genesisL2Block, uint256 activationTime);
    event GenesisL2BlockSet(uint256 genesisL2Block);
    event ProofRouterChangeScheduled(address indexed proofRouter, uint256 activationTime);
    /// @notice Emitted when an upgrade is authorized. Complements the ERC1967 `Upgraded`
    ///         event with explicit authorizer attribution (L-01 remediation).
    event UpgradeAuthorized(address indexed newImplementation, address indexed authorizer);

    // ── Constants ───────────────────────────────────────────────────────────────

    /// @dev Expected length of the public inputs ABI payload (7 × 32 = 224 bytes).
    uint256 private constant PUBLIC_INPUTS_LEN = 224;

    /// @dev Expected length of a KZG commitment (48 bytes). Used to distinguish
    ///      KZG mode from hash-only mode in submitZkValidityProofWithBlob().
    uint256 private constant KZG_COMMITMENT_LENGTH = 48;

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
    uint256 public genesisL2Block;

    mapping(address => bool) public submitters;

    /// @notice Delay (seconds) before a scheduled adapter change can be activated.
    ///         Initialized to 1 day; configurable by owner with a floor of MIN_ADAPTER_DELAY.
    uint256 public adapterChangeDelay;

    /// @notice Address of the pending adapter (zero if no change is scheduled).
    address public pendingAdapter;

    /// @notice Timestamp at which the pending adapter change can be activated.
    uint256 public pendingAdapterActivation;

    /// @notice Optional BlobKzgVerifier for EIP-4844 blob-carrying submissions.
    BlobKzgVerifier public blobKzgVerifier;

    /// @notice Optional ProofRouter for multi-proof-system routing.
    ///         When set, submitZkValidityProofRouted() dispatches to this router
    ///         instead of calling the default adapter directly.
    IProofRouter public proofRouter;

    // ── New storage appended after existing storage (UUPS upgrade) ──────────────

    bool public blobKzgVerifierChangeScheduled;
    address public pendingBlobKzgVerifier;
    uint256 public pendingBlobKzgVerifierActivation;

    // domainSeparator timelock
    bytes32 public pendingDomainSeparator;
    uint256 public pendingDomainSeparatorActivation;
    bool public domainSeparatorChangeScheduled;

    // genesisL2Block timelock
    uint256 public pendingGenesisL2Block;
    uint256 public pendingGenesisL2BlockActivation;
    bool public genesisL2BlockChangeScheduled;

    // proofRouter timelock
    bool public proofRouterChangeScheduled;
    address public pendingProofRouter;
    uint256 public pendingProofRouterActivation;

    /// @dev Storage gap to allow future upgrades to add variables without shifting slots.
    ///      Slots 0–21 are used (22 total); gap fills to 50.
    uint256[28] private __gap;

    // ── Constructor ─────────────────────────────────────────────────────────────

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // ── Initializer ─────────────────────────────────────────────────────────────

    /// @param _adapter            Address of the ZK adapter (must be non-zero).
    /// @param _domainSeparator    Domain separator binding proofs to this chain/deployment.
    /// @param _maxAcceptanceDelay Maximum age (seconds) of a window before it is rejected.
    /// @param _genesisL2Block     Expected l2Start for the genesis window (LOW-003 remediation).
    /// @param _blobKzgVerifier    Optional BlobKzgVerifier address (pass address(0) to skip).
    function initialize(
        address _adapter,
        bytes32 _domainSeparator,
        uint256 _maxAcceptanceDelay,
        uint256 _genesisL2Block,
        address _blobKzgVerifier
    ) external initializer {
        __Ownable_init(msg.sender);
        __Ownable2Step_init();
        if (_adapter == address(0)) revert AdapterZero();
        if (_maxAcceptanceDelay == 0) revert MaxAcceptanceDelayZero();
        adapter = IZkAggregatorVerifier(_adapter);
        domainSeparator = _domainSeparator;
        maxAcceptanceDelay = _maxAcceptanceDelay;
        adapterChangeDelay = 1 days;
        genesisL2Block = _genesisL2Block;
        if (_blobKzgVerifier != address(0)) {
            blobKzgVerifier = BlobKzgVerifier(_blobKzgVerifier);
            emit BlobKzgVerifierSet(_blobKzgVerifier);
        }
    }

    // ── UUPS ────────────────────────────────────────────────────────────────────

    function _authorizeUpgrade(address newImpl) internal override onlyOwner {
        emit UpgradeAuthorized(newImpl, msg.sender);
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

    /// @notice Schedule a timelocked BlobKzgVerifier change.
    ///         Pass address(0) to schedule disabling the verifier.
    function scheduleBlobKzgVerifierChange(address _verifier) external onlyOwner {
        pendingBlobKzgVerifier = _verifier;
        pendingBlobKzgVerifierActivation = block.timestamp + adapterChangeDelay;
        blobKzgVerifierChangeScheduled = true;
        emit BlobKzgVerifierChangeScheduled(_verifier, pendingBlobKzgVerifierActivation);
    }

    /// @notice Activate a previously scheduled BlobKzgVerifier change.
    function activateBlobKzgVerifierChange() external onlyOwner {
        if (!blobKzgVerifierChangeScheduled) revert NoPendingBlobKzgVerifier();
        if (block.timestamp < pendingBlobKzgVerifierActivation) {
            revert TimelockActive(pendingBlobKzgVerifierActivation);
        }
        blobKzgVerifier = BlobKzgVerifier(pendingBlobKzgVerifier);
        emit BlobKzgVerifierSet(pendingBlobKzgVerifier);
        pendingBlobKzgVerifier = address(0);
        pendingBlobKzgVerifierActivation = 0;
        blobKzgVerifierChangeScheduled = false;
    }

    /// @notice Schedule a timelocked domainSeparator change.
    function scheduleDomainSeparatorChange(bytes32 _domainSeparator) external onlyOwner {
        pendingDomainSeparator = _domainSeparator;
        pendingDomainSeparatorActivation = block.timestamp + adapterChangeDelay;
        domainSeparatorChangeScheduled = true;
        emit DomainSeparatorChangeScheduled(_domainSeparator, pendingDomainSeparatorActivation);
    }

    /// @notice Activate a previously scheduled domainSeparator change.
    function activateDomainSeparatorChange() external onlyOwner {
        if (!domainSeparatorChangeScheduled) revert NoPendingDomainSeparator();
        if (block.timestamp < pendingDomainSeparatorActivation) {
            revert TimelockActive(pendingDomainSeparatorActivation);
        }
        domainSeparator = pendingDomainSeparator;
        emit DomainSeparatorSet(pendingDomainSeparator);
        pendingDomainSeparator = bytes32(0);
        pendingDomainSeparatorActivation = 0;
        domainSeparatorChangeScheduled = false;
    }

    /// @notice Schedule a timelocked genesisL2Block change.
    function scheduleGenesisL2BlockChange(uint256 _genesisL2Block) external onlyOwner {
        pendingGenesisL2Block = _genesisL2Block;
        pendingGenesisL2BlockActivation = block.timestamp + adapterChangeDelay;
        genesisL2BlockChangeScheduled = true;
        emit GenesisL2BlockChangeScheduled(_genesisL2Block, pendingGenesisL2BlockActivation);
    }

    /// @notice Activate a previously scheduled genesisL2Block change.
    function activateGenesisL2BlockChange() external onlyOwner {
        if (!genesisL2BlockChangeScheduled) revert NoPendingGenesisL2Block();
        if (block.timestamp < pendingGenesisL2BlockActivation) revert TimelockActive(pendingGenesisL2BlockActivation);
        genesisL2Block = pendingGenesisL2Block;
        emit GenesisL2BlockSet(pendingGenesisL2Block);
        pendingGenesisL2Block = 0;
        pendingGenesisL2BlockActivation = 0;
        genesisL2BlockChangeScheduled = false;
    }

    /// @notice Wire the ProofRouter for the first time (first-time only, no timelock).
    ///         Once set, use scheduleProofRouterChange / activateProofRouterChange.
    function setProofRouter(address _proofRouter) external onlyOwner {
        if (address(proofRouter) != address(0)) revert ProofRouterAlreadySet();
        if (_proofRouter == address(0)) revert ProofRouterZero();
        proofRouter = IProofRouter(_proofRouter);
        emit ProofRouterSet(_proofRouter);
    }

    /// @notice Schedule a timelocked ProofRouter change.
    ///         Pass address(0) to schedule disabling the router.
    function scheduleProofRouterChange(address _proofRouter) external onlyOwner {
        pendingProofRouter = _proofRouter;
        pendingProofRouterActivation = block.timestamp + adapterChangeDelay;
        proofRouterChangeScheduled = true;
        emit ProofRouterChangeScheduled(_proofRouter, pendingProofRouterActivation);
    }

    /// @notice Activate a previously scheduled ProofRouter change after the timelock.
    function activateProofRouterChange() external onlyOwner {
        if (!proofRouterChangeScheduled) revert NoPendingProofRouter();
        if (block.timestamp < pendingProofRouterActivation) revert TimelockActive(pendingProofRouterActivation);
        proofRouter = IProofRouter(pendingProofRouter);
        emit ProofRouterSet(pendingProofRouter);
        pendingProofRouter = address(0);
        pendingProofRouterActivation = 0;
        proofRouterChangeScheduled = false;
    }

    // ── Submission ──────────────────────────────────────────────────────────────

    /// @notice Submit a ZK validity proof for the next contiguous window.
    /// @param proof         Encoded proof bytes (format depends on the adapter).
    /// @param publicInputs  224-byte ABI-encoded public inputs.
    function submitZkValidityProof(bytes calldata proof, bytes calldata publicInputs) external whenNotPaused {
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

    /// @notice Submit a ZK validity proof via the ProofRouter routing layer.
    ///         Dispatches to the adapter registered for the given proofSystemId.
    ///         Enforces the same domain, contiguity, and staleness constraints as
    ///         submitZkValidityProof(). Requires proofRouter to be configured.
    /// @param proofSystemId  Numeric identifier of the proof system (1=Groth16, 2=Plonk, 3=Halo2).
    /// @param proof          Encoded proof bytes (adapter-specific format).
    /// @param publicInputs   224-byte ABI-encoded public inputs.
    function submitZkValidityProofRouted(uint8 proofSystemId, bytes calldata proof, bytes calldata publicInputs)
        external
        whenNotPaused
    {
        if (address(proofRouter) == address(0)) revert ProofRouterZero();
        _submitRouted(proofSystemId, proof, publicInputs);
    }

    /// @notice Submit a ZK validity proof carried in an EIP-4844 blob transaction.
    ///         Verifies the blob via BlobKzgVerifier before accepting the proof batch.
    ///         If blobKzgVerifier is not set, falls back to hash-only verification
    ///         via the BlobVerifier library.
    /// @param proof              Encoded proof bytes.
    /// @param publicInputs       224-byte ABI-encoded public inputs.
    /// @param expectedBlobHash   Expected versioned hash of blob at blobIndex.
    /// @param blobDataHash       Hash of the actual blob data payload (for indexer reference).
    /// @param blobIndex          Index of the blob in the transaction sidecar.
    /// @param openingPoint       z value for KZG point evaluation (ignored in hash-only mode).
    /// @param claimedValue       y value: claimed evaluation p(z) = y (ignored in hash-only mode).
    /// @param commitment         KZG commitment, 48 bytes (ignored in hash-only mode).
    /// @param kzgProof           KZG proof, 48 bytes (ignored in hash-only mode).
    /// @param batchId            Proof batch identifier for the BlobVerified event.
    /// @param maxBlobBaseFee     Maximum blob base fee caller accepts (wei).
    /// @dev Verification mode is determined at runtime:
    ///      - KZG mode: used when blobKzgVerifier is set AND commitment is 48 bytes.
    ///      - Hash-only mode: used when blobKzgVerifier is address(0) OR commitment
    ///        is not 48 bytes. In hash-only mode, expectedBlobHash must match blobhash(0).
    ///      Callers that always want KZG verification should call BlobKzgVerifier directly
    ///      and revert if the verifier is not set.
    function submitZkValidityProofWithBlob(
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 expectedBlobHash,
        bytes32 blobDataHash,
        uint256 blobIndex,
        bytes32 openingPoint,
        bytes32 claimedValue,
        bytes calldata commitment,
        bytes calldata kzgProof,
        bytes32 batchId,
        uint256 maxBlobBaseFee
    ) external whenNotPaused {
        // KZG mode: verifier is set AND commitment is the expected 48-byte length.
        // Falls back to hash-only if verifier is not configured or commitment is absent/malformed.
        if (address(blobKzgVerifier) != address(0) && commitment.length == KZG_COMMITMENT_LENGTH) {
            blobKzgVerifier.verifyBlob(
                blobIndex, openingPoint, claimedValue, commitment, kzgProof, batchId, maxBlobBaseFee
            );
        } else {
            BlobVerifier.verifyBlobHash(blobIndex, expectedBlobHash);
        }

        _submit(proof, publicInputs);

        bytes32 versionedHash = blobhash(blobIndex);
        emit BlobProofSubmitted(nextWindowIndex - 1, versionedHash, blobDataHash);
    }

    // ── Internal ────────────────────────────────────────────────────────────────

    /// @dev Shared validation and state update for all submission paths.
    ///      Performs auth, ABI decoding, domain binding, contiguity, staleness,
    ///      and STF binding checks, then updates state (CEI pattern — LOW-005).
    ///      Returns decoded values needed by the caller's verification step.
    struct ValidatedSubmission {
        bytes32 stfCommitment;
        uint256 windowIndex;
        uint256 l2Start;
        uint256 l2End;
        bytes32 outputRoot;
    }

    function _validateAndPrepare(bytes calldata publicInputs) internal returns (ValidatedSubmission memory v) {
        // Auth check
        if (!permissionless && !submitters[msg.sender] && msg.sender != owner()) {
            revert NotAuthorized();
        }

        // ABI length check (cheapest possible — pure calldata length comparison)
        if (publicInputs.length != PUBLIC_INPUTS_LEN) revert BadInputsLen();

        // Decode the seven public input words
        uint256 l2Start;
        uint256 l2End;
        bytes32 outputRoot;
        bytes32 l1BlockHash;
        bytes32 inputDomainSeparator;
        uint256 windowCloseTimestamp;
        (v.stfCommitment, l2Start, l2End, outputRoot, l1BlockHash, inputDomainSeparator, windowCloseTimestamp) =
            abi.decode(publicInputs, (bytes32, uint256, uint256, bytes32, bytes32, bytes32, uint256));

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
        {
            bytes32 expectedStf = keccak256(
                abi.encode(l2Start, l2End, outputRoot, l1BlockHash, inputDomainSeparator, windowCloseTimestamp)
            );
            if (v.stfCommitment != expectedStf) revert StfBindingMismatch();
        }

        // ── Effects (LOW-005 CEI remediation) ─────────────────────────────────
        // Update state BEFORE the external verify() call to prevent
        // reentrancy from replaying the same window index.
        v.windowIndex = nextWindowIndex;
        nextWindowIndex = v.windowIndex + 1;
        lastL2EndBlock = l2End;

        v.l2Start = l2Start;
        v.l2End = l2End;
        v.outputRoot = outputRoot;
    }

    /// @dev Emits the standard triple of events after successful verification.
    function _emitProofEvents(
        ValidatedSubmission memory v,
        bytes32 programVKey,
        bytes32 policyHash,
        bytes32 proverSetDigest,
        bytes calldata proof
    ) internal {
        emit OutputProposed(v.windowIndex, v.outputRoot, v.l2Start, v.l2End, v.stfCommitment);
        emit ZkProofAccepted(v.windowIndex, programVKey, policyHash, proverSetDigest);
        emit ProofConsumed(v.windowIndex, keccak256(proof));
    }

    /// @dev Core submission logic. Returns the proverSetDigest for optional event emission.
    function _submit(bytes calldata proof, bytes calldata publicInputs) internal returns (bytes32) {
        ValidatedSubmission memory v = _validateAndPrepare(publicInputs);

        // ── Interactions ──────────────────────────────────────────────────────
        (bool valid, bytes32 verifiedStfCommitment, bytes32 programVKey, bytes32 policyHash, bytes32 proverSetDigest) =
            adapter.verify(proof, publicInputs);
        if (!valid) revert ProofInvalid();
        if (verifiedStfCommitment != v.stfCommitment) revert StfMismatch();

        _emitProofEvents(v, programVKey, policyHash, proverSetDigest, proof);
        return proverSetDigest;
    }

    /// @dev Routed submission logic. Dispatches verification through the ProofRouter
    ///      instead of calling the default adapter directly.
    function _submitRouted(uint8 proofSystemId, bytes calldata proof, bytes calldata publicInputs)
        internal
        returns (bytes32)
    {
        ValidatedSubmission memory v = _validateAndPrepare(publicInputs);

        // ── Interactions: route through ProofRouter ───────────────────────────
        (bool valid, bytes32 verifiedStfCommitment, bytes32 programVKey, bytes32 policyHash, bytes32 proverSetDigest) =
            proofRouter.routeProofAggregated(proofSystemId, proof, publicInputs);
        if (!valid) revert ProofInvalid();
        if (verifiedStfCommitment != v.stfCommitment) revert StfMismatch();

        _emitProofEvents(v, programVKey, policyHash, proverSetDigest, proof);
        return proverSetDigest;
    }
}
