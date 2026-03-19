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

    // ── Constants ───────────────────────────────────────────────────────────────

    /// @dev Expected length of the public inputs ABI payload (7 × 32 = 224 bytes).
    uint256 private constant PUBLIC_INPUTS_LEN = 224;

    // ── Storage ─────────────────────────────────────────────────────────────────

    IZkAggregatorVerifier public adapter;
    bytes32 public domainSeparator;
    uint256 public maxAcceptanceDelay;
    bool public permissionless;
    bool public paused;

    uint256 public nextWindowIndex;
    uint256 public lastL2EndBlock;

    mapping(address => bool) public proposers;
    mapping(address => bool) public submitters;

    // ── Constructor ─────────────────────────────────────────────────────────────

    /// @param _adapter            Address of the ZK adapter (must be non-zero).
    /// @param _domainSeparator    Domain separator binding proofs to this chain/deployment.
    /// @param _maxAcceptanceDelay Maximum age (seconds) of a window before it is rejected.
    constructor(
        address _adapter,
        bytes32 _domainSeparator,
        uint256 _maxAcceptanceDelay
    ) {
        if (_adapter == address(0)) revert AdapterZero();
        adapter = IZkAggregatorVerifier(_adapter);
        domainSeparator = _domainSeparator;
        maxAcceptanceDelay = _maxAcceptanceDelay;
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
    }

    /// @notice Toggle permissionless mode (anyone can submit).
    function setPermissionless(bool _permissionless) external onlyOwner {
        permissionless = _permissionless;
    }

    /// @notice Grant or revoke proposer role.
    function setProposer(address account, bool allowed) external onlyOwner {
        proposers[account] = allowed;
    }

    /// @notice Grant or revoke submitter role.
    function setSubmitter(address account, bool allowed) external onlyOwner {
        submitters[account] = allowed;
    }

    /// @notice Update the maximum acceptance delay.
    function setMaxAcceptanceDelay(uint256 _delay) external onlyOwner {
        maxAcceptanceDelay = _delay;
    }

    /// @notice Replace the adapter.
    function setAdapter(address _adapter) external onlyOwner {
        if (_adapter == address(0)) revert AdapterZero();
        adapter = IZkAggregatorVerifier(_adapter);
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
    /// @param proof         Encoded proof bytes.
    /// @param publicInputs  224-byte ABI-encoded public inputs.
    /// @param metaLocator   Optional off-chain locator (capped at 96 bytes).
    function submitZkValidityProofWithMeta(
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes calldata metaLocator
    ) external whenNotPaused {
        require(metaLocator.length <= 96, "locator too long");
        _submit(proof, publicInputs);
    }

    // ── Internal ────────────────────────────────────────────────────────────────

    function _submit(
        bytes calldata proof,
        bytes calldata publicInputs
    ) internal {
        // Auth check
        if (!permissionless && !submitters[msg.sender] && msg.sender != owner()) {
            revert NotAuthorized();
        }

        // ABI length check
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

        // Domain binding
        if (inputDomainSeparator != domainSeparator) revert DomainMismatch();

        // Contiguity: l2Start must equal lastL2EndBlock (except for genesis window)
        if (nextWindowIndex > 0 && l2Start != lastL2EndBlock) revert NotContiguous();

        // Staleness
        if (maxAcceptanceDelay > 0 && block.timestamp > windowCloseTimestamp + maxAcceptanceDelay) {
            revert TooOld();
        }

        // Verify via adapter
        (
            bool valid,
            bytes32 verifiedStfCommitment,
            bytes32 programVKey,
            bytes32 policyHash,
            bytes32 proverSetDigest
        ) = adapter.verify(proof, publicInputs);
        require(valid, "proof invalid");
        require(verifiedStfCommitment == stfCommitment, "stf mismatch");

        // Suppress unused variable warnings — l1BlockHash and outputRoot are
        // bound inside publicInputs and verified through the adapter's
        // stfCommitment check. We decode them to ensure the ABI is well-formed
        // but do not need to reference them individually here.
        l1BlockHash;
        outputRoot;

        // Update state
        uint256 windowIndex = nextWindowIndex;
        nextWindowIndex = windowIndex + 1;
        lastL2EndBlock = l2End;

        // Emit events
        emit OutputProposed(windowIndex, outputRoot, l2Start, l2End, stfCommitment);
        emit ZkProofAccepted(windowIndex, programVKey, policyHash, proverSetDigest);
    }
}
