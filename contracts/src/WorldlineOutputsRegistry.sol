// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "./utils/Ownable.sol";

/// @title WorldlineOutputsRegistry
/// @notice Timelocked registry for managing {programVKey, policyHash, oracle}
///         tuples per domain. Uses a two-step schedule/activate flow to ensure
///         changes are visible before taking effect.
contract WorldlineOutputsRegistry is Ownable {
    // ── Errors ──────────────────────────────────────────────────────────────────

    error TimelockNotElapsed();
    error NoPendingEntry();
    error TimelockTooShort(uint256 required, uint256 given);
    error NoActiveEntry();

    // ── Events ──────────────────────────────────────────────────────────────────

    event OutputScheduled(
        bytes32 indexed domainKey,
        bytes32 programVKey,
        bytes32 policyHash,
        address oracle,
        uint256 activationTime
    );

    event OutputActivated(
        bytes32 indexed domainKey,
        bytes32 programVKey,
        bytes32 policyHash,
        address oracle
    );

    event OutputRescheduled(
        bytes32 indexed domainKey,
        bytes32 programVKey,
        bytes32 policyHash,
        address oracle,
        uint256 activationTime
    );

    event MinTimelockSet(uint256 minTimelock);

    // ── Types ───────────────────────────────────────────────────────────────────

    struct OutputEntry {
        bytes32 programVKey;
        bytes32 policyHash;
        address oracle;
        bool active;
    }

    struct PendingEntry {
        bytes32 programVKey;
        bytes32 policyHash;
        address oracle;
        uint256 activationTime;
        bool exists;
    }

    // ── Storage ─────────────────────────────────────────────────────────────────

    /// @notice Absolute minimum floor for `minTimelock`. Prevents governance from
    ///         setting a dangerously short timelock (e.g. 1 second). HI-002 remediation.
    uint256 public constant MIN_TIMELOCK_FLOOR = 1 days;

    /// @notice Minimum timelock duration in seconds (must be >= MIN_TIMELOCK_FLOOR).
    uint256 public minTimelock;

    /// @notice Active entries keyed by keccak256(chainIdHash, domainTag).
    mapping(bytes32 => OutputEntry) public activeEntries;

    /// @notice Pending entries awaiting activation.
    mapping(bytes32 => PendingEntry) public pendingEntries;

    // ── Constructor ─────────────────────────────────────────────────────────────

    /// @param _minTimelock Minimum delay in seconds before a scheduled entry can be activated.
    ///                     Must be >= MIN_TIMELOCK_FLOOR (1 day).
    constructor(uint256 _minTimelock) {
        if (_minTimelock < MIN_TIMELOCK_FLOOR) revert TimelockTooShort(MIN_TIMELOCK_FLOOR, _minTimelock);
        minTimelock = _minTimelock;
    }

    // ── Admin ───────────────────────────────────────────────────────────────────

    /// @notice Update the minimum timelock duration.
    /// @dev The new value must be >= MIN_TIMELOCK_FLOOR (1 day) to prevent
    ///      governance from setting a dangerously short timelock. HI-002 remediation.
    function setMinTimelock(uint256 _minTimelock) external onlyOwner {
        if (_minTimelock < MIN_TIMELOCK_FLOOR) revert TimelockTooShort(MIN_TIMELOCK_FLOOR, _minTimelock);
        minTimelock = _minTimelock;
        emit MinTimelockSet(_minTimelock);
    }

    // ── Domain key helper ───────────────────────────────────────────────────────

    /// @notice Compute the domain key from chain ID hash and domain tag.
    function domainKey(
        bytes32 chainIdHash,
        bytes32 domainTag
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(chainIdHash, domainTag));
    }

    // ── Schedule ────────────────────────────────────────────────────────────────

    /// @notice Schedule a new output entry for a domain. Activation is delayed
    ///         by at least `minTimelock` seconds.
    /// @param _domainKey  The domain key (use `domainKey()` to compute).
    /// @param programVKey The program verifying key.
    /// @param policyHash  Hash of the canonical policy JSON.
    /// @param oracle      Address of the oracle/adapter for this domain.
    function schedule(
        bytes32 _domainKey,
        bytes32 programVKey,
        bytes32 policyHash,
        address oracle
    ) external onlyOwner {
        uint256 activationTime = block.timestamp + minTimelock;
        bool overwriting = pendingEntries[_domainKey].exists;

        pendingEntries[_domainKey] = PendingEntry({
            programVKey: programVKey,
            policyHash: policyHash,
            oracle: oracle,
            activationTime: activationTime,
            exists: true
        });

        if (overwriting) {
            emit OutputRescheduled(_domainKey, programVKey, policyHash, oracle, activationTime);
        } else {
            emit OutputScheduled(_domainKey, programVKey, policyHash, oracle, activationTime);
        }
    }

    // ── Activate ────────────────────────────────────────────────────────────────

    /// @notice Activate a previously scheduled entry after the timelock has elapsed.
    /// @param _domainKey The domain key to activate.
    function activate(bytes32 _domainKey) external {
        PendingEntry storage pending = pendingEntries[_domainKey];
        if (!pending.exists) revert NoPendingEntry();
        if (block.timestamp < pending.activationTime) revert TimelockNotElapsed();

        // Cache values before delete to avoid redundant storage reads
        bytes32 vkey = pending.programVKey;
        bytes32 policy = pending.policyHash;
        address oracleAddr = pending.oracle;

        activeEntries[_domainKey] = OutputEntry({
            programVKey: vkey,
            policyHash: policy,
            oracle: oracleAddr,
            active: true
        });

        delete pendingEntries[_domainKey];

        emit OutputActivated(_domainKey, vkey, policy, oracleAddr);
    }

    // ── View ────────────────────────────────────────────────────────────────────

    /// @notice Check if a domain has an active entry.
    function isActive(bytes32 _domainKey) external view returns (bool) {
        return activeEntries[_domainKey].active;
    }

    /// @notice Get the active entry for a domain.
    function getActiveEntry(
        bytes32 _domainKey
    ) external view returns (OutputEntry memory) {
        if (!activeEntries[_domainKey].active) revert NoActiveEntry();
        return activeEntries[_domainKey];
    }
}
