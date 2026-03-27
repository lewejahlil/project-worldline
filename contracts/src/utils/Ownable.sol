// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Two-Step Ownable
/// @notice Minimal two-step ownership transfer. The new owner must explicitly call
///         `acceptOwnership()` to complete the transfer, preventing accidental transfers
///         to wrong addresses.
/// @dev HI-003 remediation: replaces single-step transfer with two-step pattern.
abstract contract Ownable {
    // ── Custom errors ────────────────────────────────────────────────────────

    error NotOwner();
    error NotPendingOwner();
    error NoPendingTransfer();
    error NewOwnerIsZero();

    // ── Events ───────────────────────────────────────────────────────────────

    /// @notice Emitted when a two-step ownership transfer is initiated.
    event OwnershipTransferStarted(address indexed currentOwner, address indexed newOwner);

    /// @notice Emitted when ownership is fully transferred (after acceptance).
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // ── Storage ──────────────────────────────────────────────────────────────

    address private _owner;
    address private _pendingOwner;

    // ── Constructor ──────────────────────────────────────────────────────────

    constructor() {
        _owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    // ── Modifiers ────────────────────────────────────────────────────────────

    modifier onlyOwner() {
        if (msg.sender != _owner) revert NotOwner();
        _;
    }

    // ── Views ────────────────────────────────────────────────────────────────

    /// @notice Returns the current owner address.
    function owner() public view returns (address) {
        return _owner;
    }

    /// @notice Returns the pending owner address (zero if no transfer is pending).
    function pendingOwner() public view returns (address) {
        return _pendingOwner;
    }

    // ── Two-step transfer ────────────────────────────────────────────────────

    /// @notice Initiate an ownership transfer. The new owner must call `acceptOwnership()`
    ///         to complete the transfer. Does NOT change `_owner` until accepted.
    /// @param newOwner The address that will become the new owner after acceptance.
    function transferOwnership(address newOwner) public onlyOwner {
        if (newOwner == address(0)) revert NewOwnerIsZero();
        _pendingOwner = newOwner;
        emit OwnershipTransferStarted(_owner, newOwner);
    }

    /// @notice Complete a pending ownership transfer. Callable only by the pending owner.
    function acceptOwnership() public {
        if (_pendingOwner == address(0)) revert NoPendingTransfer();
        if (msg.sender != _pendingOwner) revert NotPendingOwner();
        address oldOwner = _owner;
        _owner = _pendingOwner;
        _pendingOwner = address(0);
        emit OwnershipTransferred(oldOwner, msg.sender);
    }
}
