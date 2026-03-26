// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "./utils/Ownable.sol";
import {WorldlineRegistry} from "./WorldlineRegistry.sol";

/// @title WorldlineCompat
/// @notice Thin compatibility facade that delegates to WorldlineRegistry using
///         stable method signatures. Legacy callers interact with this contract
///         instead of the registry directly, allowing the registry to evolve its
///         internal interface without breaking existing integrations.
contract WorldlineCompat is Ownable {
    WorldlineRegistry public immutable registry;

    error RegistryZero();
    error DevOnly();

    /// @param _registry Address of the WorldlineRegistry this facade wraps.
    constructor(address _registry) {
        if (_registry == address(0)) revert RegistryZero();
        registry = WorldlineRegistry(_registry);
    }

    /// @notice Register a new circuit through the registry.
    /// @dev Caller must be the owner of this compat facade. The registry must
    ///      have this contract set as its compatFacade address.
    function registerCircuit(
        bytes32 id,
        string calldata description,
        address verifier,
        string calldata abiURI
    ) external onlyOwner {
        registry.registerCircuit(id, description, verifier, abiURI);
    }

    /// @notice Register a new driver through the registry.
    function registerDriver(
        bytes32 id,
        string calldata version,
        string calldata endpoint
    ) external onlyOwner {
        registry.registerDriver(id, version, endpoint);
    }

    /// @notice Register a new plugin through the registry.
    function registerPlugin(
        bytes32 id,
        string calldata version,
        address implementation,
        bytes32 circuitId
    ) external onlyOwner {
        registry.registerPlugin(id, version, implementation, circuitId);
    }

    /// @notice Deprecate a plugin through the registry.
    function deprecatePlugin(bytes32 id) external onlyOwner {
        registry.deprecatePlugin(id);
    }

    /// @notice Read a circuit from the registry (view, no delegation needed).
    function getCircuit(
        bytes32 id
    ) external view returns (WorldlineRegistry.Circuit memory) {
        return registry.getCircuit(id);
    }

    /// @notice Read a driver from the registry.
    function getDriver(
        bytes32 id
    ) external view returns (WorldlineRegistry.Driver memory) {
        return registry.getDriver(id);
    }

    /// @notice Read a plugin from the registry.
    function getPlugin(
        bytes32 id
    ) external view returns (WorldlineRegistry.Plugin memory) {
        return registry.getPlugin(id);
    }

    /// @notice Verify a ZK proof through the registry.
    /// @dev DEV-ONLY — restricted to local devnets (chainid 31337). HI-004 remediation.
    function verify(
        bytes32 circuitId,
        uint256 secret,
        uint256 publicHash
    ) external view returns (bool) {
        if (block.chainid != 31337) revert DevOnly();
        return registry.verify(circuitId, secret, publicHash);
    }
}
