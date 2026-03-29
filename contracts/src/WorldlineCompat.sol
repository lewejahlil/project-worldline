// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

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

    /// @param _registry Address of the WorldlineRegistry this facade wraps.
    constructor(address _registry) {
        if (_registry == address(0)) revert RegistryZero();
        registry = WorldlineRegistry(_registry);
    }

    /// @notice Register a new circuit through the registry.
    /// @dev Caller must be the owner of this compat facade. The registry must
    ///      have this contract set as its compatFacade address.
    /// @param id          Unique identifier for the circuit.
    /// @param description Human-readable description of the circuit.
    /// @param verifier    Address of the on-chain verifier contract.
    /// @param abiURI      URI pointing to the circuit's ABI specification.
    function registerCircuit(
        bytes32 id,
        string calldata description,
        address verifier,
        string calldata abiURI
    ) external onlyOwner {
        registry.registerCircuit(id, description, verifier, abiURI);
    }

    /// @notice Register a new driver through the registry.
    /// @param id       Unique identifier for the driver.
    /// @param version  Semantic version string (e.g. "1.0.0").
    /// @param endpoint URL or URI of the driver's service endpoint.
    function registerDriver(
        bytes32 id,
        string calldata version,
        string calldata endpoint
    ) external onlyOwner {
        registry.registerDriver(id, version, endpoint);
    }

    /// @notice Register a new plugin through the registry.
    /// @param id             Unique identifier for the plugin.
    /// @param version        Semantic version string.
    /// @param implementation Address of the plugin's implementation contract.
    /// @param circuitId      Identifier of the circuit this plugin is bound to.
    function registerPlugin(
        bytes32 id,
        string calldata version,
        address implementation,
        bytes32 circuitId
    ) external onlyOwner {
        registry.registerPlugin(id, version, implementation, circuitId);
    }

    /// @notice Deprecate a plugin through the registry.
    /// @param id Identifier of the plugin to deprecate.
    function deprecatePlugin(bytes32 id) external onlyOwner {
        registry.deprecatePlugin(id);
    }

    /// @notice Read a circuit from the registry (view, no delegation needed).
    /// @param id Identifier of the circuit to retrieve.
    /// @return The Circuit struct containing description, verifier address, and ABI URI.
    function getCircuit(
        bytes32 id
    ) external view returns (WorldlineRegistry.Circuit memory) {
        return registry.getCircuit(id);
    }

    /// @notice Read a driver from the registry.
    /// @param id Identifier of the driver to retrieve.
    /// @return The Driver struct containing version and endpoint.
    function getDriver(
        bytes32 id
    ) external view returns (WorldlineRegistry.Driver memory) {
        return registry.getDriver(id);
    }

    /// @notice Read a plugin from the registry.
    /// @param id Identifier of the plugin to retrieve.
    /// @return The Plugin struct containing version, implementation, circuit binding, and deprecation status.
    function getPlugin(
        bytes32 id
    ) external view returns (WorldlineRegistry.Plugin memory) {
        return registry.getPlugin(id);
    }

}
