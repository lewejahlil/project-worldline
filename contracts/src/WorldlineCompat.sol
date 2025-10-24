// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {WorldlineRegistry} from "./WorldlineRegistry.sol";

/// @title WorldlineCompat
/// @notice User-facing façade that presents a stable ABI for client SDKs. It simply
///         proxies calls to the underlying registry but keeps method signatures
///         backwards compatible with previous beta releases.
contract WorldlineCompat {
    WorldlineRegistry public immutable registry;

    constructor(WorldlineRegistry _registry) {
        registry = _registry;
    }

    function registerCircuit(
        bytes32 id,
        string calldata description,
        address verifier,
        string calldata abiURI
    ) external {
        registry.registerCircuit(id, description, verifier, abiURI);
    }

    function registerDriver(bytes32 id, string calldata version, string calldata endpoint) external {
        registry.registerDriver(id, version, endpoint);
    }

    function registerPlugin(
        bytes32 id,
        string calldata version,
        address implementation,
        bytes32 circuitId
    ) external {
        registry.registerPlugin(id, version, implementation, circuitId);
    }

    function deprecatePlugin(bytes32 id) external {
        registry.deprecatePlugin(id);
    }

    function getCircuit(bytes32 id) external view returns (WorldlineRegistry.Circuit memory) {
        return registry.getCircuit(id);
    }

    function getDriver(bytes32 id) external view returns (WorldlineRegistry.Driver memory) {
        return registry.getDriver(id);
    }

    function getPlugin(bytes32 id) external view returns (WorldlineRegistry.Plugin memory) {
        return registry.getPlugin(id);
    }

    function verify(bytes32 circuitId, uint256 secret, uint256 publicHash) external view {
        registry.verify(circuitId, secret, publicHash);
    }
}
