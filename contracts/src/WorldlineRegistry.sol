// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "./utils/Ownable.sol";
import {Verifier} from "./zk/Verifier.sol";

/// @title WorldlineRegistry
/// @notice Stores metadata about available circuits, drivers, and plugins.
contract WorldlineRegistry is Ownable {
    // ---------------------------------------------------------------
    // Existence-check convention:
    //   - Circuit  → bytes(circuits[id].description).length == 0
    //   - Driver   → bytes(drivers[id].version).length == 0
    //   - Plugin   → plugins[id].implementation == address(0)
    // Each struct uses a non-default field as its sentinel value.
    // ---------------------------------------------------------------

    struct Circuit {
        bytes32 id;
        string description;
        address verifier;
        string abiURI;
    }

    struct Driver {
        bytes32 id;
        string version;
        string endpoint;
    }

    struct Plugin {
        bytes32 id;
        string version;
        address implementation;
        bytes32 circuitId;
        bool deprecated;
    }

    event CircuitRegistered(bytes32 indexed id, address verifier);
    event DriverRegistered(bytes32 indexed id, string version);
    event PluginRegistered(bytes32 indexed id, address implementation);
    event PluginDeprecated(bytes32 indexed id);
    event CompatFacadeSet(address indexed compat);

    mapping(bytes32 => Circuit) private circuits;
    mapping(bytes32 => Driver) private drivers;
    mapping(bytes32 => Plugin) private plugins;

    Verifier public immutable defaultVerifier;
    address public compatFacade;

    /// @param verifier Address of the default ZK verifier contract (must be non-zero).
    constructor(address verifier) {
        require(verifier != address(0), "invalid verifier");
        defaultVerifier = Verifier(verifier);
    }

    modifier onlyAdmin() {
        require(msg.sender == owner() || msg.sender == compatFacade, "not authorised");
        _;
    }

    /// @notice Update the compatibility facade address.
    /// @param compat Address of the new compat facade (address(0) to disable).
    function setCompatFacade(address compat) external onlyOwner {
        compatFacade = compat;
        emit CompatFacadeSet(compat);
    }

    /// @notice Register a new ZK circuit in the directory.
    /// @param id Unique circuit identifier.
    /// @param description Human-readable description (must be non-empty).
    /// @param verifier Per-circuit verifier override; address(0) falls back to defaultVerifier.
    /// @param abiURI URI pointing to the circuit ABI/artifact.
    function registerCircuit(
        bytes32 id,
        string calldata description,
        address verifier,
        string calldata abiURI
    ) external onlyAdmin {
        require(id != bytes32(0), "invalid circuit id");
        require(bytes(circuits[id].description).length == 0, "circuit exists");

        circuits[id] = Circuit({id: id, description: description, verifier: verifier, abiURI: abiURI});
        emit CircuitRegistered(id, verifier);
    }

    /// @notice Retrieve a registered circuit by ID.
    /// @param id The circuit identifier.
    /// @return The Circuit metadata struct.
    function getCircuit(bytes32 id) external view returns (Circuit memory) {
        Circuit memory circuit = circuits[id];
        require(bytes(circuit.description).length != 0, "circuit missing");
        return circuit;
    }

    /// @notice Register a new aggregator driver.
    /// @param id Unique driver identifier.
    /// @param version Semver version string.
    /// @param endpoint URL of the driver's RPC endpoint.
    function registerDriver(bytes32 id, string calldata version, string calldata endpoint) external onlyAdmin {
        require(id != bytes32(0), "invalid driver id");
        require(bytes(drivers[id].version).length == 0, "driver exists");
        drivers[id] = Driver({id: id, version: version, endpoint: endpoint});
        emit DriverRegistered(id, version);
    }

    /// @notice Retrieve a registered driver by ID.
    /// @param id The driver identifier.
    /// @return The Driver metadata struct.
    function getDriver(bytes32 id) external view returns (Driver memory) {
        Driver memory driver = drivers[id];
        require(bytes(driver.version).length != 0, "driver missing");
        return driver;
    }

    /// @notice Register a new prover plugin linked to an existing circuit.
    /// @param id Unique plugin identifier.
    /// @param version Semver version string.
    /// @param implementation Address of the plugin contract (must be non-zero).
    /// @param circuitId ID of the circuit this plugin proves (must already exist).
    function registerPlugin(
        bytes32 id,
        string calldata version,
        address implementation,
        bytes32 circuitId
    ) external onlyAdmin {
        require(id != bytes32(0), "invalid plugin id");
        require(implementation != address(0), "invalid implementation");
        require(!plugins[id].deprecated && plugins[id].implementation == address(0), "plugin exists");
        require(bytes(circuits[circuitId].description).length != 0, "circuit missing");

        plugins[id] = Plugin({
            id: id,
            version: version,
            implementation: implementation,
            circuitId: circuitId,
            deprecated: false
        });

        emit PluginRegistered(id, implementation);
    }

    /// @notice Mark a plugin as deprecated. It remains queryable but flagged.
    /// @param id The plugin identifier.
    function deprecatePlugin(bytes32 id) external onlyAdmin {
        Plugin storage plugin = plugins[id];
        require(plugin.implementation != address(0), "plugin missing");
        plugin.deprecated = true;
        emit PluginDeprecated(id);
    }

    /// @notice Retrieve a registered plugin by ID.
    /// @param id The plugin identifier.
    /// @return The Plugin metadata struct.
    function getPlugin(bytes32 id) external view returns (Plugin memory) {
        Plugin memory plugin = plugins[id];
        require(plugin.implementation != address(0), "plugin missing");
        return plugin;
    }

    /// @notice Verify a ZK proof against a registered circuit's verifier.
    /// @param circuitId The circuit to verify against.
    /// @param secret The private input (dev-mode only).
    /// @param publicHash The expected public commitment.
    /// @return True if verification succeeds; reverts otherwise.
    function verify(bytes32 circuitId, uint256 secret, uint256 publicHash) external view returns (bool) {
        Circuit memory circuit = circuits[circuitId];
        require(bytes(circuit.description).length != 0, "circuit missing");
        address verifier = circuit.verifier;
        if (verifier == address(0)) {
            verifier = address(defaultVerifier);
        }
        require(verifier != address(0), "no verifier configured");
        Verifier(verifier).verifyProof(secret, publicHash);
        return true;
    }
}
