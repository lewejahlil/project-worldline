// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "./utils/Ownable.sol";
import {Verifier} from "./zk/Verifier.sol";

/// @title WorldlineRegistry
/// @notice Stores metadata about available circuits, drivers, and plugins.
contract WorldlineRegistry is Ownable {
    // ── Errors ──────────────────────────────────────────────────────────────────

    error InvalidVerifier();
    error NotAuthorised();
    error InvalidCircuitId();
    error CircuitExists();
    error CircuitMissing();
    error InvalidDriverId();
    error DriverExists();
    error DriverMissing();
    error InvalidPluginId();
    error InvalidImplementation();
    error PluginExists();
    error PluginMissing();
    error NoVerifierConfigured();
    error DevOnly();
    error NoPendingFacade();
    error FacadeTimelockActive(uint256 activationTime);
    error FacadeDelayTooShort(uint256 required, uint256 given);

    // ── Types ───────────────────────────────────────────────────────────────────

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
    event CompatFacadeChangeScheduled(address indexed compat, uint256 activationTime);
    event FacadeChangeDelaySet(uint256 delay);

    mapping(bytes32 => Circuit) private circuits;
    mapping(bytes32 => Driver) private drivers;
    mapping(bytes32 => Plugin) private plugins;

    mapping(bytes32 => bool) private circuitExists;
    mapping(bytes32 => bool) private driverExists;
    mapping(bytes32 => bool) private pluginExists;

    /// @notice Minimum floor for `facadeChangeDelay`. MED-005 remediation.
    uint256 public constant MIN_FACADE_DELAY = 1 days;

    Verifier public immutable defaultVerifier;
    address public compatFacade;

    /// @notice Delay (seconds) before a scheduled facade change can be activated.
    uint256 public facadeChangeDelay;

    /// @notice Address of the pending compat facade (zero if no change scheduled).
    address public pendingCompatFacade;

    /// @notice Timestamp at which the pending facade change can be activated.
    uint256 public pendingFacadeActivation;

    /// @notice Whether a facade change has been scheduled (needed because address(0)
    ///         is a valid target to disable the facade).
    bool public facadeChangeScheduled;

    /// @param verifier Address of the default ZK verifier contract (must be non-zero).
    constructor(address verifier) {
        if (verifier == address(0)) revert InvalidVerifier();
        defaultVerifier = Verifier(verifier);
        facadeChangeDelay = 1 days;
    }

    modifier onlyAdmin() {
        if (msg.sender != owner() && msg.sender != compatFacade) revert NotAuthorised();
        _;
    }

    /// @notice Schedule a timelocked compat facade change. The new facade cannot be
    ///         activated until `facadeChangeDelay` seconds have passed.
    ///         Pass address(0) to schedule disabling the facade. MED-005 remediation.
    /// @param compat Address of the new compat facade to schedule.
    function scheduleCompatFacade(address compat) external onlyOwner {
        pendingCompatFacade = compat;
        pendingFacadeActivation = block.timestamp + facadeChangeDelay;
        facadeChangeScheduled = true;
        emit CompatFacadeChangeScheduled(compat, pendingFacadeActivation);
    }

    /// @notice Activate a previously scheduled compat facade change after the timelock.
    function activateCompatFacade() external onlyOwner {
        if (!facadeChangeScheduled) revert NoPendingFacade();
        if (block.timestamp < pendingFacadeActivation) revert FacadeTimelockActive(pendingFacadeActivation);
        compatFacade = pendingCompatFacade;
        emit CompatFacadeSet(pendingCompatFacade);
        pendingCompatFacade = address(0);
        pendingFacadeActivation = 0;
        facadeChangeScheduled = false;
    }

    /// @notice Update the facade change delay. Subject to a minimum floor of MIN_FACADE_DELAY.
    /// @param _delay New delay in seconds (must be >= MIN_FACADE_DELAY).
    function setFacadeChangeDelay(uint256 _delay) external onlyOwner {
        if (_delay < MIN_FACADE_DELAY) revert FacadeDelayTooShort(MIN_FACADE_DELAY, _delay);
        facadeChangeDelay = _delay;
        emit FacadeChangeDelaySet(_delay);
    }

    /// @notice Directly set the compat facade address (first-time wiring only).
    /// @dev This bypasses the timelock and should only be called once during initial
    ///      deployment to wire the facade. Once set, use scheduleCompatFacade/activateCompatFacade.
    ///      Reverts if a facade is already set.
    /// @param compat Address of the compat facade to set.
    function setCompatFacade(address compat) external onlyOwner {
        if (compatFacade != address(0)) revert FacadeTimelockActive(0);
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
        if (id == bytes32(0)) revert InvalidCircuitId();
        if (circuitExists[id]) revert CircuitExists();

        circuits[id] = Circuit({id: id, description: description, verifier: verifier, abiURI: abiURI});
        circuitExists[id] = true;
        emit CircuitRegistered(id, verifier);
    }

    /// @notice Retrieve a registered circuit by ID.
    /// @param id The circuit identifier.
    /// @return The Circuit metadata struct.
    function getCircuit(bytes32 id) external view returns (Circuit memory) {
        if (!circuitExists[id]) revert CircuitMissing();
        return circuits[id];
    }

    /// @notice Register a new aggregator driver.
    /// @param id Unique driver identifier.
    /// @param version Semver version string.
    /// @param endpoint URL of the driver's RPC endpoint.
    function registerDriver(bytes32 id, string calldata version, string calldata endpoint) external onlyAdmin {
        if (id == bytes32(0)) revert InvalidDriverId();
        if (driverExists[id]) revert DriverExists();
        drivers[id] = Driver({id: id, version: version, endpoint: endpoint});
        driverExists[id] = true;
        emit DriverRegistered(id, version);
    }

    /// @notice Retrieve a registered driver by ID.
    /// @param id The driver identifier.
    /// @return The Driver metadata struct.
    function getDriver(bytes32 id) external view returns (Driver memory) {
        if (!driverExists[id]) revert DriverMissing();
        return drivers[id];
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
        if (id == bytes32(0)) revert InvalidPluginId();
        if (implementation == address(0)) revert InvalidImplementation();
        if (pluginExists[id]) revert PluginExists();
        if (!circuitExists[circuitId]) revert CircuitMissing();

        plugins[id] = Plugin({
            id: id,
            version: version,
            implementation: implementation,
            circuitId: circuitId,
            deprecated: false
        });
        pluginExists[id] = true;

        emit PluginRegistered(id, implementation);
    }

    /// @notice Mark a plugin as deprecated. It remains queryable but flagged.
    /// @param id The plugin identifier.
    function deprecatePlugin(bytes32 id) external onlyAdmin {
        if (!pluginExists[id]) revert PluginMissing();
        Plugin storage plugin = plugins[id];
        plugin.deprecated = true;
        emit PluginDeprecated(id);
    }

    /// @notice Retrieve a registered plugin by ID.
    /// @param id The plugin identifier.
    /// @return The Plugin metadata struct.
    function getPlugin(bytes32 id) external view returns (Plugin memory) {
        if (!pluginExists[id]) revert PluginMissing();
        return plugins[id];
    }

    /// @notice Verify a ZK proof against a registered circuit's verifier.
    /// @param circuitId The circuit to verify against.
    /// @param secret The private input (dev-mode only).
    /// @param publicHash The expected public commitment.
    /// @return True if verification succeeds; reverts otherwise.
    /// @dev DEV-ONLY — This function exposes the raw secret on-chain and is restricted
    ///      to local devnets (chainid 31337) only. In production, proof verification
    ///      goes through the adapter interface, never this method. HI-004 remediation.
    function verify(bytes32 circuitId, uint256 secret, uint256 publicHash) external view returns (bool) {
        if (block.chainid != 31337) revert DevOnly();
        if (!circuitExists[circuitId]) revert CircuitMissing();
        Circuit memory circuit = circuits[circuitId];
        address verifier = circuit.verifier;
        if (verifier == address(0)) {
            verifier = address(defaultVerifier);
        }
        if (verifier == address(0)) revert NoVerifierConfigured();
        Verifier(verifier).verifyProof(secret, publicHash);
        return true;
    }
}
