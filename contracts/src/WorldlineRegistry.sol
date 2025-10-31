// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "./utils/Ownable.sol";
import {Verifier} from "./zk/Verifier.sol";

/// @title WorldlineRegistry
/// @notice Stores metadata about available circuits, drivers, and plugins.
contract WorldlineRegistry is Ownable {
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

    constructor(address verifier) {
        defaultVerifier = Verifier(verifier);
    }

    modifier onlyAdmin() {
        require(msg.sender == owner() || msg.sender == compatFacade, "not authorised");
        _;
    }

    function setCompatFacade(address compat) external onlyOwner {
        compatFacade = compat;
        emit CompatFacadeSet(compat);
    }

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

    function getCircuit(bytes32 id) external view returns (Circuit memory) {
        Circuit memory circuit = circuits[id];
        require(bytes(circuit.description).length != 0, "circuit missing");
        return circuit;
    }

    function registerDriver(bytes32 id, string calldata version, string calldata endpoint) external onlyAdmin {
        require(id != bytes32(0), "invalid driver id");
        drivers[id] = Driver({id: id, version: version, endpoint: endpoint});
        emit DriverRegistered(id, version);
    }

    function getDriver(bytes32 id) external view returns (Driver memory) {
        Driver memory driver = drivers[id];
        require(bytes(driver.version).length != 0, "driver missing");
        return driver;
    }

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

    function deprecatePlugin(bytes32 id) external onlyAdmin {
        Plugin storage plugin = plugins[id];
        require(plugin.implementation != address(0), "plugin missing");
        plugin.deprecated = true;
        emit PluginDeprecated(id);
    }

    function getPlugin(bytes32 id) external view returns (Plugin memory) {
        Plugin memory plugin = plugins[id];
        require(plugin.implementation != address(0), "plugin missing");
        return plugin;
    }

    function verify(bytes32 circuitId, uint256 secret, uint256 publicHash) external view {
        Circuit memory circuit = circuits[circuitId];
        address verifier = circuit.verifier;
        if (verifier == address(0)) {
            verifier = address(defaultVerifier);
        }
        Verifier(verifier).verifyProof(secret, publicHash);
    }
}
