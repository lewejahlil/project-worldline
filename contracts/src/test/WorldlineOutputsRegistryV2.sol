// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {WorldlineOutputsRegistry} from "../WorldlineOutputsRegistry.sol";

/// @notice V2 test implementation — adds version() for upgrade verification.
/// @custom:oz-upgrades-from WorldlineOutputsRegistry
contract WorldlineOutputsRegistryV2 is WorldlineOutputsRegistry {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function version() external pure returns (uint8) {
        return 2;
    }
}
