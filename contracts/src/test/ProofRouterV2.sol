// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ProofRouter} from "../ProofRouter.sol";

/// @notice V2 test implementation — adds version() for upgrade verification.
/// @custom:oz-upgrades-from ProofRouter
contract ProofRouterV2 is ProofRouter {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function version() external pure returns (uint8) {
        return 2;
    }
}
