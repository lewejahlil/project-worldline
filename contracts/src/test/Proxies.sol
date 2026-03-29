// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Imported so Hardhat compiles the ERC1967Proxy artifact, which is needed by
// devnet/smoke.ts to deploy UUPS proxies without the hardhat-upgrades plugin.
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
