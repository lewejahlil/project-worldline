// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface VmScript {
    function startBroadcast() external;
    function stopBroadcast() external;
}

contract Script {
    VmScript internal constant vm = VmScript(address(uint160(uint256(keccak256("hevm cheat code")))));
}
