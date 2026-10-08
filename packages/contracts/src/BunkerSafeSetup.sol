// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IBunkerRotationGuard {
    function initialize(address[20] calldata owners) external;
}

interface ISafeGuardManager {
    function setGuard(address guard) external;
}

/// @notice One-shot setup helper executed by delegatecall during Safe.setup.
/// @dev Runs in the Safe context, so external calls originate from the Safe itself.
contract BunkerSafeSetup {
    function setup(address guard, address[20] calldata owners) external {
        if (guard == address(0) || guard.code.length == 0) revert();
        IBunkerRotationGuard(guard).initialize(owners);
        ISafeGuardManager(address(this)).setGuard(guard);
    }
}
