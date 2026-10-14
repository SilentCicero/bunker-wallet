// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Safe} from "@safe-global/safe-contracts/contracts/Safe.sol";
import {SafeProxyFactory} from "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import {BunkerHybridRotationGuard} from "./BunkerHybridRotationGuard.sol";
import {HybridSafeOwner, C10SafeOwner, MLDSA44SafeOwner} from "./HybridSafeOwner.sol";

/// @dev No user-chosen delegatecall target/data; this helper ONLY installs its immutable guard.
contract BunkerHybridSetup {
    address public immutable guard;
    address public immutable proxyFactory;

    constructor(address guard_, address proxyFactory_) {
        require(block.chainid == 31337);
        guard = guard_;
        proxyFactory = proxyFactory_;
    }

    function install() external {
        require(block.chainid == 31337 && msg.sender == proxyFactory);
        Safe(payable(address(this))).setGuard(guard);
    }
}

/// @notice Local research only. Fixture admission is NOT ML-DSA public-key validation.
contract BunkerHybridFactory {
    struct Dependency {
        address target;
        bytes32 codeHash;
    }

    struct Key {
        uint256 algorithm;
        bytes32 seed;
        bytes32 root;
        address blob;
    }
    address public immutable singleton;
    bytes32 public immutable singletonCodeHash;
    SafeProxyFactory public immutable proxyFactory;
    bytes32 public immutable proxyFactoryCodeHash;
    BunkerHybridRotationGuard public immutable guard;
    bytes32 public immutable guardCodeHash;
    BunkerHybridSetup public immutable setup;
    bytes32 public immutable setupCodeHash;
    address public immutable c10Verifier;
    bytes32 public immutable c10VerifierCodeHash;
    address public immutable mldsaVerifier;
    bytes32 public immutable mldsaVerifierCodeHash;
    // Constructor-only finite local fixture allowlist. Empty list disables ML-DSA creation.
    mapping(bytes32 => bool) public admittedLocalFixture;
    mapping(address => bytes32) public adapterCodeHash;
    mapping(address => bool) public createdSafe;
    error Policy();
    event Created(address indexed safe, address indexed adapter);

    constructor(
        Dependency memory singleton_,
        Dependency memory proxyFactory_,
        Dependency memory multiSend_,
        Dependency memory c10_,
        Dependency memory mldsa_,
        bytes32[] memory localFixtures
    ) {
        if (block.chainid != 31337) revert Policy();
        _pin(singleton_);
        _pin(proxyFactory_);
        _pin(multiSend_);
        _pin(c10_);
        _pin(mldsa_);
        singleton = singleton_.target;
        singletonCodeHash = singleton_.codeHash;
        proxyFactory = SafeProxyFactory(proxyFactory_.target);
        proxyFactoryCodeHash = proxyFactory_.codeHash;
        c10Verifier = c10_.target;
        c10VerifierCodeHash = c10_.codeHash;
        mldsaVerifier = mldsa_.target;
        mldsaVerifierCodeHash = mldsa_.codeHash;
        for (uint256 i; i < localFixtures.length; ++i) {
            if (localFixtures[i] == 0) revert Policy();
            admittedLocalFixture[localFixtures[i]] = true;
        }
        guard = new BunkerHybridRotationGuard(singleton_.target, multiSend_.target);
        guardCodeHash = address(guard).codehash;
        setup = new BunkerHybridSetup(address(guard), proxyFactory_.target);
        setupCodeHash = address(setup).codehash;
    }

    function _pin(Dependency memory dep) private view {
        if (dep.target.code.length == 0 || dep.codeHash == 0 || dep.target.codehash != dep.codeHash) revert Policy();
    }

    function _intact() private view {
        if (
            block.chainid != 31337 || singleton.codehash != singletonCodeHash
                || address(proxyFactory).codehash != proxyFactoryCodeHash || address(guard).codehash != guardCodeHash
                || address(setup).codehash != setupCodeHash
        ) revert Policy();
    }

    function _deploy(Key calldata key, uint256 epoch) private returns (HybridSafeOwner adapter) {
        if (key.algorithm == 1 && key.blob == address(0)) {
            adapter = new C10SafeOwner(key.seed, key.root, c10Verifier, c10VerifierCodeHash, epoch);
        } else if (key.algorithm == 2 && key.seed == 0 && key.root == 0 && admittedLocalFixture[key.blob.codehash]) {
            adapter = new MLDSA44SafeOwner(key.blob, key.blob.codehash, mldsaVerifier, mldsaVerifierCodeHash, epoch);
        } else {
            revert Policy();
        }
        adapterCodeHash[address(adapter)] = address(adapter).codehash;
    }

    function create(address ec, address[20] calldata sequence, Key calldata key, uint256 salt)
        external
        returns (address safe, address pq)
    {
        _intact();
        HybridSafeOwner adapter = _deploy(key, 0);
        pq = address(adapter);
        address[] memory owners = new address[](2);
        owners[0] = ec;
        owners[1] = pq;
        bytes memory initializer = abi.encodeCall(
            Safe.setup,
            (
                owners,
                2,
                address(setup),
                abi.encodeCall(setup.install, ()),
                address(0),
                address(0),
                0,
                payable(address(0))
            )
        );
        safe = address(proxyFactory.createChainSpecificProxyWithNonce(singleton, initializer, salt));
        adapter.bind(safe);
        guard.initialize(safe, ec, pq, sequence);
        createdSafe[safe] = true;
        emit Created(safe, pq);
    }

    /// @dev Anyone may prepare a candidate; ONLY the current two owners can install it via the guard grammar.
    function createRotationAdapter(address safe, Key calldata key) external returns (address) {
        _intact();
        if (!createdSafe[safe]) revert Policy();
        address[] memory owners = Safe(payable(safe)).getOwners();
        guard.attest(safe, owners[0], owners[1]);
        HybridSafeOwner current = HybridSafeOwner(owners[1]);
        if (key.algorithm != current.algorithm()) revert Policy();
        HybridSafeOwner adapter = _deploy(key, current.epoch() + 1);
        if (guard.consumedPQKey(safe, adapter.keyId())) revert Policy();
        adapter.bind(safe);
        return address(adapter);
    }
}
