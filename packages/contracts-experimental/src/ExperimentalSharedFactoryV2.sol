// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Safe} from "@safe-global/safe-contracts/contracts/Safe.sol";
import {SafeProxyFactory} from "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import {ExperimentalRotationGuard} from "./ExperimentalRotationGuard.sol";
import {ExperimentalSetup} from "./ExperimentalFactory.sol";
import {ExperimentalOwner, ExperimentalC10Owner, ExperimentalMLDSAOwner} from "./ExperimentalOwner.sol";

/// @notice Versioned shared infrastructure for disposable Sepolia tests; NOT deployed publicly.
/// @dev The trusted browser must verify ML-DSA blob == prepare(publicKey) BEFORE the payable call.
contract ExperimentalSharedFactoryV2 {
    struct Dependency { address target; bytes32 codeHash; }
    struct Key { uint256 algorithm; bytes32 seed; bytes32 root; address blob; bytes publicKey; }
    uint256 public constant factoryVersion = 2;
    address public immutable singleton;
    bytes32 public immutable singletonCodeHash;
    SafeProxyFactory public immutable proxyFactory;
    bytes32 public immutable proxyFactoryCodeHash;
    ExperimentalRotationGuard public immutable guard;
    bytes32 public immutable guardCodeHash;
    ExperimentalSetup public immutable setup;
    bytes32 public immutable setupCodeHash;
    address public immutable c10Verifier;
    bytes32 public immutable c10VerifierCodeHash;
    address public immutable mldsaHelper;
    address public immutable mldsaVerifier;
    bytes32 public immutable mldsaVerifierCodeHash;
    mapping(address => bytes32) public adapterCodeHash;
    mapping(address => bool) public createdSafe;
    mapping(address => bool) public usedInitialOwner;
    error Policy();
    event Created(address indexed safe, address indexed adapter);

    constructor(Dependency memory singleton_, Dependency memory proxyFactory_, Dependency memory multiSend_,
        Dependency memory c10_, Dependency memory mldsa_, Dependency memory helper_, bytes32 proxyCodeHash) {
        if (block.chainid != 11155111) revert Policy();
        _pin(singleton_); _pin(proxyFactory_); _pin(multiSend_); _pin(c10_); _pin(mldsa_); _pin(helper_);
        if (helper_.codeHash != 0x4afb4435879cdf8e50474c7aab2bc3a679caed432550ad6dba64f509309a817b) revert Policy();
        singleton = singleton_.target; singletonCodeHash = singleton_.codeHash;
        proxyFactory = SafeProxyFactory(proxyFactory_.target); proxyFactoryCodeHash = proxyFactory_.codeHash;
        c10Verifier = c10_.target; c10VerifierCodeHash = c10_.codeHash;
        mldsaVerifier = mldsa_.target; mldsaVerifierCodeHash = mldsa_.codeHash; mldsaHelper = helper_.target;
        guard = new ExperimentalRotationGuard(singleton_.target, multiSend_.target, proxyCodeHash);
        guardCodeHash = address(guard).codehash;
        setup = new ExperimentalSetup(address(guard), proxyFactory_.target);
        setupCodeHash = address(setup).codehash;
    }

    function _pin(Dependency memory dep) private view {
        if (dep.target.code.length == 0 || dep.codeHash == 0 || dep.target.codehash != dep.codeHash) revert Policy();
    }

    function _intact() private view {
        if (block.chainid != 11155111 || singleton.codehash != singletonCodeHash
            || address(proxyFactory).codehash != proxyFactoryCodeHash || address(guard).codehash != guardCodeHash
            || address(setup).codehash != setupCodeHash || c10Verifier.codehash != c10VerifierCodeHash
            || mldsaVerifier.codehash != mldsaVerifierCodeHash
            || mldsaHelper.codehash != 0x4afb4435879cdf8e50474c7aab2bc3a679caed432550ad6dba64f509309a817b) revert Policy();
    }

    function _deploy(Key calldata key, uint256 epoch) private returns (ExperimentalOwner adapter) {
        if (key.algorithm == 1 && key.blob == address(0) && key.publicKey.length == 0) {
            adapter = new ExperimentalC10Owner(key.seed, key.root, c10Verifier, c10VerifierCodeHash, epoch);
        } else if (key.algorithm == 2 && key.seed == 0 && key.root == 0 && key.publicKey.length == 1312) {
            adapter = new ExperimentalMLDSAOwner(key.publicKey, key.blob, key.blob.codehash,
                mldsaVerifier, mldsaVerifierCodeHash, epoch, mldsaHelper);
        } else revert Policy();
        adapterCodeHash[address(adapter)] = address(adapter).codehash;
    }

    function createAndFund(address ec, address[20] calldata sequence, Key calldata key, uint256 salt)
        external payable returns (address safe, address pq) {
        _intact();
        if (msg.sender != ec || usedInitialOwner[ec] || msg.value == 0) revert Policy();
        ExperimentalOwner adapter = _deploy(key, 0);
        pq = address(adapter);
        address[] memory owners = new address[](2);
        owners[0] = ec; owners[1] = pq;
        bytes memory initializer = abi.encodeCall(Safe.setup, (owners, 2, address(setup),
            abi.encodeCall(setup.install, ()), address(0), address(0), 0, payable(address(0))));
        safe = address(proxyFactory.createChainSpecificProxyWithNonce(singleton, initializer, salt));
        adapter.bind(safe);
        guard.initialize(safe, ec, pq, sequence);
        createdSafe[safe] = true;
        usedInitialOwner[ec] = true;
        (bool funded,) = payable(safe).call{value: msg.value}("");
        if (!funded) revert Policy();
        emit Created(safe, pq);
    }

    /// @dev Register only a candidate. Guarded Safe two-owner execution must install it later.
    function createRotationAdapter(address safe, Key calldata key) external returns (address) {
        _intact();
        if (!createdSafe[safe]) revert Policy();
        address[] memory owners = Safe(payable(safe)).getOwners();
        guard.attest(safe, owners[0], owners[1]);
        ExperimentalOwner current = ExperimentalOwner(owners[1]);
        if (key.algorithm != current.algorithm()) revert Policy();
        ExperimentalOwner adapter = _deploy(key, current.epoch() + 1);
        if (guard.consumedPQKey(safe, adapter.keyId())) revert Policy();
        adapter.bind(safe);
        return address(adapter);
    }
}
