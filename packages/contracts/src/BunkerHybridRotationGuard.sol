// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {BaseGuard} from "@safe-global/safe-contracts/contracts/base/GuardManager.sol";
import {Enum} from "@safe-global/safe-contracts/contracts/common/Enum.sol";
import {Safe} from "@safe-global/safe-contracts/contracts/Safe.sol";
import {SafeProxy} from "@safe-global/safe-contracts/contracts/proxies/SafeProxy.sol";
import {HybridSafeOwner} from "./HybridSafeOwner.sol";

interface IHybridFactory {
    function adapterCodeHash(address adapter) external view returns (bytes32);
}

/// @notice Local-only, unaudited 2-of-2 ETH rotation policy. No generic execution authority.
contract BunkerHybridRotationGuard is BaseGuard {
    address public constant SENTINEL = address(1);
    uint256 public constant NEXT_OWNER_GAS = 0.001 ether;
    uint256 private constant HALF_N = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    bytes32 private constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    bytes32 private constant FALLBACK_SLOT = 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
    address public immutable factory;
    address public immutable singleton;
    bytes32 public immutable singletonCodeHash;
    address public immutable multiSendCallOnly;
    bytes32 public immutable multiSendCodeHash;

    struct State {
        address ec;
        address pq;
        uint8 nextIndex;
        bool executing;
        address pendingEC;
        address pendingPQ;
        bytes32 renewal;
        uint8 action;
    }
    mapping(address => State) public state;
    mapping(address => mapping(uint256 => address)) public committedOwner;
    mapping(address => mapping(address => bool)) public consumed;
    mapping(address => mapping(bytes32 => bool)) public consumedPQKey;
    error Policy();

    constructor(address singleton_, address multiSend_) {
        if (block.chainid != 31337 || singleton_.code.length == 0 || multiSend_.code.length == 0) revert Policy();
        factory = msg.sender;
        singleton = singleton_;
        singletonCodeHash = singleton_.codehash;
        multiSendCallOnly = multiSend_;
        multiSendCodeHash = multiSend_.codehash;
    }

    function initialize(address safe, address ec, address pq, address[20] calldata sequence) external {
        if (block.chainid != 31337 || msg.sender != factory || state[safe].ec != address(0)) revert Policy();
        _eoa(safe, ec);
        _adapter(safe, pq);
        state[safe].ec = ec;
        state[safe].pq = pq;
        consumed[safe][ec] = true;
        consumedPQKey[safe][HybridSafeOwner(pq).keyId()] = true;
        _commit(safe, sequence);
        attest(safe, ec, pq);
    }

    function _eoa(address safe, address owner) private view {
        if (owner == address(0) || owner == SENTINEL || owner == safe || owner.code.length != 0) revert Policy();
    }

    function _commit(address safe, address[20] memory sequence) private {
        for (uint256 i; i < 20; ++i) {
            address owner = sequence[i];
            _eoa(safe, owner);
            if (consumed[safe][owner]) revert Policy();
            consumed[safe][owner] = true;
            committedOwner[safe][i] = owner;
        }
    }

    function _adapter(address safe, address pq) private view {
        bytes32 hash = IHybridFactory(factory).adapterCodeHash(pq);
        if (
            hash == 0 || pq.codehash != hash || HybridSafeOwner(pq).safe() != safe
                || HybridSafeOwner(pq).factory() != factory || !HybridSafeOwner(pq).dependenciesIntact()
        ) revert Policy();
    }

    function attest(address safe, address ec, address pq) public view {
        if (
            block.chainid != 31337 || safe.codehash != keccak256(type(SafeProxy).runtimeCode)
                || singleton.codehash != singletonCodeHash || multiSendCallOnly.codehash != multiSendCodeHash
        ) revert Policy();
        Safe wallet = Safe(payable(safe));
        address[] memory owners = wallet.getOwners();
        if (owners.length != 2 || owners[0] != ec || owners[1] != pq || wallet.getThreshold() != 2) revert Policy();
        _eoa(safe, ec);
        _adapter(safe, pq);
        (address[] memory modules, address cursor) = wallet.getModulesPaginated(SENTINEL, 1);
        if (
            modules.length != 0 || cursor != SENTINEL
                || bytes32(wallet.getStorageAt(0, 1)) != bytes32(uint256(uint160(singleton)))
                || bytes32(wallet.getStorageAt(uint256(GUARD_SLOT), 1)) != bytes32(uint256(uint160(address(this))))
                || bytes32(wallet.getStorageAt(uint256(FALLBACK_SLOT), 1)) != 0
        ) revert Policy();
    }

    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures,
        address
    ) external override {
        if (
            to != multiSendCallOnly || value != 0 || operation != Enum.Operation.DelegateCall || safeTxGas != 0
                || baseGas != 0 || gasPrice != 0 || gasToken != address(0) || refundReceiver != address(0)
        ) revert Policy();
        _check(data, signatures);
    }

    function _check(bytes memory data, bytes memory signatures) private {
        State storage s = state[msg.sender];
        if (s.ec == address(0) || s.executing) revert Policy();
        attest(msg.sender, s.ec, s.pq);
        _signatures(signatures, s.ec, s.pq);
        if (data.length < 68 || bytes4(data) != bytes4(keccak256("multiSend(bytes)"))) revert Policy();
        bytes memory raw = abi.decode(_slice(data, 4, data.length - 4), (bytes));
        if (keccak256(data) != keccak256(abi.encodeWithSignature("multiSend(bytes)", raw))) revert Policy();
        s.pendingEC = s.ec;
        s.pendingPQ = s.pq;
        bytes memory expected;
        if (raw.length == 355 && s.nextIndex < 19) {
            address recipient = address(uint160(_word(raw, 1) >> 96));
            uint256 amount = _word(raw, 21);
            if (recipient == address(0) || recipient == msg.sender || amount == 0) revert Policy();
            s.pendingEC = committedOwner[msg.sender][s.nextIndex];
            _eoa(msg.sender, s.pendingEC);
            expected = bytes.concat(
                _call(recipient, amount, ""),
                _call(s.pendingEC, NEXT_OWNER_GAS, ""),
                _swap(msg.sender, SENTINEL, s.ec, s.pendingEC)
            );
            s.action = 1;
        } else if (raw.length == 185) {
            address next = address(uint160(_word(raw, 153)));
            _adapter(msg.sender, next);
            if (
                HybridSafeOwner(next).algorithm() != HybridSafeOwner(s.pq).algorithm()
                    || HybridSafeOwner(next).epoch() != HybridSafeOwner(s.pq).epoch() + 1
                    || consumedPQKey[msg.sender][HybridSafeOwner(next).keyId()]
            ) revert Policy();
            s.pendingPQ = next;
            expected = _swap(msg.sender, s.ec, s.pq, next);
            s.action = 2;
        } else if (raw.length == 999 && s.nextIndex == 19) {
            address[20] memory sequence = abi.decode(_slice(raw, 359, 640), (address[20]));
            s.pendingEC = committedOwner[msg.sender][19];
            _eoa(msg.sender, s.pendingEC);
            bytes memory renewal = abi.encodeCall(this.renew, (sequence));
            s.renewal = keccak256(renewal);
            expected = bytes.concat(
                _call(s.pendingEC, NEXT_OWNER_GAS, ""),
                _swap(msg.sender, SENTINEL, s.ec, s.pendingEC),
                _call(address(this), 0, renewal)
            );
            s.action = 3;
        } else {
            revert Policy();
        }
        if (keccak256(raw) != keccak256(expected)) revert Policy();
        s.executing = true;
    }

    function renew(address[20] calldata sequence) external {
        State storage s = state[msg.sender];
        if (
            block.chainid != 31337 || !s.executing || s.action != 3 || s.renewal == 0
                || keccak256(msg.data) != s.renewal
        ) revert Policy();
        attest(msg.sender, s.pendingEC, s.pq);
        _commit(msg.sender, sequence);
        s.nextIndex = 0;
        s.renewal = 0;
    }

    function checkAfterExecution(bytes32, bool success) external override {
        State storage s = state[msg.sender];
        if (!s.executing || !success || s.renewal != 0) revert Policy();
        attest(msg.sender, s.pendingEC, s.pendingPQ);
        if (s.action == 1) ++s.nextIndex;
        if (s.action == 2) consumedPQKey[msg.sender][HybridSafeOwner(s.pendingPQ).keyId()] = true;
        s.ec = s.pendingEC;
        s.pq = s.pendingPQ;
        s.pendingEC = address(0);
        s.pendingPQ = address(0);
        s.action = 0;
        s.executing = false;
    }

    function _signatures(bytes memory sig, address ec, address pq) private pure {
        uint256 length = HybridSafeOwner(pq).signatureLength();
        if (sig.length != 162 + length || _word(sig, 130) != length) revert Policy();
        uint256 contractPos = ec < pq ? 65 : 0;
        uint256 ecPos = 65 - contractPos;
        if (
            _word(sig, contractPos) != uint256(uint160(pq)) || _word(sig, contractPos + 32) != 130
                || sig[contractPos + 64] != 0
        ) revert Policy();
        uint256 r = _word(sig, ecPos);
        uint256 ss = _word(sig, ecPos + 32);
        uint8 v = uint8(sig[ecPos + 64]);
        if (r == 0 || ss == 0 || ss > HALF_N || (v != 27 && v != 28)) revert Policy();
        // Safe has already recovered/checked sorted owner identities before calling this guard.
    }

    function _word(bytes memory data, uint256 offset) private pure returns (uint256 value) {
        if (offset + 32 > data.length) revert Policy();
        assembly { value := mload(add(add(data, 32), offset)) }
    }

    function _slice(bytes memory data, uint256 start, uint256 length) private pure returns (bytes memory out) {
        if (start + length > data.length) revert Policy();
        out = new bytes(length);
        for (uint256 i; i < length; ++i) {
            out[i] = data[start + i];
        }
    }

    function _call(address to, uint256 value, bytes memory data) private pure returns (bytes memory) {
        return abi.encodePacked(uint8(0), to, value, data.length, data);
    }

    function _swap(address safe, address prev, address oldOwner, address next) private pure returns (bytes memory) {
        return _call(safe, 0, abi.encodeWithSignature("swapOwner(address,address,address)", prev, oldOwner, next));
    }
}
