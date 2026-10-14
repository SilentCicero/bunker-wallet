// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Safe} from "@safe-global/safe-contracts/contracts/Safe.sol";
import {SafeProxyFactory} from "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import {SafeProxy} from "@safe-global/safe-contracts/contracts/proxies/SafeProxy.sol";
import {MultiSendCallOnly} from "@safe-global/safe-contracts/contracts/libraries/MultiSendCallOnly.sol";
import {Enum} from "@safe-global/safe-contracts/contracts/common/Enum.sol";
import {BunkerHybridFactory} from "../src/BunkerHybridFactory.sol";
import {BunkerHybridRotationGuard} from "../src/BunkerHybridRotationGuard.sol";
import {HybridSafeOwner, C10SafeOwner, MLDSA44SafeOwner} from "../src/HybridSafeOwner.sol";

interface HybridVm {
    function addr(uint256) external returns (address);
    function sign(uint256, bytes32) external returns (uint8, bytes32, bytes32);
    function deal(address, uint256) external;
    function prank(address) external;
    function expectRevert() external;
    function expectRevert(bytes4) external;
    function getNonce(address) external view returns (uint64);
    function etch(address, bytes calldata) external;
    function chainId(uint256) external;
    function store(address, bytes32, bytes32) external;
}

// Deliberately NOT cryptography. Test-only doubles verify a key+message commitment in raw signature framing.
contract MockC10Verifier {
    uint256 public mode;

    function setMode(uint256 mode_) external {
        mode = mode_;
    }

    function verify(bytes32 seed, bytes32 root, bytes32 message, bytes calldata sig) external view returns (bool) {
        if (mode == 1) revert("mock revert");
        if (mode == 2) {
            assembly {
                mstore(0, 1)
                return(0, 1)
            }
        }
        if (mode == 3) {
            assembly {
                mstore(0, 2)
                return(0, 32)
            }
        }
        if (mode == 4) {
            assembly {
                mstore(0, 1)
                return(0, 64)
            }
        }
        if (mode == 5) return false;
        return sig.length == 4008 && bytes32(sig[:32]) == keccak256(abi.encode(seed, root, message));
    }
}

contract MockMLDSA44Verifier {
    function verify(address blob, bytes calldata message, bytes calldata sig) external view returns (bool) {
        return message.length == 32 && sig.length == 2420
            && bytes32(sig[:32]) == keccak256(abi.encode(blob.codehash, bytes32(message)));
    }
}

contract MockStatefulVerifier {
    uint256 public writes;

    fallback() external {
        ++writes;
        assembly {
            mstore(0, 1)
            return(0, 32)
        }
    }
}

contract HybridSimulationMutation {
    function mutate(address recipient) external {
        assembly { sstore(0, 123456) }
        (bool ok,) = recipient.call{value: 1 ether}("");
        require(ok);
    }
}

contract HybridRevertingRecipient {
    receive() external payable {
        revert();
    }
}

contract HybridReentrantRecipient {
    address private safe;
    bytes private transaction;
    bool public blocked;
    bytes4 public reason;

    constructor(address safe_, bytes memory transaction_) {
        safe = safe_;
        transaction = transaction_;
    }

    receive() external payable {
        (bool ok, bytes memory result) = safe.call(transaction);
        blocked = !ok;
        reason = bytes4(result);
    }
}

contract BunkerHybridIntegrationTest {
    HybridVm private constant vm = HybridVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    Safe private singleton;
    SafeProxyFactory private proxies;
    MultiSendCallOnly private multi;
    MockC10Verifier private c10;
    MockMLDSA44Verifier private mldsa;
    BunkerHybridFactory private factory;
    BunkerHybridRotationGuard private guard;
    Safe private safe;
    HybridSafeOwner private pq;
    uint256 private ecKey = 0xA11CE;
    address[20] private sequence;
    address private constant BLOB1 = address(0xB101);
    address private constant BLOB2 = address(0xB102);

    function setUp() public {
        singleton = new Safe();
        proxies = new SafeProxyFactory();
        multi = new MultiSendCallOnly();
        c10 = new MockC10Verifier();
        mldsa = new MockMLDSA44Verifier();
        bytes memory blob = new bytes(20545);
        blob[1] = 0x01;
        vm.etch(BLOB1, blob);
        blob[1] = 0x02;
        vm.etch(BLOB2, blob);
        bytes32[] memory fixtures = new bytes32[](2);
        fixtures[0] = BLOB1.codehash;
        fixtures[1] = BLOB2.codehash;
        factory = new BunkerHybridFactory(
            _dep(address(singleton)),
            _dep(address(proxies)),
            _dep(address(multi)),
            _dep(address(c10)),
            _dep(address(mldsa)),
            fixtures
        );
        guard = factory.guard();
        for (uint256 i; i < 20; ++i) {
            sequence[i] = vm.addr(1000 + i);
        }
        (address wallet, address adapter) = factory.create(vm.addr(ecKey), sequence, _key(1), 1);
        safe = Safe(payable(wallet));
        pq = HybridSafeOwner(adapter);
        vm.deal(wallet, 100 ether);
    }

    function _dep(address target) private view returns (BunkerHybridFactory.Dependency memory) {
        return BunkerHybridFactory.Dependency(target, target.codehash);
    }

    function _key(uint256 id) private pure returns (BunkerHybridFactory.Key memory) {
        return BunkerHybridFactory.Key(1, bytes32(id << 128), bytes32((id + 1) << 128), address(0));
    }

    function _call(address to, uint256 value, bytes memory data) private pure returns (bytes memory) {
        return abi.encodePacked(uint8(0), to, value, data.length, data);
    }

    function _swap(address prev, address oldOwner, address next) private view returns (bytes memory) {
        return
            _call(address(safe), 0, abi.encodeWithSignature("swapOwner(address,address,address)", prev, oldOwner, next));
    }

    function _outer(bytes memory raw) private pure returns (bytes memory) {
        return abi.encodeCall(MultiSendCallOnly.multiSend, (raw));
    }

    function _spend(address next, address recipient) private view returns (bytes memory) {
        // getOwners, rather than deriving a mock EC address, preserves actual linked-list predecessor.
        return _outer(
            bytes.concat(
                _call(recipient, 1 ether, ""),
                _call(next, 0.001 ether, ""),
                _swap(address(1), safe.getOwners()[0], next)
            )
        );
    }

    function _preimage(bytes memory data) private view returns (bytes memory) {
        return safe.encodeTransactionData(
            address(multi), 0, data, Enum.Operation.DelegateCall, 0, 0, 0, address(0), address(0), safe.nonce()
        );
    }

    function _raw(HybridSafeOwner adapter, bytes memory preimage) private view returns (bytes memory raw) {
        bytes32 digest = adapter.messageDigest(preimage);
        bytes32 proof;
        if (adapter.algorithm() == 1) {
            C10SafeOwner owner = C10SafeOwner(address(adapter));
            proof = keccak256(abi.encode(owner.pkSeed(), owner.pkRoot(), digest));
        } else {
            proof = keccak256(abi.encode(adapter.keyId(), digest));
        }
        raw = new bytes(adapter.signatureLength());
        assembly { mstore(add(raw, 32), proof) }
    }

    function _signatures(uint256 key, bytes memory data) private returns (bytes memory) {
        return _signPreimage(key, _preimage(data));
    }

    function _signPreimage(uint256 key, bytes memory preimage) private returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, keccak256(preimage));
        bytes memory ec = abi.encodePacked(r, s, v);
        bytes memory contractSig = abi.encodePacked(bytes32(uint256(uint160(address(pq)))), uint256(130), uint8(0));
        bytes memory raw = _raw(pq, preimage);
        return bytes.concat(
            vm.addr(key) < address(pq) ? bytes.concat(ec, contractSig) : bytes.concat(contractSig, ec),
            abi.encode(raw.length),
            raw
        );
    }

    function _exec(bytes memory data, bytes memory sig) private returns (bool) {
        return safe.execTransaction(
            address(multi), 0, data, Enum.Operation.DelegateCall, 0, 0, 0, address(0), payable(address(0)), sig
        );
    }

    function _valid(uint256 key, bytes memory data) private {
        require(_exec(data, _signatures(key, data)), "exec failed");
    }

    function _fails(bytes memory data, bytes memory sig) private {
        vm.expectRevert();
        _exec(data, sig);
    }

    function _attest(address ec, address adapter) private view {
        guard.attest(address(safe), ec, adapter);
    }

    function testDigestFormulaVector() public {
        // Identical fixed vector in packages/safe/src/hybrid.test.ts, through the actual adapter function.
        vm.etch(address(100), hex"00");
        vm.etch(address(300), hex"00");
        C10SafeOwner template = new C10SafeOwner(
            bytes32(uint256(1) << 128), bytes32(uint256(2) << 128), address(300), keccak256(hex"00"), 7
        );
        vm.etch(address(200), address(template).code);
        C10SafeOwner adapter = C10SafeOwner(address(200));
        adapter.bind(address(100));
        bytes32 domain = keccak256(
            abi.encode(
                keccak256("EIP712Domain(uint256 chainId,address verifyingContract)"), uint256(31337), address(100)
            )
        );
        bytes memory preimage = abi.encodePacked(hex"1901", domain, bytes32(uint256(123)));
        require(
            adapter.messageDigest(preimage) == 0x9dcd1c137a47b5d7c35f2b55600b2b94f6007234fc8afe245b7bacff7efbee70,
            "TS digest mismatch"
        );
    }

    function testPairRequiredAndBothNumericOrderings() public {
        bool lower;
        bool higher;
        for (uint256 i; i < 8; ++i) {
            uint256 key = 7000 + i;
            (address wallet, address adapter) = factory.create(vm.addr(key), sequence, _key(i + 10), i + 10);
            safe = Safe(payable(wallet));
            pq = HybridSafeOwner(adapter);
            vm.deal(wallet, 5 ether);
            if (vm.addr(key) < adapter) lower = true;
            else higher = true;
            bytes memory data = _spend(sequence[0], address(0xCAFE));
            bytes memory sig = _signatures(key, data);
            bytes memory ecOnly = new bytes(65);
            uint256 start = vm.addr(key) < adapter ? 0 : 65;
            for (uint256 j; j < 65; ++j) {
                ecOnly[j] = sig[start + j];
            }
            _fails(data, ecOnly);
            bytes memory pqOnly = bytes.concat(
                abi.encodePacked(bytes32(uint256(uint160(adapter))), uint256(65), uint8(0)),
                abi.encode(uint256(4008)),
                _raw(pq, _preimage(data))
            );
            _fails(data, pqOnly);
            _valid(key, data);
            _attest(sequence[0], adapter);
            _fails(data, sig); // stale nonce + previous EC owner
        }
        require(lower && higher, "missing numeric ordering");
    }

    function testRenewalBeyondNineteenAndFreshKeysOnly() public {
        uint256 signer = ecKey;
        for (uint256 i; i < 19; ++i) {
            _valid(signer, _spend(sequence[i], address(0xCAFE)));
            signer = 1000 + i;
        }
        bytes memory exhausted = _spend(sequence[19], address(0xCAFE));
        _fails(exhausted, _signatures(signer, exhausted));
        address[20] memory next;
        for (uint256 i; i < 20; ++i) {
            next[i] = vm.addr(2000 + i);
        }
        bytes memory prefix =
            bytes.concat(_call(sequence[19], 0.001 ether, ""), _swap(address(1), sequence[18], sequence[19]));
        address[20] memory invalid = next;
        invalid[19] = sequence[0];
        bytes memory bad =
            _outer(bytes.concat(prefix, _call(address(guard), 0, abi.encodeCall(guard.renew, (invalid)))));
        _fails(bad, _signatures(signer, bad));
        _attest(sequence[18], address(pq));
        // Memory array assignment aliases; restore before constructing successful renewal.
        next[19] = vm.addr(2019);
        bytes memory data = _outer(bytes.concat(prefix, _call(address(guard), 0, abi.encodeCall(guard.renew, (next)))));
        _valid(signer, data);
        _attest(sequence[19], address(pq));
        _valid(1019, _spend(next[0], address(0xCAFE)));
        _attest(next[0], address(pq));
    }

    function testPQRotationRequiresOldPairAndRejectsKeyReuse() public {
        HybridSafeOwner old = pq;
        address next = factory.createRotationAdapter(address(safe), _key(3));
        bytes memory data = _outer(_swap(vm.addr(ecKey), address(old), next));
        pq = HybridSafeOwner(next);
        _fails(data, _signatures(ecKey, data));
        pq = old;
        _valid(ecKey, data);
        pq = HybridSafeOwner(next);
        _attest(vm.addr(ecKey), next);
        require(pq.epoch() == 1, "epoch");
        vm.expectRevert();
        factory.createRotationAdapter(address(safe), _key(1));
        _valid(ecKey, _spend(sequence[0], address(0xCAFE)));
    }

    function testMLDSAFixtureAdmissionExecutionAndRotation() public {
        BunkerHybridFactory.Key memory key = BunkerHybridFactory.Key(2, 0, 0, BLOB1);
        (address wallet, address adapter) = factory.create(vm.addr(ecKey), sequence, key, 77);
        safe = Safe(payable(wallet));
        pq = HybridSafeOwner(adapter);
        vm.deal(wallet, 10 ether);
        _valid(ecKey, _spend(sequence[0], address(0xCAFE)));
        key.blob = BLOB2;
        address next = factory.createRotationAdapter(wallet, key);
        _valid(1000, _outer(_swap(sequence[0], adapter, next)));
        pq = HybridSafeOwner(next);
        _attest(sequence[0], next);
        key.blob = BLOB1;
        vm.expectRevert();
        factory.createRotationAdapter(wallet, key);
        bytes memory unknown = new bytes(20545);
        vm.etch(address(0xB103), unknown);
        key.blob = address(0xB103);
        vm.expectRevert();
        factory.create(vm.addr(ecKey), sequence, key, 88);
        bytes memory data = _spend(sequence[1], address(0xCAFE));
        bytes memory sig = _signatures(1000, data);
        vm.etch(BLOB2, unknown);
        _fails(data, sig);
    }

    function testReplacementIntegrityAndAttestationFailClosed() public {
        BunkerHybridFactory.Key memory key = BunkerHybridFactory.Key(2, 0, 0, BLOB1);
        (address wallet, address adapter) = factory.create(vm.addr(ecKey), sequence, key, 78);
        safe = Safe(payable(wallet));
        pq = HybridSafeOwner(adapter);
        key.blob = BLOB2;
        address next = factory.createRotationAdapter(wallet, key);
        bytes memory data = _outer(_swap(vm.addr(ecKey), adapter, next));
        bytes memory sig = _signatures(ecKey, data);
        bytes memory original = BLOB2.code;
        bytes memory changed = bytes.concat(original);
        changed[1] = 0x03; // Exact same length, different identity after candidate admission.
        vm.etch(BLOB2, changed);
        _fails(data, sig);
        require(safe.nonce() == 0 && !guard.consumedPQKey(wallet, HybridSafeOwner(next).keyId()), "partial rotation");
        (address ec, address activePQ,, bool executing, address pendingEC, address pendingPQ,, uint8 action) =
            guard.state(wallet);
        require(
            ec == vm.addr(ecKey) && activePQ == adapter && !executing && pendingEC == address(0)
                && pendingPQ == address(0) && action == 0,
            "stuck rotation"
        );
        _attest(ec, adapter);
        vm.etch(BLOB2, original);
        require(_exec(data, sig), "retry after rollback failed");
        pq = HybridSafeOwner(next);
        _attest(ec, next);
        vm.etch(BLOB2, changed);
        vm.expectRevert(BunkerHybridRotationGuard.Policy.selector);
        guard.attest(wallet, ec, next);
        vm.etch(BLOB2, original);
        vm.etch(address(mldsa), hex"00");
        vm.expectRevert(BunkerHybridRotationGuard.Policy.selector);
        guard.attest(wallet, ec, next);
    }

    function testSafeAcceptedAlternateECDSAFormsStillFailGuard() public {
        bytes memory data = _spend(sequence[0], address(0xCAFE));
        bytes memory preimage = _preimage(data);
        bytes32 hash = keccak256(preimage);
        uint256 ecPos = vm.addr(ecKey) < address(pq) ? 0 : 65;
        for (uint256 i; i < 2; ++i) {
            bytes memory sig = _signatures(ecKey, data);
            bytes32 signingHash = i == 0 ? keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)) : hash;
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ecKey, signingHash);
            if (i == 0) {
                v += 4;
            } else {
                s = bytes32(uint256(0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141) - uint256(s));
                v = v == 27 ? 28 : 27;
            }
            bytes memory entry = abi.encodePacked(r, s, v);
            for (uint256 j; j < 65; ++j) {
                sig[ecPos + j] = entry[j];
            }
            safe.checkSignatures(hash, preimage, sig); // Prove rejection is the guard, not failed Safe recovery.
            vm.expectRevert(BunkerHybridRotationGuard.Policy.selector);
            _exec(data, sig);
        }
        require(safe.nonce() == 0, "nonce changed");
        _valid(ecKey, data);
    }

    function testSignatureFramingAndNoApprovedHashBypass() public {
        bytes memory data = _spend(sequence[0], address(0xCAFE));
        bytes memory good = _signatures(ecKey, data);
        uint256 c = vm.addr(ecKey) < address(pq) ? 65 : 0;
        uint256 e = 65 - c;
        for (uint256 i; i < 10; ++i) {
            bytes memory bad = bytes.concat(good);
            if (i == 0) bad[c + 63] = 0x81; // offset129
            if (i == 1) bad[c] = 0x01; // high address bits ignored by Safe, forbidden by guard
            if (i == 2) bad[161] = 0xa7; // raw length4007
            if (i == 3) bad[e + 64] = 0x1f; // eth_sign
            if (i == 4) bad = bytes.concat(good, hex"00");
            if (i == 5) {
                assembly { mstore(add(add(bad, 32), e), 0) }
            }
            if (i == 6) bad[e + 32] = 0xff; // high s
            if (i == 7) {
                assembly { mstore(bad, sub(mload(bad), 1)) }
            }
            if (i == 8) {
                for (uint256 j; j < 65; ++j) {
                    bad[j] = good[j + 65];
                    bad[j + 65] = good[j];
                }
            }
            if (i == 9) {
                for (uint256 j; j < 65; ++j) {
                    bad[j] = good[j + 65];
                }
            }
            _fails(data, bad);
        }
        bytes32 hash = keccak256(_preimage(data));
        vm.prank(vm.addr(ecKey));
        safe.approveHash(hash);
        bytes memory approved = bytes.concat(good);
        bytes memory entry = abi.encodePacked(bytes32(uint256(uint160(vm.addr(ecKey)))), bytes32(0), uint8(1));
        for (uint256 j; j < 65; ++j) {
            approved[e + j] = entry[j];
        }
        _fails(data, approved);
        _valid(ecKey, data);
    }

    function testAdapterCallerDomainFramingKeyEpochAndVerifierFailures() public {
        bytes memory data = _spend(sequence[0], address(0xCAFE));
        bytes memory pre = _preimage(data);
        bytes memory raw = _raw(pq, pre);
        vm.expectRevert();
        pq.isValidSignature(pre, raw);
        vm.prank(address(safe));
        require(pq.isValidSignature(pre, raw) == 0x20c13b0b, "legacy magic");
        for (uint256 i; i < 5; ++i) {
            bytes memory badPre = bytes.concat(pre);
            bytes memory badRaw = bytes.concat(raw);
            if (i == 0) badPre[0] = 0;
            if (i == 1) badPre[2] = bytes1(uint8(badPre[2]) ^ 1);
            if (i == 2) badPre[65] = bytes1(uint8(badPre[65]) ^ 1);
            if (i == 3) badRaw[0] = bytes1(uint8(badRaw[0]) ^ 1);
            if (i == 4) badPre = bytes.concat(pre, hex"00");
            vm.prank(address(safe));
            vm.expectRevert();
            pq.isValidSignature(badPre, badRaw);
        }
        C10SafeOwner other = new C10SafeOwner(
            bytes32(uint256(1) << 128), bytes32(uint256(2) << 128), address(c10), address(c10).codehash, 1
        );
        vm.expectRevert();
        other.isValidSignature(pre, raw);
        other.bind(address(safe));
        vm.prank(address(safe)); // adapter/epoch domain changed
        vm.expectRevert();
        other.isValidSignature(pre, raw);
        bytes memory sig = _signatures(ecKey, data);
        for (uint256 i = 1; i <= 5; ++i) {
            c10.setMode(i);
            _fails(data, sig);
        }
        c10.setMode(0);
        vm.etch(address(c10), hex"60006000f3");
        _fails(data, sig);
    }

    function testPublicReadChecksAndWrongChainSafeKey() public {
        bytes memory data = _spend(sequence[0], address(0xCAFE));
        bytes memory pre = _preimage(data);
        bytes memory sig = _signatures(ecKey, data);
        safe.checkSignatures(keccak256(pre), pre, sig);
        bytes memory raw = _raw(pq, pre);
        bytes32 wrongDomain = keccak256(
            abi.encode(
                keccak256("EIP712Domain(uint256 chainId,address verifyingContract)"), uint256(31337), address(999)
            )
        );
        bytes memory bad = bytes.concat(pre);
        assembly { mstore(add(bad, 34), wrongDomain) }
        vm.prank(address(safe));
        vm.expectRevert();
        pq.isValidSignature(bad, raw);
        C10SafeOwner otherKey = new C10SafeOwner(
            bytes32(uint256(8) << 128), bytes32(uint256(9) << 128), address(c10), address(c10).codehash, 0
        );
        otherKey.bind(address(safe));
        raw = _raw(otherKey, pre);
        vm.prank(address(safe));
        vm.expectRevert();
        pq.isValidSignature(pre, raw);
        raw = _raw(pq, pre);
        vm.chainId(1);
        vm.prank(address(safe));
        vm.expectRevert();
        pq.isValidSignature(pre, raw);
        vm.expectRevert();
        guard.attest(address(safe), vm.addr(ecKey), address(pq));
        vm.chainId(31337);
    }

    function testAtomicBindingAndLocalOnly() public {
        vm.expectRevert();
        pq.bind(address(this));
        vm.expectRevert();
        guard.initialize(address(safe), vm.addr(ecKey), address(pq), sequence);
        C10SafeOwner unbound = new C10SafeOwner(
            bytes32(uint256(4) << 128), bytes32(uint256(5) << 128), address(c10), address(c10).codehash, 0
        );
        vm.prank(address(0xBAD));
        vm.expectRevert();
        unbound.bind(address(safe));
        bytes memory pre = _preimage("");
        vm.expectRevert();
        unbound.messageDigest(pre);
        address[20] memory invalid = sequence;
        invalid[19] = invalid[0];
        vm.expectRevert();
        factory.create(vm.addr(ecKey), invalid, _key(90), 90);
        require(!factory.createdSafe(address(0)), "partial create");
        vm.chainId(11155111);
        vm.expectRevert();
        factory.create(vm.addr(ecKey), sequence, _key(90), 90);
        vm.expectRevert();
        unbound.bind(address(safe));
        vm.expectRevert();
        new C10SafeOwner(bytes32(uint256(4) << 128), bytes32(uint256(5) << 128), address(c10), address(c10).codehash, 0);
        vm.chainId(31337);
        vm.expectRevert();
        new C10SafeOwner(bytes32(uint256(4)), bytes32(uint256(5) << 128), address(c10), address(c10).codehash, 0);
    }

    function _predictedCreate(uint256 salt)
        private
        view
        returns (address adapter, address wallet)
    {
        uint64 nonce = vm.getNonce(address(factory));
        require(nonce > 0 && nonce < 128, "test RLP range");
        adapter = address(uint160(uint256(keccak256(abi.encodePacked(hex"d694", address(factory), uint8(nonce))))));
        address[] memory initial = new address[](2);
        initial[0] = safe.getOwners()[0];
        initial[1] = adapter;
        // The sequence is initialized after creation, not part of the Safe initializer.
        bytes memory initializer = abi.encodeCall(
            Safe.setup,
            (
                initial,
                2,
                address(factory.setup()),
                abi.encodeWithSignature("install()"),
                address(0),
                address(0),
                0,
                payable(address(0))
            )
        );
        bytes32 createSalt = keccak256(abi.encodePacked(keccak256(initializer), salt, block.chainid));
        bytes32 initHash =
            keccak256(abi.encodePacked(type(SafeProxy).creationCode, uint256(uint160(address(singleton)))));
        wallet = address(uint160(uint256(keccak256(abi.encodePacked(hex"ff", address(proxies), createSalt, initHash)))));
    }

    function testAtomicRollbackOccupiedAddressAndPrefunding() public {
        (address adapter, address wallet) = _predictedCreate(99);
        uint64 nonce = vm.getNonce(address(factory));
        vm.deal(wallet, 1 ether);
        address[20] memory invalid = sequence;
        invalid[19] = invalid[0];
        vm.expectRevert();
        factory.create(vm.addr(ecKey), invalid, _key(90), 99);
        require(adapter.code.length == 0 && wallet.code.length == 0 && wallet.balance == 1 ether, "partial deployment");
        require(
            vm.getNonce(address(factory)) == nonce && factory.adapterCodeHash(adapter) == 0
                && !factory.createdSafe(wallet),
            "partial registry"
        );
        vm.etch(wallet, hex"00"); // Occupied CREATE2 target must roll back the candidate as well.
        vm.expectRevert();
        factory.create{gas: 5000000}(vm.addr(ecKey), sequence, _key(90), 99);
        require(
            adapter.code.length == 0 && vm.getNonce(address(factory)) == nonce, "occupied deployment leaked adapter"
        );
        vm.etch(wallet, "");
        (address created, address owner) = factory.create(vm.addr(ecKey), sequence, _key(90), 99);
        require(created == wallet && owner == adapter && wallet.balance == 1 ether, "prediction or prefunding changed");
        guard.attest(wallet, vm.addr(ecKey), adapter);
    }

    function testSimulationCannotPersistStorageOrTransfers() public {
        HybridSimulationMutation mutation = new HybridSimulationMutation();
        uint256 balance = address(safe).balance;
        uint256 recipientBalance = address(0xCAFE).balance;
        bytes memory beforeSlot = safe.getStorageAt(0, 1);
        vm.expectRevert();
        safe.simulateAndRevert(address(mutation), abi.encodeCall(mutation.mutate, (address(0xCAFE))));
        require(
            keccak256(safe.getStorageAt(0, 1)) == keccak256(beforeSlot) && safe.nonce() == 0,
            "persistent simulation storage"
        );
        require(
            address(safe).balance == balance && address(0xCAFE).balance == recipientBalance,
            "persistent simulation transfer"
        );
        _attest(vm.addr(ecKey), address(pq));
    }

    function testForbiddenSafeMutationsAndMalformedBatch() public {
        bytes[6] memory forbidden = [
            abi.encodeWithSignature("enableModule(address)", address(this)),
            abi.encodeWithSignature("removeOwner(address,address,uint256)", address(1), vm.addr(ecKey), 1),
            abi.encodeWithSignature("changeThreshold(uint256)", 1),
            abi.encodeWithSignature("setGuard(address)", address(0)),
            abi.encodeWithSignature("setFallbackHandler(address)", address(this)),
            abi.encodeWithSignature("swapOwner(address,address,address)", address(1), vm.addr(ecKey), address(this))
        ];
        for (uint256 i; i < forbidden.length; ++i) {
            bytes memory data = _outer(_call(address(safe), 0, forbidden[i]));
            _fails(data, _signatures(ecKey, data));
        }
        vm.expectRevert();
        safe.execTransactionFromModule(address(this), 0, "", Enum.Operation.Call);
        bytes memory good = _spend(sequence[0], address(0xCAFE));
        for (uint256 i; i < 5; ++i) {
            bytes memory bad = bytes.concat(good);
            if (i == 0) bad[68] = 0x01; // nested delegatecall
            if (i == 1) bad[bad.length - 1] = 0x01; // nonzero ABI padding
            if (i == 2) bad[68 + 85 + 52] = 0x01; // wrong funding
            if (i == 3) bad = bytes.concat(bad, new bytes(32));
            if (i == 4) bad[68 + 255 + 4] = 0x01; // noncanonical swap address upper bits
            _fails(bad, _signatures(ecKey, bad));
        }
        bytes memory sig = _signatures(ecKey, good);
        vm.expectRevert();
        safe.execTransaction(
            address(multi), 0, good, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), sig
        );
        _attest(vm.addr(ecKey), address(pq));
    }

    function testRollbackAndReentry() public {
        HybridRevertingRecipient receiver = new HybridRevertingRecipient();
        bytes memory data = _spend(sequence[0], address(receiver));
        uint256 nonce = safe.nonce();
        _fails(data, _signatures(ecKey, data));
        require(safe.nonce() == nonce && sequence[0].balance == 0, "partial failure");
        _attest(vm.addr(ecKey), address(pq));
        bytes memory nested = _spend(sequence[0], address(0xCAFE));
        bytes memory innerPreimage = safe.encodeTransactionData(
            address(multi), 0, nested, Enum.Operation.DelegateCall, 0, 0, 0, address(0), address(0), safe.nonce() + 1
        );
        bytes memory sig = _signPreimage(ecKey, innerPreimage);
        HybridReentrantRecipient reentrant = new HybridReentrantRecipient(
            address(safe),
            abi.encodeCall(
                safe.execTransaction,
                (address(multi), 0, nested, Enum.Operation.DelegateCall, 0, 0, 0, address(0), payable(address(0)), sig)
            )
        );
        _valid(ecKey, _spend(sequence[0], address(reentrant)));
        require(
            reentrant.blocked() && reentrant.reason() == BunkerHybridRotationGuard.Policy.selector,
            "guard must stop correctly signed reentry"
        );
        _attest(sequence[0], address(pq));
    }

    function testUnregisteredAdapterAndStaticcallOnly() public {
        C10SafeOwner impostor = new C10SafeOwner(
            bytes32(uint256(9) << 128), bytes32(uint256(10) << 128), address(c10), address(c10).codehash, 1
        );
        impostor.bind(address(safe));
        bytes memory swap = _outer(_swap(vm.addr(ecKey), address(pq), address(impostor)));
        _fails(swap, _signatures(ecKey, swap));
        MockStatefulVerifier stateful = new MockStatefulVerifier();
        C10SafeOwner adapter = new C10SafeOwner(
            bytes32(uint256(9) << 128), bytes32(uint256(10) << 128), address(stateful), address(stateful).codehash, 0
        );
        adapter.bind(address(safe));
        bytes memory pre = _preimage("");
        bytes memory raw = new bytes(4008);
        vm.prank(address(safe));
        vm.expectRevert();
        adapter.isValidSignature{gas: 100000}(pre, raw);
        require(stateful.writes() == 0, "verifier wrote state");
    }

    function testSignedForbiddenGasRefundOperationAndTarget() public {
        bytes memory data = _spend(sequence[0], address(0xCAFE));
        for (uint256 i; i < 8; ++i) {
            address to = i == 0 ? address(c10) : address(multi);
            uint256 value = i == 1 ? 1 : 0;
            Enum.Operation op = i == 2 ? Enum.Operation.Call : Enum.Operation.DelegateCall;
            uint256 txGas = i == 3 ? 1000000 : 0;
            uint256 baseGas = i == 4 ? 1 : 0;
            uint256 price = i == 5 ? 1 : 0;
            address token = i == 6 ? address(c10) : address(0);
            address payable refund = payable(i == 7 ? address(this) : address(0));
            bytes memory pre =
                safe.encodeTransactionData(to, value, data, op, txGas, baseGas, price, token, refund, safe.nonce());
            bytes memory sig = _signPreimage(ecKey, pre);
            vm.expectRevert();
            safe.execTransaction(to, value, data, op, txGas, baseGas, price, token, refund, sig);
        }
    }

    function testChangedDependenciesAndSlotsRejectAttestation() public {
        bytes memory original = address(multi).code;
        vm.etch(address(multi), hex"00");
        vm.expectRevert();
        guard.attest(address(safe), vm.addr(ecKey), address(pq));
        vm.etch(address(multi), original);
        original = address(singleton).code;
        vm.etch(address(singleton), hex"00");
        vm.expectRevert();
        guard.attest(address(safe), vm.addr(ecKey), address(pq));
        vm.etch(address(singleton), original);
        bytes32 slot = 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
        vm.store(address(safe), slot, bytes32(uint256(9)));
        vm.expectRevert();
        guard.attest(address(safe), vm.addr(ecKey), address(pq));
        vm.store(address(safe), slot, 0);
        slot = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
        vm.store(address(safe), slot, 0);
        vm.expectRevert();
        guard.attest(address(safe), vm.addr(ecKey), address(pq));
    }

    function testAttestationRejectsMaliciousModule() public {
        // Transaction guards cannot intercept module execution: explicitly demonstrate the invariant boundary.
        vm.prank(address(safe));
        safe.enableModule(address(this));
        vm.expectRevert();
        guard.attest(address(safe), vm.addr(ecKey), address(pq));
        require(
            safe.execTransactionFromModule(address(0xCAFE), 1 ether, "", Enum.Operation.Call), "module bypass absent"
        );
    }
}
