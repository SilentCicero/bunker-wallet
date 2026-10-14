// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Safe} from "@safe-global/safe-contracts/contracts/Safe.sol";
import {SafeProxy} from "@safe-global/safe-contracts/contracts/proxies/SafeProxy.sol";
import {SafeProxyFactory} from "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import {MultiSendCallOnly} from "@safe-global/safe-contracts/contracts/libraries/MultiSendCallOnly.sol";
import {Enum} from "@safe-global/safe-contracts/contracts/common/Enum.sol";
import {ExperimentalFactory, ExperimentalSetup} from "../src/ExperimentalFactory.sol";
import {ExperimentalRotationGuard} from "../src/ExperimentalRotationGuard.sol";
import {ExperimentalOwner, ExperimentalMLDSAOwner} from "../src/ExperimentalOwner.sol";

interface VmLegacy {
    function chainId(uint256 chain) external;
    function etch(address target, bytes calldata code) external;
    function readFile(string calldata path) external returns (string memory);
    function parseBytes(string calldata value) external pure returns (bytes memory);
    function prank(address caller) external;
    function expectRevert() external;
}

contract LegacyFactoryTest {
    VmLegacy private constant vm = VmLegacy(address(uint160(uint256(keccak256("hevm cheat code")))));
    address private constant EC = address(0xBEEF);
    address private constant HELPER = address(0x1234);
    address private constant C10 = address(0x4567);
    address private constant MLDSA = address(0x8901);
    address private constant BLOB = address(0xABCD);

    ExperimentalFactory private factory;

    function _dependency(address target) private view returns (ExperimentalFactory.Dependency memory) {
        return ExperimentalFactory.Dependency(target, target.codehash);
    }

    function _sequence() private pure returns (address[20] memory owners) {
        for (uint256 i; i < owners.length; ++i) {
            owners[i] = address(uint160(0x1000 + i));
        }
    }

    function _c10Key(uint256 seed) private pure returns (ExperimentalFactory.Key memory) {
        return ExperimentalFactory.Key(1, bytes32(seed << 128), bytes32(uint256(2) << 128), address(0), "");
    }

    function _mldsaKey() private pure returns (ExperimentalFactory.Key memory) {
        bytes memory publicKey = new bytes(1312);
        for (uint256 i; i < publicKey.length; ++i) {
            publicKey[i] = 0x55;
        }
        return ExperimentalFactory.Key(2, 0, 0, BLOB, publicKey);
    }

    function setUp() public {
        vm.chainId(11155111);
        Safe singleton = new Safe();
        SafeProxyFactory proxies = new SafeProxyFactory();
        MultiSendCallOnly multi = new MultiSendCallOnly();
        vm.etch(HELPER, vm.parseBytes(string.concat("0x", vm.readFile("../../packages/pq/verifiers/mldsa/helper.hex"))));
        vm.etch(C10, hex"600160005260206000f3");
        vm.etch(MLDSA, hex"600160005260206000f3");
        vm.etch(BLOB, new bytes(20545));
        factory = new ExperimentalFactory(
            _dependency(address(singleton)),
            _dependency(address(proxies)),
            _dependency(address(multi)),
            _dependency(C10),
            _dependency(MLDSA),
            _dependency(HELPER),
            keccak256(type(SafeProxy).runtimeCode)
        );
    }

    function testLegacyC10CreationAndCandidateRegistration() public {
        (address safe, address pq) = factory.create(EC, _sequence(), _c10Key(1), 0);
        require(factory.createdSafe(safe), "Safe not registered");
        Safe wallet = Safe(payable(safe));
        address[] memory owners = wallet.getOwners();
        require(wallet.getThreshold() == 2 && owners.length == 2, "wrong threshold");
        require(owners[0] == EC && owners[1] == pq, "wrong owners");
        factory.guard().attest(safe, EC, pq);
        address candidate = factory.createRotationAdapter(safe, _c10Key(3));
        require(ExperimentalOwner(candidate).safe() == safe, "candidate not bound");
        require(wallet.getOwners()[1] == pq, "candidate installed without signatures");
    }

    function testOwnerRejectsUnauthorizedMalformedAndChangedVerifier() public {
        (address safe, address pq) = factory.create(EC, _sequence(), _c10Key(1), 0);
        ExperimentalOwner adapter = ExperimentalOwner(pq);
        bytes memory preimage = abi.encodePacked(
            hex"1901",
            keccak256(
                abi.encode(keccak256("EIP712Domain(uint256 chainId,address verifyingContract)"), block.chainid, safe)
            ),
            bytes32(uint256(1))
        );
        bytes memory sig = new bytes(4008);
        vm.expectRevert();
        adapter.isValidSignature(preimage, sig); // Only the installed Safe may call the adapter.
        vm.prank(safe);
        require(adapter.isValidSignature(preimage, sig) == 0x20c13b0b, "mock verifier rejected");
        vm.prank(safe);
        vm.expectRevert();
        adapter.isValidSignature(preimage, new bytes(4007));
        preimage[2] ^= 0x01;
        vm.prank(safe);
        vm.expectRevert();
        adapter.isValidSignature(preimage, sig);
        preimage[2] ^= 0x01;
        vm.etch(C10, hex"00");
        vm.prank(safe);
        vm.expectRevert();
        adapter.isValidSignature(preimage, sig);
    }

    function _call(address target, uint256 value, bytes memory data) private pure returns (bytes memory) {
        return abi.encodePacked(uint8(0), target, value, data.length, data);
    }

    function _signatures(address pq) private pure returns (bytes memory) {
        bytes memory ec = abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(1)), hex"1b");
        bytes memory contractOwner = abi.encodePacked(bytes32(uint256(uint160(pq))), bytes32(uint256(130)), hex"00");
        return bytes.concat(
            EC < pq ? bytes.concat(ec, contractOwner) : bytes.concat(contractOwner, ec),
            bytes32(uint256(4008)),
            new bytes(4008)
        );
    }

    function _check(address safe, bytes memory raw, bytes memory sig, bool reject) private {
        ExperimentalRotationGuard guard = factory.guard();
        address multiSend = guard.multiSendCallOnly();
        if (reject) vm.expectRevert();
        vm.prank(safe);
        guard.checkTransaction(
            multiSend,
            0,
            abi.encodeWithSignature("multiSend(bytes)", raw),
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            sig,
            address(0)
        );
    }

    function testLegacyGuardRejectsPolicyBypassesAndAcceptsAtomicSend() public {
        (address safe, address pq) = factory.create(EC, _sequence(), _c10Key(1), 0);
        address next = _sequence()[0];
        bytes memory transfer = _call(address(0xFEED), 1 ether, "");
        bytes memory funding = _call(next, 0.001 ether, "");
        bytes memory swap =
            _call(safe, 0, abi.encodeWithSignature("swapOwner(address,address,address)", address(1), EC, next));
        bytes memory sig = _signatures(pq);
        _check(safe, transfer, sig, true); // Missing mandatory rotation.
        _check(safe, bytes.concat(transfer, _call(next, 0.002 ether, ""), swap), sig, true);
        _check(safe, bytes.concat(_call(address(0xFEED), 0, hex"1234"), funding, swap), sig, true);
        _check(safe, bytes.concat(transfer, funding, swap), new bytes(65), true);
        ExperimentalRotationGuard guard = factory.guard();
        vm.expectRevert();
        guard.renew(_sequence()); // No renewal without authenticated execution.
        _check(safe, bytes.concat(transfer, funding, swap), sig, false);
    }

    function testLegacyMLDSACreation() public {
        (address safe, address pq) = factory.create(EC, _sequence(), _mldsaKey(), 1);
        require(ExperimentalMLDSAOwner(pq).pkBlob() == BLOB, "wrong blob");
        factory.guard().attest(safe, EC, pq);
    }

    function testRejectsForgedInitializationAndInvalidKeys() public {
        ExperimentalRotationGuard guard = factory.guard();
        ExperimentalSetup setup = factory.setup();
        vm.expectRevert();
        guard.initialize(address(0xCAFE), EC, address(0xDEAD), _sequence());
        vm.expectRevert();
        setup.install();
        vm.expectRevert();
        factory.createRotationAdapter(address(0xCAFE), _c10Key(1));

        address[20] memory duplicate = _sequence();
        duplicate[1] = duplicate[0];
        vm.expectRevert();
        factory.create(EC, duplicate, _c10Key(1), 2);

        (address safe, address pq) = factory.create(EC, _sequence(), _c10Key(1), 2);
        vm.expectRevert();
        factory.createRotationAdapter(safe, _c10Key(1));
        vm.expectRevert();
        factory.createRotationAdapter(safe, _mldsaKey());
        vm.expectRevert();
        ExperimentalOwner(pq).bind(address(0xCAFE));
    }

    function testRejectsChangedDependencyAndWrongChain() public {
        vm.etch(C10, hex"00");
        vm.expectRevert();
        factory.create(EC, _sequence(), _c10Key(1), 0);
        vm.chainId(1);
        vm.expectRevert();
        factory.create(EC, _sequence(), _c10Key(1), 0);
    }
}
