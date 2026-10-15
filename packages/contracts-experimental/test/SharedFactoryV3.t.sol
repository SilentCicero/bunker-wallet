// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Safe} from "@safe-global/safe-contracts/contracts/Safe.sol";
import {SafeProxy} from "@safe-global/safe-contracts/contracts/proxies/SafeProxy.sol";
import {SafeProxyFactory} from "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import {MultiSendCallOnly} from "@safe-global/safe-contracts/contracts/libraries/MultiSendCallOnly.sol";
import {ExperimentalSharedFactoryV3} from "../src/ExperimentalSharedFactoryV3.sol";
import {ExperimentalOwner, ExperimentalMLDSAOwner} from "../src/ExperimentalOwner.sol";
import {ExperimentalRotationGuardV3} from "../src/ExperimentalRotationGuardV3.sol";
import {Enum} from "@safe-global/safe-contracts/contracts/common/Enum.sol";

interface VmV3 {
    function chainId(uint256) external;
    function etch(address, bytes calldata) external;
    function readFile(string calldata) external returns (string memory);
    function parseBytes(string calldata) external pure returns (bytes memory);
    function deal(address, uint256) external;
    function prank(address) external;
    function expectRevert() external;
}

/// @dev Mock verifier: guard policy only; real PQ signatures belong in Anvil lifecycle.
contract SharedFactoryV3Test {
    VmV3 constant vm = VmV3(address(uint160(uint256(keccak256("hevm cheat code")))));
    ExperimentalSharedFactoryV3 factory;
    address constant EC = address(0xBEEF);
    address constant HELPER = address(0x1234);
    address constant C10 = address(0x4567);
    address constant MLDSA = address(0x8901);
    address constant BLOB = address(0xABCD);

    function dependency(address target) private view returns (ExperimentalSharedFactoryV3.Dependency memory) {
        return ExperimentalSharedFactoryV3.Dependency(target, target.codehash);
    }

    function sequence() private pure returns (address[20] memory result) {
        for (uint256 i; i < 20; ++i) {
            result[i] = address(uint160(0x1000 + i));
        }
    }

    function c10Key(uint256 seed) private pure returns (ExperimentalSharedFactoryV3.Key memory) {
        return ExperimentalSharedFactoryV3.Key(1, bytes32(seed << 128), bytes32(uint256(2) << 128), address(0), "");
    }

    function mldsaKey() private pure returns (ExperimentalSharedFactoryV3.Key memory result) {
        bytes memory publicKey = new bytes(1312);
        for (uint256 i; i < publicKey.length; ++i) {
            publicKey[i] = 0x55;
        }
        result = ExperimentalSharedFactoryV3.Key(2, 0, 0, BLOB, publicKey);
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
        factory = new ExperimentalSharedFactoryV3(
            dependency(address(singleton)),
            dependency(address(proxies)),
            dependency(address(multi)),
            dependency(C10),
            dependency(MLDSA),
            dependency(HELPER),
            keccak256(type(SafeProxy).runtimeCode)
        );
        vm.deal(EC, 1 ether);
    }

    function testC10CreatesFundsAttestsAndRegistersCandidate() public {
        vm.prank(EC);
        (address safe, address pq) = factory.createAndFund{value: 0.1 ether}(EC, sequence(), c10Key(1), 0);
        require(safe.balance == 0.1 ether && factory.createdSafe(safe) && factory.usedInitialOwner(EC));
        require(Safe(payable(safe)).getThreshold() == 2);
        address[] memory owners = Safe(payable(safe)).getOwners();
        require(owners.length == 2 && owners[0] == EC && owners[1] == pq);
        factory.guard().attest(safe, EC, pq);
        address candidate = factory.createRotationAdapter(safe, c10Key(3));
        require(ExperimentalOwner(candidate).safe() == safe && factory.adapterCodeHash(candidate) == candidate.codehash);
        require(Safe(payable(safe)).getOwners()[1] == pq); // Registration cannot change the installed owner.
        vm.expectRevert();
        factory.createRotationAdapter(safe, mldsaKey());
        vm.expectRevert(); // Already consumed by this Safe.
        factory.createRotationAdapter(safe, c10Key(1));
        vm.prank(EC);
        vm.expectRevert();
        factory.createAndFund{value: 0.1 ether}(EC, sequence(), c10Key(3), 1);
    }

    function testMLDSACreatesUsingPredeployedBlob() public {
        vm.prank(EC);
        (address safe, address pq) = factory.createAndFund{value: 0.1 ether}(EC, sequence(), mldsaKey(), 0);
        require(ExperimentalMLDSAOwner(pq).pkBlob() == BLOB && safe.balance == 0.1 ether);
        factory.guard().attest(safe, EC, pq);
    }

    function testRejectsWrongCallerZeroValueBrokenDependencyAndBadBlob() public {
        vm.expectRevert();
        factory.createAndFund{value: 0.1 ether}(EC, sequence(), c10Key(1), 0);
        vm.prank(EC);
        vm.expectRevert();
        factory.createAndFund(EC, sequence(), c10Key(1), 0);
        ExperimentalSharedFactoryV3.Key memory malformed = mldsaKey();
        malformed.blob = address(0x9999);
        vm.prank(EC);
        vm.expectRevert();
        factory.createAndFund{value: 0.1 ether}(EC, sequence(), malformed, 0);
        vm.etch(C10, hex"00");
        vm.prank(EC);
        vm.expectRevert();
        factory.createAndFund{value: 0.1 ether}(EC, sequence(), c10Key(1), 0);
        require(!factory.usedInitialOwner(EC));
    }

    function testBadSequenceRollsBackFundingAndAllowsCorrectRetry() public {
        address[20] memory invalid = sequence();
        invalid[1] = invalid[0];
        vm.prank(EC);
        vm.expectRevert();
        factory.createAndFund{value: 0.1 ether}(EC, invalid, c10Key(1), 0);
        require(EC.balance == 1 ether && !factory.usedInitialOwner(EC));
        vm.prank(EC);
        (address safe,) = factory.createAndFund{value: 0.1 ether}(EC, sequence(), c10Key(1), 0);
        require(safe.balance == 0.1 ether && EC.balance == 0.9 ether);
    }

    function packed(address target, uint256 value, bytes memory data) private pure returns (bytes memory) {
        return abi.encodePacked(uint8(0), target, value, data.length, data);
    }

    function signatures(address pq) private pure returns (bytes memory) {
        bytes memory ec = abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(1)), hex"1b");
        bytes memory contractOwner = abi.encodePacked(bytes32(uint256(uint160(pq))), bytes32(uint256(130)), hex"00");
        return bytes.concat(
            EC < pq ? bytes.concat(ec, contractOwner) : bytes.concat(contractOwner, ec),
            bytes32(uint256(4008)),
            new bytes(4008)
        );
    }

    function check(address safe, address pq, bytes memory raw, bool reject) private {
        checkSigned(safe, raw, signatures(pq), reject);
    }

    function checkSigned(address safe, bytes memory raw, bytes memory sig, bool reject) private {
        ExperimentalRotationGuardV3 guard = factory.guard();
        address multi = guard.multiSendCallOnly();
        if (reject) vm.expectRevert();
        vm.prank(safe);
        guard.checkTransaction(
            multi,
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

    function testArbitraryExternalCallMustEndInExactRotation() public {
        vm.prank(EC);
        (address safe, address pq) = factory.createAndFund{value: 0.1 ether}(EC, sequence(), c10Key(1), 0);
        address next = sequence()[0];
        bytes memory suffix = bytes.concat(
            packed(next, 0.001 ether, ""),
            packed(safe, 0, abi.encodeWithSignature("swapOwner(address,address,address)", address(1), EC, next))
        );
        bytes memory payload = abi.encodeWithSignature("transfer(address,uint256)", address(0xCAFE), 7);
        bytes memory batch = bytes.concat(packed(address(0xFEED), 0, payload), suffix);
        check(safe, pq, batch, false);
    }

    function testMultipleExternalCallsMustEndInExactRotation() public {
        vm.prank(EC);
        (address safe, address pq) = factory.createAndFund{value: 0.1 ether}(EC, sequence(), c10Key(1), 0);
        address next = sequence()[0];
        bytes memory suffix = bytes.concat(
            packed(next, 0.001 ether, ""),
            packed(safe, 0, abi.encodeWithSignature("swapOwner(address,address,address)", address(1), EC, next))
        );
        check(
            safe,
            pq,
            bytes.concat(packed(address(0xFEED), 0, hex"1234"), packed(address(0xCAFE), 1, hex"deadbeef"), suffix),
            false
        );
    }

    function testEightExternalCallsAreAcceptedAtPolicyBoundary() public {
        vm.prank(EC);
        (address safe, address pq) = factory.createAndFund{value: 0.1 ether}(EC, sequence(), c10Key(1), 0);
        bytes memory calls;
        for (uint256 i; i < 8; ++i) {
            calls = bytes.concat(calls, packed(address(0xFEED), 0, hex"1234"));
        }
        address next = sequence()[0];
        bytes memory suffix = bytes.concat(
            packed(next, 0.001 ether, ""),
            packed(safe, 0, abi.encodeWithSignature("swapOwner(address,address,address)", address(1), EC, next))
        );
        check(safe, pq, bytes.concat(calls, suffix), false);
    }

    function testRejectsMalformedPQSignatureFraming() public {
        vm.prank(EC);
        (address safe, address pq) = factory.createAndFund{value: 0.1 ether}(EC, sequence(), c10Key(1), 0);
        address next = sequence()[0];
        bytes memory batch = bytes.concat(
            packed(address(0xFEED), 0, hex"1234"),
            packed(next, 0.001 ether, ""),
            packed(safe, 0, abi.encodeWithSignature("swapOwner(address,address,address)", address(1), EC, next))
        );
        bytes memory sig = signatures(pq);
        uint256 contractPos = EC < pq ? 65 : 0;
        uint256 ecPos = 65 - contractPos;
        sig[contractPos + 64] = 0x01;
        checkSigned(safe, batch, sig, true);
        sig[contractPos + 64] = 0x00;
        sig[ecPos + 64] = 0x00;
        checkSigned(safe, batch, sig, true);
        sig[ecPos + 64] = 0x1b;
        sig[ecPos + 32] = 0x80;
        checkSigned(safe, batch, sig, true);
        sig[ecPos + 32] = 0x00;
        sig[161] = 0xa9; // Invalid dynamic signature length (4009, not 4008).
        checkSigned(safe, batch, sig, true);
    }

    function testFuzzRejectsInvalidCallCountAndTruncatedCalldata(uint8 requested) public {
        vm.prank(EC);
        (address safe, address pq) = factory.createAndFund{value: 0.1 ether}(EC, sequence(), c10Key(1), 0);
        address next = sequence()[0];
        bytes memory suffix = bytes.concat(
            packed(next, 0.001 ether, ""),
            packed(safe, 0, abi.encodeWithSignature("swapOwner(address,address,address)", address(1), EC, next))
        );
        uint256 count = uint256(requested) % 11;
        if (count > 0 && count <= 8) count = 9;
        bytes memory calls;
        for (uint256 i; i < count; ++i) {
            calls = bytes.concat(calls, packed(address(0xFEED), 0, hex"1234"));
        }
        check(safe, pq, bytes.concat(calls, suffix), true);

        bytes memory truncated = bytes.concat(packed(address(0xFEED), 0, hex"1234"), suffix);
        assembly {
            mstore(add(truncated, 0x55), not(0)) // First CALL calldata length overflows policy bounds.
        }
        check(safe, pq, truncated, true);
    }

    function testRejectsMalformedAndPrivilegedExternalCall() public {
        vm.prank(EC);
        (address safe, address pq) = factory.createAndFund{value: 0.1 ether}(EC, sequence(), c10Key(1), 0);
        address next = sequence()[0];
        bytes memory suffix = bytes.concat(
            packed(next, 0.001 ether, ""),
            packed(safe, 0, abi.encodeWithSignature("swapOwner(address,address,address)", address(1), EC, next))
        );
        bytes memory callData = packed(address(0xFEED), 0, hex"1234");
        check(safe, pq, callData, true); // no rotation
        check(safe, pq, bytes.concat(suffix, callData), true); // rotation first
        check(safe, pq, bytes.concat(callData, suffix, callData), true); // extra call after suffix
        check(safe, pq, bytes.concat(packed(pq, 0, hex"1234"), suffix), true);
        check(safe, pq, bytes.concat(packed(address(factory), 0, hex"1234"), suffix), true);
        check(safe, pq, bytes.concat(packed(address(factory.proxyFactory()), 0, hex"1234"), suffix), true);
        check(safe, pq, bytes.concat(packed(address(0xFEED), 0, new bytes(8193)), suffix), true);
        bytes memory tooMany;
        for (uint256 i; i < 9; ++i) {
            tooMany = bytes.concat(tooMany, callData);
        }
        check(safe, pq, bytes.concat(tooMany, suffix), true);
        bytes memory malformed = bytes.concat(callData, packed(address(0xCAFE), 0, hex"deadbeef"), suffix);
        malformed[callData.length] = 0x01;
        check(safe, pq, malformed, true);
        check(safe, pq, bytes.concat(packed(safe, 0, hex"1234"), suffix), true);
        check(safe, pq, bytes.concat(packed(address(factory.guard()), 0, hex"1234"), suffix), true);
        check(safe, pq, bytes.concat(packed(address(factory.guard().multiSendCallOnly()), 0, hex"1234"), suffix), true);
        check(
            safe,
            pq,
            bytes.concat(
                packed(address(0xFEED), 0, hex"1234"),
                packed(next, 0.002 ether, ""),
                packed(safe, 0, abi.encodeWithSignature("swapOwner(address,address,address)", address(1), EC, next))
            ),
            true
        );
        bytes memory delegateBatch = bytes.concat(callData, suffix);
        delegateBatch[0] = 0x01;
        check(safe, pq, delegateBatch, true);
    }
}
