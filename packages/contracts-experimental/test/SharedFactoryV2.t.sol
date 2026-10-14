// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Safe} from "@safe-global/safe-contracts/contracts/Safe.sol";
import {SafeProxy} from "@safe-global/safe-contracts/contracts/proxies/SafeProxy.sol";
import {SafeProxyFactory} from "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import {MultiSendCallOnly} from "@safe-global/safe-contracts/contracts/libraries/MultiSendCallOnly.sol";
import {ExperimentalSharedFactoryV2} from "../src/ExperimentalSharedFactoryV2.sol";
import {ExperimentalOwner, ExperimentalMLDSAOwner} from "../src/ExperimentalOwner.sol";

interface VmV2 {
    function chainId(uint256) external;
    function etch(address, bytes calldata) external;
    function readFile(string calldata) external returns (string memory);
    function parseBytes(string calldata) external pure returns (bytes memory);
    function deal(address, uint256) external;
    function prank(address) external;
    function expectRevert() external;
}

/// @dev Mock verifiers test factory policy only; real C10/ML-DSA signatures belong in the Anvil lifecycle.
contract SharedFactoryV2Test {
    VmV2 constant vm = VmV2(address(uint160(uint256(keccak256("hevm cheat code")))));
    ExperimentalSharedFactoryV2 factory;
    address constant EC = address(0xBEEF);
    address constant HELPER = address(0x1234);
    address constant C10 = address(0x4567);
    address constant MLDSA = address(0x8901);
    address constant BLOB = address(0xABCD);

    function dependency(address target) private view returns (ExperimentalSharedFactoryV2.Dependency memory) {
        return ExperimentalSharedFactoryV2.Dependency(target, target.codehash);
    }

    function sequence() private pure returns (address[20] memory result) {
        for (uint256 i; i < 20; ++i) result[i] = address(uint160(0x1000 + i));
    }

    function c10Key(uint256 seed) private pure returns (ExperimentalSharedFactoryV2.Key memory) {
        return ExperimentalSharedFactoryV2.Key(1, bytes32(seed << 128), bytes32(uint256(2) << 128), address(0), "");
    }

    function mldsaKey() private pure returns (ExperimentalSharedFactoryV2.Key memory result) {
        bytes memory publicKey = new bytes(1312);
        for (uint256 i; i < publicKey.length; ++i) publicKey[i] = 0x55;
        result = ExperimentalSharedFactoryV2.Key(2, 0, 0, BLOB, publicKey);
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
        factory = new ExperimentalSharedFactoryV2(dependency(address(singleton)), dependency(address(proxies)),
            dependency(address(multi)), dependency(C10), dependency(MLDSA), dependency(HELPER),
            keccak256(type(SafeProxy).runtimeCode));
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
        vm.expectRevert(); factory.createRotationAdapter(safe, mldsaKey());
        vm.expectRevert(); factory.createRotationAdapter(safe, c10Key(1)); // Already consumed by this Safe.
        vm.prank(EC); vm.expectRevert(); factory.createAndFund{value: 0.1 ether}(EC, sequence(), c10Key(3), 1);
    }

    function testMLDSACreatesUsingPredeployedBlob() public {
        vm.prank(EC);
        (address safe, address pq) = factory.createAndFund{value: 0.1 ether}(EC, sequence(), mldsaKey(), 0);
        require(ExperimentalMLDSAOwner(pq).pkBlob() == BLOB && safe.balance == 0.1 ether);
        factory.guard().attest(safe, EC, pq);
    }

    function testRejectsWrongCallerZeroValueBrokenDependencyAndBadBlob() public {
        vm.expectRevert(); factory.createAndFund{value: 0.1 ether}(EC, sequence(), c10Key(1), 0);
        vm.prank(EC); vm.expectRevert(); factory.createAndFund(EC, sequence(), c10Key(1), 0);
        ExperimentalSharedFactoryV2.Key memory malformed = mldsaKey();malformed.blob = address(0x9999);
        vm.prank(EC); vm.expectRevert(); factory.createAndFund{value: 0.1 ether}(EC, sequence(), malformed, 0);
        vm.etch(C10, hex"00");
        vm.prank(EC); vm.expectRevert(); factory.createAndFund{value: 0.1 ether}(EC, sequence(), c10Key(1), 0);
        require(!factory.usedInitialOwner(EC));
    }

    function testBadSequenceRollsBackFundingAndAllowsCorrectRetry() public {
        address[20] memory invalid = sequence();invalid[1] = invalid[0];
        vm.prank(EC); vm.expectRevert(); factory.createAndFund{value: 0.1 ether}(EC, invalid, c10Key(1), 0);
        require(EC.balance == 1 ether && !factory.usedInitialOwner(EC));
        vm.prank(EC); (address safe,) = factory.createAndFund{value: 0.1 ether}(EC, sequence(), c10Key(1), 0);
        require(safe.balance == 0.1 ether && EC.balance == 0.9 ether);
    }
}
