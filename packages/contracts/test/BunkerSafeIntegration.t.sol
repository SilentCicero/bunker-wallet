// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Safe} from "@safe-global/safe-contracts/contracts/Safe.sol";
import {SafeProxy} from "@safe-global/safe-contracts/contracts/proxies/SafeProxy.sol";
import {SafeProxyFactory} from "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import {MultiSendCallOnly} from "@safe-global/safe-contracts/contracts/libraries/MultiSendCallOnly.sol";
import {Enum} from "@safe-global/safe-contracts/contracts/common/Enum.sol";
import {BunkerRotationGuard} from "../src/BunkerRotationGuard.sol";
import {BunkerSafeSetup} from "../src/BunkerSafeSetup.sol";

interface Vm {
    function addr(uint256 privateKey) external returns (address);
    function deal(address who, uint256 newBalance) external;
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function expectRevert() external;
    function prank(address caller) external;
}

contract RevertingReceiver { receive() external payable { revert(); } }

contract BunkerSafeIntegrationTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address private constant SENTINEL = address(0x1);

    Safe private singleton;
    SafeProxyFactory private factory;
    MultiSendCallOnly private multiSend;
    BunkerRotationGuard private guard;
    BunkerSafeSetup private helper;
    Safe private safe;
    uint256 private ownerKey = 0xA11CE;
    uint256[20] private futureKeys;
    address[20] private futureOwners;

    function setUp() public {
        singleton = new Safe();
        factory = new SafeProxyFactory();
        multiSend = new MultiSendCallOnly();
        guard = new BunkerRotationGuard(address(multiSend), address(multiSend).codehash);
        helper = new BunkerSafeSetup();
        for (uint256 i; i < 20; ++i) {
            futureKeys[i] = 1000 + i;
            futureOwners[i] = vm.addr(futureKeys[i]);
        }
        address[] memory owners = new address[](1);
        owners[0] = vm.addr(ownerKey);
        bytes memory helperData = abi.encodeCall(BunkerSafeSetup.setup, (address(guard), futureOwners));
        bytes memory initializer = abi.encodeCall(Safe.setup, (owners, 1, address(helper), helperData, address(0), address(0), 0, payable(address(0))));
        SafeProxy proxy = factory.createChainSpecificProxyWithNonce(address(singleton), initializer, 1);
        safe = Safe(payable(address(proxy)));
        vm.deal(address(safe), 100 ether);
    }

    function _packedCall(address to, uint256 value, bytes memory data) private pure returns (bytes memory) {
        return abi.encodePacked(uint8(0), to, value, data.length, data);
    }

    function _execute(uint256 signerKey, address recipient, uint256 amount, address nextOwner) private returns (bool) {
        address current = vm.addr(signerKey);
        bytes memory swapData = abi.encodeWithSignature("swapOwner(address,address,address)", SENTINEL, current, nextOwner);
        bytes memory transactions = bytes.concat(
            _packedCall(recipient, amount, ""),
            _packedCall(nextOwner, 0.001 ether, ""),
            _packedCall(address(safe), 0, swapData)
        );
        bytes memory data = abi.encodeCall(MultiSendCallOnly.multiSend, transactions);
        uint256 nonce = safe.nonce();
        bytes32 txHash = safe.getTransactionHash(address(multiSend), 0, data, Enum.Operation.DelegateCall, 0, 0, 0, address(0), payable(address(0)), nonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, txHash);
        return safe.execTransaction(address(multiSend), 0, data, Enum.Operation.DelegateCall, 0, 0, 0, address(0), payable(address(0)), abi.encodePacked(r, s, v));
    }

    function testRejectsUnpinnedMultiSendCodeHash() public {
        vm.expectRevert();
        new BunkerRotationGuard(address(multiSend), bytes32(uint256(1)));
    }

    function testRejectsSentinelFutureOwnerDuringAtomicSetup() public {
        BunkerRotationGuard secondGuard = new BunkerRotationGuard(address(multiSend), address(multiSend).codehash);
        address[20] memory invalidOwners = futureOwners;
        invalidOwners[3] = SENTINEL;
        address[] memory owners = new address[](1);
        owners[0] = vm.addr(ownerKey);
        bytes memory helperData = abi.encodeCall(BunkerSafeSetup.setup, (address(secondGuard), invalidOwners));
        bytes memory initializer = abi.encodeCall(Safe.setup, (owners, 1, address(helper), helperData, address(0), address(0), 0, payable(address(0))));
        vm.expectRevert();
        factory.createChainSpecificProxyWithNonce(address(singleton), initializer, 2);
    }

    function executeForTest(uint256 signerKey, address recipient, uint256 amount, address nextOwner) external returns (bool) {
        require(msg.sender == address(this), "self only");
        return _execute(signerKey, recipient, amount, nextOwner);
    }

    function testRecipientFailureRollsBackOwnerAndGuardIndex() public {
        RevertingReceiver recipient = new RevertingReceiver();
        (bool ok,) = address(this).call(abi.encodeCall(this.executeForTest, (ownerKey, address(recipient), 1 ether, futureOwners[0])));
        require(!ok, "recipient failure accepted");
        address[] memory owners = safe.getOwners();
        require(owners.length == 1 && owners[0] == vm.addr(ownerKey), "owner changed");
        (, uint8 nextIndex,, bool executing) = guard.state(address(safe));
        require(nextIndex == 0 && !executing, "guard changed");
    }

    function testAtomicSetupAndCanonicalPaddedRotation() public {
        address recipient = vm.addr(777);
        address[] memory owners = safe.getOwners();
        require(owners.length == 1 && owners[0] == vm.addr(ownerKey), "initial owner");
        (bytes32 root, uint8 nextIndex, bool initialized, bool executing) = guard.state(address(safe));
        require(root != bytes32(0) && nextIndex == 0 && initialized && !executing, "guard initialization");
        require(_execute(ownerKey, recipient, 1 ether, futureOwners[0]), "execution");
        require(recipient.balance == 1 ether, "recipient amount");
        require(futureOwners[0].balance == 0.001 ether, "next owner gas");
        owners = safe.getOwners();
        require(owners.length == 1 && owners[0] == futureOwners[0], "rotated owner");
        (, nextIndex,, executing) = guard.state(address(safe));
        require(nextIndex == 1 && !executing, "guard index");
    }

    function testRejectsMissingNextOwnerFunding() public {
        address recipient = vm.addr(778);
        bytes memory swapData = abi.encodeWithSignature("swapOwner(address,address,address)", SENTINEL, vm.addr(ownerKey), futureOwners[0]);
        bytes memory transactions = bytes.concat(_packedCall(recipient, 1 ether, ""), _packedCall(address(safe), 0, swapData));
        bytes memory data = abi.encodeCall(MultiSendCallOnly.multiSend, transactions);
        bytes32 txHash = safe.getTransactionHash(address(multiSend), 0, data, Enum.Operation.DelegateCall, 0, 0, 0, address(0), payable(address(0)), safe.nonce());
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, txHash);
        vm.expectRevert();
        safe.execTransaction(address(multiSend), 0, data, Enum.Operation.DelegateCall, 0, 0, 0, address(0), payable(address(0)), abi.encodePacked(r, s, v));
    }

    function testRejectsWrongNextOwnerFundingAmount() public {
        address recipient = vm.addr(779);
        bytes memory swapData = abi.encodeWithSignature("swapOwner(address,address,address)", SENTINEL, vm.addr(ownerKey), futureOwners[0]);
        bytes memory transactions = bytes.concat(
            _packedCall(recipient, 1 ether, ""),
            _packedCall(futureOwners[0], 0.002 ether, ""),
            _packedCall(address(safe), 0, swapData)
        );
        bytes memory data = abi.encodeCall(MultiSendCallOnly.multiSend, transactions);
        bytes32 txHash = safe.getTransactionHash(address(multiSend), 0, data, Enum.Operation.DelegateCall, 0, 0, 0, address(0), payable(address(0)), safe.nonce());
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, txHash);
        vm.expectRevert();
        safe.execTransaction(address(multiSend), 0, data, Enum.Operation.DelegateCall, 0, 0, 0, address(0), payable(address(0)), abi.encodePacked(r, s, v));
    }

    function testSequenceExhaustionIsExplicit() public {
        address recipient = vm.addr(780);
        uint256 signer = ownerKey;
        for (uint256 i; i < 19; ++i) {
            require(_execute(signer, recipient, 0.01 ether, futureOwners[i]), "rotation");
            signer = futureKeys[i];
        }
        require(guard.rotationsRemaining(address(safe)) == 0, "remaining");
        vm.prank(address(safe));
        vm.expectRevert();
        guard.checkTransaction(address(multiSend), 0, "", Enum.Operation.DelegateCall, 0, 0, 0, address(0), payable(address(0)), new bytes(65), address(this));
    }
}
