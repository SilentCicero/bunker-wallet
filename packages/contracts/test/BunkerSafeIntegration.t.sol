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
contract ReenteringReceiver {
    address target;
    bool public attempted;
    bool public accepted;
    constructor(address _target) { target = _target; }
    receive() external payable {
        attempted = true;
        (accepted,) = target.call(abi.encodeWithSignature("reenterForTest()"));
    }
}
contract CreatedOwner { receive() external payable {} }
contract DeployingReceiver {
    function candidate() external view returns(address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), bytes32(0), keccak256(type(CreatedOwner).creationCode))))));
    }
    receive() external payable { new CreatedOwner{salt: bytes32(0)}(); }
}

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
        bytes memory helperData = abi.encodeCall(BunkerSafeSetup.setup, (address(guard)));
        bytes memory initializer = abi.encodeCall(Safe.setup, (owners, 1, address(helper), helperData, address(0), address(0), 0, payable(address(0))));
        SafeProxy proxy = factory.createChainSpecificProxyWithNonce(address(singleton), initializer, 1);
        safe = Safe(payable(address(proxy)));
        vm.deal(address(safe), 100 ether);
    }

    function _packedCall(address to, uint256 value, bytes memory data) private pure returns (bytes memory) {
        return abi.encodePacked(uint8(0), to, value, data.length, data);
    }

    function _execute(uint256 signerKey, address recipient, uint256 amount, address nextOwner) private returns (bool) {
        return _executeAtNonce(signerKey, recipient, amount, nextOwner, safe.nonce());
    }

    function _executeAtNonce(uint256 signerKey, address recipient, uint256 amount, address nextOwner, uint256 nonce) private returns (bool) {
        bytes memory data;
        {
        bytes memory swapData = abi.encodeWithSignature("swapOwner(address,address,address)", SENTINEL, vm.addr(signerKey), nextOwner);
        bytes memory transactions = bytes.concat(
            _packedCall(recipient, amount, ""),
            _packedCall(nextOwner, 0.001 ether, ""),
            _packedCall(address(safe), 0, swapData)
        );
        data = abi.encodeCall(MultiSendCallOnly.multiSend, transactions);
        }
        bytes32 txHash = safe.getTransactionHash(address(multiSend), 0, data, Enum.Operation.DelegateCall, 0, 0, 0, address(0), payable(address(0)), nonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, txHash);
        return safe.execTransaction(address(multiSend), 0, data, Enum.Operation.DelegateCall, 0, 0, 0, address(0), payable(address(0)), abi.encodePacked(r, s, v));
    }

    function testDynamicTwentyFiveRotations() public {
        uint256 signer = ownerKey;
        for (uint256 i; i < 25; ++i) {
            uint256 nextKey = 9000 + i;
            require(_execute(signer, vm.addr(777), 0.01 ether, vm.addr(nextKey)), "dynamic rotation");
            require(guard.consumed(address(safe), vm.addr(signer)), "history missing");
            signer = nextKey;
        }
    }

    function testRejectsUnpinnedMultiSendCodeHash() public {
        vm.expectRevert();
        new BunkerRotationGuard(address(multiSend), bytes32(uint256(1)));
    }

    function testRejectsSentinelNextOwner() public {
        vm.expectRevert();
        this.executeForTest(ownerKey, vm.addr(777), 1 ether, SENTINEL);
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
        (, uint256 nextIndex,, bool executing) = guard.state(address(safe));
        require(nextIndex == 0 && !executing, "guard changed");
        require(safe.nonce() == 0, "nonce changed");
        require(address(safe).balance == 100 ether && address(recipient).balance == 0, "ETH changed");
        require(futureOwners[0].balance == 0 && !guard.consumed(address(safe), futureOwners[0]), "candidate consumed or funded");
        require(guard.consumed(address(safe), vm.addr(ownerKey)), "initial owner history lost");
        require(_execute(ownerKey, vm.addr(777), 1 ether, futureOwners[0]), "retry failed");
    }

    function testAtomicSetupAndCanonicalPaddedRotation() public {
        address recipient = vm.addr(777);
        address[] memory owners = safe.getOwners();
        require(owners.length == 1 && owners[0] == vm.addr(ownerKey), "initial owner");
        (address pending, uint256 nextIndex, bool initialized, bool executing) = guard.state(address(safe));
        require(pending == address(0) && nextIndex == 0 && initialized && !executing, "guard initialization");
        require(_execute(ownerKey, recipient, 1 ether, futureOwners[0]), "execution");
        require(recipient.balance == 1 ether, "recipient amount");
        require(futureOwners[0].balance == 0.001 ether, "next owner gas");
        owners = safe.getOwners();
        require(owners.length == 1 && owners[0] == futureOwners[0], "rotated owner");
        (, nextIndex,, executing) = guard.state(address(safe));
        require(nextIndex == 1 && !executing, "guard index");
    }

    function reenterForTest() external {
        require(_execute(ownerKey, vm.addr(777), 0.01 ether, vm.addr(9900)), "nested execution");
    }

    function testRecipientCannotReenterWithValidCurrentSignature() public {
        ReenteringReceiver receiver = new ReenteringReceiver(address(this));
        require(_execute(ownerKey, address(receiver), 1 ether, vm.addr(9901)), "outer execution");
        require(receiver.attempted() && !receiver.accepted(), "reentrancy accepted");
        require(!guard.consumed(address(safe), vm.addr(9900)), "nested candidate consumed");
        (,uint256 count,,bool executing) = guard.state(address(safe));
        require(count == 1 && !executing && safe.nonce() == 1, "state");
    }

    function testRejectsOwnerCodeCreatedDuringTransfer() public {
        DeployingReceiver receiver = new DeployingReceiver();
        address candidate = receiver.candidate();
        (bool ok,) = address(this).call(abi.encodeCall(this.executeForTest, (ownerKey, address(receiver), 1 ether, candidate)));
        require(!ok, "contract owner installed during transfer");
        require(candidate.code.length == 0 && !guard.consumed(address(safe), candidate), "deployment did not roll back");
        require(safe.nonce() == 0 && address(safe).balance == 100 ether, "transaction did not roll back");
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

    function executeAtNonceForTest(uint256 signer, address candidate, uint256 nonce) external returns(bool) {
        require(msg.sender == address(this), "self only");
        return _executeAtNonce(signer, vm.addr(777), 0.01 ether, candidate, nonce);
    }

    function testSimultaneousPendingRotationsOnlyOneCanWin() public {
        uint256 pendingNonce = safe.nonce();
        address winner = vm.addr(9001);
        address loser = vm.addr(9002);
        require(_executeAtNonce(ownerKey, vm.addr(777), 0.01 ether, winner, pendingNonce), "winner");
        (bool ok,) = address(this).call(abi.encodeCall(this.executeAtNonceForTest, (ownerKey, loser, pendingNonce)));
        require(!ok, "stale pending accepted");
        require(guard.consumed(address(safe), winner) && !guard.consumed(address(safe), loser), "consumption");
        require(safe.getOwners()[0] == winner && safe.nonce() == 1, "state");
        (,uint256 count,,) = guard.state(address(safe)); require(count == 1, "counter");
        require(_execute(9001, vm.addr(777), 0.01 ether, loser), "loser candidate should remain available");
    }

    function testAllHistoricalOwnersRejectedIncludingInitial() public {
        uint256 signer = ownerKey;
        for (uint256 i; i < 25; ++i) {
            require(_execute(signer, vm.addr(780), 0.01 ether, vm.addr(9000+i)), "rotation");
            signer = 9000+i;
        }
        for (uint256 i; i <= 25; ++i) {
            address historical = i == 0 ? vm.addr(ownerKey) : vm.addr(8999+i);
            (bool ok,) = address(this).call(abi.encodeCall(this.executeForTest, (signer, vm.addr(780), 1 ether, historical)));
            require(!ok, "historical reuse");
        }
        (,uint256 count,,) = guard.state(address(safe));
        require(count == 25, "counter");
    }
}
