// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Safe} from "@safe-global/safe-contracts/contracts/Safe.sol";
import {SafeProxy} from "@safe-global/safe-contracts/contracts/proxies/SafeProxy.sol";
import {SafeProxyFactory} from "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import {MultiSendCallOnly} from "@safe-global/safe-contracts/contracts/libraries/MultiSendCallOnly.sol";
import {Enum} from "@safe-global/safe-contracts/contracts/common/Enum.sol";
import {BunkerRotationGuardV3} from "../src/BunkerRotationGuardV3.sol";
import {BunkerSafeSetupV3} from "../src/BunkerSafeSetupV3.sol";

interface Vm {
    function addr(uint256 privateKey) external returns (address);
    function deal(address who, uint256 newBalance) external;
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function expectRevert() external;
    function prank(address caller) external;
    function etch(address target, bytes calldata code) external;
}

contract RevertingReceiver {
    receive() external payable {
        revert();
    }
}

contract V3Target {
    uint256 public value;

    function set(uint256 next) external {
        value = next;
    }

    function fail() external pure {
        revert();
    }
}

contract BunkerSafeV3Test {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address private constant SENTINEL = address(0x1);

    Safe private singleton;
    SafeProxyFactory private factory;
    MultiSendCallOnly private multiSend;
    BunkerRotationGuardV3 private guard;
    BunkerSafeSetupV3 private helper;
    Safe private safe;
    uint256 private ownerKey = 0xA11CE;
    uint256[20] private futureKeys;
    address[20] private futureOwners;

    function setUp() public {
        singleton = new Safe();
        factory = new SafeProxyFactory();
        multiSend = new MultiSendCallOnly();
        guard = new BunkerRotationGuardV3(address(multiSend), address(multiSend).codehash);
        helper = new BunkerSafeSetupV3();
        for (uint256 i; i < 20; ++i) {
            futureKeys[i] = 1000 + i;
            futureOwners[i] = vm.addr(futureKeys[i]);
        }
        address[] memory owners = new address[](1);
        owners[0] = vm.addr(ownerKey);
        bytes memory helperData = abi.encodeCall(BunkerSafeSetupV3.setup, (address(guard), futureOwners));
        bytes memory initializer = abi.encodeCall(
            Safe.setup, (owners, 1, address(helper), helperData, address(0), address(0), 0, payable(address(0)))
        );
        SafeProxy proxy = factory.createChainSpecificProxyWithNonce(address(singleton), initializer, 1);
        safe = Safe(payable(address(proxy)));
        vm.deal(address(safe), 100 ether);
    }

    function _packedCall(address to, uint256 value, bytes memory data) private pure returns (bytes memory) {
        return abi.encodePacked(uint8(0), to, value, data.length, data);
    }

    function _execute(uint256 signerKey, address recipient, uint256 amount, address nextOwner) private returns (bool) {
        address current = vm.addr(signerKey);
        bytes memory swapData =
            abi.encodeWithSignature("swapOwner(address,address,address)", SENTINEL, current, nextOwner);
        bytes memory transactions = bytes.concat(
            _packedCall(recipient, amount, ""),
            _packedCall(nextOwner, 0.001 ether, ""),
            _packedCall(address(safe), 0, swapData)
        );
        bytes memory data = abi.encodeCall(MultiSendCallOnly.multiSend, transactions);
        uint256 nonce = safe.nonce();
        bytes32 txHash = safe.getTransactionHash(
            address(multiSend), 0, data, Enum.Operation.DelegateCall, 0, 0, 0, address(0), payable(address(0)), nonce
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, txHash);
        return safe.execTransaction(
            address(multiSend),
            0,
            data,
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            abi.encodePacked(r, s, v)
        );
    }

    function testRejectsUnpinnedMultiSendCodeHash() public {
        vm.expectRevert();
        new BunkerRotationGuardV3(address(multiSend), bytes32(uint256(1)));
    }

    function testRejectsSentinelFutureOwnerDuringAtomicSetup() public {
        BunkerRotationGuardV3 secondGuard = new BunkerRotationGuardV3(address(multiSend), address(multiSend).codehash);
        address[20] memory invalidOwners = futureOwners;
        invalidOwners[3] = SENTINEL;
        address[] memory owners = new address[](1);
        owners[0] = vm.addr(ownerKey);
        bytes memory helperData = abi.encodeCall(BunkerSafeSetupV3.setup, (address(secondGuard), invalidOwners));
        bytes memory initializer = abi.encodeCall(
            Safe.setup, (owners, 1, address(helper), helperData, address(0), address(0), 0, payable(address(0)))
        );
        vm.expectRevert();
        factory.createChainSpecificProxyWithNonce(address(singleton), initializer, 2);
    }

    function executeForTest(uint256 signerKey, address recipient, uint256 amount, address nextOwner)
        external
        returns (bool)
    {
        require(msg.sender == address(this), "self only");
        return _execute(signerKey, recipient, amount, nextOwner);
    }

    function testRecipientFailureRollsBackOwnerAndGuardIndex() public {
        RevertingReceiver recipient = new RevertingReceiver();
        (bool ok,) = address(this)
            .call(abi.encodeCall(this.executeForTest, (ownerKey, address(recipient), 1 ether, futureOwners[0])));
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
        bytes memory swapData =
            abi.encodeWithSignature("swapOwner(address,address,address)", SENTINEL, vm.addr(ownerKey), futureOwners[0]);
        bytes memory transactions =
            bytes.concat(_packedCall(recipient, 1 ether, ""), _packedCall(address(safe), 0, swapData));
        bytes memory data = abi.encodeCall(MultiSendCallOnly.multiSend, transactions);
        bytes32 txHash = safe.getTransactionHash(
            address(multiSend),
            0,
            data,
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            safe.nonce()
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, txHash);
        vm.expectRevert();
        safe.execTransaction(
            address(multiSend),
            0,
            data,
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            abi.encodePacked(r, s, v)
        );
    }

    function testRejectsWrongNextOwnerFundingAmount() public {
        address recipient = vm.addr(779);
        bytes memory swapData =
            abi.encodeWithSignature("swapOwner(address,address,address)", SENTINEL, vm.addr(ownerKey), futureOwners[0]);
        bytes memory transactions = bytes.concat(
            _packedCall(recipient, 1 ether, ""),
            _packedCall(futureOwners[0], 0.002 ether, ""),
            _packedCall(address(safe), 0, swapData)
        );
        bytes memory data = abi.encodeCall(MultiSendCallOnly.multiSend, transactions);
        bytes32 txHash = safe.getTransactionHash(
            address(multiSend),
            0,
            data,
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            safe.nonce()
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, txHash);
        vm.expectRevert();
        safe.execTransaction(
            address(multiSend),
            0,
            data,
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            abi.encodePacked(r, s, v)
        );
    }

    function _batch(bytes memory transactions, bool reject) private returns (bool) {
        bytes memory data = abi.encodeCall(MultiSendCallOnly.multiSend, transactions);
        bytes32 txHash = safe.getTransactionHash(
            address(multiSend),
            0,
            data,
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            safe.nonce()
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, txHash);
        if (reject) vm.expectRevert();
        return safe.execTransaction(
            address(multiSend),
            0,
            data,
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            abi.encodePacked(r, s, v)
        );
    }

    function _suffix() private returns (bytes memory) {
        return bytes.concat(
            _packedCall(futureOwners[0], 0.001 ether, ""),
            _packedCall(
                address(safe),
                0,
                abi.encodeWithSignature(
                    "swapOwner(address,address,address)", SENTINEL, vm.addr(ownerKey), futureOwners[0]
                )
            )
        );
    }

    function testMultipleCallsAndCalldataRotateAtomically() public {
        V3Target target = new V3Target();
        address recipient = vm.addr(777);
        require(
            _batch(
                bytes.concat(
                    _packedCall(address(target), 0, abi.encodeCall(V3Target.set, (42))),
                    _packedCall(recipient, 1 ether, ""),
                    _suffix()
                ),
                false
            )
        );
        require(target.value() == 42 && recipient.balance == 1 ether && safe.getOwners()[0] == futureOwners[0]);
        (, uint8 index,,) = guard.state(address(safe));
        require(index == 1);
    }

    function testEightExternalCallsAndRotation() public {
        bytes memory calls;
        for (uint256 i; i < 8; ++i) {
            calls = bytes.concat(calls, _packedCall(address(0xFEED), 0, hex"1234"));
        }
        require(_batch(bytes.concat(calls, _suffix()), false), "eight calls rejected");
        require(safe.getOwners()[0] == futureOwners[0], "owner did not rotate");
    }

    function testFuzzRejectsInvalidExternalCallCount(uint8 requested) public {
        uint256 count = uint256(requested) % 11;
        if (count >= 1 && count <= 8) return;

        bytes memory calls;
        for (uint256 i; i < count; ++i) {
            calls = bytes.concat(calls, _packedCall(address(0xFEED), 0, hex"1234"));
        }
        _batch(bytes.concat(calls, _suffix()), true);
        require(safe.nonce() == 0, "invalid count changed nonce");
    }

    function testFuzzRejectsMalformedLengthsAndFunding(uint256 length, uint96 funding) public {
        bytes memory entry = _packedCall(address(0xFEED), 0, hex"1234");
        if (length == 2) length = type(uint256).max;
        assembly {
            mstore(add(entry, 0x55), length) // MultiSend entry data-length word, offset 53.
        }
        _batch(bytes.concat(entry, _suffix()), true);
        if (funding == 0.001 ether) return;
        bytes memory swapData =
            abi.encodeWithSignature("swapOwner(address,address,address)", SENTINEL, vm.addr(ownerKey), futureOwners[0]);
        bytes memory wrongFunding = bytes.concat(
            _packedCall(address(0xFEED), 0, hex"1234"),
            _packedCall(futureOwners[0], funding, ""),
            _packedCall(address(safe), 0, swapData)
        );
        _batch(wrongFunding, true);
        require(safe.nonce() == 0, "malformed batch changed nonce");
    }

    function testRejectsOverflowedOuterBatchLengthWithoutStateChanges() public {
        bytes memory transactions = bytes.concat(_packedCall(address(0xFEED), 0, hex"1234"), _suffix());
        bytes memory data = abi.encodeCall(MultiSendCallOnly.multiSend, transactions);
        assembly {
            mstore(add(data, 0x44), not(0)) // ABI bytes length at selector + offset + 32.
        }
        bytes32 txHash = safe.getTransactionHash(
            address(multiSend),
            0,
            data,
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            safe.nonce()
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, txHash);
        vm.expectRevert();
        _execSigned(data, abi.encodePacked(r, s, v));
        require(safe.nonce() == 0, "overflow changed nonce");
        (, uint8 index,, bool executing) = guard.state(address(safe));
        require(index == 0 && !executing, "overflow changed guard");
    }

    function testRevertingCallKeepsOwnerAndContractState() public {
        V3Target target = new V3Target();
        _batch(
            bytes.concat(
                _packedCall(address(target), 0, abi.encodeCall(V3Target.set, (42))),
                _packedCall(address(target), 0, abi.encodeCall(V3Target.fail, ())),
                _suffix()
            ),
            true
        );
        require(target.value() == 0 && safe.getOwners()[0] == vm.addr(ownerKey));
        (, uint8 index,,) = guard.state(address(safe));
        require(index == 0);
    }

    function testRejectsPrivilegedTargetsAndDelegatecall() public {
        for (uint256 i; i < 5; ++i) {
            address to = i == 0
                ? address(safe)
                : i == 1
                    ? address(guard)
                    : i == 2
                        ? address(multiSend)
                        : i == 3
                            ? 0x41675C099F32341bf84BFc5382aF534df5C7461a
                            : 0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67;
            _batch(bytes.concat(_packedCall(to, 0, hex"1234"), _suffix()), true);
        }
        bytes memory delegate = bytes.concat(_packedCall(address(0xFEED), 0, ""), _suffix());
        delegate[0] = 0x01;
        _batch(delegate, true);
    }

    function _execSigned(bytes memory data, bytes memory sig) private returns (bool) {
        return safe.execTransaction(
            address(multiSend), 0, data, Enum.Operation.DelegateCall, 0, 0, 0, address(0), payable(address(0)), sig
        );
    }

    function testMalformedSignatureReplayAndChangedDependencyFailClosed() public {
        bytes memory data =
            abi.encodeCall(MultiSendCallOnly.multiSend, bytes.concat(_packedCall(address(0xFEED), 1, ""), _suffix()));
        bytes32 txHash = safe.getTransactionHash(
            address(multiSend),
            0,
            data,
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            safe.nonce()
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, txHash);
        vm.expectRevert();
        _execSigned(data, abi.encodePacked(r, s, bytes1(0x00)));
        vm.expectRevert();
        _execSigned(data, abi.encodePacked(r, s));
        require(safe.nonce() == 0, "invalid signature changed nonce");
        bytes memory original = address(multiSend).code;
        vm.etch(address(multiSend), hex"00");
        vm.expectRevert();
        _execSigned(data, abi.encodePacked(r, s, v));
        vm.etch(address(multiSend), original);
        require(_execSigned(data, abi.encodePacked(r, s, v)));
        vm.expectRevert();
        _execSigned(data, abi.encodePacked(r, s, v));
        (, uint8 index,, bool executing) = guard.state(address(safe));
        require(index == 1 && !executing && safe.getOwners()[0] == futureOwners[0]);
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
        guard.checkTransaction(
            address(multiSend),
            0,
            "",
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            new bytes(65),
            address(this)
        );
    }
}
