// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {BaseGuard} from "@safe-global/safe-contracts/contracts/base/GuardManager.sol";
import {Enum} from "@safe-global/safe-contracts/contracts/common/Enum.sol";

interface ISafeView {
    function getOwners() external view returns (address[] memory);
    function getThreshold() external view returns (uint256);
    function getModulesPaginated(address start, uint256 pageSize) external view returns (address[] memory array, address next);
}

/// @notice Unaudited fixed-sequence guard for local/Sepolia testing only.
/// @dev Dynamic refill, upgrades, modules, refunds, and arbitrary calls are intentionally absent.
contract BunkerRotationGuard is BaseGuard {
    uint256 public constant BATCH_SIZE = 20;
    uint256 public constant ORDINARY_ROTATION_LIMIT = 19; // index 19 remains reserved for audited migration.
    address public constant SENTINEL = address(0x1);
    bytes4 private constant MULTISEND = bytes4(keccak256("multiSend(bytes)"));
    bytes4 private constant SWAP_OWNER = bytes4(keccak256("swapOwner(address,address,address)"));
    bytes32 private constant DOMAIN = keccak256("BUNKER_OWNER_V1");
    uint256 private constant SECP256K1_HALF_N = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    struct State { bytes32 root; uint8 nextIndex; bool initialized; bool executing; }
    address public immutable multiSendCallOnly;
    bytes32 public immutable multiSendCodeHash;
    mapping(address safe => State) public state;
    mapping(address safe => mapping(uint256 index => address owner)) public committedOwner;
    mapping(address safe => mapping(address owner => bool used)) public consumed;

    error Policy();
    event SequenceInitialized(address indexed safe, bytes32 indexed root);
    event RotationAuthorized(address indexed safe, uint256 indexed index, address indexed nextOwner);

    constructor(address _multiSendCallOnly, bytes32 _multiSendCodeHash) {
        if (_multiSendCallOnly == address(0) || _multiSendCodeHash == bytes32(0)) revert Policy();
        multiSendCallOnly = _multiSendCallOnly; multiSendCodeHash = _multiSendCodeHash;
    }

    /// @dev Must be called by the Safe during atomic setup before it is funded.
    function initialize(address[20] calldata owners) external {
        State storage s = state[msg.sender]; if (s.initialized) revert Policy();
        address[] memory currentOwners = ISafeView(msg.sender).getOwners();
        if (currentOwners.length != 1 || ISafeView(msg.sender).getThreshold() != 1) revert Policy();
        address currentOwner = currentOwners[0];
        bytes32[] memory level = new bytes32[](32);
        for (uint256 i; i < BATCH_SIZE; ++i) {
            address owner = owners[i]; if (owner == address(0) || owner == currentOwner || consumed[msg.sender][owner]) revert Policy();
            consumed[msg.sender][owner] = true; committedOwner[msg.sender][i] = owner;
            level[i] = keccak256(abi.encodePacked(bytes1(0), DOMAIN, block.chainid, msg.sender, uint32(1), uint8(i), owner));
        }
        bytes32 empty = keccak256(hex"02"); for (uint256 i=BATCH_SIZE;i<32;++i) level[i]=empty;
        for (uint256 width=32;width>1;width/=2) for(uint256 i;i<width;i+=2) level[i/2]=keccak256(abi.encodePacked(bytes1(0x01),level[i],level[i+1]));
        s.root=level[0];s.initialized=true;emit SequenceInitialized(msg.sender,level[0]);
    }

    function rotationsRemaining(address safe) external view returns (uint256) { uint256 i=state[safe].nextIndex; return i>=ORDINARY_ROTATION_LIMIT?0:ORDINARY_ROTATION_LIMIT-i; }

    function checkTransaction(address to,uint256 value,bytes memory data,Enum.Operation operation,uint256,uint256 baseGas,uint256 gasPrice,address gasToken,address payable refundReceiver,bytes memory signatures,address) external override {
        State storage s=state[msg.sender];
        if(!s.initialized||s.executing||to!=multiSendCallOnly||value!=0||operation!=Enum.Operation.DelegateCall||baseGas!=0||gasPrice!=0||gasToken!=address(0)||refundReceiver!=address(0))revert Policy();
        if(multiSendCallOnly.codehash!=multiSendCodeHash||signatures.length!=65||s.nextIndex>=ORDINARY_ROTATION_LIMIT)revert Policy();
        uint256 sigS;uint8 sigV;assembly{sigS:=mload(add(signatures,0x40)) sigV:=byte(0,mload(add(signatures,0x60)))}if(sigS>SECP256K1_HALF_N||(sigV!=27&&sigV!=28))revert Policy();
        (address current,address next)=_parseBatch(data,msg.sender);address expected=committedOwner[msg.sender][s.nextIndex];if(next!=expected||current==next)revert Policy();
        address[] memory owners=ISafeView(msg.sender).getOwners();if(owners.length!=1||owners[0]!=current||ISafeView(msg.sender).getThreshold()!=1)revert Policy();
        (address[] memory modules,address cursor)=ISafeView(msg.sender).getModulesPaginated(SENTINEL,1);if(modules.length!=0||cursor!=SENTINEL)revert Policy();
        s.executing=true;emit RotationAuthorized(msg.sender,s.nextIndex,next);
    }

    function checkAfterExecution(bytes32,bool success) external override {
        State storage s=state[msg.sender];if(!s.executing||!success)revert Policy();address expected=committedOwner[msg.sender][s.nextIndex];address[] memory owners=ISafeView(msg.sender).getOwners();if(owners.length!=1||owners[0]!=expected||ISafeView(msg.sender).getThreshold()!=1)revert Policy();
        (address[] memory modules,address cursor)=ISafeView(msg.sender).getModulesPaginated(SENTINEL,1);if(modules.length!=0||cursor!=SENTINEL)revert Policy();unchecked{++s.nextIndex;}s.executing=false;
    }

    function _parseBatch(bytes memory outer,address safe) private pure returns(address current,address next){
        if(outer.length<4+64||bytes4(outer)!=MULTISEND)revert Policy();uint256 offset;uint256 length;assembly{offset:=mload(add(outer,0x24)) length:=mload(add(outer,0x44))}if(offset!=32||outer.length!=68+length)revert Policy();uint256 p=68;
        (uint8 op1,address to1,uint256 value1,uint256 len1)=_header(outer,p);if(op1!=0||to1==safe||to1==address(0)||value1==0||len1!=0)revert Policy();p+=85;
        (uint8 op2,address to2,uint256 value2,uint256 len2)=_header(outer,p);if(op2!=0||to2!=safe||value2!=0||len2!=100||p+85+100!=outer.length)revert Policy();p+=85;
        bytes4 selector;address prev;assembly{selector:=mload(add(add(outer,0x20),p)) prev:=and(mload(add(add(outer,0x24),p)),0xffffffffffffffffffffffffffffffffffffffff) current:=and(mload(add(add(outer,0x44),p)),0xffffffffffffffffffffffffffffffffffffffff) next:=and(mload(add(add(outer,0x64),p)),0xffffffffffffffffffffffffffffffffffffffff)}if(selector!=SWAP_OWNER||prev!=SENTINEL)revert Policy();
    }
    function _header(bytes memory data,uint256 p) private pure returns(uint8 op,address to,uint256 value,uint256 len){if(p+85>data.length)revert Policy();assembly{op:=byte(0,mload(add(add(data,0x20),p)))to:=shr(96,mload(add(add(data,0x21),p)))value:=mload(add(add(data,0x35),p))len:=mload(add(add(data,0x55),p))}}
}
