// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {BaseGuard} from "@safe-global/safe-contracts/contracts/base/GuardManager.sol";
import {Enum} from "@safe-global/safe-contracts/contracts/common/Enum.sol";

interface ISafeView {
    function getOwners() external view returns (address[] memory);
    function getThreshold() external view returns (uint256);
    function getModulesPaginated(address start, uint256 pageSize) external view returns (address[] memory array, address next);
}

/// @notice Unaudited fixed-sequence guard for local/Ethereum Sepolia testing only.
/// @dev Dynamic refill, upgrades, modules, refunds, and arbitrary calls are intentionally absent.
contract BunkerRotationGuard is BaseGuard {
    uint256 public constant BATCH_SIZE = 20;
    uint256 public constant ORDINARY_ROTATION_LIMIT = 19; // index 19 remains reserved for audited migration.
    uint256 public constant NEXT_OWNER_GAS = 0.001 ether;
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
        if ((block.chainid != 11155111 && block.chainid != 31337) || _multiSendCallOnly == address(0) || _multiSendCodeHash == bytes32(0) || _multiSendCallOnly.codehash != _multiSendCodeHash) revert Policy();
        multiSendCallOnly = _multiSendCallOnly; multiSendCodeHash = _multiSendCodeHash;
    }

    /// @dev Must be called by the Safe during atomic setup before it is funded.
    function initialize(address[20] calldata owners) external {
        State storage s = state[msg.sender]; if (s.initialized) revert Policy();
        address[] memory currentOwners = ISafeView(msg.sender).getOwners();
        if (currentOwners.length != 1 || ISafeView(msg.sender).getThreshold() != 1) revert Policy();
        address currentOwner = currentOwners[0];
        if (currentOwner == SENTINEL || currentOwner == msg.sender || currentOwner.code.length != 0) revert Policy();
        bytes32[] memory level = new bytes32[](32);
        for (uint256 i; i < BATCH_SIZE; ++i) {
            address owner = owners[i]; if (owner == address(0) || owner == SENTINEL || owner == msg.sender || owner == currentOwner || owner.code.length != 0 || consumed[msg.sender][owner]) revert Policy();
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
        (address current,address next)=_parseBatch(data,msg.sender);address expected=committedOwner[msg.sender][s.nextIndex];if(next!=expected||current==next||current.code.length!=0||next.code.length!=0)revert Policy();
        address[] memory owners=ISafeView(msg.sender).getOwners();if(owners.length!=1||owners[0]!=current||ISafeView(msg.sender).getThreshold()!=1)revert Policy();
        (address[] memory modules,address cursor)=ISafeView(msg.sender).getModulesPaginated(SENTINEL,1);if(modules.length!=0||cursor!=SENTINEL)revert Policy();
        s.executing=true;emit RotationAuthorized(msg.sender,s.nextIndex,next);
    }

    function checkAfterExecution(bytes32,bool success) external override {
        State storage s=state[msg.sender];if(!s.executing||!success)revert Policy();address expected=committedOwner[msg.sender][s.nextIndex];address[] memory owners=ISafeView(msg.sender).getOwners();if(owners.length!=1||owners[0]!=expected||ISafeView(msg.sender).getThreshold()!=1)revert Policy();
        (address[] memory modules,address cursor)=ISafeView(msg.sender).getModulesPaginated(SENTINEL,1);if(modules.length!=0||cursor!=SENTINEL)revert Policy();unchecked{++s.nextIndex;}s.executing=false;
    }

    function _parseBatch(bytes memory outer,address safe) private pure returns(address current,address next){
        if(outer.length<4+64||bytes4(outer)!=MULTISEND)revert Policy();uint256 offset;uint256 length;assembly{offset:=mload(add(outer,0x24)) length:=mload(add(outer,0x44))}uint256 rawEnd=68+length;uint256 paddedEnd=68+((length+31)/32)*32;if(offset!=32||outer.length!=paddedEnd)revert Policy();for(uint256 i=rawEnd;i<paddedEnd;++i)if(outer[i]!=0)revert Policy();uint256 p=68;address funded;
        { (uint8 op,address to,uint256 amount,uint256 len)=_header(outer,p);if(op!=0||to==safe||to==address(0)||amount==0||len!=0)revert Policy(); }p+=85;
        { (uint8 op,address to,uint256 amount,uint256 len)=_header(outer,p);if(op!=0||to==safe||to==address(0)||amount!=NEXT_OWNER_GAS||len!=0)revert Policy();funded=to; }p+=85;
        { (uint8 op,address to,uint256 amount,uint256 len)=_header(outer,p);if(op!=0||to!=safe||amount!=0||len!=100||p+85+100!=rawEnd)revert Policy(); }p+=85;
        bytes4 selector;address prev;assembly{selector:=mload(add(add(outer,0x20),p)) prev:=and(mload(add(add(outer,0x24),p)),0xffffffffffffffffffffffffffffffffffffffff) current:=and(mload(add(add(outer,0x44),p)),0xffffffffffffffffffffffffffffffffffffffff) next:=and(mload(add(add(outer,0x64),p)),0xffffffffffffffffffffffffffffffffffffffff)}if(selector!=SWAP_OWNER||prev!=SENTINEL||funded!=next)revert Policy();
    }
    function _header(bytes memory data,uint256 p) private pure returns(uint8 op,address to,uint256 value,uint256 len){if(p+85>data.length)revert Policy();assembly{op:=byte(0,mload(add(add(data,0x20),p)))to:=shr(96,mload(add(add(data,0x21),p)))value:=mload(add(add(data,0x35),p))len:=mload(add(add(data,0x55),p))}}
}
