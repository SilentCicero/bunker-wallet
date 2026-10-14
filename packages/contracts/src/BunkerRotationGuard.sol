// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {BaseGuard} from "@safe-global/safe-contracts/contracts/base/GuardManager.sol";
import {Enum} from "@safe-global/safe-contracts/contracts/common/Enum.sol";

interface ISafeView {
    function getOwners() external view returns (address[] memory);
    function getThreshold() external view returns (uint256);
    function getModulesPaginated(address start, uint256 pageSize) external view returns (address[] memory array, address next);
}

/// @notice Unaudited V2 dynamic owner guard for local/Ethereum Sepolia testing only.
/// @dev A compromised current signer can substitute an attacker-controlled fresh owner.
contract BunkerRotationGuard is BaseGuard {
    uint256 public constant VERSION = 2;
    uint256 public constant NEXT_OWNER_GAS = 0.001 ether;
    address public constant SENTINEL = address(0x1);
    bytes4 private constant MULTISEND = bytes4(keccak256("multiSend(bytes)"));
    bytes4 private constant SWAP_OWNER = bytes4(keccak256("swapOwner(address,address,address)"));
    uint256 private constant SECP256K1_HALF_N = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    struct State { address pendingOwner; uint256 rotationCount; bool initialized; bool executing; }
    address public immutable multiSendCallOnly;
    bytes32 public immutable multiSendCodeHash;
    mapping(address safe => State) public state;
    mapping(address safe => mapping(address owner => bool used)) public consumed;

    error Policy();
    event Initialized(address indexed safe, address indexed initialOwner);
    event RotationAuthorized(address indexed safe, uint256 indexed index, address indexed nextOwner);

    constructor(address _multiSendCallOnly, bytes32 _multiSendCodeHash) {
        if ((block.chainid != 11155111 && block.chainid != 31337) || _multiSendCallOnly == address(0) || _multiSendCodeHash == bytes32(0) || _multiSendCallOnly.codehash != _multiSendCodeHash) revert Policy();
        multiSendCallOnly = _multiSendCallOnly; multiSendCodeHash = _multiSendCodeHash;
    }

    /// @dev Must be called by the Safe during atomic setup before it is funded.
    function initialize() external {
        State storage s = state[msg.sender]; if (s.initialized) revert Policy();
        address[] memory currentOwners = ISafeView(msg.sender).getOwners();
        if (currentOwners.length != 1 || ISafeView(msg.sender).getThreshold() != 1) revert Policy();
        address currentOwner = currentOwners[0];
        if (currentOwner == address(0) || currentOwner == SENTINEL || currentOwner == msg.sender || currentOwner.code.length != 0) revert Policy();
        consumed[msg.sender][currentOwner] = true;
        s.initialized = true;
        emit Initialized(msg.sender, currentOwner);
    }


    function checkTransaction(address to,uint256 value,bytes memory data,Enum.Operation operation,uint256,uint256 baseGas,uint256 gasPrice,address gasToken,address payable refundReceiver,bytes memory signatures,address) external override {
        State storage s=state[msg.sender];
        if(!s.initialized||s.executing||to!=multiSendCallOnly||value!=0||operation!=Enum.Operation.DelegateCall||baseGas!=0||gasPrice!=0||gasToken!=address(0)||refundReceiver!=address(0))revert Policy();
        if(multiSendCallOnly.codehash!=multiSendCodeHash||signatures.length!=65)revert Policy();
        uint256 sigS;uint8 sigV;assembly{sigS:=mload(add(signatures,0x40)) sigV:=byte(0,mload(add(signatures,0x60)))}if(sigS>SECP256K1_HALF_N||(sigV!=27&&sigV!=28))revert Policy();
        (address current,address next)=_parseBatch(data,msg.sender);if(next==address(0)||next==SENTINEL||next==msg.sender||consumed[msg.sender][next]||current==next||current.code.length!=0||next.code.length!=0)revert Policy();
        address[] memory owners=ISafeView(msg.sender).getOwners();if(owners.length!=1||owners[0]!=current||ISafeView(msg.sender).getThreshold()!=1)revert Policy();
        (address[] memory modules,address cursor)=ISafeView(msg.sender).getModulesPaginated(SENTINEL,1);if(modules.length!=0||cursor!=SENTINEL)revert Policy();
        s.executing=true;s.pendingOwner=next;emit RotationAuthorized(msg.sender,s.rotationCount,next);
    }

    function checkAfterExecution(bytes32,bool success) external override {
        State storage s=state[msg.sender];if(!s.executing||!success)revert Policy();address expected=s.pendingOwner;address[] memory owners=ISafeView(msg.sender).getOwners();if(owners.length!=1||owners[0]!=expected||expected.code.length!=0||ISafeView(msg.sender).getThreshold()!=1)revert Policy();
        (address[] memory modules,address cursor)=ISafeView(msg.sender).getModulesPaginated(SENTINEL,1);if(modules.length!=0||cursor!=SENTINEL)revert Policy();consumed[msg.sender][expected]=true;++s.rotationCount;s.pendingOwner=address(0);s.executing=false;
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
