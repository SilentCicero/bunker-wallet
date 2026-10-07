// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Unaudited Ethereum Sepolia-only demonstration of a stable address with a rotating ECDSA owner.
/// @dev This is not Safe and must never hold meaningful funds.
contract BunkerDemoWallet {
    uint256 public constant NEXT_OWNER_GAS = 0.001 ether;
    address public owner;
    uint64 public rotationIndex;
    bool private executing;

    error Unauthorized();
    error InvalidNextOwner();
    error TransferFailed();
    error InvalidMessage();
    error WrongChain();
    event OwnerRotated(address indexed previousOwner, address indexed nextOwner, uint64 indexed rotationIndex);
    event DemoMessage(address indexed wallet, uint64 indexed rotationIndex, string message);

    constructor(address initialOwner) payable {
        if (block.chainid != 11155111) revert WrongChain();
        if (initialOwner == address(0)) revert InvalidNextOwner();
        owner = initialOwner;
    }

    receive() external payable {}

    function sendETH(address payable recipient, uint256 amount, address nextOwner) external {
        _authorize(nextOwner);
        (bool sent,) = recipient.call{value: amount}("");
        if (!sent) revert TransferFailed();
        _rotate(nextOwner);
    }

    function sendERC20(address token, address recipient, uint256 amount, address nextOwner) external {
        _authorize(nextOwner);
        if (token.code.length == 0) revert TransferFailed();
        (bool ok, bytes memory result) = token.call(abi.encodeWithSignature("transfer(address,uint256)", recipient, amount));
        if (!ok || (result.length != 0 && !abi.decode(result, (bool)))) revert TransferFailed();
        _rotate(nextOwner);
    }

    function postMessage(string calldata message, address nextOwner) external {
        bytes memory text = bytes(message);
        if (text.length == 0 || text.length > 140) revert InvalidMessage();
        _authorize(nextOwner);
        emit DemoMessage(address(this), rotationIndex, message);
        _rotate(nextOwner);
    }

    function _authorize(address nextOwner) private {
        if (msg.sender != owner || executing) revert Unauthorized();
        if (nextOwner == address(0) || nextOwner == owner || nextOwner.code.length != 0) revert InvalidNextOwner();
        executing = true;
    }

    function _rotate(address nextOwner) private {
        address previous = owner;
        if (address(this).balance < NEXT_OWNER_GAS) revert TransferFailed();
        (bool funded,) = payable(nextOwner).call{value: NEXT_OWNER_GAS}("");
        if (!funded) revert TransferFailed();
        owner = nextOwner;
        unchecked { ++rotationIndex; }
        executing = false;
        emit OwnerRotated(previous, nextOwner, rotationIndex);
    }
}
