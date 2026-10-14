// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {MLDSA44Verifier} from "../src/MLDSA44Verifier.sol";

interface Vm {
    function readFileBinary(string calldata path) external returns (bytes memory);
    function readFile(string calldata path) external returns (string memory);
    function parseBytes(string calldata value) external pure returns (bytes memory);
    function etch(address target, bytes calldata code) external;
    function expectRevert() external;
}

contract MLDSAVerifierTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address private constant HELPER = address(0x1001);
    address private constant BLOB = address(0x1002);

    MLDSA44Verifier private verifier;
    bytes private signature;
    bytes private blob;
    bytes private message;

    function setUp() public {
        vm.etch(HELPER, vm.parseBytes(string.concat("0x", vm.readFile("helper.hex"))));
        blob = vm.readFileBinary("../../test-vectors/mldsa-public-test.blob");
        signature = vm.readFileBinary("../../test-vectors/mldsa-public-test.sig");
        message = new bytes(32);
        for (uint256 i; i < message.length; ++i) {
            message[i] = 0x02;
        }
        vm.etch(BLOB, blob);
        verifier = new MLDSA44Verifier(HELPER);
    }

    function testValidPublicVector() public {
        require(verifier.verify(BLOB, message, signature), "valid signature rejected");
    }

    function testRejectsChangedMessageSignatureAndBlob() public {
        message[0] ^= 0x01;
        require(!verifier.verify(BLOB, message, signature), "message changed");
        message[0] ^= 0x01;
        signature[0] ^= 0x01;
        require(!verifier.verify(BLOB, message, signature), "signature changed");
        signature[0] ^= 0x01;
        vm.etch(BLOB, hex"00");
        require(!verifier.verify(BLOB, message, signature), "short blob accepted");
        vm.etch(BLOB, blob);
        require(verifier.verify(BLOB, message, signature), "valid blob not restored");
    }

    function testRejectsWrongHelperAtConstructionAndAfterDeployment() public {
        vm.expectRevert();
        new MLDSA44Verifier(address(0xDEAD));
        vm.etch(HELPER, hex"00");
        vm.expectRevert();
        verifier.verify(BLOB, message, signature);
    }

    function testFuzzRejectsNon2420ByteSignatures(uint16 length) public {
        if (length == 2420) return;
        require(!verifier.verify(BLOB, message, new bytes(length)), "wrong signature length accepted");
    }
}
