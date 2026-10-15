// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {SphincsC10Asm} from "../src/SPHINCs-C10Asm.sol";

interface Vm {
    function readFileBinary(string calldata path) external returns (bytes memory);
    function expectRevert() external;
}

contract C10VerifierTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 private constant SEED = bytes32(uint256(0x01010101010101010101010101010101) << 128);
    bytes32 private constant ROOT = bytes32(uint256(0x42091ce501796f008e9b5ac204f2beb6) << 128);
    bytes32 private constant MESSAGE = 0x0202020202020202020202020202020202020202020202020202020202020202;

    SphincsC10Asm private verifier;
    bytes private signature;

    function setUp() public {
        verifier = new SphincsC10Asm();
        // Public zero-secret fixture: seed input = 48 bytes of 0x01; message = 32 bytes of 0x02.
        signature = vm.readFileBinary("../../test-vectors/c10-public-test.sig");
    }

    function testValidPublicVector() public {
        require(verifier.verify(SEED, ROOT, MESSAGE, signature), "valid signature rejected");
    }

    function _rejects(bytes32 seed, bytes32 root, bytes32 message, bytes memory sig) private view returns (bool) {
        (bool ok, bytes memory result) =
            address(verifier).staticcall(abi.encodeCall(SphincsC10Asm.verify, (seed, root, message, sig)));
        return !ok || result.length != 32 || !abi.decode(result, (bool));
    }

    function testRejectsChangedMessageSignatureAndRoot() public view {
        require(_rejects(SEED, ROOT, bytes32(uint256(MESSAGE) ^ 1), signature), "message changed");
        bytes memory changed = signature;
        changed[0] = bytes1(uint8(changed[0]) ^ 1);
        require(_rejects(SEED, ROOT, MESSAGE, changed), "signature changed");
        require(_rejects(SEED, bytes32(uint256(ROOT) ^ (uint256(1) << 128)), MESSAGE, signature), "root changed");
    }

    function testRejectsNoncanonicalKeysAndSignatureLengths() public {
        vm.expectRevert();
        verifier.verify(bytes32(uint256(SEED) | 1), ROOT, MESSAGE, signature);
        vm.expectRevert();
        verifier.verify(SEED, bytes32(uint256(ROOT) | 1), MESSAGE, signature);
        vm.expectRevert();
        verifier.verify(SEED, ROOT, MESSAGE, new bytes(4007));
        vm.expectRevert();
        verifier.verify(SEED, ROOT, MESSAGE, new bytes(4009));
    }

    function testFuzzRejectsNon4008ByteSignatures(uint16 length) public {
        if (length == 4008) return;
        vm.expectRevert();
        verifier.verify(SEED, ROOT, MESSAGE, new bytes(length));
    }
}
