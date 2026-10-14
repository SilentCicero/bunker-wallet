// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Local research only. Implements Safe 1.4.1's legacy contract-owner ABI.
abstract contract HybridSafeOwner {
    bytes32 public constant MESSAGE_DOMAIN = keccak256("BUNKER_HYBRID_PQ_V1");
    bytes32 private constant SAFE_DOMAIN = keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");
    uint256 public constant version = 1;
    uint256 public immutable algorithm;
    bytes32 public immutable keyId;
    address public immutable verifier;
    bytes32 public immutable verifierCodeHash;
    uint256 public immutable epoch;
    address public immutable factory;
    address public safe;
    error InvalidOwner();

    constructor(uint256 algorithm_, bytes32 keyId_, address verifier_, bytes32 hash_, uint256 epoch_) {
        if (block.chainid != 31337 || verifier_.code.length == 0 || verifier_.codehash != hash_) revert InvalidOwner();
        algorithm = algorithm_;
        keyId = keyId_;
        verifier = verifier_;
        verifierCodeHash = hash_;
        epoch = epoch_;
        factory = msg.sender;
    }

    function bind(address safe_) external {
        if (block.chainid != 31337 || msg.sender != factory || safe != address(0) || safe_.code.length == 0) {
            revert InvalidOwner();
        }
        safe = safe_;
    }

    function signatureLength() public pure virtual returns (uint256);

    /// @dev Raw 32-byte digest is the C10 message, or the ML-DSA message with empty context.
    function messageDigest(bytes calldata preimage) public view returns (bytes32) {
        if (
            block.chainid != 31337 || safe == address(0) || preimage.length != 66 || bytes2(preimage[:2]) != 0x1901
                || bytes32(preimage[2:34]) != keccak256(abi.encode(SAFE_DOMAIN, block.chainid, safe))
        ) revert InvalidOwner();
        return keccak256(
            abi.encode(
                MESSAGE_DOMAIN,
                block.chainid,
                safe,
                keccak256(preimage),
                algorithm,
                version,
                address(this),
                keyId,
                verifier,
                verifierCodeHash,
                epoch
            )
        );
    }

    /// @dev Integrity only, NOT proof that a verifier or registered key is cryptographically sound.
    function dependenciesIntact() public view returns (bool) {
        return block.chainid == 31337 && verifier.codehash == verifierCodeHash && _keyIntact();
    }

    function isValidSignature(bytes calldata preimage, bytes calldata signature) external view returns (bytes4) {
        if (msg.sender != safe || safe == address(0) || signature.length != signatureLength() || !dependenciesIntact()) revert InvalidOwner();
        bytes memory input = _verificationCall(messageDigest(preimage), signature);
        (bool ok, bytes memory output) = verifier.staticcall(input);
        if (!ok || output.length != 32) revert InvalidOwner();
        uint256 result;
        assembly { result := mload(add(output, 32)) }
        if (result != 1) revert InvalidOwner();
        return 0x20c13b0b;
    }

    function _keyIntact() internal view virtual returns (bool) {
        return true;
    }
    function _verificationCall(bytes32 digest, bytes calldata signature) internal view virtual returns (bytes memory);
}

interface IC10Verifier {
    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig) external view returns (bool);
}

contract C10SafeOwner is HybridSafeOwner {
    bytes32 public immutable pkSeed;
    bytes32 public immutable pkRoot;

    constructor(bytes32 seed, bytes32 root, address verifier_, bytes32 hash_, uint256 epoch_)
        HybridSafeOwner(1, keccak256(abi.encode(seed, root)), verifier_, hash_, epoch_)
    {
        // Upstream C10 uses top-128-bit values, NOT right-aligned uint128 values.
        if (uint128(uint256(seed)) != 0 || uint128(uint256(root)) != 0 || seed == 0 || root == 0) {
            revert InvalidOwner();
        }
        pkSeed = seed;
        pkRoot = root;
    }

    function signatureLength() public pure override returns (uint256) {
        return 4008;
    }

    function _verificationCall(bytes32 digest, bytes calldata signature) internal view override returns (bytes memory) {
        return abi.encodeCall(IC10Verifier.verify, (pkSeed, pkRoot, digest, signature));
    }
}

interface IMLDSA44Verifier {
    function verify(address pkBlob, bytes calldata message, bytes calldata signature) external view returns (bool);
}

/// @notice NOT reviewed key registration: only an explicitly admitted local fixture codehash is usable.
contract MLDSA44SafeOwner is HybridSafeOwner {
    address public immutable pkBlob;
    bytes32 public immutable blobCodeHash;

    constructor(address blob, bytes32 localFixtureCodeHash, address verifier_, bytes32 hash_, uint256 epoch_)
        HybridSafeOwner(2, localFixtureCodeHash, verifier_, hash_, epoch_)
    {
        // Length is framing, NOT validation of genuine/non-degenerate ML-DSA key material.
        if (localFixtureCodeHash == 0 || blob.code.length != 20545 || blob.codehash != localFixtureCodeHash) {
            revert InvalidOwner();
        }
        pkBlob = blob;
        blobCodeHash = localFixtureCodeHash;
    }

    function signatureLength() public pure override returns (uint256) {
        return 2420;
    }

    function _keyIntact() internal view override returns (bool) {
        return pkBlob.code.length == 20545 && pkBlob.codehash == blobCodeHash;
    }

    function _verificationCall(bytes32 digest, bytes calldata signature) internal view override returns (bytes memory) {
        return abi.encodeCall(IMLDSA44Verifier.verify, (pkBlob, abi.encodePacked(digest), signature));
    }
}
