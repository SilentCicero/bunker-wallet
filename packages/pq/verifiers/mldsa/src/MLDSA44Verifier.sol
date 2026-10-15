// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {IMLDSAVerifier} from "./IMLDSAVerifier.sol";
import {shake256Fast170, shake256Batch170} from "./FastKeccak170.sol";
import {
    unpackHFast,
    unpackZPacked,
    useHintSwar,
    sampleInBallPacked,
    matvecRow
} from "./Decode.sol";
import {nttFwV3, nttFwTable} from "./Ntt.sol";
import {nttInvV3, nttInvTable} from "./InvNtt.sol";

// Size and layout of the public-key data contract produced by prepare/prepare.py.
// The deployed code is 0x00 || tr || t1hat || Ahat (20,545 bytes); the leading
// zero byte satisfies EIP-3541 (deployed code must not start with 0xEF), so the
// payload is read from code offset 1.
uint256 constant PK_SIZE = 20544; // payload bytes (excluding the 0x00 prefix)
uint256 constant PK_T1_OFF = 64; // t1hat = NTT(2^d * t1), 4 polys x 32 words
uint256 constant PK_A_OFF = 4160; // Ahat = ExpandA(rho), 16 polys row-major

/// @title  MLDSA44Verifier — FIPS 204 ML-DSA-44 signature verification in pure EVM
/// @notice Implements ML-DSA.Verify (FIPS 204 Algorithm 3) for the ML-DSA-44
///         parameter set, non-prehashed, with an empty context string: the
///         verifier itself forms M' = 0x00 || 0x00 || M.
/// @dev    UNAUDITED research code — see README.md and docs/SAFETY.md before any
///         deployment. In particular, the pk blob MUST be validated at
///         registration time (docs/SAFETY.md section 3); the verifier cannot
///         detect a well-formed blob that was not derived from a genuine key.
contract MLDSA44Verifier is IMLDSAVerifier {
    /// @dev keccak256 of the 21,622-byte Keccak-f[1600] helper runtime
    ///      (helpers/f1600_170.hex, built by tools/build_f1600_batch.py). The
    ///      helper is deployed byte-for-byte as raw code, so its EXTCODEHASH is
    ///      a toolchain-independent constant.
    ///      Recompute with: cast keccak "0x$(tr -d '\n' < helpers/f1600_170.hex)"
    ///
    ///      Binding the helper by CONTENT rather than by address is load-bearing:
    ///      a hostile permutation helper can make the verifier accept a valid
    ///      signature for a different, never-signed message (docs/SAFETY.md
    ///      section 2.3). The hash is asserted at construction and again on
    ///      every verify() call, which also guards against the helper account
    ///      being replaced after deployment. The per-call check is effectively
    ///      free: EXTCODEHASH is the first touch of the helper account, so it
    ///      absorbs the cold-account charge the following STATICCALLs would
    ///      otherwise pay.
    bytes32 private constant F1600_CODEHASH =
        0x4afb4435879cdf8e50474c7aab2bc3a679caed432550ad6dba64f509309a817b;

    /// @dev Address of the Keccak-f[1600] permutation helper (raw runtime code,
    ///      deployed separately; see helpers/f1600_170.hex).
    address private immutable F1600;

    error BadHelper(); // helper account's code hash does not match F1600_CODEHASH

    /// @param f1600Helper address of the deployed Keccak-f[1600] helper; its
    ///        code hash is verified against F1600_CODEHASH.
    constructor(address f1600Helper) {
        if (f1600Helper.codehash != F1600_CODEHASH) revert BadHelper();
        F1600 = f1600Helper;
    }

    /// @inheritdoc IMLDSAVerifier
    function verify(address pkBlob, bytes calldata message, bytes calldata signature)
        external
        view
        returns (bool)
    {
        // Re-assert the helper binding by content, not by address.
        if (F1600.codehash != F1600_CODEHASH) revert BadHelper();
        return _verify(pkBlob, message, signature);
    }

    /// FIPS 204 Algorithm 3 (ML-DSA.Verify), with (tr, t1hat, Ahat) precomputed
    /// into the pk blob so that pkDecode/ExpandA/NTT(t1) never run on-chain.
    function _verify(address pkPtr, bytes calldata message, bytes calldata sig)
        internal
        view
        returns (bool)
    {
        // sigDecode (FIPS 204 Alg. 27): fixed 2420-byte encoding for ML-DSA-44.
        if (sig.length != 2420) return false;

        if (!_pkSizeOk(pkPtr)) return false;

        // h = HintBitUnpack(sig[2336:2420]) with ALL of FIPS 204's validity
        // conditions (monotone indices, count bounds, zero padding); total
        // weight must not exceed omega = 80.
        uint256[4] memory hMasks;
        {
            bool hOk;
            uint256 hWeight;
            (hOk, hMasks, hWeight) = unpackHFast(sig[2336:2420]);
            if (!hOk || hWeight > 80) return false;
        }
        // z = sigDecode(sig[32:2336]) with the STRICT norm check
        // ||z||inf < gamma1 - beta (FIPS 204 Alg. 3 step; strict inequality).
        uint256[][] memory zp;
        {
            bool normOk;
            (zp, normOk) = unpackZPacked(sig[32:2336]);
            if (!normOk) return false;
        }

        bytes memory mu = _computeMu(pkPtr, message);

        uint256[][] memory r = _wPrimeRows(pkPtr, bytes32(sig[0:32]), zp);

        bytes memory w1 = useHintSwar(hMasks, r);

        return _finalHash(mu, w1) == bytes32(sig[0:32]);
    }

    /// The pk blob is consumed LAZILY (tr for mu, then one A row + one t1 row
    /// per matvec row into a reused scratch buffer) instead of being copied
    /// whole: the 20,544-byte resident copy would sit below every later
    /// allocation and inflate the quadratic memory-expansion cost of the whole
    /// pipeline. EXTCODECOPY zero-pads silently, so the code size is checked
    /// EXACTLY up front: any absent, truncated or oversized blob fails closed.
    function _pkSizeOk(address pkPtr) private view returns (bool pkOk) {
        assembly ("memory-safe") {
            // deployed code is 0x00 || payload (EIP-3541), payload at offset 1
            if eq(extcodesize(pkPtr), add(PK_SIZE, 1)) { pkOk := 1 }
        }
    }

    /// mu = SHAKE256(tr || 0x00 || 0x00 || M, 64) — tr is the pk payload's
    /// first 64 bytes (code offset 1), empty context.
    /// Uses the helper's one-call batched SHAKE256 entry point. The single
    /// preimage length that entry point cannot express is 800 bytes (it would
    /// be dispatched as a raw permutation), i.e. |M| == 734; that length falls
    /// back to the lane-level sponge, which is bit-identical.
    function _computeMu(address pkPtr, bytes calldata message) private view returns (bytes memory mu) {
        bytes memory muIn = new bytes(66 + message.length);
        assembly ("memory-safe") {
            let d := add(muIn, 32)
            extcodecopy(pkPtr, d, 1, 64)
            calldatacopy(add(d, 66), message.offset, message.length)
        }
        mu = muIn.length == 800
            ? shake256Fast170(muIn, 64, F1600)
            : shake256Batch170(muIn, 64, F1600);
    }

    /// w'approx = NTT^-1(Ahat o NTT(z) - NTT(c) o t1hat), row by row:
    /// cHat = NTT(SampleInBall(cTilde)); zHat_j = NTT(z_j);
    /// row i: A[i] (.) zHat + (KQ28 - cHat o t1hat[i]) -> InvNTT.
    /// Rows are returned in the packed-SWAR layout (useHintSwar consumes it
    /// directly). The forward NTTs require canonical (< q) input — guaranteed
    /// by unpackZPacked and sampleInBallPacked — and emit LAZY lanes (< 17q,
    /// C9a/C9f), exactly the domain the matvec accumulator admits (O7/O8).
    /// The RAW lazy accumulator (lanes <= 4(q-1)(17q-1) + q*2^28 < 2^53, Z3
    /// obligation O8) feeds nttInvV3 directly: the inverse NTT folds the
    /// reduction into its first layer (S14/C9g) and emits canonical rows.
    function _wPrimeRows(address pkPtr, bytes32 cTilde, uint256[][] memory zp)
        private
        view
        returns (uint256[][] memory r)
    {
        uint256[] memory ntProf = new uint256[](10);
        // Both twiddle tables are built ONCE here and passed to all nine
        // transforms; building them inside the transforms cost ~800 gas of
        // stores per call and leaked 9 KB of never-read memory into every
        // later allocation's expansion term (-10,321 gas end to end).
        uint256 fwT = nttFwTable();
        uint256 invT = nttInvTable();

        uint256[] memory cHat = nttFwV3(sampleInBallPacked(cTilde, F1600), ntProf, fwT);

        for (uint256 j = 0; j < 4; ++j) {
            zp[j] = nttFwV3(zp[j], ntProf, fwT);
        }

        // reused 5,120-byte scratch: A row i (4,096 B) || t1hat row i (1,024 B),
        // copied lazily per row (see _pkSizeOk for why the blob is not resident)
        uint256 scratch;
        assembly ("memory-safe") {
            scratch := mload(0x40)
            mstore(0x40, add(scratch, 0x1400))
        }
        r = new uint256[][](4);
        for (uint256 i = 0; i < 4; ++i) {
            assembly ("memory-safe") {
                extcodecopy(pkPtr, scratch, add(1, add(PK_A_OFF, shl(12, i))), 0x1000)
                extcodecopy(pkPtr, add(scratch, 0x1000), add(1, add(PK_T1_OFF, shl(10, i))), 0x400)
            }
            uint256[] memory acc = matvecRow(scratch, zp, cHat, scratch + 0x1000);
            nttInvV3(acc, ntProf, invT);
            r[i] = acc;
        }
    }

    /// cTilde' = SHAKE256(mu || w1Encode(w1'), 32)
    /// The 832-byte preimage spans 7 rate blocks; the batched entry point runs
    /// all 7 permutations in one staticcall (832 != 800, no fallback needed).
    function _finalHash(bytes memory mu, bytes memory w1) private view returns (bytes32 cPrime) {
        bytes memory fin;
        assembly ("memory-safe") {
            // raw allocation: the two mcopies below write all 832 bytes before
            // any is read, so Solidity's zero-fill is pure overhead
            fin := mload(0x40)
            mstore(fin, 832)
            mstore(0x40, add(fin, 0x360))
            mcopy(add(fin, 32), add(mu, 32), 64)
            mcopy(add(fin, 96), add(w1, 32), 768)
        }
        bytes memory ct2 = shake256Batch170(fin, 32, F1600);
        assembly ("memory-safe") {
            cPrime := mload(add(ct2, 32))
        }
    }
}
