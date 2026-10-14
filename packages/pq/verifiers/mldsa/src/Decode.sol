// SPDX-License-Identifier: MIT
// Decode.sol — signature-decode, SampleInBall, UseHint/w1Encode and matvec
// kernels for the ML-DSA-44 verifier.
//
// All kernels operate on the packed-SWAR polynomial layout (4 coefficients per
// 256-bit word, one 64-bit lane each; lane l of word i = coefficient 4i+l):
//
//   unpackZPacked      strict FIPS 204 z decode straight into packed lanes.
//                      The encoding's 18-bit fields are byte-aligned every 4
//                      coefficients (72 bits = 9 bytes) — exactly one packed
//                      word — so each 9-byte group becomes one 256-bit store.
//                      Enforces the strict norm check |z| < gamma1 - beta
//                      (v in [79, 262065]) and canonicalises q -> 0.
//   useHintSwar        UseHint + w1Encode fused, 4 coefficients per step in
//                      64-bit lanes, consuming the inverse NTT's packed output
//                      directly. Bound argument in the block comment above the
//                      function; verified exhaustively over the full input
//                      domain (see the test battery).
//   sampleInBallPacked SampleInBall (FIPS 204 Alg. 29) writing the packed
//                      layout directly.
//   matvecRow          one row of Ahat o NTT(z) - NTT(c) o t1hat in the lazy
//                      64-bit-lane accumulator, two passes per row.
//   unpackHFast        HintBitUnpack (FIPS 204 Alg. 21) with all validity
//                      conditions, producing four 256-bit hint masks.
//
// Every kernel is differential-tested against an independently verified
// reference implementation in the test battery; the lane/overflow bounds cited
// below are machine-checked by the Z3 obligations in formal/.
pragma solidity ^0.8.25;

import {f1600Fast170, _M64_170, _squeezeBlockFast170} from "./FastKeccak170.sol";

uint256 constant MLDSA_Q = 8380417;

// --- z-decode SWAR constants (four 64-bit lanes, one per coefficient) -------
// Every one of these is the SAME per-lane constant replicated four times, which
// is what makes the single-word check below a FOUR-coefficient check: change any
// lane and one coefficient stops being decoded or checked (Z3 S8b/E4b, mutant
// M40b, and the `formal/hypotheses.py` replication tripwire).
//   Z_M18   18-bit field mask; applied ONCE to the whole word, which is what
//           lets the twelve byte terms be placed with pure left shifts and
//           their out-of-field spill be discarded in one AND (O10).
//   Z_UOFF  q + gamma1 = 8511489: u := Z_UOFF - V is the uncanonicalised
//           centered value, per lane in [8249346, 8511489] c [0, 2q).
//   Z_QB32  2^32 - q: bit 32 of (u + Z_QB32) is exactly [u >= q], the ONE
//           conditional subtraction that turns u into u mod q (so z = 0,
//           encoded as v = gamma1, canonicalises to 0 and not to q -- the
//           hazard of docs/EXPLAINER.md section 10).
//   Z_BIT32 the flag bit itself, per lane.
//   Z_NLO / Z_NHI  the STRICT FIPS 204 norm check on the STORED word:
//           bit 32 of (o + Z_NLO) is [o >= gamma1 - beta] and bit 32 of
//           (Z_NHI - o) is [o <= q - (gamma1 - beta) - 1], so their AND is
//           exactly "o is at distance >= gamma1 - beta from 0 mod q", i.e.
//           ||z||inf >= gamma1 - beta -- REJECT, boundary included (S8/E4/E5).
uint256 constant Z_M18 = 0x000000000003ffff000000000003ffff000000000003ffff000000000003ffff;
uint256 constant Z_UOFF = 0x000000000081e001000000000081e001000000000081e001000000000081e001;
uint256 constant Z_QB32 = 0x00000000ff801fff00000000ff801fff00000000ff801fff00000000ff801fff;
uint256 constant Z_BIT32 = 0x0000000100000000000000010000000000000001000000000000000100000000;
uint256 constant Z_NLO = 0x00000000fffe004e00000000fffe004e00000000fffe004e00000000fffe004e;
uint256 constant Z_NHI = 0x00000001007de04f00000001007de04f00000001007de04f00000001007de04f;
// Z_P2/Z_P4/Z_P6: the three bytes that straddle TWO 18-bit fields (bytes 2, 4
// and 6 of each 9-byte group) are placed at BOTH of their positions by ONE
// multiply, because for b < 2^8 and shifts 46 apart the two shifted copies
// occupy disjoint bit ranges, so b*(2^s + 2^t) == or(shl(s,b), shl(t,b))
// exactly (O10). Three multiplies replace six shifts, three ORs and three
// stack copies.
uint256 constant Z_P2 = 0x4000000000010000; // 2^62 + 2^16
uint256 constant Z_P4 = 0x10000000000040000000000000000000; // 2^124 + 2^78
uint256 constant Z_P6 = 0x40000000000100000000000000000000000000000000000; // 2^186 + 2^140

// ---------------------------------------------------------------------------
// (1) unpackZPacked
// ---------------------------------------------------------------------------
/// @notice decode ONE 576-byte z polynomial (64 coefficient-quads) straight into
///         the packed-SWAR layout at `dstIn`, returning a nonzero value iff any
///         coefficient violates the strict norm bound.
/// @dev    Split out of unpackZPacked. One 9-byte group = four 18-bit fields =
///         one packed word, and the whole quad -- extraction, canonicalisation
///         and the strict norm check -- is done FOUR LANES AT A TIME:
///
///           V := and(<12 byte terms, 9 of them placed by pure left shifts and
///                     the 3 doubled ones by one multiply each>, Z_M18)
///           u := sub(Z_UOFF, V)                       // q + gamma1 - v
///           o := sub(u, mul(shr(32, and(add(u, Z_QB32), Z_BIT32)), MLDSA_Q))
///           <accumulate and(add(o, Z_NLO), sub(Z_NHI, o))>   // bit 32 = reject
///
///         The verdict word is OR-accumulated through the 0x00 SCRATCH WORD
///         rather than a Yul local, and that is a measured choice, not a
///         stylistic one: one more value live across the unrolled body puts
///         the via-IR stack scheduler over its limit (no memoryguard is
///         emitted, because src/FastKeccak170.sol's byte-reversal blocks are
///         not memory-safe), and the spills it then inserts in EVERY quad cost
///         1,745 bytes of runtime and 19,916 gas. The scratch word is written
///         and read inside ONE memory-safe assembly block with no Solidity
///         statement in between, which is exactly what that area is for.
///
///         Three facts make this exactly four independent copies of the scalar
///         decoder, and all three are machine-checked rather than asserted:
///         (i) the twelve byte terms occupy pairwise DISJOINT bit ranges (top
///         bit 209), so their OR is their sum, and every bit that falls outside
///         a lane's 18-bit field is discarded by the single Z_M18 (O10) -- which
///         is also why the three bytes that appear TWICE can be emitted as one
///         `mul(byte(k, w), 2^s + 2^t)` each: disjointness makes that product
///         equal to the OR of the two shifted copies, for every byte value;
///         (ii) every lane's arithmetic stays inside its own 64 bits -- the
///         subtrahends never exceed their minuends (no borrow) and no sum
///         reaches 2^33 (no carry), so lane k of each word is a function of
///         v_k alone (S8b, O10);
///         (iii) bit 32 of a lane is the carry/borrow flag of exactly one
///         threshold comparison, which is what turns three range tests into
///         three constant adds (S8b, E4b).
///         The stored words and the per-coefficient verdict are identical to
///         the previous per-coefficient form, whose predicate
///         `iszero(lt(sub(v, 79), 261987))` and map `mod(8511489 - v, q)` the
///         reference decoder (test/ZZZ_E2ERef.sol) still carries -- it is the
///         differential oracle for this one, coefficient for coefficient.
function _unpackZPoly(uint256 srcIn, uint256 dstIn) pure returns (uint256 fail) {
    assembly ("memory-safe") {
        let src := srcIn
        let dst := dstIn
        mstore(0, 0)
        for { let b := 0 } lt(b, 16) { b := add(b, 1) } {
            {
                let w := mload(src)
                let V :=
                    and(
                        or(
                            or(
                                or(or(byte(0, w), shl(8, byte(1, w))), mul(byte(2, w), Z_P2)),
                                or(shl(70, byte(3, w)), mul(byte(4, w), Z_P4))
                            ),
                            or(
                                or(shl(132, byte(5, w)), mul(byte(6, w), Z_P6)),
                                or(shl(194, byte(7, w)), shl(202, byte(8, w)))
                            )
                        ),
                        Z_M18
                    )
                let u := sub(Z_UOFF, V)
                let o := sub(u, mul(shr(32, and(add(u, Z_QB32), Z_BIT32)), MLDSA_Q))
                mstore(0, or(mload(0), and(add(o, Z_NLO), sub(Z_NHI, o))))
                mstore(dst, o)
            }
            {
                let w := mload(add(src, 9))
                let V :=
                    and(
                        or(
                            or(
                                or(or(byte(0, w), shl(8, byte(1, w))), mul(byte(2, w), Z_P2)),
                                or(shl(70, byte(3, w)), mul(byte(4, w), Z_P4))
                            ),
                            or(
                                or(shl(132, byte(5, w)), mul(byte(6, w), Z_P6)),
                                or(shl(194, byte(7, w)), shl(202, byte(8, w)))
                            )
                        ),
                        Z_M18
                    )
                let u := sub(Z_UOFF, V)
                let o := sub(u, mul(shr(32, and(add(u, Z_QB32), Z_BIT32)), MLDSA_Q))
                mstore(0, or(mload(0), and(add(o, Z_NLO), sub(Z_NHI, o))))
                mstore(add(dst, 32), o)
            }
            {
                let w := mload(add(src, 18))
                let V :=
                    and(
                        or(
                            or(
                                or(or(byte(0, w), shl(8, byte(1, w))), mul(byte(2, w), Z_P2)),
                                or(shl(70, byte(3, w)), mul(byte(4, w), Z_P4))
                            ),
                            or(
                                or(shl(132, byte(5, w)), mul(byte(6, w), Z_P6)),
                                or(shl(194, byte(7, w)), shl(202, byte(8, w)))
                            )
                        ),
                        Z_M18
                    )
                let u := sub(Z_UOFF, V)
                let o := sub(u, mul(shr(32, and(add(u, Z_QB32), Z_BIT32)), MLDSA_Q))
                mstore(0, or(mload(0), and(add(o, Z_NLO), sub(Z_NHI, o))))
                mstore(add(dst, 64), o)
            }
            {
                let w := mload(add(src, 27))
                let V :=
                    and(
                        or(
                            or(
                                or(or(byte(0, w), shl(8, byte(1, w))), mul(byte(2, w), Z_P2)),
                                or(shl(70, byte(3, w)), mul(byte(4, w), Z_P4))
                            ),
                            or(
                                or(shl(132, byte(5, w)), mul(byte(6, w), Z_P6)),
                                or(shl(194, byte(7, w)), shl(202, byte(8, w)))
                            )
                        ),
                        Z_M18
                    )
                let u := sub(Z_UOFF, V)
                let o := sub(u, mul(shr(32, and(add(u, Z_QB32), Z_BIT32)), MLDSA_Q))
                mstore(0, or(mload(0), and(add(o, Z_NLO), sub(Z_NHI, o))))
                mstore(add(dst, 96), o)
            }
            src := add(src, 36)
            dst := add(dst, 128)
        }
        // only bit 32 of each lane carries a verdict; the rest of `bad` is the
        // arithmetic that produced them
        fail := and(mload(0), Z_BIT32)
    }
}

/// @notice strict FIPS-204 z decode straight into the packed-SWAR layout.
/// @param input the 2304-byte z region of the signature (sig[32:2336])
/// @return zp 4 polynomials, 64 words each, 4 canonical coefficients per word
///            in 64-bit lanes (lane l of word i = coefficient 4i+l)
/// @return normOk true iff every coefficient satisfies the STRICT bound
///            ||z||inf < gamma1 - beta (FIPS 204 Alg. 3); identical predicate to
///            unpackZStrict, evaluated per coefficient, OR-accumulated.
function unpackZPacked(bytes memory input) pure returns (uint256[][] memory zp, bool normOk) {
    uint256 src;
    assembly ("memory-safe") {
        src := add(input, 32)
        // RAW allocation of the outer 4-pointer array and its four 64-word
        // polynomials, in one block, exactly as matvecRow allocates its
        // accumulator: `_unpackZPoly` writes every one of the 64 words of every
        // polynomial before any is read, so Solidity's zero-fill of 260 words
        // is pure overhead (~2.6k gas). The four element pointers ARE written
        // here, so the outer array is fully initialised on exit.
        zp := mload(0x40)
        mstore(zp, 4)
        let arr := add(zp, 0xa0) // 0x20 length word + 4 x 0x20 element pointers
        let hdr := add(zp, 0x20)
        for { let p := 0 } lt(p, 4) { p := add(p, 1) } {
            mstore(hdr, arr)
            mstore(arr, 64)
            hdr := add(hdr, 0x20)
            arr := add(arr, 0x820)
        }
        mstore(0x40, arr)
    }
    uint256 fail;
    unchecked {
        for (uint256 p = 0; p < 4; ++p) {
            uint256 dst;
            uint256[] memory zpp = zp[p];
            assembly ("memory-safe") {
                dst := add(zpp, 32)
            }
            // 576 bytes of encoding = 64 quads = one polynomial
            fail |= _unpackZPoly(src + 576 * p, dst);
        }
    }
    normOk = (fail == 0);
}

// ---------------------------------------------------------------------------
// (2) useHintSwar — fused UseHint + w1Encode, 4 coefficients per step
// ---------------------------------------------------------------------------
// Bit-identical to UseHint + w1Encode of FIPS 204 (Algorithms 40 and 28),
// exhaustively verified against the reference over all 8,380,417 x 2 inputs.
//
// Per 64-bit lane, with r < q = 8380417 (guaranteed: nttInvV3 emits canonical
// lanes) and D = 2*gamma2 = 190464, gamma2 = 95232:
//
//   Q0  = (r * MDIV) >> 39                 MDIV = ceil(2^39/D) = 2886403
//                                          exact for every r < q (brute-forced
//                                          over the full domain); the lane
//                                          product r*MDIV <= 24,189,257,883,648
//                                          < 2^45, so no lane can carry into the
//                                          next (lane budget 2^64) and Q0 <= 44
//                                          fits the 6-bit REP6 mask.
//   R0  = r - Q0*D                         Q0*D < 64*190464 < 2^24, never borrows
//   C   = [R0 > gamma2]                    bit 32 of R0 + (2^32 - 95233); R0 <
//                                          2^18 so the sum is < 2^33, lane-local
//   S1  = Q0 + C  <= 44
//   NEG = [R0 == 0] | C                    r0 <= 0 in the centred representation
//   ADJ = [hint] ? (1 + 42*NEG) : 0        43 == -1 (mod 44)
//   T   = S1 + ADJ  <= 87                  ONE reduction, not two: the FIPS
//                                          r+ - r0 == q-1 special case is
//                                          "S1 == 44 maps to 0", i.e. S1 mod 44,
//                                          and (S1 mod 44 + ADJ) mod 44 ==
//                                          (S1 + ADJ) mod 44 -- so the
//                                          intermediate reduction is redundant
//                                          given the final one.
//   OUT = T - 44*((T*M44) >> 12)           M44 = ceil(2^12/44) = 94; the shifted
//                                          product equals floor(T/44) for EVERY
//                                          T < 131 (brute-forced; obligation
//                                          C17), and T <= 87 here, so OUT =
//                                          T mod 44 exactly. The lane product
//                                          T*94 <= 8178 < 2^14 stays lane-local
//                                          and (T*94) >> 12 <= 1 fits the REP1
//                                          mask.
//
// then the four 6-bit results are gathered into one 24-bit w1Encode field by a
// SINGLE multiply: OUT * GATHERK with GATHERK = 2^174 + 2^116 + 2^58 + 1 puts
// lane k at bit 174 + 6k and every off-diagonal product outside [174, 198).
//
// VERIFICATION: the exact 256-bit model of this routine was checked against the
// FIPS 204 reference EXHAUSTIVELY over the whole domain (all 8,380,417 values of
// r x both hint bits = 16,760,834 cases, 0 mismatches) plus 560,000 mixed-lane
// cases including every 4-tuple of 10 boundary values x all 16 hint patterns.
// The test battery re-checks it on-chain against an independent per-coefficient
// reference implementation.
uint256 constant SW_REP1 = 0x0000000000000001000000000000000100000000000000010000000000000001;
uint256 constant SW_REP6 = 0x000000000000003f000000000000003f000000000000003f000000000000003f;
uint256 constant SW_K32G2 = 0x00000000fffe8bff00000000fffe8bff00000000fffe8bff00000000fffe8bff;
uint256 constant SW_K321 = 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff;
// NOTE: the per-lane replications of 42 and 44 (SW_REP42/SW_REP44) that stood
// here were declared and never read -- the kernel multiplies by the literals --
// and a constant no check covers is exactly the surface an attacker
// looks for. They are deleted, and obligation C18's `dec_no_dead_constants_remain`
// keeps them (and SW_K3244, the second reduction of a useHintSwar that no longer
// exists) from coming back unnoticed.
uint256 constant SW_GATHERK = 0x0000000000000000000040000000000000100000000000000400000000000001;
uint256 constant SW_MDIV = 2886403;
uint256 constant SW_D = 190464;
uint256 constant SW_M44 = 94; // ceil(2^12/44): exact floor(T/44) for every T < 131

/// @param hMasks per-polynomial hint bitmasks (bit j = hint for coefficient j)
/// @param r      4 polynomials, 64 packed words each, CANONICAL lanes (< q)
/// @return w1    the 768-byte w1Encode output (6 bits per coefficient)
function useHintSwar(uint256[4] memory hMasks, uint256[][] memory r) pure returns (bytes memory w1) {
    // The output is written in 24-byte chunks by whole-word mstores, so the
    // LAST chunk's store reaches 8 bytes past byte 768. The buffer is therefore
    // allocated with 32 bytes of slack and its length word set back to 768: the
    // slack stays inside this object's own allocation, below the free-memory
    // pointer, so nothing else can ever be handed it (the same discipline
    // shake256Fast170's whole-rate-block squeeze buffer uses).
    // RAW allocation (matvecRow's idiom): every one of the 768 output bytes is
    // written by the loop below before any is read, so Solidity's zero-fill of
    // the 800-byte buffer is pure overhead.
    assembly ("memory-safe") {
        w1 := mload(0x40)
        mstore(0x40, add(w1, 0x340)) // 0x20 length + 800 bytes of payload
        mstore(w1, 768)
        // 16-entry table: tbl[h] = full 64-bit lane mask for each set bit of h
        let tbl := mload(0x40)
        mstore(0x40, add(tbl, 512))
            mstore(add(tbl, 0), 0x0000000000000000000000000000000000000000000000000000000000000000)
            mstore(add(tbl, 32), 0x000000000000000000000000000000000000000000000000ffffffffffffffff)
            mstore(add(tbl, 64), 0x00000000000000000000000000000000ffffffffffffffff0000000000000000)
            mstore(add(tbl, 96), 0x00000000000000000000000000000000ffffffffffffffffffffffffffffffff)
            mstore(add(tbl, 128), 0x0000000000000000ffffffffffffffff00000000000000000000000000000000)
            mstore(add(tbl, 160), 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff)
            mstore(add(tbl, 192), 0x0000000000000000ffffffffffffffffffffffffffffffff0000000000000000)
            mstore(add(tbl, 224), 0x0000000000000000ffffffffffffffffffffffffffffffffffffffffffffffff)
            mstore(add(tbl, 256), 0xffffffffffffffff000000000000000000000000000000000000000000000000)
            mstore(add(tbl, 288), 0xffffffffffffffff00000000000000000000000000000000ffffffffffffffff)
            mstore(add(tbl, 320), 0xffffffffffffffff0000000000000000ffffffffffffffff0000000000000000)
            mstore(add(tbl, 352), 0xffffffffffffffff0000000000000000ffffffffffffffffffffffffffffffff)
            mstore(add(tbl, 384), 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000)
            mstore(add(tbl, 416), 0xffffffffffffffffffffffffffffffff0000000000000000ffffffffffffffff)
            mstore(add(tbl, 448), 0xffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000)
            mstore(add(tbl, 480), 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
        let dst := add(w1, 32)
        for { let i := 0 } lt(i, 4) { i := add(i, 1) } {
            let hm := mload(add(hMasks, shl(5, i)))
            let src := add(mload(add(add(r, 32), shl(5, i))), 32)
            let end := add(src, 0x800)
            // EIGHT packed words (32 coefficients) per iteration: that is
            // exactly 24 output bytes, so the 96 per-byte mstore8/shift/address
            // ops of eight groups collapse into ONE byte-reversal and ONE
            // mstore, and the ~47-gas loop tax is paid a quarter as often.
            for {} lt(src, end) { src := add(src, 0x100) } {
                let W := mload(src)
                let Q0 := and(shr(39, mul(W, SW_MDIV)), SW_REP6)
                let R0 := sub(W, mul(Q0, SW_D))
                let C := and(shr(32, add(R0, SW_K32G2)), SW_REP1)
                let NEG := or(and(not(shr(32, add(R0, SW_K321))), SW_REP1), C)
                let ADJ := and(add(SW_REP1, mul(NEG, 42)), mload(add(tbl, shl(5, and(hm, 15)))))
                let S := add(add(Q0, C), ADJ)
                S := sub(S, mul(and(shr(12, mul(S, SW_M44)), SW_REP1), 44))
                let L := and(shr(174, mul(S, SW_GATHERK)), 0xffffff)
                W := mload(add(src, 0x20))
                Q0 := and(shr(39, mul(W, SW_MDIV)), SW_REP6)
                R0 := sub(W, mul(Q0, SW_D))
                C := and(shr(32, add(R0, SW_K32G2)), SW_REP1)
                NEG := or(and(not(shr(32, add(R0, SW_K321))), SW_REP1), C)
                ADJ := and(add(SW_REP1, mul(NEG, 42)), mload(add(tbl, shl(5, and(shr(4, hm), 15)))))
                S := add(add(Q0, C), ADJ)
                S := sub(S, mul(and(shr(12, mul(S, SW_M44)), SW_REP1), 44))
                L := or(L, shl(24, and(shr(174, mul(S, SW_GATHERK)), 0xffffff)))
                W := mload(add(src, 0x40))
                Q0 := and(shr(39, mul(W, SW_MDIV)), SW_REP6)
                R0 := sub(W, mul(Q0, SW_D))
                C := and(shr(32, add(R0, SW_K32G2)), SW_REP1)
                NEG := or(and(not(shr(32, add(R0, SW_K321))), SW_REP1), C)
                ADJ := and(add(SW_REP1, mul(NEG, 42)), mload(add(tbl, shl(5, and(shr(8, hm), 15)))))
                S := add(add(Q0, C), ADJ)
                S := sub(S, mul(and(shr(12, mul(S, SW_M44)), SW_REP1), 44))
                L := or(L, shl(48, and(shr(174, mul(S, SW_GATHERK)), 0xffffff)))
                W := mload(add(src, 0x60))
                Q0 := and(shr(39, mul(W, SW_MDIV)), SW_REP6)
                R0 := sub(W, mul(Q0, SW_D))
                C := and(shr(32, add(R0, SW_K32G2)), SW_REP1)
                NEG := or(and(not(shr(32, add(R0, SW_K321))), SW_REP1), C)
                ADJ := and(add(SW_REP1, mul(NEG, 42)), mload(add(tbl, shl(5, and(shr(12, hm), 15)))))
                S := add(add(Q0, C), ADJ)
                S := sub(S, mul(and(shr(12, mul(S, SW_M44)), SW_REP1), 44))
                L := or(L, shl(72, and(shr(174, mul(S, SW_GATHERK)), 0xffffff)))
                W := mload(add(src, 0x80))
                Q0 := and(shr(39, mul(W, SW_MDIV)), SW_REP6)
                R0 := sub(W, mul(Q0, SW_D))
                C := and(shr(32, add(R0, SW_K32G2)), SW_REP1)
                NEG := or(and(not(shr(32, add(R0, SW_K321))), SW_REP1), C)
                ADJ := and(add(SW_REP1, mul(NEG, 42)), mload(add(tbl, shl(5, and(shr(16, hm), 15)))))
                S := add(add(Q0, C), ADJ)
                S := sub(S, mul(and(shr(12, mul(S, SW_M44)), SW_REP1), 44))
                L := or(L, shl(96, and(shr(174, mul(S, SW_GATHERK)), 0xffffff)))
                W := mload(add(src, 0xa0))
                Q0 := and(shr(39, mul(W, SW_MDIV)), SW_REP6)
                R0 := sub(W, mul(Q0, SW_D))
                C := and(shr(32, add(R0, SW_K32G2)), SW_REP1)
                NEG := or(and(not(shr(32, add(R0, SW_K321))), SW_REP1), C)
                ADJ := and(add(SW_REP1, mul(NEG, 42)), mload(add(tbl, shl(5, and(shr(20, hm), 15)))))
                S := add(add(Q0, C), ADJ)
                S := sub(S, mul(and(shr(12, mul(S, SW_M44)), SW_REP1), 44))
                L := or(L, shl(120, and(shr(174, mul(S, SW_GATHERK)), 0xffffff)))
                W := mload(add(src, 0xc0))
                Q0 := and(shr(39, mul(W, SW_MDIV)), SW_REP6)
                R0 := sub(W, mul(Q0, SW_D))
                C := and(shr(32, add(R0, SW_K32G2)), SW_REP1)
                NEG := or(and(not(shr(32, add(R0, SW_K321))), SW_REP1), C)
                ADJ := and(add(SW_REP1, mul(NEG, 42)), mload(add(tbl, shl(5, and(shr(24, hm), 15)))))
                S := add(add(Q0, C), ADJ)
                S := sub(S, mul(and(shr(12, mul(S, SW_M44)), SW_REP1), 44))
                L := or(L, shl(144, and(shr(174, mul(S, SW_GATHERK)), 0xffffff)))
                W := mload(add(src, 0xe0))
                Q0 := and(shr(39, mul(W, SW_MDIV)), SW_REP6)
                R0 := sub(W, mul(Q0, SW_D))
                C := and(shr(32, add(R0, SW_K32G2)), SW_REP1)
                NEG := or(and(not(shr(32, add(R0, SW_K321))), SW_REP1), C)
                ADJ := and(add(SW_REP1, mul(NEG, 42)), mload(add(tbl, shl(5, and(shr(28, hm), 15)))))
                S := add(add(Q0, C), ADJ)
                S := sub(S, mul(and(shr(12, mul(S, SW_M44)), SW_REP1), 44))
                L := or(L, shl(168, and(shr(174, mul(S, SW_GATHERK)), 0xffffff)))
                // byte-reverse L so ONE mstore lays its 24 little-endian bytes down in
                // order; the 8-byte tail lands on the next chunk (or, for the last
                // chunk, inside w1's own 800-byte allocation) and is rewritten there.
                let a := and(L, 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00)
                L := or(shr(8, a), shl(8, xor(L, a)))
                a := and(L, 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000)
                L := or(shr(16, a), shl(16, xor(L, a)))
                a := and(L, 0xffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000)
                L := or(shr(32, a), shl(32, xor(L, a)))
                a := and(L, 0xffffffffffffffff0000000000000000ffffffffffffffff0000000000000000)
                L := or(shr(64, a), shl(64, xor(L, a)))
                mstore(dst, or(shr(128, L), shl(128, L)))
                dst := add(dst, 24)
                hm := shr(32, hm)
            }
        }

    }
}

// ---------------------------------------------------------------------------
// (3) sampleInBallPacked — SampleInBall (FIPS 204 Alg. 29, tau = 39) writing
//     the packed-SWAR layout directly. SHAKE256 stream consumption (one block
//     absorbed, byte-wise rejection sampling on the squeeze stream) follows
//     FIPS 204 exactly.
// ---------------------------------------------------------------------------
function sampleInBallPacked(bytes32 cTilde, address f1600) view returns (uint256[] memory c) {
    uint256[25] memory st;
    // The squeeze destination. _squeezeBlockFast170 touches EXACTLY
    // [bp, bp + 136): its fifth store is placed at bp + 104 and carries lanes
    // 13..16, so it lands FLUSH with the end of the rate block instead of
    // overhanging it. (The "168 = 136 + a 24-byte spill" reservation below was
    // sized for a 160-byte write there; docs/SAFETY.md section 4.1 pins the
    // footprint that the routine actually has.) The 192 bytes
    // reserved here are therefore 136 of squeeze plus 56 of slack, all inside
    // this object's own allocation and below the free-memory pointer. Only a
    // squeeze DESTINATION: the absorb never touches it (see below).
    uint256 bp;
    assembly ("memory-safe") {
        // raw allocation: _squeezeBlockFast170 writes all 136 rate bytes before
        // any is read, so Solidity's zero-fill is pure overhead. The reservation
        // keeps the free pointer 32-byte aligned.
        bp := add(mload(0x40), 32)
        mstore(0x40, add(bp, 192))
        // Absorbing the one and only rate block into a ZERO sponge state is
        // assignment, not XOR-with-reload: the padded block is
        // c~(32 bytes) || 0x1f || 0x00*102 || 0x80, so lanes 0..3 are c~'s
        // 8-byte groups read little-endian, lane 4 is the 0x1f domain byte
        // (byte 32 = lane 4's least significant byte), lane 16 is the 0x80
        // final bit (byte 135 = lane 16's most significant byte), and the other
        // 21 lanes stay zero. That is bit-for-bit what _xorBlockFast170 would
        // compute here, at ~1/5 the gas; the general absorb remains the
        // differential oracle (test/SEC_sampleinball.t.sol, test/Kernels.t.sol
        // and the ACVP chain all compare this sampler against samplers that use
        // it, over the full 136-byte stream including refills).
        //
        // grev: reverse the byte order inside each 8-byte group of the word --
        // the same transform the general absorb applies, kept in the two-mask
        // form here because this is on the hot path and solc schedules that
        // form one stack slot tighter.
        let v := cTilde
        v := or(
            and(shl(8, v), 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00),
            and(shr(8, v), 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff)
        )
        v := or(
            and(shl(16, v), 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000),
            and(shr(16, v), 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff)
        )
        v := or(
            and(shl(32, v), 0xffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000),
            and(shr(32, v), 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff)
        )
        mstore(st, shr(192, v)) // lane 0 = LE(c~[0:8])
        mstore(add(st, 32), and(shr(128, v), _M64_170)) // lane 1 = LE(c~[8:16])
        mstore(add(st, 64), and(shr(64, v), _M64_170)) // lane 2 = LE(c~[16:24])
        mstore(add(st, 96), and(v, _M64_170)) // lane 3 = LE(c~[24:32])
        mstore(add(st, 128), 0x1f) // lane 4 = 0x1f domain padding
        mstore(add(st, 512), 0x8000000000000000) // lane 16 = 0x80 final bit
    }
    f1600Fast170(st, f1600);
    _squeezeBlockFast170(st, bp);
    uint256 signInt = st[0];
    c = new uint256[](64); // 64 packed words, zeroed
    uint256 base;
    assembly ("memory-safe") {
        base := add(c, 32)
    }
    uint256 pos = 8;
    uint256 i = 217;
    unchecked {
        // The WHOLE tau-draw loop of FIPS 204 Alg. 29 runs inside ONE assembly
        // block: the rejection scan, the sign bit and the swap-and-set are a
        // few dozen gas of real work each, and paying Solidity's per-draw loop
        // framing plus the entry/exit of two assembly blocks around them cost
        // more than the draws themselves (see GasCalibration). The block LEAVES
        // only to refill the squeeze buffer, which needs a helper STATICCALL:
        // `exhausted` is set with `i` NOT advanced, so the outer loop permutes,
        // squeezes, resets pos and re-enters — and the re-entered scan restarts
        // the SAME draw from the new block's first byte, which is exactly the
        // original `j := 256; continue` semantics and keeps the stream
        // byte-exact (a second permutation is needed with probability < 2^-200,
        // C10).
        while (true) {
            bool exhausted;
            assembly ("memory-safe") {
                for {} lt(i, 256) { i := add(i, 1) } {
                    // rejection scan: consume squeeze bytes until one is <= i.
                    // j = 256 is a sentinel > i, so an already-empty block
                    // forces a refill instead of an out-of-range draw.
                    let j := 256
                    for {} lt(pos, 136) {} {
                        j := byte(0, mload(add(bp, pos)))
                        pos := add(pos, 1)
                        if iszero(gt(j, i)) { break }
                    }
                    if gt(j, i) {
                        exhausted := 1
                        break
                    }
                    // sign bit -> v in {1, q-1}, branchless
                    let v := add(1, mul(and(signInt, 1), 8380415))
                    signInt := shr(1, signInt)
                    // c[i] := c[j]  (i is strictly increasing and >= 217, j <= i,
                    // so lane i has never been written: a plain OR suffices; for
                    // j == i the lane is still zero and the OR is a no-op, then
                    // the masked c[j] := v store below writes the same lane)
                    let pi := add(base, shl(5, shr(2, i)))
                    let pj := add(base, shl(5, shr(2, j)))
                    let sj := shl(6, and(j, 3))
                    let vj := and(shr(sj, mload(pj)), 0xffffffffffffffff)
                    mstore(pi, or(mload(pi), shl(shl(6, and(i, 3)), vj)))
                    // c[j] := v
                    mstore(pj, or(and(mload(pj), not(shl(sj, 0xffffffffffffffff))), shl(sj, v)))
                }
            }
            if (!exhausted) break;
            f1600Fast170(st, f1600);
            _squeezeBlockFast170(st, bp);
            pos = 0;
        }
    }
}


// ---------------------------------------------------------------------------
// (4) macCompactPre / macSubCT1Pre — pre-shifted-lane matvec MACs
// ---------------------------------------------------------------------------
// Rather than extracting each z lane down to bit 0 before multiplying, the z
// word is masked IN PLACE: `and(wz, M64L{k})` is the value z_k * 2^(64k) and
// `mul(a_k, that)` is already the product in lane position, because
// a_k * z_k < (q-1)*(17q-1) < 2^51 never reaches the top of a 64-bit lane
// (the top lane's product is < 2^51 * 2^192 = 2^243 < 2^256): zHat/cHat lanes
// come from the LAZY forward NTT and are < 17q, not canonical.  The four
// lane-disjoint terms are then combined with ADD instead of SHL+OR.
// Lane disjointness of the pre-shifted products is Z3 obligation O7.
//
// ACCUMULATOR BOUNDS (Z3 obligation O8): each accumulator lane receives four
// products < (q-1)*(17q-1) plus one (KQ28 - c*t1) term < KQ28, total
// < 2^53 << 2^64, so lanes never carry into their neighbours.
// KQ28 = q << 28 = 2,249,601,058,865,152 > (17q-1)*(q-1) = 1,193,933,463,748,608,
// so every lane of (KQ28REP - sum(c_k*t1_k << 64k)) stays non-negative and no
// lane can borrow from its neighbour; KQ28 is a multiple of q, so the added
// offset vanishes under the inverse NTT's entry reduction (S14).  The lane
// total is O8's/C9g's ACC_ENTRY = 4(q-1)(17q-1) + q*2^28 = 7,025,334,913,859,584,
// dominated by the inverse NTT's ACCQ30 = q*2^30 entry offset.
uint256 constant MV_M32 = 0xffffffff;
uint256 constant MV_L0 = 0x000000000000000000000000000000000000000000000000ffffffffffffffff;
uint256 constant MV_L1 = 0x00000000000000000000000000000000ffffffffffffffff0000000000000000;
uint256 constant MV_L2 = 0x0000000000000000ffffffffffffffff00000000000000000000000000000000;
uint256 constant MV_L3 = 0xffffffffffffffff000000000000000000000000000000000000000000000000;
uint256 constant MV_KQ28REP = 0x0007fe00100000000007fe00100000000007fe00100000000007fe0010000000;

/// acc[lane] += A[coeff] * z[lane]; A in the pk's compact 8x32-bit/word layout,
/// z packed 4x64-bit lazy lanes (< 17q). One A word feeds two accumulator words.
function macCompactPre(uint256[] memory acc, uint256 aPtr, uint256[] memory z) pure {
    assembly ("memory-safe") {
        let pz := add(z, 0x20)
        let pd := add(acc, 0x20)
        let ae := add(aPtr, 0x400)
        for {} lt(aPtr, ae) {} {
            let wa := mload(aPtr)
            let wz := mload(pz)
            mstore(
                pd,
                add(
                    mload(pd),
                    add(
                        add(
                            mul(and(wa, MV_M32), and(wz, MV_L0)),
                            mul(and(shr(32, wa), MV_M32), and(wz, MV_L1))
                        ),
                        add(
                            mul(and(shr(64, wa), MV_M32), and(wz, MV_L2)),
                            mul(and(shr(96, wa), MV_M32), and(wz, MV_L3))
                        )
                    )
                )
            )
            wz := mload(add(pz, 0x20))
            pd := add(pd, 0x20)
            mstore(
                pd,
                add(
                    mload(pd),
                    add(
                        add(
                            mul(and(shr(128, wa), MV_M32), and(wz, MV_L0)),
                            mul(and(shr(160, wa), MV_M32), and(wz, MV_L1))
                        ),
                        add(
                            mul(and(shr(192, wa), MV_M32), and(wz, MV_L2)),
                            mul(shr(224, wa), and(wz, MV_L3))
                        )
                    )
                )
            )
            aPtr := add(aPtr, 0x20)
            pz := add(pz, 0x40)
            pd := add(pd, 0x20)
        }
    }
}

/// acc[lane] += KQ28 - c[lane] * t1[coeff]  (the -c*t1 term of A*z - c*t1,
/// folded into the same lazy accumulator). c packed 4x64 lazy lanes (< 17q),
/// t1 in the pk's compact 8x32-bit/word layout.
function macSubCT1Pre(uint256[] memory acc, uint256[] memory c, uint256 tPtr) pure {
    assembly ("memory-safe") {
        let cp := add(c, 0x20)
        let pd := add(acc, 0x20)
        let te := add(tPtr, 0x400)
        for {} lt(tPtr, te) {} {
            let wt := mload(tPtr)
            let wc := mload(cp)
            mstore(
                pd,
                add(
                    mload(pd),
                    sub(
                        MV_KQ28REP,
                        add(
                            add(
                                mul(and(wt, MV_M32), and(wc, MV_L0)),
                                mul(and(shr(32, wt), MV_M32), and(wc, MV_L1))
                            ),
                            add(
                                mul(and(shr(64, wt), MV_M32), and(wc, MV_L2)),
                                mul(and(shr(96, wt), MV_M32), and(wc, MV_L3))
                            )
                        )
                    )
                )
            )
            wc := mload(add(cp, 0x20))
            pd := add(pd, 0x20)
            mstore(
                pd,
                add(
                    mload(pd),
                    sub(
                        MV_KQ28REP,
                        add(
                            add(
                                mul(and(shr(128, wt), MV_M32), and(wc, MV_L0)),
                                mul(and(shr(160, wt), MV_M32), and(wc, MV_L1))
                            ),
                            add(
                                mul(and(shr(192, wt), MV_M32), and(wc, MV_L2)),
                                mul(shr(224, wt), and(wc, MV_L3))
                            )
                        )
                    )
                )
            )
            tPtr := add(tPtr, 0x20)
            cp := add(cp, 0x40)
            pd := add(pd, 0x20)
        }
    }
}

// ---------------------------------------------------------------------------
// (6) matvecRow — the whole A[i].z - c.t1[i] row in TWO passes over the
//     accumulator instead of five.
// ---------------------------------------------------------------------------
// Separate read-modify-write passes over the 64-word accumulator are dominated
// by loop framing and redundant mload/mstore traffic, so the row is computed in
// two fused passes of two A-rows each (fusing all five terms into one pass is
// not possible: it would need >16 live Yul locals and the legacy codegen would
// spill).
//
// Pass 1 WRITES the accumulator (no read — and the buffer is allocated raw, so
// Solidity's zero-fill is skipped; every word is written before any is read);
// pass 2 accumulates the remaining two A-rows and the -c*t1 term.
//
// BOUNDS: identical to macCompactPre/macSubCT1Pre (Z3 obligations O7/O8) —
// four products < (q-1)*(17q-1) plus one term < KQ28, so every lane stays
// < 2^53 (O8's ACC_ENTRY).
function matvecRow(uint256 aRow, uint256[][] memory z, uint256[] memory c, uint256 tPtr)
    pure
    returns (uint256[] memory acc)
{
    assembly ("memory-safe") {
        // raw allocation: pass 1 writes every word, so no zero-fill is needed
        acc := mload(0x40)
        mstore(acc, 64)
        mstore(0x40, add(acc, 0x820))
    }
    assembly ("memory-safe") {
        // ---- pass 1: acc = A[i][0].z0 + A[i][1].z1 (2 A-words / 4 acc
        //      words per iteration: ~47 gas loop tax halved, see GasCalibration)
        let ap := aRow
        let p0 := add(mload(add(z, 0x20)), 0x20)
        let p1 := add(mload(add(z, 0x40)), 0x20)
        let pd := add(acc, 0x20)
        let ae := add(aRow, 0x400)
        for {} lt(ap, ae) {} {
            let wa0 := mload(ap)
            let wa1 := mload(add(ap, 1024))
            let x0 := mload(p0)
            let x1 := mload(p1)
            mstore(
                pd,
                add(
                    add(
                        add(mul(and(wa0, MV_M32), and(x0, MV_L0)), mul(and(shr(32, wa0), MV_M32), and(x0, MV_L1))),
                        add(mul(and(shr(64, wa0), MV_M32), and(x0, MV_L2)), mul(and(shr(96, wa0), MV_M32), and(x0, MV_L3)))
                    ),
                    add(
                        add(mul(and(wa1, MV_M32), and(x1, MV_L0)), mul(and(shr(32, wa1), MV_M32), and(x1, MV_L1))),
                        add(mul(and(shr(64, wa1), MV_M32), and(x1, MV_L2)), mul(and(shr(96, wa1), MV_M32), and(x1, MV_L3)))
                    )
                )
            )
            x0 := mload(add(p0, 0x20))
            x1 := mload(add(p1, 0x20))
            mstore(
                add(pd, 0x20),
                add(
                    add(
                        add(
                            mul(and(shr(128, wa0), MV_M32), and(x0, MV_L0)),
                            mul(and(shr(160, wa0), MV_M32), and(x0, MV_L1))
                        ),
                        add(
                            mul(and(shr(192, wa0), MV_M32), and(x0, MV_L2)),
                            mul(shr(224, wa0), and(x0, MV_L3))
                        )
                    ),
                    add(
                        add(
                            mul(and(shr(128, wa1), MV_M32), and(x1, MV_L0)),
                            mul(and(shr(160, wa1), MV_M32), and(x1, MV_L1))
                        ),
                        add(
                            mul(and(shr(192, wa1), MV_M32), and(x1, MV_L2)),
                            mul(shr(224, wa1), and(x1, MV_L3))
                        )
                    )
                )
            )
            wa0 := mload(add(ap, 0x20))
            wa1 := mload(add(ap, 0x420))
            x0 := mload(add(p0, 0x40))
            x1 := mload(add(p1, 0x40))
            mstore(
                add(pd, 0x40),
                add(
                    add(
                        add(mul(and(wa0, MV_M32), and(x0, MV_L0)), mul(and(shr(32, wa0), MV_M32), and(x0, MV_L1))),
                        add(mul(and(shr(64, wa0), MV_M32), and(x0, MV_L2)), mul(and(shr(96, wa0), MV_M32), and(x0, MV_L3)))
                    ),
                    add(
                        add(mul(and(wa1, MV_M32), and(x1, MV_L0)), mul(and(shr(32, wa1), MV_M32), and(x1, MV_L1))),
                        add(mul(and(shr(64, wa1), MV_M32), and(x1, MV_L2)), mul(and(shr(96, wa1), MV_M32), and(x1, MV_L3)))
                    )
                )
            )
            x0 := mload(add(p0, 0x60))
            x1 := mload(add(p1, 0x60))
            mstore(
                add(pd, 0x60),
                add(
                    add(
                        add(
                            mul(and(shr(128, wa0), MV_M32), and(x0, MV_L0)),
                            mul(and(shr(160, wa0), MV_M32), and(x0, MV_L1))
                        ),
                        add(
                            mul(and(shr(192, wa0), MV_M32), and(x0, MV_L2)),
                            mul(shr(224, wa0), and(x0, MV_L3))
                        )
                    ),
                    add(
                        add(
                            mul(and(shr(128, wa1), MV_M32), and(x1, MV_L0)),
                            mul(and(shr(160, wa1), MV_M32), and(x1, MV_L1))
                        ),
                        add(
                            mul(and(shr(192, wa1), MV_M32), and(x1, MV_L2)),
                            mul(shr(224, wa1), and(x1, MV_L3))
                        )
                    )
                )
            )
            ap := add(ap, 0x40)
            p0 := add(p0, 0x80)
            p1 := add(p1, 0x80)
            pd := add(pd, 0x80)
        }
    }
    assembly ("memory-safe") {
        // ---- pass 2: acc += A[i][2].z2 + A[i][3].z3 + (KQ28 - c.t1[i])
        //      (2 A-words / 4 acc words per iteration, as in pass 1)
        let ap := add(aRow, 2048)
        let p0 := add(mload(add(z, 0x60)), 0x20)
        let p1 := add(mload(add(z, 0x80)), 0x20)
        let cp := add(c, 0x20)
        let pd := add(acc, 0x20)
        let ae := add(aRow, 3072)
        for {} lt(ap, ae) {} {
            let wa0 := mload(ap)
            let wa1 := mload(add(ap, 1024))
            let wt := mload(tPtr)
            {
                let x0 := mload(p0)
                let x1 := mload(p1)
                let x2 := mload(cp)
                mstore(
                    pd,
                    add(
                        add(
                            mload(pd),
                            sub(
                                MV_KQ28REP,
                                add(
                                    add(
                                        mul(and(wt, MV_M32), and(x2, MV_L0)),
                                        mul(and(shr(32, wt), MV_M32), and(x2, MV_L1))
                                    ),
                                    add(
                                        mul(and(shr(64, wt), MV_M32), and(x2, MV_L2)),
                                        mul(and(shr(96, wt), MV_M32), and(x2, MV_L3))
                                    )
                                )
                            )
                        ),
                        add(
                            add(
                                add(
                                    mul(and(wa0, MV_M32), and(x0, MV_L0)),
                                    mul(and(shr(32, wa0), MV_M32), and(x0, MV_L1))
                                ),
                                add(
                                    mul(and(shr(64, wa0), MV_M32), and(x0, MV_L2)),
                                    mul(and(shr(96, wa0), MV_M32), and(x0, MV_L3))
                                )
                            ),
                            add(
                                add(
                                    mul(and(wa1, MV_M32), and(x1, MV_L0)),
                                    mul(and(shr(32, wa1), MV_M32), and(x1, MV_L1))
                                ),
                                add(
                                    mul(and(shr(64, wa1), MV_M32), and(x1, MV_L2)),
                                    mul(and(shr(96, wa1), MV_M32), and(x1, MV_L3))
                                )
                            )
                        )
                    )
                )
            }
            {
                let x0 := mload(add(p0, 0x20))
                let x1 := mload(add(p1, 0x20))
                let x2 := mload(add(cp, 0x20))
                mstore(
                    add(pd, 0x20),
                    add(
                        add(
                            mload(add(pd, 0x20)),
                            sub(
                                MV_KQ28REP,
                                add(
                                    add(
                                        mul(and(shr(128, wt), MV_M32), and(x2, MV_L0)),
                                        mul(and(shr(160, wt), MV_M32), and(x2, MV_L1))
                                    ),
                                    add(
                                        mul(and(shr(192, wt), MV_M32), and(x2, MV_L2)),
                                        mul(shr(224, wt), and(x2, MV_L3))
                                    )
                                )
                            )
                        ),
                        add(
                            add(
                                add(
                                    mul(and(shr(128, wa0), MV_M32), and(x0, MV_L0)),
                                    mul(and(shr(160, wa0), MV_M32), and(x0, MV_L1))
                                ),
                                add(
                                    mul(and(shr(192, wa0), MV_M32), and(x0, MV_L2)),
                                    mul(shr(224, wa0), and(x0, MV_L3))
                                )
                            ),
                            add(
                                add(
                                    mul(and(shr(128, wa1), MV_M32), and(x1, MV_L0)),
                                    mul(and(shr(160, wa1), MV_M32), and(x1, MV_L1))
                                ),
                                add(
                                    mul(and(shr(192, wa1), MV_M32), and(x1, MV_L2)),
                                    mul(shr(224, wa1), and(x1, MV_L3))
                                )
                            )
                        )
                    )
                )
            }
            wa0 := mload(add(ap, 0x20))
            wa1 := mload(add(ap, 0x420))
            wt := mload(add(tPtr, 0x20))
            {
                let x0 := mload(add(p0, 0x40))
                let x1 := mload(add(p1, 0x40))
                let x2 := mload(add(cp, 0x40))
                mstore(
                    add(pd, 0x40),
                    add(
                        add(
                            mload(add(pd, 0x40)),
                            sub(
                                MV_KQ28REP,
                                add(
                                    add(
                                        mul(and(wt, MV_M32), and(x2, MV_L0)),
                                        mul(and(shr(32, wt), MV_M32), and(x2, MV_L1))
                                    ),
                                    add(
                                        mul(and(shr(64, wt), MV_M32), and(x2, MV_L2)),
                                        mul(and(shr(96, wt), MV_M32), and(x2, MV_L3))
                                    )
                                )
                            )
                        ),
                        add(
                            add(
                                add(
                                    mul(and(wa0, MV_M32), and(x0, MV_L0)),
                                    mul(and(shr(32, wa0), MV_M32), and(x0, MV_L1))
                                ),
                                add(
                                    mul(and(shr(64, wa0), MV_M32), and(x0, MV_L2)),
                                    mul(and(shr(96, wa0), MV_M32), and(x0, MV_L3))
                                )
                            ),
                            add(
                                add(
                                    mul(and(wa1, MV_M32), and(x1, MV_L0)),
                                    mul(and(shr(32, wa1), MV_M32), and(x1, MV_L1))
                                ),
                                add(
                                    mul(and(shr(64, wa1), MV_M32), and(x1, MV_L2)),
                                    mul(and(shr(96, wa1), MV_M32), and(x1, MV_L3))
                                )
                            )
                        )
                    )
                )
            }
            {
                let x0 := mload(add(p0, 0x60))
                let x1 := mload(add(p1, 0x60))
                let x2 := mload(add(cp, 0x60))
                mstore(
                    add(pd, 0x60),
                    add(
                        add(
                            mload(add(pd, 0x60)),
                            sub(
                                MV_KQ28REP,
                                add(
                                    add(
                                        mul(and(shr(128, wt), MV_M32), and(x2, MV_L0)),
                                        mul(and(shr(160, wt), MV_M32), and(x2, MV_L1))
                                    ),
                                    add(
                                        mul(and(shr(192, wt), MV_M32), and(x2, MV_L2)),
                                        mul(shr(224, wt), and(x2, MV_L3))
                                    )
                                )
                            )
                        ),
                        add(
                            add(
                                add(
                                    mul(and(shr(128, wa0), MV_M32), and(x0, MV_L0)),
                                    mul(and(shr(160, wa0), MV_M32), and(x0, MV_L1))
                                ),
                                add(
                                    mul(and(shr(192, wa0), MV_M32), and(x0, MV_L2)),
                                    mul(shr(224, wa0), and(x0, MV_L3))
                                )
                            ),
                            add(
                                add(
                                    mul(and(shr(128, wa1), MV_M32), and(x1, MV_L0)),
                                    mul(and(shr(160, wa1), MV_M32), and(x1, MV_L1))
                                ),
                                add(
                                    mul(and(shr(192, wa1), MV_M32), and(x1, MV_L2)),
                                    mul(shr(224, wa1), and(x1, MV_L3))
                                )
                            )
                        )
                    )
                )
            }
            ap := add(ap, 0x40)
            tPtr := add(tPtr, 0x40)
            p0 := add(p0, 0x80)
            p1 := add(p1, 0x80)
            cp := add(cp, 0x80)
            pd := add(pd, 0x80)
        }
    }
}


// ---------------------------------------------------------------------------
// (7) unpackHFast — HintBitUnpack (FIPS 204 Algorithm 21)
// ---------------------------------------------------------------------------
// Parses the 84-byte hint region of the signature into four 256-bit masks
// (bit j of masks[i] = hint bit for coefficient j of polynomial i), enforcing
// ALL of the algorithm's validity conditions: per-polynomial index lists
// strictly increasing, cut positions non-decreasing and <= omega, and every
// unused index byte zero.  Any violation returns ok = false (the caller
// rejects), so exactly one encoding is accepted per hint set — Z3 obligations
// E12/E13 prove uniqueness and canonicality of the accepted encoding.
function unpackHFast(bytes memory hBytes)
    pure
    returns (bool ok, uint256[4] memory masks, uint256 weight)
{
    assembly ("memory-safe") {
        // Fail closed on a short encoding: every check below reads bytes 0..83
        // unconditionally, so nothing shorter is decodable. The shipped call
        // site passes exactly the 84 bytes sig[2336:2420]. `ok` stays false and
        // `weight` stays 0 for anything shorter, and no load leaves the object.
        if iszero(lt(mload(hBytes), 84)) {
            let d := add(hBytes, 32)
            // byte j is read as the LOW byte of the word at dm31 + j, i.e. from
            // the 32 bytes ENDING at byte j; for j = 0 that word starts inside
            // this object's own length field. Reading at d + j instead would
            // reach 31 bytes PAST byte j and leave the object at the tail.
            let dm31 := add(hBytes, 1)
            let bad := 0

            // the four cut counters y[80..83], from the word at d+52 = region
            // bytes 52..83, i.e. the LAST 32 bytes of the 84-byte region, so
            // the load stays inside it. byte 28 is y[80] ... byte 31 is y[83].
            let cw := mload(add(d, 52))
            let c0 := byte(28, cw)
            let c1 := byte(29, cw)
            let c2 := byte(30, cw)
            let c3 := byte(31, cw)

            // FIPS 204 Alg. 21 line 4, first disjunct: the cut counters are
            // non-decreasing (y[w+i] >= y[w+i-1], with y[w-1] = 0, which the
            // unsigned byte c0 satisfies for free).
            bad := or(bad, or(or(gt(c0, c1), gt(c1, c2)), gt(c2, c3)))
            // FIPS 204 Alg. 21 line 4, second disjunct: no counter exceeds
            // omega = 80. With the counters non-decreasing, bounding the LAST
            // one bounds every one of them, and the accepted total weight is
            // exactly y[83] <= omega.
            bad := or(bad, gt(c3, 80))

            // FIPS 204 Alg. 21 lines 16-18: every UNUSED index byte is zero.
            // Branchless: shifting the index bytes left by 8*y[83] bits drops
            // the used prefix and leaves exactly the padding, so the padding is
            // all-zero iff the three shifted words are. An EVM shift of 256 or
            // more yields 0, which is exactly "this word holds no padding".
            // w2 carries index bytes 64..79 in its HIGH 16 bytes.
            {
                let w0 := mload(d) // index bytes 0..31
                let w1 := mload(add(d, 32)) // index bytes 32..63
                let w2 := shl(128, mload(add(d, 48))) // index bytes 64..79
                let s1 := mul(gt(c3, 32), sub(c3, 32))
                let s2 := mul(gt(c3, 64), sub(c3, 64))
                let pad :=
                    or(or(shl(shl(3, c3), w0), shl(shl(3, s1), w1)), shl(shl(3, s2), w2))
                bad := or(bad, iszero(iszero(pad)))
            }

            // index scan, one polynomial at a time
            let mp := masks
            let kIdx := 0
            for { let i := 0 } lt(i, 4) { i := add(i, 1) } {
                let cut := byte(add(28, i), cw)
                // SCAN BOUND. The two counter checks above already reject every
                // encoding whose counters run backwards or exceed omega, so on
                // an ACCEPTED encoding this clamp is the identity. It is here
                // so that the scan provably cannot read outside the 80 index
                // bytes on a REJECTED one either.
                cut := sub(cut, mul(sub(cut, 80), gt(cut, 80)))
                let m := 0
                // prevP = (previous index) + 1, reset to 0 at each row start,
                // so the FIRST index of a row is unconstrained (index 0 is
                // legal) and `First <- Index` resets per polynomial.
                let prevP := 0
                for { let j := kIdx } lt(j, cut) { j := add(j, 1) } {
                    let idx := and(mload(add(dm31, j)), 0xff)
                    // FIPS 204 Alg. 21 line 12: indices STRICTLY increasing
                    // inside one polynomial. idx < prevP <=> idx <= previous.
                    bad := or(bad, lt(idx, prevP))
                    prevP := add(idx, 1)
                    m := or(m, shl(idx, 1))
                }
                mstore(mp, m)
                mp := add(mp, 32)
                kIdx := cut
            }

            ok := iszero(bad)
            // a rejected encoding reports weight 0, as before
            weight := mul(c3, ok)
        }
    }
}
