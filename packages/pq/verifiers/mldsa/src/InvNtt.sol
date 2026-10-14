// SPDX-License-Identifier: MIT
// InvNtt.sol — packed-SWAR inverse NTT (FIPS 204 Alg. 42)
//
// Inverse NTT over the same packed layout (nttInvV3) + (un)packing helpers.
// The matvec accumulator's reduction is FOLDED INTO the fused layer-1/2 block:
// input lanes are the verifier's raw lazy-accumulator values (<= ACC_ENTRY =
// 4(q-1)(17q-1) + q*2^28 < 2^53, Z3 obligation O8). Layers 1 and 2 are in-word, so
// their lanes are extracted to scalars anyway; on scalars the EVM's native
// mulmod/mod has no domain restriction, so the raw lanes are consumed directly
// with multiple-of-q offsets (ACCQ30/ACCQ31) and every lane exits the block
// < 2q (S14). Sum-lanes double per layer from there (bounded by 256q < 2^31);
// twiddle products are reduced over the extended inverse domain
// 128q(q-1) < 2^53 by the TWO-STEP LANE-LOCAL BARRETT of src/Ntt.sol (coarse
// step MU33 = floor(2^33/q) = 1025, then the unit step floor(2^23/q) == 1; the
// widest intermediate is 128q(q-1)*MU33 < 2^63, so all four lanes reduce in
// place with no spreading), and the final layer folds the n^-1 scaling and
// canonicalisation (mod, not Barrett) into one pass, so outputs are canonical
// (< q) — the precondition useHintSwar relies on. The eight layers run as FOUR
// passes: the in-word entry fold + L1+L2, then RADIX-4 FUSED L3+L4 and L5+L6
// (one quad of words loaded once, both layers on the stack, one store), then
// the fused L7+L8+scale. Fusion is a SCHEDULING change only — a fused block's
// second layer consumes the first layer's outputs (sums < 2Kq, diffs < 2q), so
// its K*q offset still dominates and every Barrett product stays inside the
// verified domain. Machine-checked by Z3
// obligations C9c/C9d/C9g, C11b, S6/S6b/S14 and the Lean theorems in
// formal/lean/Mldsa/Barrett.lean; C16 extracts the fused pass structure from
// this file's Yul.
pragma solidity ^0.8.25;

uint256 constant Q = 8380417; // Dilithium prime, 23 bits
uint256 constant MU33 = 1025; // floor(2^33 / Q), the coarse Barrett constant
// qhat mask, 31 bits per 64-bit lane. After shr(33, mul(w, MU33)) the NEXT
// lane's bits begin at bit 31 of this lane, and a lane's qhat is < 2^31 exactly
// when its own product is < 2^64 -- so ONE mask both extracts the quotient and
// stops a lane from seeing its neighbour. The second step reuses it: its
// quotient is < 2^10 and its neighbour's bits begin at bit 41.
uint256 constant QHATM31 = 0x000000007fffffff000000007fffffff000000007fffffff000000007fffffff;
uint256 constant NINV = 8347681; // n^{-1} mod q (== N_MINUS_1_MOD_Q)
uint256 constant S8P = 0xb662; // psirev_inv[1] * NINV mod q (folded L8 twiddle)
uint256 constant LANE = 0xffffffffffffffff; // 64-bit lane mask
uint256 constant TWOQ = 0xffc002; // 2q (scalar offsets, in-word layers)
// q*2^30 and q*2^31: multiple-of-q offsets that dominate one / two raw
// accumulator lanes (ACC_ENTRY <= q*2^30, 2*ACC_ENTRY <= q*2^31), so the
// layer-1/2 mulmod operands never borrow (S14)
uint256 constant ACCQ30 = 0x1ff80040000000; // q << 30
uint256 constant ACCQ31 = 0x3ff00080000000; // q << 31
// K*q replicated in four 64-bit lanes: nonnegative-offset constants per layer
uint256 constant TWOQ4 = 0x0000000000ffc0020000000000ffc0020000000000ffc0020000000000ffc002;
uint256 constant Q4_4 = 0x0000000001ff80040000000001ff80040000000001ff80040000000001ff8004;
uint256 constant Q4_8 = 0x0000000003ff00080000000003ff00080000000003ff00080000000003ff0008;
uint256 constant Q4_16 = 0x0000000007fe00100000000007fe00100000000007fe00100000000007fe0010;
uint256 constant Q4_32 = 0x000000000ffc0020000000000ffc0020000000000ffc0020000000000ffc0020;
uint256 constant Q4_64 = 0x000000001ff80040000000001ff80040000000001ff80040000000001ff80040;
uint256 constant Q4_128 = 0x000000003ff00080000000003ff00080000000003ff00080000000003ff00080;

// ---------------------------------------------------------------------------
// The inverse twiddle table, materialised ONCE per verify() instead of once per
// transform.  It is a 1,024-byte constant, and building it inside nttInvV3 meant
// building it FOUR times (one per matvec row) and leaking 4 KB of memory that is
// never read again: measured at ~800 gas of stores per call plus the quadratic
// expansion the leak carries into every later allocation.  The table is now a
// parameter; `add(psirev, 0x20*k)` inside the transform addresses exactly the
// same words it always did, so not one line of the transform's Yul moves.
// C16 sees this: the twiddle literals stay inside the FILE digest, and the
// transform's head region stays INERT (it no longer holds the table at all).
// ---------------------------------------------------------------------------
function nttInvTable() pure returns (uint256 tbl) {
    // inverse twiddle table, identical to test/vendor/ZKNOX_NTT_dilithium.sol:nttInv
    // (8 twiddles per word, 32-bit fields; index j = word j>>3, field j&7).
    // Word 0 fields 1..7 are consumed as hardcoded literals in L6..L8 below.
    uint256[32] memory psirev = [
        uint256(0x30d9d6002c008e002fffce0030d99600466a9a00467a98003681ff00000001),
        0x92e530049d22c0056f251005f601d00466d7e000f56b700775e6f0012a239,
        0x3140e40065b78a005a6e22006996130009ce440036b44a0054e96a005d072c,
        0x336d6d003dff4d00573c2f00198d770035c75a00069fcd00758d1300146280,
        0x2c35a2004f29df007760c90044d19400535c2700639693004cd1d600638491,
        0x4bc3e40065078e000c798000368ac200468d0b001d89b7001a32fc003c45e5,
        0x79dc5d0071b414006f28d5003580cc006042ec003d532d004e680d005ef9ef,
        0x48e8d7004f4ee300560ec20036b98e002f77a2005fcf5f0047580a006e2d3e,
        0x7a8d75000500a8007071ea0023ec27003a4483001d54cd0022213600654186,
        0x6b2d61002a5acb0056ee7b002a66a40034e991005c957b0009f7db0007019b,
        0x141b2e005a513600518cb500766595004457e10012b7a500533b09004c6357,
        0x275b35006497da00247c3100226787004abda3003fd3830013d63000240acf,
        0x3f931900353a7f00618b1b0030c94000656188007c4872003197ea004e27a8,
        0x688eff007882a8006e5847002d33580008a163007d4929005a4d150032e0ef,
        0x59974d0060edab00624f5f003a392d0054fa66002d87650010ee0c00406d79,
        0x50fc10006c6148002836d10045191200400ab500312d17002fa12000042e8c,
        0x49f9d0049fe24003ca555003995230062e1ed000bee33006fc8f3000b292a,
        0x21577c005035cf005be39c002176bf002dff14001a324e00533a1b0005fe03,
        0x507ceb0010d5f000781f10000872f60072c011004b87dd007dbc2d00171aa8,
        0x42ebd200002e670014e9950051c998004c8d2b007c98a100778da1000bc189,
        0x4322ca0058acce0018a6aa006594a4006676db0060edfb006e1eb300336939,
        0x2e4a8e000529f4005778470051f32d0027de750040930c00746ff8003d61de,
        0x168979006172c30059dc440015420700781fea0012202d000b0f44001bfe1e,
        0x18c53a005fc03b00243b02001f088f0076ee000011ffdd0077d1940029dc73,
        0x6fff4001d53ca004239fd0034fac50060c299001caf46000c7e4900213f95,
        0x522036007db5f600015cd5005987870014ac8c0076848b0013fe350021d9e3,
        0x46b24f005cd6de006cf49a003a920f004f1ce500578bdd006cbcd300003081,
        0x3f4458001b0c2c005e69d7001a5a70005b71c800371c66000418a8003087a8,
        0x19b6a100340a88005701fb0039827400362f1e00762bcd0003d24e00257751,
        0x6ca4007352f40070792c00257281001e34690067826b003c60d000395d69,
        0x6dd5de007e8b5900762802003c817a003c600900230a4d00321fb30038b752,
        0x7fd928001d883c002894c500163712005747c9001b2a030000e70c00559189
    ];
    // the transform addresses the table by raw pointer, so passing it costs
    // nothing: a `uint256[32] memory` parameter would be COPIED on every
    // internal call (32 words x 9 transforms, measured +1,795 gas).
    assembly ("memory-safe") {
        tbl := psirev
    }
}

// ---------------------------------------------------------------------------
// Packed SWAR inverse NTT with the accumulator reduction folded into layer 1.
// Input: 64 words, 4 coefficients per word in 64-bit lanes, every lane
// <= ACC_ENTRY = 4(q-1)(17q-1) + q*2^28 < 2^53 (raw matvec accumulator lanes, or
// anything smaller — canonical input is the special case). Output: same
// packing, canonical (< q), equal coefficient-wise to nttInv of the input
// reduced mod q (n^{-1} scaling included).
// prof: >= 5 words; prof[0] = gas() at start, then a snapshot after each of
// the FOUR passes (entry fold + L1+L2, L3+L4, L5+L6, L7+L8+scale). These
// markers are the CODE anchors Z3 obligation C16 slices its layer blocks on.
// ---------------------------------------------------------------------------
function nttInvV3(uint256[] memory a, uint256[] memory prof, uint256 psirev)
    view
    returns (uint256[] memory)
{
    assembly ("memory-safe") {
        let B := add(a, 0x20)
        let PR := add(prof, 0x20)
        mstore(PR, gas())

        // ---- Layers 1+2 fused (in-word), with the matvec accumulator's
        //      reduction FOLDED IN. Input lanes are raw lazy-accumulator
        //      values (<= ACC_ENTRY < 2^53, O8/C9g). These two layers are
        //      in-word butterflies, so the lanes are extracted to scalars
        //      anyway — and on scalars the EVM's native mulmod/mod (which has
        //      no domain restriction at all) is cheaper than any Barrett
        //      plumbing, so the raw lanes are consumed DIRECTLY:
        //      L1 t=1: pairs (u0,u1) with Sa and (u2,u3) with Sb (h=128,
        //      twiddles idx 128+2w, 129+2w: table words 16..31, two per data
        //      word); the difference operand is offset by ACCQ30 = q*2^30
        //      >= ACC_ENTRY (multiple of q, so the residue is unchanged and
        //      the subtraction never borrows) and reduced by mulmod, so the
        //      L1 difference lanes are canonical; the L1 sum lanes stay raw
        //      (<= 2*ACC_ENTRY < 2^54).
        //      L2 t=2: pairs (s01,s23) and (d01,d23) share Sc (h=64, idx
        //      64+w: words 8..15, one per data word); the sum-side difference
        //      operand is offset by ACCQ31 = q*2^31 >= 2*ACC_ENTRY and both
        //      differences are reduced by mulmod (canonical); the sum-sum
        //      lane is canonicalised with addmod and the diff-sum lane is the
        //      sum of two canonical lanes (< 2q). Every lane therefore exits
        //      < 2q — inside the < 4q entry bound layer 3's Q4_4 offset
        //      assumes (S14 -> S6/C9g linkage).
        //      FOUR data words straight-line per iteration: one w1 table word
        //      (8 fields = 2 L1 twiddles x 4 words) and half a w2 word are
        //      consumed per pass, which removes an entire loop level (the
        //      measured ~50-gas EVM loop tax, test/GasCalibration.t.sol).
        {
            let tp1 := add(psirev, 0x200)
            let tp2 := add(psirev, 0x100)
            let p := B
            for { let i8 := 0 } lt(i8, 8) { i8 := add(i8, 1) } {
                let w2 := mload(tp2)
                tp2 := add(tp2, 0x20)
                for { let h := 0 } lt(h, 2) { h := add(h, 1) } {
                    let w1 := mload(tp1)
                    tp1 := add(tp1, 0x20)
                    let x := mload(p)
                    let u0 := and(x, LANE)
                    let u1 := and(shr(64, x), LANE)
                    let s01 := add(u0, u1)
                    let d01 := mulmod(sub(add(u0, ACCQ30), u1), and(w1, 0xffffffff), Q)
                    let s23 := add(and(shr(128, x), LANE), shr(192, x))
                    let d23 := mulmod(sub(add(and(shr(128, x), LANE), ACCQ30), shr(192, x)), and(shr(32, w1), 0xffffffff), Q)
                    let Sc := and(w2, 0xffffffff)
                    mstore(
                        p,
                        or(
                            or(
                                addmod(s01, s23, Q),
                                shl(64, add(d01, d23))
                            ),
                            or(
                                shl(128, mulmod(sub(add(s01, ACCQ31), s23), Sc, Q)),
                                shl(192, mulmod(sub(add(d01, TWOQ), d23), Sc, Q))
                            )
                        )
                    )
                    x := mload(add(p, 0x20))
                    u0 := and(x, LANE)
                    u1 := and(shr(64, x), LANE)
                    s01 := add(u0, u1)
                    d01 := mulmod(sub(add(u0, ACCQ30), u1), and(shr(64, w1), 0xffffffff), Q)
                    s23 := add(and(shr(128, x), LANE), shr(192, x))
                    d23 := mulmod(sub(add(and(shr(128, x), LANE), ACCQ30), shr(192, x)), and(shr(96, w1), 0xffffffff), Q)
                    Sc := and(shr(32, w2), 0xffffffff)
                    mstore(
                        add(p, 0x20),
                        or(
                            or(
                                addmod(s01, s23, Q),
                                shl(64, add(d01, d23))
                            ),
                            or(
                                shl(128, mulmod(sub(add(s01, ACCQ31), s23), Sc, Q)),
                                shl(192, mulmod(sub(add(d01, TWOQ), d23), Sc, Q))
                            )
                        )
                    )
                    x := mload(add(p, 0x40))
                    u0 := and(x, LANE)
                    u1 := and(shr(64, x), LANE)
                    s01 := add(u0, u1)
                    d01 := mulmod(sub(add(u0, ACCQ30), u1), and(shr(128, w1), 0xffffffff), Q)
                    s23 := add(and(shr(128, x), LANE), shr(192, x))
                    d23 := mulmod(sub(add(and(shr(128, x), LANE), ACCQ30), shr(192, x)), and(shr(160, w1), 0xffffffff), Q)
                    Sc := and(shr(64, w2), 0xffffffff)
                    mstore(
                        add(p, 0x40),
                        or(
                            or(
                                addmod(s01, s23, Q),
                                shl(64, add(d01, d23))
                            ),
                            or(
                                shl(128, mulmod(sub(add(s01, ACCQ31), s23), Sc, Q)),
                                shl(192, mulmod(sub(add(d01, TWOQ), d23), Sc, Q))
                            )
                        )
                    )
                    x := mload(add(p, 0x60))
                    u0 := and(x, LANE)
                    u1 := and(shr(64, x), LANE)
                    s01 := add(u0, u1)
                    d01 := mulmod(sub(add(u0, ACCQ30), u1), and(shr(192, w1), 0xffffffff), Q)
                    s23 := add(and(shr(128, x), LANE), shr(192, x))
                    d23 := mulmod(sub(add(and(shr(128, x), LANE), ACCQ30), shr(192, x)), shr(224, w1), Q)
                    Sc := and(shr(96, w2), 0xffffffff)
                    mstore(
                        add(p, 0x60),
                        or(
                            or(
                                addmod(s01, s23, Q),
                                shl(64, add(d01, d23))
                            ),
                            or(
                                shl(128, mulmod(sub(add(s01, ACCQ31), s23), Sc, Q)),
                                shl(192, mulmod(sub(add(d01, TWOQ), d23), Sc, Q))
                            )
                        )
                    )
                    w2 := shr(128, w2)
                    p := add(p, 0x80)
                }
            }
        }
        mstore(add(PR, 0x20), gas())

        // ---- Layers 3+4 fused (radix-4): one quad of 4 CONSECUTIVE words is
        //      loaded once and both GS layers run on the stack (4 loads +
        //      4 stores per 4 butterflies instead of 8 + 8).
        //      L3 (t=4, word stride 1, K=4, Q4_4) pairs (w, w+1) with
        //      psirev_inv[32+2i] and (w+2, w+3) with psirev_inv[32+2i+1];
        //      L4 (t=8, word stride 2, K=8, Q4_8) then pairs the two L3 SUM
        //      lanes and the two L3 DIFF lanes, both with psirev_inv[16+i].
        //      Entry bounds are unchanged by the fusion: L4's operands are L3's
        //      outputs -- sums < 8q, diffs < 2q -- so the Q4_8 offset still
        //      dominates and every product stays inside the verified Barrett
        //      domain (S6/C9d/C9g).
        {
            let tp3 := add(psirev, 0x80)
            let tp4 := add(psirev, 0x40)
            let pq := B
            for { let wi := 0 } lt(wi, 2) { wi := add(wi, 1) } {
                let w4 := mload(tp4)
                tp4 := add(tp4, 0x20)
                for { let k := 0 } lt(k, 2) { k := add(k, 1) } {
                    let w3 := mload(tp3)
                    tp3 := add(tp3, 0x20)
                    for { let j := 0 } lt(j, 4) { j := add(j, 1) } {
                        let S3a := and(w3, 0xffffffff)
                        let S3b := and(shr(32, w3), 0xffffffff)
                        w3 := shr(64, w3)
                        let S4 := and(w4, 0xffffffff)
                        w4 := shr(32, w4)
                        let u0 := mload(pq)
                        let u1 := mload(add(pq, 0x20))
                        let s0 := add(u0, u1)
                        let d0 := mul(sub(add(u0, Q4_4), u1), S3a)
                        d0 := sub(d0, mul(and(shr(33, mul(d0, MU33)), QHATM31), Q))
                        d0 := sub(d0, mul(and(shr(23, d0), QHATM31), Q))
                        let u2 := mload(add(pq, 0x40))
                        let u3 := mload(add(pq, 0x60))
                        let s1 := add(u2, u3)
                        let d1 := mul(sub(add(u2, Q4_4), u3), S3b)
                        d1 := sub(d1, mul(and(shr(33, mul(d1, MU33)), QHATM31), Q))
                        d1 := sub(d1, mul(and(shr(23, d1), QHATM31), Q))
                        mstore(pq, add(s0, s1))
                        mstore(add(pq, 0x20), add(d0, d1))
                        let t0 := mul(sub(add(s0, Q4_8), s1), S4)
                        t0 := sub(t0, mul(and(shr(33, mul(t0, MU33)), QHATM31), Q))
                        t0 := sub(t0, mul(and(shr(23, t0), QHATM31), Q))
                        mstore(add(pq, 0x40), t0)
                        t0 := mul(sub(add(d0, Q4_8), d1), S4)
                        t0 := sub(t0, mul(and(shr(33, mul(t0, MU33)), QHATM31), Q))
                        t0 := sub(t0, mul(and(shr(23, t0), QHATM31), Q))
                        mstore(add(pq, 0x60), t0)
                        pq := add(pq, 0x80)
                    }
                }
            }
        }
        mstore(add(PR, 0x40), gas())

        // ---- Layers 5+6 fused (radix-4): quad (w, w+4, w+8, w+12) inside each
        //      16-word layer-6 group g. L5 (t=16, word stride 4, K=16, Q4_16)
        //      pairs (w, w+4) with psirev_inv[8+2g] and (w+8, w+12) with
        //      psirev_inv[8+2g+1]; L6 (t=32, word stride 8, K=32, Q4_32) then
        //      pairs the two sum lanes and the two diff lanes with
        //      psirev_inv[4+g]. Same argument as above: L6's operands are L5's
        //      outputs (sums < 32q, diffs < 2q), so Q4_32 still dominates.
        {
            let w5 := mload(add(psirev, 0x20))
            let w6 := 0x30d9d6002c008e002fffce0030d996
            let gp := B
            for { let g := 0 } lt(g, 4) { g := add(g, 1) } {
                let S5a := and(w5, 0xffffffff)
                let S5b := and(shr(32, w5), 0xffffffff)
                w5 := shr(64, w5)
                let S6 := and(w6, 0xffffffff)
                w6 := shr(32, w6)
                let pq := gp
                let pe := add(gp, 0x80)
                for {} lt(pq, pe) { pq := add(pq, 0x20) } {
                    let u0 := mload(pq)
                    let u1 := mload(add(pq, 0x80))
                    let s0 := add(u0, u1)
                    let d0 := mul(sub(add(u0, Q4_16), u1), S5a)
                    d0 := sub(d0, mul(and(shr(33, mul(d0, MU33)), QHATM31), Q))
                    d0 := sub(d0, mul(and(shr(23, d0), QHATM31), Q))
                    let u2 := mload(add(pq, 0x100))
                    let u3 := mload(add(pq, 0x180))
                    let s1 := add(u2, u3)
                    let d1 := mul(sub(add(u2, Q4_16), u3), S5b)
                    d1 := sub(d1, mul(and(shr(33, mul(d1, MU33)), QHATM31), Q))
                    d1 := sub(d1, mul(and(shr(23, d1), QHATM31), Q))
                    mstore(pq, add(s0, s1))
                    mstore(add(pq, 0x80), add(d0, d1))
                    let t0 := mul(sub(add(s0, Q4_32), s1), S6)
                    t0 := sub(t0, mul(and(shr(33, mul(t0, MU33)), QHATM31), Q))
                    t0 := sub(t0, mul(and(shr(23, t0), QHATM31), Q))
                    mstore(add(pq, 0x100), t0)
                    t0 := mul(sub(add(d0, Q4_32), d1), S6)
                    t0 := sub(t0, mul(and(shr(33, mul(t0, MU33)), QHATM31), Q))
                    t0 := sub(t0, mul(and(shr(23, t0), QHATM31), Q))
                    mstore(add(pq, 0x180), t0)
                }
                gp := add(gp, 0x200)
            }
        }
        mstore(add(PR, 0x60), gas())

        // ---- Layers 7+8 fused, n^{-1} scaling and canonicalization folded in.
        //      L7 (t=64, h=2): word w pairs w+16 with S7a = idx2 = 0x467a98,
        //      word w+32 pairs w+48 with S7b = idx3 = 0x466a9a; inputs < 64q,
        //      K=64, two-step Barrett -> diffs < 2q, sums < 128q.
        //      L8 (t=128, h=1): (sAB,sCD) and (dAB,dCD); sums get one shared
        //      NINV multiply, diffs use the folded twiddle S8P = idx1*NINV;
        //      all per-lane values < 256q * q < 2^55, canonicalized with mod.
        {
            let pA := B
            let pB := add(B, 0x200)
            let pC := add(B, 0x400)
            let pD := add(B, 0x600)
            for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                let A := mload(pA)
                let Bw := mload(pB)
                let C := mload(pC)
                let D := mload(pD)
                // L7 on (A,Bw) with S7a
                let sAB := add(A, Bw)
                let t0 := mul(sub(add(A, Q4_64), Bw), 0x467a98)
                t0 := sub(t0, mul(and(shr(33, mul(t0, MU33)), QHATM31), Q))
                let dAB := sub(t0, mul(and(shr(23, t0), QHATM31), Q))
                // L7 on (C,D) with S7b
                let sCD := add(C, D)
                t0 := mul(sub(add(C, Q4_64), D), 0x466a9a)
                t0 := sub(t0, mul(and(shr(33, mul(t0, MU33)), QHATM31), Q))
                let dCD := sub(t0, mul(and(shr(23, t0), QHATM31), Q))
                // L8 + scaling: out[w] = (sAB+sCD)*NINV, out[w+32] = (sAB-sCD)*S8P,
                // out[w+16] = (dAB+dCD)*NINV, out[w+48] = (dAB-dCD)*S8P, all mod q.
                t0 := mul(add(sAB, sCD), NINV)
                mstore(
                    pA,
                    or(
                        or(mod(and(t0, LANE), Q), shl(64, mod(and(shr(64, t0), LANE), Q))),
                        or(shl(128, mod(and(shr(128, t0), LANE), Q)), shl(192, mod(shr(192, t0), Q)))
                    )
                )
                t0 := mul(sub(add(sAB, Q4_128), sCD), S8P)
                mstore(
                    pC,
                    or(
                        or(mod(and(t0, LANE), Q), shl(64, mod(and(shr(64, t0), LANE), Q))),
                        or(shl(128, mod(and(shr(128, t0), LANE), Q)), shl(192, mod(shr(192, t0), Q)))
                    )
                )
                t0 := mul(add(dAB, dCD), NINV)
                mstore(
                    pB,
                    or(
                        or(mod(and(t0, LANE), Q), shl(64, mod(and(shr(64, t0), LANE), Q))),
                        or(shl(128, mod(and(shr(128, t0), LANE), Q)), shl(192, mod(shr(192, t0), Q)))
                    )
                )
                t0 := mul(sub(add(dAB, TWOQ4), dCD), S8P)
                mstore(
                    pD,
                    or(
                        or(mod(and(t0, LANE), Q), shl(64, mod(and(shr(64, t0), LANE), Q))),
                        or(shl(128, mod(and(shr(128, t0), LANE), Q)), shl(192, mod(shr(192, t0), Q)))
                    )
                )
                pA := add(pA, 0x20)
                pB := add(pB, 0x20)
                pC := add(pC, 0x20)
                pD := add(pD, 0x20)
            }
        }
        mstore(add(PR, 0x80), gas())
    }
    return a;
}

// ---------------------------------------------------------------------------
// Scalar lazy reduction used by nttInvV3, exposed for direct verification: for
// x <= 128q(q-1) < 2^53 (the worst product in any inverse layer, at L7) returns
// r with r = x (mod q), 0 <= r < 2q. TWO Barrett steps, both LANE-LOCAL -- the
// widest intermediate is 128q(q-1)*MU33 < 2^63, half a bit-width to spare --
// which is what lets the packed form reduce all four 64-bit lanes with the same
// four opcodes and no spreading:
//   step 1   x1 := x  - Q*floor(x  * MU33 / 2^33)    MU33 = floor(2^33/Q) = 1025
//   step 2   r  := x1 - Q*floor(x1        / 2^23)    floor(2^23/Q) == 1, elided
// ---------------------------------------------------------------------------
function invLazyBarrett(uint256 x) pure returns (uint256 r) {
    assembly ("memory-safe") {
        r := sub(x, mul(shr(33, mul(x, MU33)), Q))
        r := sub(r, mul(shr(23, r), Q))
    }
}

// ---------------------------------------------------------------------------
// Layout converters, identical to the forward's (kept local so this file has
// no dependency on files owned by other work streams).
// ---------------------------------------------------------------------------
function ipackCoeffs(uint256[] memory a) pure returns (uint256[] memory w) {
    w = new uint256[](64);
    assembly ("memory-safe") {
        let pa := add(a, 0x20)
        let pw := add(w, 0x20)
        let pe := add(pa, 0x2000)
        for {} lt(pa, pe) {} {
            mstore(
                pw,
                or(
                    or(mload(pa), shl(64, mload(add(pa, 0x20)))),
                    or(shl(128, mload(add(pa, 0x40))), shl(192, mload(add(pa, 0x60))))
                )
            )
            pa := add(pa, 0x80)
            pw := add(pw, 0x20)
        }
    }
}

function iunpackCoeffs(uint256[] memory w) pure returns (uint256[] memory a) {
    a = new uint256[](256);
    assembly ("memory-safe") {
        let pw := add(w, 0x20)
        let pa := add(a, 0x20)
        let pe := add(pw, 0x800)
        for {} lt(pw, pe) {} {
            let x := mload(pw)
            mstore(pa, and(x, LANE))
            mstore(add(pa, 0x20), and(shr(64, x), LANE))
            mstore(add(pa, 0x40), and(shr(128, x), LANE))
            mstore(add(pa, 0x60), shr(192, x))
            pw := add(pw, 0x20)
            pa := add(pa, 0x80)
        }
    }
}
