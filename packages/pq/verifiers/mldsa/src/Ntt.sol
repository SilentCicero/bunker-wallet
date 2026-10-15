// SPDX-License-Identifier: MIT
// Ntt.sol — packed-SWAR forward NTT + MAC/reduce kernels (FIPS 204 Alg. 41)
//
// ===========================================================================
// WHAT THE SHIPPED VERIFIER ACTUALLY REACHES, AND WHAT IT DOES NOT
// ===========================================================================
// `src/MLDSA44Verifier.sol` imports exactly TWO names from this file:
//
//     nttFwV3      the packed-SWAR forward transform described below
//     nttFwTable   its hoisted twiddle table
//
// Everything else here is reachable only from `test/`, is compiled into no
// deployed contract, and is present because this file and its text-identical
// copy `test/ZZZ_NttVariants.sol` must AGREE (Z3 obligation C16's
// `all_shipped_fwd_copies_agree` / `fwd_shipped_sources_are_the_pinned_bytes`
// digest both and require the same value — that agreement is what carries the
// lane-bound micro-tests run against the variant copy over to the shipped
// one). Naming the boundary here is therefore the honest alternative to
// splitting the file, which would only move the same code to a third place:
//
//     nttFwV2                             the one-coefficient-per-word
//                                         BENCHMARK transform, kept as the
//                                         gas baseline the packed form is
//                                         measured against
//                                         (test/ZZZ_nttvariants.t.sol,
//                                         test/ZZZR_size.t.sol)
//     lazyBarrett                         the scalar model of the two-step
//                                         reduction, the oracle the FV/FV2
//                                         obligation harnesses compare against
//     packCoeffs / unpackCoeffs           layout conversions for the tests
//     macOne / macOneLazy / reduceOne     one-coefficient-per-word MAC
//                                         BENCHMARKS (the matvec baseline)
//     macPackedExact / macPackedLazy /    packed MAC models; the SHIPPED
//     reducePacked                        matvec is `matvecRow` in
//                                         src/Decode.sol, not these
//
// If you are auditing the deployed bytecode, read `nttFwV3` and `nttFwTable`
// and nothing else in this file. Nothing below either of those two is on any
// path from `MLDSA44Verifier.verify()`.
// ===========================================================================
//
// 4-coefficient-per-word (64-bit lanes) forward NTT (nttFwV3) plus the
// packing/MAC/reduction kernels it shares with the matvec. Inputs must be
// CANONICAL (< q); outputs are LAZY — every lane < 17q, congruent mod q to
// the exact transform — which is exactly the domain the lazy matvec
// accumulator admits (O7/O8), the only consumer. Twiddle products are reduced
// with a lazy TWO-STEP LANE-LOCAL BARRETT -- a coarse step with
// MU33 = floor(2^33/q) = 1025 followed by the unit step floor(2^23/q) == 1,
// every intermediate product under 2^64, so all four lanes reduce in place
// with no spreading and no repacking -- except the final layer's scalar
// products, which use the EVM's native mulmod;
// additions are never reduced — lane values grow by <= 2q per layer, bounded
// by (2L+1)q <= 17q < 2^28 after all 8 layers. The eight layers run as THREE
// FUSED PASSES: two RADIX-8 blocks (L1+L2+L3 and L4+L5+L6, each loading one
// OCTET of eight words once, running three layers on the stack and storing
// once) and the in-word L7+L8. That halves — for the octet blocks, thirds —
// the memory traffic, the pointer arithmetic and the loop count relative to
// one pass per layer at identical arithmetic. Fusion is a SCHEDULING change
// only: each layer of a fused block consumes the previous layer's outputs,
// which satisfy that layer's entry bound by construction, so every lane bound
// below is exactly as it was. The
// two Barrett constants, their full input domain (up to 15q(q-1) < 2^50), the
// lane-locality of every product and the per-layer growth schedule are
// machine-checked (Z3 obligations C1, C1b, C9a-C9g, C16, S1-S5, S7, S13 and
// the Lean theorems in
// formal/lean/Mldsa/Barrett.lean); C16 extracts the FUSED PASS STRUCTURE from
// this file's Yul and fails if the block partition or its offsets move.
pragma solidity ^0.8.25;

uint256 constant Q = 8380417; // Dilithium prime, 23 bits
uint256 constant MU33 = 1025; // floor(2^33 / Q), the coarse Barrett constant
// qhat mask, 31 bits per 64-bit lane. After shr(33, mul(w, MU33)) the NEXT
// lane's bits begin at bit 31 of this lane, and a lane's qhat is < 2^31 exactly
// when its own product is < 2^64 -- so ONE mask both extracts the quotient and
// stops a lane from seeing its neighbour. The second step reuses it: its
// quotient is < 2^10 and its neighbour's bits begin at bit 41.
uint256 constant QHATM31 = 0x000000007fffffff000000007fffffff000000007fffffff000000007fffffff;
uint256 constant LANE = 0xffffffffffffffff; // 64-bit lane mask
// 2q, replicated in four 64-bit lanes and as a scalar
uint256 constant TWOQ4 = 0x0000000000ffc0020000000000ffc0020000000000ffc0020000000000ffc002;
uint256 constant TWOQ = 0xffc002;

// ---------------------------------------------------------------------------
// V2: tight one-coefficient-per-word forward NTT (same layout/outputs as nttFw)
// prof: >= 9 words; prof[k] = gas() snapshot before layer k+1 (prof[8] = end).
// ---------------------------------------------------------------------------
function nttFwV2(uint256[] memory a, uint256[] memory prof) view returns (uint256[] memory) {
    uint256[32] memory psirev = [
        uint256(0x4f066b004fe0330053df73004f062b003965690039756700495e0200000001),
        0x6d3dc8000881920070894a0039728300207fe40028edb000360dd50076b1ae,
        0x6b7d81000a52ee00794034004a18a70066528a0028a3d20041e0b4004c7294,
        0x22d8d5002af69700492bb7007611bd001649ee002571df001a2877004e9f1d,
        0x11b2c3003887f7002010a20050685f004926730029d13f0030911e0036f72a,
        0x20e612003177f400428cd4001f9d15004a5f350010b72c000e2bed000603a4,
        0x439a1c0065ad050062564a003952f60049553f00736681001ad87300341c1d,
        0x1c5b7000330e2b001c496e002c83da003b0e6d00087f380030b6220053aa5f,
        0x7bb17500503ee1004eb2ea003fd54c003ac6ef0057a93000137eb9002ee3f1,
        0x3f7288006ef1f50052589c002ae59b0045a6d4001d90a2001ef256002648b4,
        0x4cff12002592ec000296d800773e9e0052aca9001187ba00075d5900175102,
        0x31b859004e48170003978f001a7e79004f16c1001e54e6004aa58200404ce8,
        0x5bd532006c09d100400c7e0035225e005d787a005b63d0001b4827005884cc,
        0x337caa002ca4f8006d285c003b882000097a6c002e534c00258ecb006bc4d3,
        0x78de660075e82600234a86004af6700055795d0028f186005585360014b2a0,
        0x1a9e7b005dbecb00628b3400459b7e005bf3da000f6e17007adf590005528c,
        0x2a4e78007ef8f50064b5fe002898380069a8ef00574b3c006257c5000006d9,
        0x4728af004dc04e005cd5b400437ff800435e870009b7ff000154a800120a23,
        0x46829800437f3100185d960061ab98005a6d80000f66d5000c8d0d007f735d,
        0x5a68b0007c0db30009b4340049b0e300465d8d0028de06004bd57900662960,
        0x4f5859007bc7590048c39b00246e39006585910021762a0064d3d500409ba9,
        0x7faf800013232e002854240030c31c00454df20012eb670023092300392db2,
        0x5e061e006be1cc00095b76006b33750026587a007e832c00022a0b002dbfcb,
        0x5ea06c007361b8006330bb001f1d68004ae53c003da60400628c370078e00d,
        0x56038e00080e6d006de0240008f2010060d772005ba4ff00201fc600671ac7,
        0x63e1e30074d0bd006dbfd40007c017006a9dfa002603bd001e6d3e00695688,
        0x427e23000b7009003f4cf50058018c002decd4002867ba007ab60d00519573,
        0x4c76c80011c14e001ef20600196926001a4b5d0067395700273333003cbd37,
        0x741e780008526000034760003352d6002e1669006af66c007fb19a003cf42f,
        0x68c559000223d400345824000d1ff000776d0b0007c0f1006f0a11002f6316,
        0x79e1fe002ca5e60065adb30051e0ed005e69420023fc65002faa32005e8885,
        0x74b6d70010170e0073f1ce001cfe1400464ade00433aac0035e1dd007b4064
    ];

    assembly ("memory-safe") {
        let B := add(a, 0x20)
        let PR := add(prof, 0x20)
        mstore(PR, gas())

        // ---- Layer 1: m=1, t=128 (tb=0x1000), single group, S = psirev[1]
        {
            let p := B
            let pt := add(B, 0x1000)
            let pe := add(B, 0x1000)
            for {} lt(p, pe) {} {
                let u := mload(p)
                let v := mulmod(mload(pt), 0x495e02, Q)
                mstore(pt, addmod(u, sub(Q, v), Q))
                mstore(p, addmod(u, v, Q))
                p := add(p, 0x20)
                pt := add(pt, 0x20)
                u := mload(p)
                v := mulmod(mload(pt), 0x495e02, Q)
                mstore(pt, addmod(u, sub(Q, v), Q))
                mstore(p, addmod(u, v, Q))
                p := add(p, 0x20)
                pt := add(pt, 0x20)
                u := mload(p)
                v := mulmod(mload(pt), 0x495e02, Q)
                mstore(pt, addmod(u, sub(Q, v), Q))
                mstore(p, addmod(u, v, Q))
                p := add(p, 0x20)
                pt := add(pt, 0x20)
                u := mload(p)
                v := mulmod(mload(pt), 0x495e02, Q)
                mstore(pt, addmod(u, sub(Q, v), Q))
                mstore(p, addmod(u, v, Q))
                p := add(p, 0x20)
                pt := add(pt, 0x20)
            }
        }
        mstore(add(PR, 0x20), gas())

        // ---- Layer 2: m=2, t=64 (tb=0x800), 2 groups, S = psirev[2..3]
        {
            let w := 0x0039656900397567
            let gp := B
            for { let g := 0 } lt(g, 2) { g := add(g, 1) } {
                let S := and(w, 0xffffffff)
                w := shr(32, w)
                let p := gp
                let pt := add(gp, 0x800)
                let pe := add(gp, 0x800)
                for {} lt(p, pe) {} {
                    let u := mload(p)
                    let v := mulmod(mload(pt), S, Q)
                    mstore(pt, addmod(u, sub(Q, v), Q))
                    mstore(p, addmod(u, v, Q))
                    p := add(p, 0x20)
                    pt := add(pt, 0x20)
                    u := mload(p)
                    v := mulmod(mload(pt), S, Q)
                    mstore(pt, addmod(u, sub(Q, v), Q))
                    mstore(p, addmod(u, v, Q))
                    p := add(p, 0x20)
                    pt := add(pt, 0x20)
                    u := mload(p)
                    v := mulmod(mload(pt), S, Q)
                    mstore(pt, addmod(u, sub(Q, v), Q))
                    mstore(p, addmod(u, v, Q))
                    p := add(p, 0x20)
                    pt := add(pt, 0x20)
                    u := mload(p)
                    v := mulmod(mload(pt), S, Q)
                    mstore(pt, addmod(u, sub(Q, v), Q))
                    mstore(p, addmod(u, v, Q))
                    p := add(p, 0x20)
                    pt := add(pt, 0x20)
                }
                gp := add(gp, 0x1000)
            }
        }
        mstore(add(PR, 0x40), gas())

        // ---- Layer 3: m=4, t=32 (tb=0x400), 4 groups, S = psirev[4..7]
        {
            let w := 0x004f066b004fe0330053df73004f062b
            let gp := B
            for { let g := 0 } lt(g, 4) { g := add(g, 1) } {
                let S := and(w, 0xffffffff)
                w := shr(32, w)
                let p := gp
                let pt := add(gp, 0x400)
                let pe := add(gp, 0x400)
                for {} lt(p, pe) {} {
                    let u := mload(p)
                    let v := mulmod(mload(pt), S, Q)
                    mstore(pt, addmod(u, sub(Q, v), Q))
                    mstore(p, addmod(u, v, Q))
                    p := add(p, 0x20)
                    pt := add(pt, 0x20)
                    u := mload(p)
                    v := mulmod(mload(pt), S, Q)
                    mstore(pt, addmod(u, sub(Q, v), Q))
                    mstore(p, addmod(u, v, Q))
                    p := add(p, 0x20)
                    pt := add(pt, 0x20)
                    u := mload(p)
                    v := mulmod(mload(pt), S, Q)
                    mstore(pt, addmod(u, sub(Q, v), Q))
                    mstore(p, addmod(u, v, Q))
                    p := add(p, 0x20)
                    pt := add(pt, 0x20)
                    u := mload(p)
                    v := mulmod(mload(pt), S, Q)
                    mstore(pt, addmod(u, sub(Q, v), Q))
                    mstore(p, addmod(u, v, Q))
                    p := add(p, 0x20)
                    pt := add(pt, 0x20)
                }
                gp := add(gp, 0x800)
            }
        }
        mstore(add(PR, 0x60), gas())

        // ---- Layer 4: m=8, t=16 (tb=0x200), 8 groups, S = psirev[8..15] (word 1)
        {
            let w := mload(add(psirev, 0x20))
            let gp := B
            for { let g := 0 } lt(g, 8) { g := add(g, 1) } {
                let S := and(w, 0xffffffff)
                w := shr(32, w)
                let p := gp
                let pt := add(gp, 0x200)
                let pe := add(gp, 0x200)
                for {} lt(p, pe) {} {
                    let u := mload(p)
                    let v := mulmod(mload(pt), S, Q)
                    mstore(pt, addmod(u, sub(Q, v), Q))
                    mstore(p, addmod(u, v, Q))
                    p := add(p, 0x20)
                    pt := add(pt, 0x20)
                    u := mload(p)
                    v := mulmod(mload(pt), S, Q)
                    mstore(pt, addmod(u, sub(Q, v), Q))
                    mstore(p, addmod(u, v, Q))
                    p := add(p, 0x20)
                    pt := add(pt, 0x20)
                    u := mload(p)
                    v := mulmod(mload(pt), S, Q)
                    mstore(pt, addmod(u, sub(Q, v), Q))
                    mstore(p, addmod(u, v, Q))
                    p := add(p, 0x20)
                    pt := add(pt, 0x20)
                    u := mload(p)
                    v := mulmod(mload(pt), S, Q)
                    mstore(pt, addmod(u, sub(Q, v), Q))
                    mstore(p, addmod(u, v, Q))
                    p := add(p, 0x20)
                    pt := add(pt, 0x20)
                }
                gp := add(gp, 0x400)
            }
        }
        mstore(add(PR, 0x80), gas())

        // ---- Layer 5: m=16, t=8 (tb=0x100), 16 groups, words 2..3; 8 bflys straight-line
        {
            let tp := add(psirev, 0x40)
            let gp := B
            for { let wi := 0 } lt(wi, 2) { wi := add(wi, 1) } {
                let w := mload(tp)
                tp := add(tp, 0x20)
                for { let g := 0 } lt(g, 8) { g := add(g, 1) } {
                    let S := and(w, 0xffffffff)
                    w := shr(32, w)
                    let p := gp
                    let pt := add(gp, 0x100)
                    let u := mload(p)
                    let v := mulmod(mload(pt), S, Q)
                    mstore(pt, addmod(u, sub(Q, v), Q))
                    mstore(p, addmod(u, v, Q))
                    p := add(p, 0x20)
                    pt := add(pt, 0x20)
                    u := mload(p)
                    v := mulmod(mload(pt), S, Q)
                    mstore(pt, addmod(u, sub(Q, v), Q))
                    mstore(p, addmod(u, v, Q))
                    p := add(p, 0x20)
                    pt := add(pt, 0x20)
                    u := mload(p)
                    v := mulmod(mload(pt), S, Q)
                    mstore(pt, addmod(u, sub(Q, v), Q))
                    mstore(p, addmod(u, v, Q))
                    p := add(p, 0x20)
                    pt := add(pt, 0x20)
                    u := mload(p)
                    v := mulmod(mload(pt), S, Q)
                    mstore(pt, addmod(u, sub(Q, v), Q))
                    mstore(p, addmod(u, v, Q))
                    p := add(p, 0x20)
                    pt := add(pt, 0x20)
                    u := mload(p)
                    v := mulmod(mload(pt), S, Q)
                    mstore(pt, addmod(u, sub(Q, v), Q))
                    mstore(p, addmod(u, v, Q))
                    p := add(p, 0x20)
                    pt := add(pt, 0x20)
                    u := mload(p)
                    v := mulmod(mload(pt), S, Q)
                    mstore(pt, addmod(u, sub(Q, v), Q))
                    mstore(p, addmod(u, v, Q))
                    p := add(p, 0x20)
                    pt := add(pt, 0x20)
                    u := mload(p)
                    v := mulmod(mload(pt), S, Q)
                    mstore(pt, addmod(u, sub(Q, v), Q))
                    mstore(p, addmod(u, v, Q))
                    p := add(p, 0x20)
                    pt := add(pt, 0x20)
                    u := mload(p)
                    v := mulmod(mload(pt), S, Q)
                    mstore(pt, addmod(u, sub(Q, v), Q))
                    mstore(p, addmod(u, v, Q))
                    gp := add(gp, 0x200)
                }
            }
        }
        mstore(add(PR, 0xa0), gas())

        // ---- Layer 6: m=32, t=4 (tb=0x80), 32 groups, words 4..7; 4 bflys straight-line
        {
            let tp := add(psirev, 0x80)
            let gp := B
            for { let wi := 0 } lt(wi, 4) { wi := add(wi, 1) } {
                let w := mload(tp)
                tp := add(tp, 0x20)
                for { let g := 0 } lt(g, 8) { g := add(g, 1) } {
                    let S := and(w, 0xffffffff)
                    w := shr(32, w)
                    let p := gp
                    let pt := add(gp, 0x80)
                    let u := mload(p)
                    let v := mulmod(mload(pt), S, Q)
                    mstore(pt, addmod(u, sub(Q, v), Q))
                    mstore(p, addmod(u, v, Q))
                    p := add(p, 0x20)
                    pt := add(pt, 0x20)
                    u := mload(p)
                    v := mulmod(mload(pt), S, Q)
                    mstore(pt, addmod(u, sub(Q, v), Q))
                    mstore(p, addmod(u, v, Q))
                    p := add(p, 0x20)
                    pt := add(pt, 0x20)
                    u := mload(p)
                    v := mulmod(mload(pt), S, Q)
                    mstore(pt, addmod(u, sub(Q, v), Q))
                    mstore(p, addmod(u, v, Q))
                    p := add(p, 0x20)
                    pt := add(pt, 0x20)
                    u := mload(p)
                    v := mulmod(mload(pt), S, Q)
                    mstore(pt, addmod(u, sub(Q, v), Q))
                    mstore(p, addmod(u, v, Q))
                    gp := add(gp, 0x100)
                }
            }
        }
        mstore(add(PR, 0xc0), gas())

        // ---- Layer 7: m=64, t=2 (tb=0x40), 64 groups, words 8..15; 2 bflys straight-line
        {
            let tp := add(psirev, 0x100)
            let gp := B
            for { let wi := 0 } lt(wi, 8) { wi := add(wi, 1) } {
                let w := mload(tp)
                tp := add(tp, 0x20)
                for { let g := 0 } lt(g, 8) { g := add(g, 1) } {
                    let S := and(w, 0xffffffff)
                    w := shr(32, w)
                    let u := mload(gp)
                    let v := mulmod(mload(add(gp, 0x40)), S, Q)
                    mstore(add(gp, 0x40), addmod(u, sub(Q, v), Q))
                    mstore(gp, addmod(u, v, Q))
                    u := mload(add(gp, 0x20))
                    v := mulmod(mload(add(gp, 0x60)), S, Q)
                    mstore(add(gp, 0x60), addmod(u, sub(Q, v), Q))
                    mstore(add(gp, 0x20), addmod(u, v, Q))
                    gp := add(gp, 0x80)
                }
            }
        }
        mstore(add(PR, 0xe0), gas())

        // ---- Layer 8: m=128, t=1 (tb=0x20), 128 groups, words 16..31
        {
            let tp := add(psirev, 0x200)
            let gp := B
            for { let wi := 0 } lt(wi, 16) { wi := add(wi, 1) } {
                let w := mload(tp)
                tp := add(tp, 0x20)
                for { let g := 0 } lt(g, 8) { g := add(g, 1) } {
                    let S := and(w, 0xffffffff)
                    w := shr(32, w)
                    let u := mload(gp)
                    let v := mulmod(mload(add(gp, 0x20)), S, Q)
                    mstore(add(gp, 0x20), addmod(u, sub(Q, v), Q))
                    mstore(gp, addmod(u, v, Q))
                    gp := add(gp, 0x40)
                }
            }
        }
        mstore(add(PR, 0x100), gas())
    }
    return a;
}

// ---------------------------------------------------------------------------
// The forward twiddle table, materialised ONCE per verify() instead of once per
// transform.  It is a 1,024-byte constant, and building it inside nttFwV3 meant
// building it FIVE times (four z rows and c) and leaking 5 KB of memory that is
// never read again: measured at ~800 gas of stores per call plus the quadratic
// expansion the leak carries into every later allocation.  The table is now a
// parameter; `add(psirev, 0x20*k)` inside the transform addresses exactly the
// same words it always did, so not one line of the transform's Yul moves.
// C16 sees this: the twiddle literals stay inside the FILE digest, and the
// transform's head region stays INERT (it no longer holds the table at all).
// ---------------------------------------------------------------------------
function nttFwTable() pure returns (uint256 tbl) {
    uint256[32] memory psirev = [
        uint256(0x4f066b004fe0330053df73004f062b003965690039756700495e0200000001),
        0x6d3dc8000881920070894a0039728300207fe40028edb000360dd50076b1ae,
        0x6b7d81000a52ee00794034004a18a70066528a0028a3d20041e0b4004c7294,
        0x22d8d5002af69700492bb7007611bd001649ee002571df001a2877004e9f1d,
        0x11b2c3003887f7002010a20050685f004926730029d13f0030911e0036f72a,
        0x20e612003177f400428cd4001f9d15004a5f350010b72c000e2bed000603a4,
        0x439a1c0065ad050062564a003952f60049553f00736681001ad87300341c1d,
        0x1c5b7000330e2b001c496e002c83da003b0e6d00087f380030b6220053aa5f,
        0x7bb17500503ee1004eb2ea003fd54c003ac6ef0057a93000137eb9002ee3f1,
        0x3f7288006ef1f50052589c002ae59b0045a6d4001d90a2001ef256002648b4,
        0x4cff12002592ec000296d800773e9e0052aca9001187ba00075d5900175102,
        0x31b859004e48170003978f001a7e79004f16c1001e54e6004aa58200404ce8,
        0x5bd532006c09d100400c7e0035225e005d787a005b63d0001b4827005884cc,
        0x337caa002ca4f8006d285c003b882000097a6c002e534c00258ecb006bc4d3,
        0x78de660075e82600234a86004af6700055795d0028f186005585360014b2a0,
        0x1a9e7b005dbecb00628b3400459b7e005bf3da000f6e17007adf590005528c,
        0x2a4e78007ef8f50064b5fe002898380069a8ef00574b3c006257c5000006d9,
        0x4728af004dc04e005cd5b400437ff800435e870009b7ff000154a800120a23,
        0x46829800437f3100185d960061ab98005a6d80000f66d5000c8d0d007f735d,
        0x5a68b0007c0db30009b4340049b0e300465d8d0028de06004bd57900662960,
        0x4f5859007bc7590048c39b00246e39006585910021762a0064d3d500409ba9,
        0x7faf800013232e002854240030c31c00454df20012eb670023092300392db2,
        0x5e061e006be1cc00095b76006b33750026587a007e832c00022a0b002dbfcb,
        0x5ea06c007361b8006330bb001f1d68004ae53c003da60400628c370078e00d,
        0x56038e00080e6d006de0240008f2010060d772005ba4ff00201fc600671ac7,
        0x63e1e30074d0bd006dbfd40007c017006a9dfa002603bd001e6d3e00695688,
        0x427e23000b7009003f4cf50058018c002decd4002867ba007ab60d00519573,
        0x4c76c80011c14e001ef20600196926001a4b5d0067395700273333003cbd37,
        0x741e780008526000034760003352d6002e1669006af66c007fb19a003cf42f,
        0x68c559000223d400345824000d1ff000776d0b0007c0f1006f0a11002f6316,
        0x79e1fe002ca5e60065adb30051e0ed005e69420023fc65002faa32005e8885,
        0x74b6d70010170e0073f1ce001cfe1400464ade00433aac0035e1dd007b4064
    ];
    // the transform addresses the table by raw pointer, so passing it costs
    // nothing: a `uint256[32] memory` parameter would be COPIED on every
    // internal call (32 words x 9 transforms, measured +1,795 gas).
    assembly ("memory-safe") {
        tbl := psirev
    }
}

// ---------------------------------------------------------------------------
// V3: packed SWAR forward NTT. Input: 64 words, 4 coefficients per word in
// 64-bit lanes (lane l of word i = coeff 4i+l), all lanes canonical (< q).
// Output: same packing, LAZY: every lane < 17q and congruent mod q to the
// nttFw output coefficient-wise (the lazy matvec accumulator — the only
// consumer — admits < 17q lanes, O7/O8).
// prof: >= 4 words; snapshot before pass A, then one after each of the THREE
// fused passes (radix-8 L1+L2+L3, radix-8 L4+L5+L6, in-word L7+L8). These
// markers are the CODE anchors Z3 obligation C16 slices its layer blocks on.
// ---------------------------------------------------------------------------
function nttFwV3(uint256[] memory a, uint256[] memory prof, uint256 psirev)
    view
    returns (uint256[] memory)
{
    assembly ("memory-safe") {
        let B := add(a, 0x20)
        let PR := add(prof, 0x20)
        mstore(PR, gas())

        // ---- Pass A: layers 1+2+3 fused (RADIX-8). One OCTET of words
        //      (i, i+8, i+16, ..., i+56) is loaded ONCE and all THREE layers
        //      run on the stack, so the pass costs 8 loads + 8 stores per 12
        //      butterflies instead of the 16 + 16 two radix-4 passes needed.
        //      The lane schedule is untouched: slot k of the octet is word
        //      i+8k, layer 1 (word stride 32) pairs slots (k, k+4) with
        //      S = psirev[1]; layer 2 (word stride 16) pairs (0,2) and (1,3)
        //      with psirev[2] (group 0, words 0..31) and (4,6), (5,7) with
        //      psirev[3] (group 1, words 32..63); layer 3 (word stride 8) pairs
        //      (0,1), (2,3), (4,5), (6,7) with psirev[4..7] (the four 16-word
        //      groups). All seven twiddles are COMPILE-TIME LITERALS. Every
        //      store is still u+V / u+2q-V, so lanes still grow by exactly 2q
        //      per LAYER (C9f/S5) -- fusion changes the pass count, not the
        //      budget, and every Barrett input stays inside the same verified
        //      domain because no layer's entry bound moves.
        {
            let p := B
            let pe := add(B, 0x100)
            for {} lt(p, pe) { p := add(p, 0x20) } {
                let u0 := mload(p)
                let t0 := mul(mload(add(p, 0x400)), 0x495e02)
                t0 := sub(t0, mul(and(shr(33, mul(t0, MU33)), QHATM31), Q))
                t0 := sub(t0, mul(and(shr(23, t0), QHATM31), Q))
                let a0 := add(u0, t0)
                let b0 := sub(add(u0, TWOQ4), t0)
                let u2 := mload(add(p, 0x200))
                t0 := mul(mload(add(p, 0x600)), 0x495e02)
                t0 := sub(t0, mul(and(shr(33, mul(t0, MU33)), QHATM31), Q))
                t0 := sub(t0, mul(and(shr(23, t0), QHATM31), Q))
                let a2 := add(u2, t0)
                let b2 := sub(add(u2, TWOQ4), t0)
                t0 := mul(a2, 0x397567)
                t0 := sub(t0, mul(and(shr(33, mul(t0, MU33)), QHATM31), Q))
                t0 := sub(t0, mul(and(shr(23, t0), QHATM31), Q))
                let c0 := add(a0, t0)
                let c2 := sub(add(a0, TWOQ4), t0)
                t0 := mul(b2, 0x396569)
                t0 := sub(t0, mul(and(shr(33, mul(t0, MU33)), QHATM31), Q))
                t0 := sub(t0, mul(and(shr(23, t0), QHATM31), Q))
                let c4 := add(b0, t0)
                let c6 := sub(add(b0, TWOQ4), t0)
                let u1 := mload(add(p, 0x100))
                t0 := mul(mload(add(p, 0x500)), 0x495e02)
                t0 := sub(t0, mul(and(shr(33, mul(t0, MU33)), QHATM31), Q))
                t0 := sub(t0, mul(and(shr(23, t0), QHATM31), Q))
                let a1 := add(u1, t0)
                let b1 := sub(add(u1, TWOQ4), t0)
                let u3 := mload(add(p, 0x300))
                t0 := mul(mload(add(p, 0x700)), 0x495e02)
                t0 := sub(t0, mul(and(shr(33, mul(t0, MU33)), QHATM31), Q))
                t0 := sub(t0, mul(and(shr(23, t0), QHATM31), Q))
                let a3 := add(u3, t0)
                let b3 := sub(add(u3, TWOQ4), t0)
                t0 := mul(a3, 0x397567)
                t0 := sub(t0, mul(and(shr(33, mul(t0, MU33)), QHATM31), Q))
                t0 := sub(t0, mul(and(shr(23, t0), QHATM31), Q))
                let c1 := add(a1, t0)
                let c3 := sub(add(a1, TWOQ4), t0)
                t0 := mul(b3, 0x396569)
                t0 := sub(t0, mul(and(shr(33, mul(t0, MU33)), QHATM31), Q))
                t0 := sub(t0, mul(and(shr(23, t0), QHATM31), Q))
                let c5 := add(b1, t0)
                let c7 := sub(add(b1, TWOQ4), t0)
                t0 := mul(c1, 0x4f062b)
                t0 := sub(t0, mul(and(shr(33, mul(t0, MU33)), QHATM31), Q))
                t0 := sub(t0, mul(and(shr(23, t0), QHATM31), Q))
                mstore(p, add(c0, t0))
                mstore(add(p, 0x100), sub(add(c0, TWOQ4), t0))
                t0 := mul(c3, 0x53df73)
                t0 := sub(t0, mul(and(shr(33, mul(t0, MU33)), QHATM31), Q))
                t0 := sub(t0, mul(and(shr(23, t0), QHATM31), Q))
                mstore(add(p, 0x200), add(c2, t0))
                mstore(add(p, 0x300), sub(add(c2, TWOQ4), t0))
                t0 := mul(c5, 0x4fe033)
                t0 := sub(t0, mul(and(shr(33, mul(t0, MU33)), QHATM31), Q))
                t0 := sub(t0, mul(and(shr(23, t0), QHATM31), Q))
                mstore(add(p, 0x400), add(c4, t0))
                mstore(add(p, 0x500), sub(add(c4, TWOQ4), t0))
                t0 := mul(c7, 0x4f066b)
                t0 := sub(t0, mul(and(shr(33, mul(t0, MU33)), QHATM31), Q))
                t0 := sub(t0, mul(and(shr(23, t0), QHATM31), Q))
                mstore(add(p, 0x600), add(c6, t0))
                mstore(add(p, 0x700), sub(add(c6, TWOQ4), t0))
            }
        }
        mstore(add(PR, 0x20), gas())

        // ---- Pass B: layers 4+5+6 fused (RADIX-8). The octet is 8
        //      CONSECUTIVE words; layer 4 (word stride 4) pairs slots (k, k+4)
        //      with psirev[8+o] (one twiddle per octet o, table word 1), layer
        //      5 (word stride 2) pairs (0,2), (1,3) with psirev[16+2o] and
        //      (4,6), (5,7) with psirev[16+2o+1] (table words 2..3), and layer
        //      6 (word stride 1) pairs (0,1), (2,3), (4,5), (6,7) with
        //      psirev[32+4o .. 32+4o+3] (table words 4..7). One table word of
        //      each of the three layers is therefore consumed per 1 / 4 / 2
        //      octets, which is what the three loop levels count down.
        {
            let w4 := mload(add(psirev, 0x20))
            let tp5 := add(psirev, 0x40)
            let tp6 := add(psirev, 0x80)
            let p := B
            for { let i := 0 } lt(i, 2) { i := add(i, 1) } {
                let w5 := mload(tp5)
                tp5 := add(tp5, 0x20)
                for { let k := 0 } lt(k, 2) { k := add(k, 1) } {
                    let w6 := mload(tp6)
                    tp6 := add(tp6, 0x20)
                    for { let m := 0 } lt(m, 2) { m := add(m, 1) } {
                        let S4 := and(w4, 0xffffffff)
                        w4 := shr(32, w4)
                        let S5a := and(w5, 0xffffffff)
                        let S5b := and(shr(32, w5), 0xffffffff)
                        w5 := shr(64, w5)
                        let S6a := and(w6, 0xffffffff)
                        let S6b := and(shr(32, w6), 0xffffffff)
                        let S6c := and(shr(64, w6), 0xffffffff)
                        let S6d := and(shr(96, w6), 0xffffffff)
                        w6 := shr(128, w6)
                        let u0 := mload(p)
                        let t0 := mul(mload(add(p, 0x80)), S4)
                        t0 := sub(t0, mul(and(shr(33, mul(t0, MU33)), QHATM31), Q))
                        t0 := sub(t0, mul(and(shr(23, t0), QHATM31), Q))
                        let a0 := add(u0, t0)
                        let b0 := sub(add(u0, TWOQ4), t0)
                        let u2 := mload(add(p, 0x40))
                        t0 := mul(mload(add(p, 0xc0)), S4)
                        t0 := sub(t0, mul(and(shr(33, mul(t0, MU33)), QHATM31), Q))
                        t0 := sub(t0, mul(and(shr(23, t0), QHATM31), Q))
                        let a2 := add(u2, t0)
                        let b2 := sub(add(u2, TWOQ4), t0)
                        t0 := mul(a2, S5a)
                        t0 := sub(t0, mul(and(shr(33, mul(t0, MU33)), QHATM31), Q))
                        t0 := sub(t0, mul(and(shr(23, t0), QHATM31), Q))
                        let c0 := add(a0, t0)
                        let c2 := sub(add(a0, TWOQ4), t0)
                        t0 := mul(b2, S5b)
                        t0 := sub(t0, mul(and(shr(33, mul(t0, MU33)), QHATM31), Q))
                        t0 := sub(t0, mul(and(shr(23, t0), QHATM31), Q))
                        let c4 := add(b0, t0)
                        let c6 := sub(add(b0, TWOQ4), t0)
                        let u1 := mload(add(p, 0x20))
                        t0 := mul(mload(add(p, 0xa0)), S4)
                        t0 := sub(t0, mul(and(shr(33, mul(t0, MU33)), QHATM31), Q))
                        t0 := sub(t0, mul(and(shr(23, t0), QHATM31), Q))
                        let a1 := add(u1, t0)
                        let b1 := sub(add(u1, TWOQ4), t0)
                        let u3 := mload(add(p, 0x60))
                        t0 := mul(mload(add(p, 0xe0)), S4)
                        t0 := sub(t0, mul(and(shr(33, mul(t0, MU33)), QHATM31), Q))
                        t0 := sub(t0, mul(and(shr(23, t0), QHATM31), Q))
                        let a3 := add(u3, t0)
                        let b3 := sub(add(u3, TWOQ4), t0)
                        t0 := mul(a3, S5a)
                        t0 := sub(t0, mul(and(shr(33, mul(t0, MU33)), QHATM31), Q))
                        t0 := sub(t0, mul(and(shr(23, t0), QHATM31), Q))
                        let c1 := add(a1, t0)
                        let c3 := sub(add(a1, TWOQ4), t0)
                        t0 := mul(b3, S5b)
                        t0 := sub(t0, mul(and(shr(33, mul(t0, MU33)), QHATM31), Q))
                        t0 := sub(t0, mul(and(shr(23, t0), QHATM31), Q))
                        let c5 := add(b1, t0)
                        let c7 := sub(add(b1, TWOQ4), t0)
                        t0 := mul(c1, S6a)
                        t0 := sub(t0, mul(and(shr(33, mul(t0, MU33)), QHATM31), Q))
                        t0 := sub(t0, mul(and(shr(23, t0), QHATM31), Q))
                        mstore(p, add(c0, t0))
                        mstore(add(p, 0x20), sub(add(c0, TWOQ4), t0))
                        t0 := mul(c3, S6b)
                        t0 := sub(t0, mul(and(shr(33, mul(t0, MU33)), QHATM31), Q))
                        t0 := sub(t0, mul(and(shr(23, t0), QHATM31), Q))
                        mstore(add(p, 0x40), add(c2, t0))
                        mstore(add(p, 0x60), sub(add(c2, TWOQ4), t0))
                        t0 := mul(c5, S6c)
                        t0 := sub(t0, mul(and(shr(33, mul(t0, MU33)), QHATM31), Q))
                        t0 := sub(t0, mul(and(shr(23, t0), QHATM31), Q))
                        mstore(add(p, 0x80), add(c4, t0))
                        mstore(add(p, 0xa0), sub(add(c4, TWOQ4), t0))
                        t0 := mul(c7, S6d)
                        t0 := sub(t0, mul(and(shr(33, mul(t0, MU33)), QHATM31), Q))
                        t0 := sub(t0, mul(and(shr(23, t0), QHATM31), Q))
                        mstore(add(p, 0xc0), add(c6, t0))
                        mstore(add(p, 0xe0), sub(add(c6, TWOQ4), t0))
                        p := add(p, 0x100)
                    }
                }
            }
        }
        mstore(add(PR, 0x40), gas())
        // ---- Layers 7+8 fused (radix-4 style), LAZY output.
        //      L7 (m=64, t=2): in-word, lanes (0,1) pair (2,3), shared S7
        //      (table words 8..15). L8 (m=128, t=1): lane 0 pairs 1 with Sa,
        //      lane 2 pairs 3 with Sb (table words 16..31). One load/store per
        //      data word; intermediate lanes stay on the stack. ALL FOUR
        //      twiddle products of the pass -- L7's two (shared S7) and L8's
        //      two -- go through the EVM's native mulmod: these layers are
        //      in-word, so their lanes are extracted to scalars anyway, and on
        //      scalars mulmod is an exact modular multiply with no domain
        //      restriction at 8 gas, which beats a shared two-step lane-local
        //      Barrett on a pair of extracted lanes. Every product is
        //      therefore CANONICAL (< q, tighter than the < 2q a Barrett
        //      leaves), so the +2q lane-growth envelope of C9a/C9f still holds
        //      with room to spare. The output lanes are NOT
        //      canonicalised: every lane exits < 17q < 2^28 (C9a/C9f), which
        //      is exactly the domain the lazy matvec accumulator admits
        //      (O7/O8: products (q-1)*(17q-1) stay lane-local, four of them
        //      plus the KQ28 offset stay under 2^53).
        //      FOUR data words straight-line per iteration: one w8 table word
        //      (8 fields = 2 twiddles x 4 words) and half a w7 word (4 fields)
        //      are consumed per pass, which removes an entire loop level --
        //      the measured ~50-gas EVM loop tax (test/GasCalibration.t.sol)
        //      was the largest single line item left in this block.
        {
            let tp7 := add(psirev, 0x100)
            let tp8 := add(psirev, 0x200)
            let p := B
            for { let wi := 0 } lt(wi, 8) { wi := add(wi, 1) } {
                let w7 := mload(tp7)
                tp7 := add(tp7, 0x20)
                for { let h := 0 } lt(h, 2) { h := add(h, 1) } {
                    let w8 := mload(tp8)
                    tp8 := add(tp8, 0x20)
                    let x := mload(p)
                    // L7 twiddle products on lanes 2,3 (shared S7, native mulmod)
                    let S7 := and(w7, 0xffffffff)
                    let v2 := mulmod(and(shr(128, x), LANE), S7, Q)
                    let v3 := mulmod(shr(192, x), S7, Q)
                    let u0 := and(x, LANE)
                    let u1 := and(shr(64, x), LANE)
                    let l0 := add(u0, v2)
                    let l2 := sub(add(u0, TWOQ), v2)
                    // L8 on (l0, u1+V3) with Sa and (l2, u1+2q-V3) with Sb;
                    // mulmod outputs are canonical (< q < 2q, so the +2q
                    // offset of the difference lanes still dominates)
                    let ya := mulmod(add(u1, v3), and(w8, 0xffffffff), Q)
                    let yb := mulmod(sub(add(u1, TWOQ), v3), and(shr(32, w8), 0xffffffff), Q)
                    mstore(
                        p,
                        or(
                            or(add(l0, ya), shl(64, sub(add(l0, TWOQ), ya))),
                            or(shl(128, add(l2, yb)), shl(192, sub(add(l2, TWOQ), yb)))
                        )
                    )
                    x := mload(add(p, 0x20))
                    // L7 twiddle products on lanes 2,3 (shared S7, native mulmod)
                    S7 := and(shr(32, w7), 0xffffffff)
                    v2 := mulmod(and(shr(128, x), LANE), S7, Q)
                    v3 := mulmod(shr(192, x), S7, Q)
                    u0 := and(x, LANE)
                    u1 := and(shr(64, x), LANE)
                    l0 := add(u0, v2)
                    l2 := sub(add(u0, TWOQ), v2)
                    // L8 on (l0, u1+V3) with Sa and (l2, u1+2q-V3) with Sb;
                    // mulmod outputs are canonical (< q < 2q, so the +2q
                    // offset of the difference lanes still dominates)
                    ya := mulmod(add(u1, v3), and(shr(64, w8), 0xffffffff), Q)
                    yb := mulmod(sub(add(u1, TWOQ), v3), and(shr(96, w8), 0xffffffff), Q)
                    mstore(
                        add(p, 0x20),
                        or(
                            or(add(l0, ya), shl(64, sub(add(l0, TWOQ), ya))),
                            or(shl(128, add(l2, yb)), shl(192, sub(add(l2, TWOQ), yb)))
                        )
                    )
                    x := mload(add(p, 0x40))
                    // L7 twiddle products on lanes 2,3 (shared S7, native mulmod)
                    S7 := and(shr(64, w7), 0xffffffff)
                    v2 := mulmod(and(shr(128, x), LANE), S7, Q)
                    v3 := mulmod(shr(192, x), S7, Q)
                    u0 := and(x, LANE)
                    u1 := and(shr(64, x), LANE)
                    l0 := add(u0, v2)
                    l2 := sub(add(u0, TWOQ), v2)
                    // L8 on (l0, u1+V3) with Sa and (l2, u1+2q-V3) with Sb;
                    // mulmod outputs are canonical (< q < 2q, so the +2q
                    // offset of the difference lanes still dominates)
                    ya := mulmod(add(u1, v3), and(shr(128, w8), 0xffffffff), Q)
                    yb := mulmod(sub(add(u1, TWOQ), v3), and(shr(160, w8), 0xffffffff), Q)
                    mstore(
                        add(p, 0x40),
                        or(
                            or(add(l0, ya), shl(64, sub(add(l0, TWOQ), ya))),
                            or(shl(128, add(l2, yb)), shl(192, sub(add(l2, TWOQ), yb)))
                        )
                    )
                    x := mload(add(p, 0x60))
                    // L7 twiddle products on lanes 2,3 (shared S7, native mulmod)
                    S7 := and(shr(96, w7), 0xffffffff)
                    v2 := mulmod(and(shr(128, x), LANE), S7, Q)
                    v3 := mulmod(shr(192, x), S7, Q)
                    u0 := and(x, LANE)
                    u1 := and(shr(64, x), LANE)
                    l0 := add(u0, v2)
                    l2 := sub(add(u0, TWOQ), v2)
                    // L8 on (l0, u1+V3) with Sa and (l2, u1+2q-V3) with Sb;
                    // mulmod outputs are canonical (< q < 2q, so the +2q
                    // offset of the difference lanes still dominates)
                    ya := mulmod(add(u1, v3), and(shr(192, w8), 0xffffffff), Q)
                    yb := mulmod(sub(add(u1, TWOQ), v3), shr(224, w8), Q)
                    mstore(
                        add(p, 0x60),
                        or(
                            or(add(l0, ya), shl(64, sub(add(l0, TWOQ), ya))),
                            or(shl(128, add(l2, yb)), shl(192, sub(add(l2, TWOQ), yb)))
                        )
                    )
                    w7 := shr(128, w7)
                    p := add(p, 0x80)
                }
            }
        }
        mstore(add(PR, 0x60), gas())
    }
    return a;
}

// ---------------------------------------------------------------------------
// Scalar lazy reduction used by V3, exposed for direct verification: for
// x <= 15q(q-1) < 2^50 (forward) returns r with r = x (mod q), 0 <= r < 2q.
// TWO Barrett steps, both LANE-LOCAL -- every intermediate product stays under
// 2^64 -- which is what lets the packed form run all four 64-bit lanes with the
// same four opcodes and no spreading:
//   step 1   x1 := x  - Q*floor(x  * MU33 / 2^33)    MU33 = floor(2^33/Q) = 1025
//   step 2   r  := x1 - Q*floor(x1        / 2^23)    floor(2^23/Q) == 1, elided
// Step 1's quotient is exact-to-within-one-part-in-2^33, so x1 < ~2^33; step 2
// is the same Barrett step with mu = 1 and closes the remaining 10 bits.
// ---------------------------------------------------------------------------
function lazyBarrett(uint256 x) pure returns (uint256 r) {
    assembly ("memory-safe") {
        r := sub(x, mul(shr(33, mul(x, MU33)), Q))
        r := sub(r, mul(shr(23, r), Q))
    }
}

// ---------------------------------------------------------------------------
// Layout converters (not part of the NTT benchmark proper)
// ---------------------------------------------------------------------------
function packCoeffs(uint256[] memory a) pure returns (uint256[] memory w) {
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

function unpackCoeffs(uint256[] memory w) pure returns (uint256[] memory a) {
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

// ---------------------------------------------------------------------------
// Pointwise multiply-accumulate kernels: c[i] = c[i] + a[i]*b[i] (mod q or lazy)
// ---------------------------------------------------------------------------

// one coefficient per word, exact (canonical in/out), 256 coeffs
function macOne(uint256[] memory c, uint256[] memory a, uint256[] memory b) pure {
    assembly ("memory-safe") {
        let pa := add(a, 0x20)
        let pb := add(b, 0x20)
        let pd := add(c, 0x20)
        let pe := add(pa, 0x2000)
        for {} lt(pa, pe) {} {
            mstore(pd, addmod(mload(pd), mulmod(mload(pa), mload(pb), Q), Q))
            pa := add(pa, 0x20)
            pb := add(pb, 0x20)
            pd := add(pd, 0x20)
            mstore(pd, addmod(mload(pd), mulmod(mload(pa), mload(pb), Q), Q))
            pa := add(pa, 0x20)
            pb := add(pb, 0x20)
            pd := add(pd, 0x20)
            mstore(pd, addmod(mload(pd), mulmod(mload(pa), mload(pb), Q), Q))
            pa := add(pa, 0x20)
            pb := add(pb, 0x20)
            pd := add(pd, 0x20)
            mstore(pd, addmod(mload(pd), mulmod(mload(pa), mload(pb), Q), Q))
            pa := add(pa, 0x20)
            pb := add(pb, 0x20)
            pd := add(pd, 0x20)
        }
    }
}

// one coefficient per word, lazy: c[i] += a[i]*b[i] unreduced (a,b canonical;
// each product < 2^46, so a full word accumulates the 4 matvec terms trivially).
function macOneLazy(uint256[] memory c, uint256[] memory a, uint256[] memory b) pure {
    assembly ("memory-safe") {
        let pa := add(a, 0x20)
        let pb := add(b, 0x20)
        let pd := add(c, 0x20)
        let pe := add(pa, 0x2000)
        for {} lt(pa, pe) {} {
            mstore(pd, add(mload(pd), mul(mload(pa), mload(pb))))
            pa := add(pa, 0x20)
            pb := add(pb, 0x20)
            pd := add(pd, 0x20)
            mstore(pd, add(mload(pd), mul(mload(pa), mload(pb))))
            pa := add(pa, 0x20)
            pb := add(pb, 0x20)
            pd := add(pd, 0x20)
            mstore(pd, add(mload(pd), mul(mload(pa), mload(pb))))
            pa := add(pa, 0x20)
            pb := add(pb, 0x20)
            pd := add(pd, 0x20)
            mstore(pd, add(mload(pd), mul(mload(pa), mload(pb))))
            pa := add(pa, 0x20)
            pb := add(pb, 0x20)
            pd := add(pd, 0x20)
        }
    }
}

// reduction pass for macOneLazy accumulators
function reduceOne(uint256[] memory c) pure {
    assembly ("memory-safe") {
        let pd := add(c, 0x20)
        let pe := add(pd, 0x2000)
        for {} lt(pd, pe) { pd := add(pd, 0x20) } {
            mstore(pd, mod(mload(pd), Q))
        }
    }
}

// packed 4-per-word, exact: per-lane extraction + mulmod/addmod, repack
function macPackedExact(uint256[] memory c, uint256[] memory a, uint256[] memory b) pure {
    assembly ("memory-safe") {
        let pa := add(a, 0x20)
        let pb := add(b, 0x20)
        let pd := add(c, 0x20)
        let pe := add(pa, 0x800)
        for {} lt(pa, pe) {} {
            let wa := mload(pa)
            let wb := mload(pb)
            let wc := mload(pd)
            mstore(
                pd,
                or(
                    or(
                        addmod(and(wc, LANE), mulmod(and(wa, LANE), and(wb, LANE), Q), Q),
                        shl(64, addmod(and(shr(64, wc), LANE), mulmod(and(shr(64, wa), LANE), and(shr(64, wb), LANE), Q), Q))
                    ),
                    or(
                        shl(
                            128,
                            addmod(and(shr(128, wc), LANE), mulmod(and(shr(128, wa), LANE), and(shr(128, wb), LANE), Q), Q)
                        ),
                        shl(192, addmod(shr(192, wc), mulmod(shr(192, wa), shr(192, wb), Q), Q))
                    )
                )
            )
            pa := add(pa, 0x20)
            pb := add(pb, 0x20)
            pd := add(pd, 0x20)
        }
    }
}

// packed 4-per-word, lazy: lanes accumulate raw products (< 2^46 each);
// safe for up to 4 accumulations per lane before reducePacked.
function macPackedLazy(uint256[] memory c, uint256[] memory a, uint256[] memory b) pure {
    assembly ("memory-safe") {
        let pa := add(a, 0x20)
        let pb := add(b, 0x20)
        let pd := add(c, 0x20)
        let pe := add(pa, 0x800)
        for {} lt(pa, pe) {} {
            let wa := mload(pa)
            let wb := mload(pb)
            mstore(
                pd,
                add(
                    mload(pd),
                    or(
                        or(
                            mul(and(wa, LANE), and(wb, LANE)),
                            shl(64, mul(and(shr(64, wa), LANE), and(shr(64, wb), LANE)))
                        ),
                        or(
                            shl(128, mul(and(shr(128, wa), LANE), and(shr(128, wb), LANE))),
                            shl(192, mul(shr(192, wa), shr(192, wb)))
                        )
                    )
                )
            )
            pa := add(pa, 0x20)
            pb := add(pb, 0x20)
            pd := add(pd, 0x20)
        }
    }
}

// per-lane canonical reduction for packed accumulators (lanes < 2^64)
function reducePacked(uint256[] memory c) pure {
    assembly ("memory-safe") {
        let pd := add(c, 0x20)
        let pe := add(pd, 0x800)
        for {} lt(pd, pe) { pd := add(pd, 0x20) } {
            let x := mload(pd)
            mstore(
                pd,
                or(
                    or(mod(and(x, LANE), Q), shl(64, mod(and(shr(64, x), LANE), Q))),
                    or(shl(128, mod(and(shr(128, x), LANE), Q)), shl(192, mod(shr(192, x), Q)))
                )
            )
        }
    }
}
