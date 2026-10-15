// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Nicolas Consigny <nicolas@ethereum.org>

pragma solidity ^0.8.28;

/// @title SphincsC10Asm — Stateless SPHINCS+ C10 verifier (shared, Yul-optimized)
/// @notice C10: W+C_F+C h=18 d=2 a=11 k=13 w=8 l=43 target_sum=205 sig=4008.
///         Sits between C11 (h=16, ~86 bit at a 2²⁰ cap) and C9 (h=20, ~112.6 bit):
///         ~104.5 bit at 2²⁰, ~609 K hashes to sign.
/// @dev    FIPS 205 §4.2 uncompressed 32-byte ADRS + keccak256, the same layout as
///         C7/C9/C11/C13. Signature byte layout and hash structure match the
///         JARDIN-layout variant in `legacy/src/`; only the ADRS word positions
///         differ there (8-byte tree vs 12-byte tree, and WOTS chain/hash in
///         ci(shl64)+cp(shl32) rather than word2(shl32)+word3(shl0)).
///         FORS is keyed by the per-message hypertree leaf via the exact FIPS field
///         split — tree=idxTree0, kp=idxLeaf0, tree_index folds in the FORS tree number
///         ((forsTree<<(A-height))|node). Domain-separated H_msg (160 bytes).
///         ADRS: layer(4) ‖ tree(12) ‖ type(4) ‖ word1 ‖ word2 ‖ word3.
///
///         Differs from C11 only in h (18 vs 16): SUBTREE_H 9 vs 8, target_sum 205 vs
///         203, and one extra auth-path node per hypertree layer (sig 4008 vs 3976).
///         The FORS section is byte-identical in layout, so HT_START is 2336 for both.
///
///         The JARDIN-layout variant at `legacy/src/SPHINCs-C10Asm.sol` is kept for
///         benchmark reproducibility; it is driven by `script/signer.py c10`, this one
///         by `c10-fips`. NOTE: this is
///         the FIPS ADRS *layout*, not FIPS SLH-DSA — WOTS+C/FORS+C counter-grinding
///         has no FIPS analog, H_msg is one-shot, and digest parsing is LSB-first.
contract SphincsC10Asm {

    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        external pure returns (bool valid)
    {
        // NOTE: this block intentionally uses Solidity's free-memory-pointer slot
        // (0x40) and the zero slot (0x60) as scratch and writes high memory without
        // updating the FMP. That is only sound because every exit below is an
        // unconditional in-assembly `return`/`revert`, so Solidity never regains
        // control with a clobbered FMP. It is therefore NOT `memory-safe` in the
        // Yul sense — do not add the ("memory-safe") annotation and do not introduce
        // a normal (fall-through) exit from this block. (matches C13, review C13-evm-f1)
        assembly {
            let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000

            if iszero(eq(sig.length, 4008)) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 18)
                mstore(0x44, "Invalid sig length")
                revert(0x00, 0x64)
            }

            // Reject non-canonical public keys (low 128 bits must be zero), mirroring
            // the C13 verifier and the SHA-2 / BLAKE2b twins. Without this a
            // non-top-aligned pkRoot can never equal the always-N_MASK'd `currentNode`,
            // silently bricking the account, and pkSeed would diverge from the signer,
            // which always masks. Fail loudly instead.
            if or(iszero(eq(pkSeed, and(pkSeed, N_MASK))), iszero(eq(pkRoot, and(pkRoot, N_MASK)))) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 18)
                mstore(0x44, "Invalid public key")
                revert(0x00, 0x64)
            }

            let seed := pkSeed
            let root := pkRoot
            mstore(0x00, seed)

            // H_msg (domain-separated, 160 bytes)
            let R := and(calldataload(sig.offset), N_MASK)
            mstore(0x20, root)
            mstore(0x40, R)
            mstore(0x60, message)
            mstore(0x80, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
            let digest := keccak256(0x00, 0xA0)

            // htIdx = (digest >> 143) & (2^18-1) — 143 = K*A; parsing is ADRS-independent.
            let htIdx := and(shr(143, digest), 0x3FFFF)

            // FORS+C (K=13, A=11) — FIPS 205 FORS field split (per-message leaf keying):
            //   tree=idxTree0 (htIdx>>SUBTREE_H), kp=idxLeaf0 (htIdx&(2^SUBTREE_H-1)),
            //   tree_index=(forsTree<<(A-height))|node, tree_height=height.
            let dVal := digest
            // Forced-zero: last index (i=12) at bits 132..142
            if and(shr(132, dVal), 0x7FF) { revert(0, 0) }

            let sigBase := sig.offset
            // SUBTREE_H = 9 (h/d = 18/2): split htIdx into bottom subtree + leaf.
            let idxLeaf0 := and(htIdx, 0x1FF)
            let idxTree0 := shr(9, htIdx)
            // forsBase: tree=idxTree0 (shl 128), type=3 (shl 96), kp=idxLeaf0 (shl 64).
            let forsBase := or(shl(128, idxTree0), or(shl(96, 3), shl(64, idxLeaf0)))
            // K-1=12 normal trees
            for { let i := 0 } lt(i, 12) { i := add(i, 1) } {
                let treeIdx := and(shr(mul(i, 11), dVal), 0x7FF) // 11-bit indices
                let secretVal := and(calldataload(add(sigBase, add(16, shl(4, i)))), N_MASK)
                // Leaf hash (height 0): word3 = (i << A) | treeIdx, A=11
                let leafAdrs := or(forsBase, or(shl(11, i), treeIdx))
                mstore(0x20, leafAdrs)
                mstore(0x40, secretVal)
                let node := and(keccak256(0x00, 0x60), N_MASK)

                let pathIdx := treeIdx
                // AUTH_START=224, auth per tree = 11*16 = 176
                let authPtr := add(sigBase, add(224, mul(i, 176)))

                // Walk A=11 auth path levels
                for { let h := 0 } lt(h, 11) { h := add(h, 1) } {
                    let sibling := and(calldataload(add(authPtr, shl(4, h))), N_MASK)
                    let parentIdx := shr(1, pathIdx)
                    // word2=height=h+1; word3 = (i << (A-1-h)) | parentIdx, A-1=10
                    mstore(0x20, or(forsBase, or(shl(32, add(h, 1)), or(shl(sub(10, h), i), parentIdx))))
                    // Branchless Merkle swap
                    let s := shl(5, and(pathIdx, 1))
                    mstore(xor(0x40, s), node)
                    mstore(xor(0x60, s), sibling)
                    node := and(keccak256(0x00, 0x80), N_MASK)
                    pathIdx := parentIdx
                }
                mstore(add(0x80, shl(5, i)), node)
            }

            // Last tree (forced-zero)
            {
                let lastSecret := and(calldataload(add(sigBase, add(16, shl(4, 12)))), N_MASK) // 16+12*16=208
                // Forced-zero tree (forsTree=12) as leaf node 0: word3 = (12 << A)
                mstore(0x20, or(forsBase, shl(11, 12)))
                mstore(0x40, lastSecret)
                // 0x80 + 12*0x20 = 0x80 + 0x180 = 0x200
                mstore(0x200, and(keccak256(0x00, 0x60), N_MASK))
            }

            // Compress 13 roots: keccak256(seed || rootsAdrs || 13 roots)
            // FORS_ROOTS: tree=idxTree0 (shl 128), type=4 (shl 96), kp=idxLeaf0 (shl 64).
            // = 32 + 32 + 13*32 = 480 = 0x1E0
            mstore(0x20, or(shl(128, idxTree0), or(shl(96, 4), shl(64, idxLeaf0))))
            for { let i := 0 } lt(i, 13) { i := add(i, 1) } {
                mstore(add(0x40, shl(5, i)), mload(add(0x80, shl(5, i))))
            }
            let forsPk := and(keccak256(0x00, 0x1E0), N_MASK)

            // ============================================================
            // Hypertree (D=2, subtree_h=9, w=8, l=43, target_sum=205)
            // ============================================================
            let currentNode := forsPk
            let idxTree := htIdx
            let sigOff := 2336 // HT_START = 16 + K*16 + (K-1)*A*16 (same as C11)

            for { let layer := 0 } lt(layer, 2) { layer := add(layer, 1) } {
                let idxLeaf := and(idxTree, 0x1FF) // 2^9 - 1
                idxTree := shr(9, idxTree)

                let wotsAdrs := or(shl(224, layer), or(shl(128, idxTree), shl(64, idxLeaf)))
                // countOff = sigOff + l*N = sigOff + 688
                let countOff := add(sigOff, 688)
                let count := shr(224, calldataload(add(sigBase, countOff)))

                mstore(0x20, wotsAdrs)
                mstore(0x40, currentNode)
                mstore(0x60, count)
                let d := keccak256(0x00, 0x80)

                // Validate digit sum = 205 (43 base-8 digits, 3 bits each)
                let digitSum := 0
                for { let ii := 0 } lt(ii, 43) { ii := add(ii, 1) } {
                    digitSum := add(digitSum, and(shr(mul(ii, 3), d), 0x7))
                }
                if iszero(eq(digitSum, 205)) { revert(0, 0) }

                // 43 WOTS chains (w=8: max 7 steps per chain)
                let wotsPtr := add(sigBase, sigOff)
                for { let i := 0 } lt(i, 43) { i := add(i, 1) } {
                    let digit := and(shr(mul(i, 3), d), 0x7)
                    let steps := sub(7, digit)
                    let val := and(calldataload(add(wotsPtr, shl(4, i))), N_MASK)
                    // FIPS WOTS_HASH: chain_address=word2 (shl 32), hash_address=word3 (shl 0)
                    let chainBase := or(wotsAdrs, shl(32, i))

                    for { let step := 0 } lt(step, steps) { step := add(step, 1) } {
                        mstore(0x20, or(chainBase, add(digit, step)))
                        mstore(0x40, val)
                        val := and(keccak256(0x00, 0x60), N_MASK)
                    }
                    mstore(add(0x80, shl(5, i)), val)
                }

                // PK compression: 32+32+43*32 = 1440 = 0x5A0
                let pkAdrs := or(shl(224, layer), or(shl(128, idxTree), or(shl(96, 1), shl(64, idxLeaf))))
                mstore(0x20, pkAdrs)
                for { let i := 0 } lt(i, 43) { i := add(i, 1) } {
                    mstore(add(0x40, shl(5, i)), mload(add(0x80, shl(5, i))))
                }
                let wotsPk := and(keccak256(0x00, 0x5A0), N_MASK)

                // Merkle auth path (9 levels)
                let authOff := add(countOff, 4)
                let treeAdrs := or(shl(224, layer), or(shl(128, idxTree), shl(96, 2)))
                let merkleNode := wotsPk
                let mIdx := idxLeaf
                let merklePtr := add(sigBase, authOff)

                for { let h := 0 } lt(h, 9) { h := add(h, 1) } {
                    let sibling := and(calldataload(add(merklePtr, shl(4, h))), N_MASK)
                    let parentIdx := shr(1, mIdx)
                    // type=2, word2=height=h+1, word3=tree_index=parentIdx
                    mstore(0x20, or(treeAdrs, or(shl(32, add(h, 1)), parentIdx)))
                    let s := shl(5, and(mIdx, 1))
                    mstore(xor(0x40, s), merkleNode)
                    mstore(xor(0x60, s), sibling)
                    merkleNode := and(keccak256(0x00, 0x80), N_MASK)
                    mIdx := parentIdx
                }

                currentNode := merkleNode
                sigOff := add(authOff, 144) // 9*16
            }

            valid := eq(currentNode, root)
            mstore(0x00, valid)
            return(0x00, 0x20)
        }
    }
}
