// SPDX-License-Identifier: MIT
// FastKeccak170.sol — SHAKE256 sponge over an external Keccak-f[1600] helper
//
// The 24-round fully-unrolled Keccak-f[1600] permutation lives in a separate
// 21,622-byte raw-runtime helper contract (helpers/f1600_170.hex, built by
// tools/build_f1600_batch.py from the generated permutation core; the "170"
// suffix marks the EIP-170-deployable build), deployed once and bound by CODE
// HASH in the verifier (see MLDSA44Verifier.F1600_CODEHASH).
//
// The helper has TWO entry points, dispatched on calldatasize:
//   * calldatasize == 800: raw Keccak-f[1600] — the 25-word state in, the
//     permuted state out (used by f1600Fast170 / shake256Fast170 below and by
//     SampleInBall's incremental squeeze);
//   * any other calldatasize: BATCHED SHAKE256 — calldata is the raw message,
//     the helper runs the whole sponge (FIPS 202 1111+pad10*1 padding, one
//     permutation per 136-byte rate block) in ONE staticcall and returns the
//     first 136-byte squeeze block (see shake256Batch170 below). A message of
//     exactly 800 bytes cannot be expressed on this path; shake256Batch170
//     rejects it and callers fall back to shake256Fast170.
//
// Both protocols are stated in CLEAN 64-bit lanes. INTERNALLY the helper holds
// each lane 4-fold replicated in its 256-bit word ("Q-form"), which makes the
// word its own rotation ring and thereby removes every 64-bit mask from the
// permutation (-4,176 gas/permutation). The lift and its inverse live entirely
// inside the callee, so neither this file nor any caller can observe it — see
// tools/build_f1600_batch.py, patches 4-6.
//
// The permutation is bit-exact against FIPS 202: verified against official
// SHAKE256 ACVP vectors and cross-checked against two independent
// implementations in the test battery; the batched sponge is additionally
// checked against the lane-level sponge here on both paths' KATs.
pragma solidity ^0.8.25;

uint256 constant _M64_170 = 0xffffffffffffffff;

/// @notice Keccak-f[1600] permutation, in place on `st` (25 words, lane i = x + 5*y).
/// @dev staticcalls `helper` (the deployed helpers/f1600_170.hex runtime) with `st` as both
///      the argument and the return buffer -- zero-copy in-place permutation.
function f1600Fast170(uint256[25] memory st, address helper) view {
    bool ok;
    assembly ("memory-safe") {
        ok := staticcall(gas(), helper, st, 800, st, 800)
        ok := and(ok, eq(returndatasize(), 800))
    }
    require(ok, "f1600-170: helper call failed");
}

/// @dev XOR one 136-byte rate block at memory `ptr` into the sponge state (lanes 0..16).
///      Whole-word loads + in-word byte reversal per 8-byte group; no byte loops.
///      Touches EXACTLY [ptr, ptr+136) -- see the lane-16 load below -- so the block
///      is honestly `memory-safe` and via-IR can emit a memoryguard for the object.
function _xorBlockFast170(uint256[25] memory st, uint256 ptr) pure {
    assembly ("memory-safe") {
        // reverse the byte order inside each 8-byte group of a 32-byte word,
        // with ONE mask per stage: taking a = w & M (the high half of every
        // 2s-bit field), the low half is exactly w ^ a, so the swap is
        // or(shr(s,a), shl(s, w^a)) -- half the PUSH32 constants of the
        // two-mask form, ~360 bytes of runtime code. Used here (and only here)
        // because the batched entry point took this absorb off the verifier's
        // hot path; _squeezeBlockFast170 below keeps the two-mask form, which
        // solc schedules a shade faster, because SampleInBall squeezes on
        // every verify.
        function grev(w) -> v {
            let a := and(w, 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00)
            v := or(shr(8, a), shl(8, xor(w, a)))
            a := and(v, 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000)
            v := or(shr(16, a), shl(16, xor(v, a)))
            a := and(v, 0xffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000)
            v := or(shr(32, a), shl(32, xor(v, a)))
        }
        let v := grev(mload(ptr)) // input bytes 0..31 -> lanes 0..3
        mstore(st, xor(mload(st), shr(192, v)))
        mstore(add(st, 32), xor(mload(add(st, 32)), and(shr(128, v), _M64_170)))
        mstore(add(st, 64), xor(mload(add(st, 64)), and(shr(64, v), _M64_170)))
        mstore(add(st, 96), xor(mload(add(st, 96)), and(v, _M64_170)))
        v := grev(mload(add(ptr, 32))) // lanes 4..7
        mstore(add(st, 128), xor(mload(add(st, 128)), shr(192, v)))
        mstore(add(st, 160), xor(mload(add(st, 160)), and(shr(128, v), _M64_170)))
        mstore(add(st, 192), xor(mload(add(st, 192)), and(shr(64, v), _M64_170)))
        mstore(add(st, 224), xor(mload(add(st, 224)), and(v, _M64_170)))
        v := grev(mload(add(ptr, 64))) // lanes 8..11
        mstore(add(st, 256), xor(mload(add(st, 256)), shr(192, v)))
        mstore(add(st, 288), xor(mload(add(st, 288)), and(shr(128, v), _M64_170)))
        mstore(add(st, 320), xor(mload(add(st, 320)), and(shr(64, v), _M64_170)))
        mstore(add(st, 352), xor(mload(add(st, 352)), and(v, _M64_170)))
        v := grev(mload(add(ptr, 96))) // lanes 12..15
        mstore(add(st, 384), xor(mload(add(st, 384)), shr(192, v)))
        mstore(add(st, 416), xor(mload(add(st, 416)), and(shr(128, v), _M64_170)))
        mstore(add(st, 448), xor(mload(add(st, 448)), and(shr(64, v), _M64_170)))
        mstore(add(st, 480), xor(mload(add(st, 480)), and(v, _M64_170)))
        // lane 16 = block bytes 128..135, loaded as the word at ptr+104 (block
        // bytes 104..135, the LAST 32 bytes of the rate block) rather than at
        // ptr+128: after grev those 8 bytes are the word's final 8-byte group,
        // so the extract is and(v, _M64_170) instead of shr(192, v) -- same two
        // opcodes, same gas -- and the load no longer reaches 24 bytes past the
        // block. That is what pins this function's footprint to exactly the 136
        // bytes its callers own.
        v := grev(mload(add(ptr, 104)))
        mstore(add(st, 512), xor(mload(add(st, 512)), and(v, _M64_170)))
    }
}

/// @dev Write one full 136-byte squeeze block from the state to memory at `outPtr`.
///      Touches EXACTLY [outPtr, outPtr+136): the fifth store is placed at outPtr+104
///      and carries lanes 13..16, so it lands flush with the end of the rate block and
///      merely rewrites lanes 13..15 with the identical bytes the fourth store just put
///      there. No overhang, hence honestly `memory-safe`.
function _squeezeBlockFast170(uint256[25] memory st, uint256 outPtr) pure {
    assembly ("memory-safe") {
        function grev(w) -> v {
            v := or(
                and(shl(8, w), 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00),
                and(shr(8, w), 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff)
            )
            v := or(
                and(shl(16, v), 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000),
                and(shr(16, v), 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff)
            )
            v := or(
                and(shl(32, v), 0xffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000),
                and(shr(32, v), 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff)
            )
        }
        mstore(
            outPtr,
            grev(or(or(or(shl(192, mload(st)), shl(128, mload(add(st, 32)))), shl(64, mload(add(st, 64)))), mload(add(st, 96))))
        )
        mstore(
            add(outPtr, 32),
            grev(
                or(
                    or(or(shl(192, mload(add(st, 128))), shl(128, mload(add(st, 160)))), shl(64, mload(add(st, 192)))),
                    mload(add(st, 224))
                )
            )
        )
        mstore(
            add(outPtr, 64),
            grev(
                or(
                    or(or(shl(192, mload(add(st, 256))), shl(128, mload(add(st, 288)))), shl(64, mload(add(st, 320)))),
                    mload(add(st, 352))
                )
            )
        )
        mstore(
            add(outPtr, 96),
            grev(
                or(
                    or(or(shl(192, mload(add(st, 384))), shl(128, mload(add(st, 416)))), shl(64, mload(add(st, 448)))),
                    mload(add(st, 480))
                )
            )
        )
        // bytes 104..135 = lanes 13,14,15,16. Overlaps the previous store on
        // bytes 104..127, writing the same three lanes again; the only NEW byte
        // range is 128..135 (lane 16), which is where the rate block ends.
        mstore(
            add(outPtr, 104),
            grev(
                or(
                    or(or(shl(192, mload(add(st, 416))), shl(128, mload(add(st, 448)))), shl(64, mload(add(st, 480)))),
                    mload(add(st, 512))
                )
            )
        )
    }
}

/// @notice One-call SHAKE256 via the helper's batched entry point.
/// @dev The whole sponge (padding, absorb, permutations, first squeeze block)
///      runs inside the helper: one STATICCALL total instead of one per rate
///      block, no caller-side XOR-absorb glue. Limits (both checked):
///      outLen <= 136 (one squeeze block) and input.length != 800 (an 800-byte
///      calldata is dispatched as a raw permutation; callers needing exactly
///      800 bytes — e.g. mu over a 734-byte message — use shake256Fast170).
///      Fails closed: any helper miss/revert/short return reverts here via the
///      returndatasize()==136 check.
function shake256Batch170(bytes memory input, uint256 outLen, address helper)
    view
    returns (bytes memory output)
{
    require(outLen <= 136, "f1600-170: outLen > rate");
    require(input.length != 800, "f1600-170: length 800 unsupported");
    bool ok;
    assembly ("memory-safe") {
        // raw allocation: the staticcall's return-data copy below writes ALL
        // outLen bytes, and a short/failed call reverts on the check that
        // follows, so Solidity's zero-fill of the buffer is pure overhead
        output := mload(0x40)
        mstore(output, outLen)
        mstore(0x40, add(add(output, 0x20), and(add(outLen, 31), not(31))))
        ok := staticcall(gas(), helper, add(input, 32), mload(input), add(output, 32), outLen)
        ok := and(ok, eq(returndatasize(), 136))
    }
    require(ok, "f1600-170: helper call failed");
}

/// @notice Minimal SHAKE256 XOF built on f1600Fast170 (helper-address parameterized).
/// @dev Rate 136 bytes, 0x1f domain padding, 0x80 final bit. Absorb and squeeze are
///      word-wise (full 32-byte loads/stores with in-word byte reversal), multi-block safe.
function shake256Fast170(bytes memory input, uint256 outLen, address helper)
    view
    returns (bytes memory output)
{
    uint256[25] memory st; // zero-initialized sponge state
    uint256 ptr;
    uint256 len = input.length;
    assembly ("memory-safe") {
        ptr := add(input, 32)
    }
    unchecked {
        // absorb full 136-byte blocks
        uint256 nFull = len / 136;
        for (uint256 i = 0; i < nFull; ++i) {
            _xorBlockFast170(st, ptr);
            f1600Fast170(st, helper);
            ptr += 136;
        }
        // final (partial or empty) block with 0x1f ... 0x80 padding
        uint256 rem = len - nFull * 136;
        bytes memory last = new bytes(136); // zeroed
        assembly ("memory-safe") {
            let dst := add(last, 32)
            mcopy(dst, ptr, rem)
            mstore8(add(dst, rem), 0x1f)
            // byte 135 is the least significant byte of the word at offset 104
            mstore(add(dst, 104), xor(mload(add(dst, 104)), 0x80))
            ptr := dst
        }
        _xorBlockFast170(st, ptr);
        f1600Fast170(st, helper);

        // squeeze. _squeezeBlockFast170 writes WHOLE 136-byte rate blocks, so the
        // buffer is allocated as whole rate blocks and its length word is then set
        // to outLen. The slack is inside this object's own allocation (the free
        // memory pointer is already past it, and nothing else can hand it out), so
        // every squeeze store stays in bounds and the block is honestly memory-safe.
        uint256 nOut = outLen == 0 ? 1 : (outLen + 135) / 136;
        output = new bytes(nOut * 136);
        uint256 outPtr;
        assembly ("memory-safe") {
            outPtr := add(output, 32)
            mstore(output, outLen)
        }
        uint256 done = 0;
        while (true) {
            _squeezeBlockFast170(st, outPtr + done);
            done += 136;
            if (done >= outLen) break;
            f1600Fast170(st, helper);
        }
    }
}
