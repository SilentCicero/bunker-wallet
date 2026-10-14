//! Keccak256-based tweakable hash primitives matching TweakableHash.sol.

use tiny_keccak::{Hasher, Keccak};

/// N_MASK: keep only top 128 bits of a 256-bit value.
const N_MASK_HI: u64 = u64::MAX;
const N_MASK_LO: u64 = u64::MAX;

pub type U256 = [u64; 4]; // big-endian word order: [0] = MSW

pub const ZERO: U256 = [0; 4];

pub fn to_bytes32(val: U256) -> [u8; 32] {
    crate::u256_to_be(&val)
}

pub fn from_bytes32(b: &[u8; 32]) -> U256 {
    crate::u256_from_be(b)
}

/// Apply N_MASK: keep top 128 bits, zero bottom 128 bits.
#[inline(always)]
pub fn mask_n(val: U256) -> U256 {
    [val[0] & N_MASK_HI, val[1] & N_MASK_LO, 0, 0]
}

/// keccak256 of arbitrary bytes → U256
pub fn keccak256(data: &[u8]) -> U256 {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    from_bytes32(&out)
}

/// keccak256(a || b || c) — 96 bytes, hot path for chain hashing
#[inline(always)]
pub fn keccak_3x32(a: U256, b: U256, c: U256) -> U256 {
    let mut buf = [0u8; 96];
    buf[0..32].copy_from_slice(&to_bytes32(a));
    buf[32..64].copy_from_slice(&to_bytes32(b));
    buf[64..96].copy_from_slice(&to_bytes32(c));
    keccak256(&buf)
}

/// keccak256(a || b || c || d) — 128 bytes
#[inline(always)]
pub fn keccak_4x32(a: U256, b: U256, c: U256, d: U256) -> U256 {
    let mut buf = [0u8; 128];
    buf[0..32].copy_from_slice(&to_bytes32(a));
    buf[32..64].copy_from_slice(&to_bytes32(b));
    buf[64..96].copy_from_slice(&to_bytes32(c));
    buf[96..128].copy_from_slice(&to_bytes32(d));
    keccak256(&buf)
}

// ===== Tweakable Hash Primitives =====

/// ADRS: pack (layer, tree, type, kp, ci, cp, ha) into U256 using the
/// **FIPS 205 §4.2 / §11.2.2 uncompressed 32-byte layout**:
///
///   bytes  0.. 4  layer address
///   bytes  4..16  tree address (96 bits big-endian; top 4 B = 0 for our use)
///   bytes 16..20  type
///   bytes 20..24  word1 (key_pair_address, or 0)
///   bytes 24..28  word2 (chain_address or tree_height, or 0)
///   bytes 28..32  word3 (hash_address or tree_index, or 0)
///
/// The (ci, cp, ha) JARDIN signature is preserved so call sites stay shared;
/// this function maps them to FIPS positions based on `atype` (FIPS 205 Table 1):
///   0 WOTS_HASH  : w1=kp, w2=ci, w3=cp     (ha must be 0)
///   1 WOTS_PK    : w1=kp, w2=0,  w3=0
///   2 TREE       : w1=0,  w2=cp, w3=ha     (ci/kp must be 0)
///   3 FORS_TREE  : w1=kp, w2=cp, w3=ha     (ci must be 0)
///   4 FORS_ROOTS : w1=kp, w2=0,  w3=0
pub fn make_adrs(layer: u32, tree: u64, atype: u32, kp: u32, ci: u32, cp: u32, ha: u32) -> U256 {
    let (w1, w2, w3): (u32, u32, u32) = match atype {
        0 => (kp, ci, cp),       // WOTS_HASH  : kp, chain_address, hash_address
        1 => (kp, 0, 0),         // WOTS_PK    : kp, 0, 0
        2 => (0, cp, ha),        // TREE       : 0, tree_height, tree_index
        3 => (kp, cp, ha),       // FORS_TREE  : kp, tree_height, tree_index
        4 => (kp, 0, 0),         // FORS_ROOTS : kp, 0, 0
        _ => panic!("unknown ADRS type {atype}"),
    };
    // U256 = [u64; 4], val[0] = bytes 0..8 (MSW), val[3] = bytes 24..32 (LSW).
    // FIPS 32-byte ADRS:
    //   bytes  0.. 4  layer            ── val[0] high 32 bits
    //   bytes  4..16  tree (96-bit; we only use low 64 bits, top 4 B = 0)
    //                                  ── val[0] low 32 bits (=0)
    //                                     val[1]               (= tree)
    //   bytes 16..20  atype            ── val[2] high 32 bits
    //   bytes 20..24  word1            ── val[2] low 32 bits
    //   bytes 24..28  word2            ── val[3] high 32 bits
    //   bytes 28..32  word3            ── val[3] low 32 bits
    [
        (layer as u64) << 32,
        tree,
        ((atype as u64) << 32) | (w1 as u64),
        ((w2 as u64) << 32) | (w3 as u64),
    ]
}

/// Th(seed, adrs, input) → 128-bit (masked)
#[inline(always)]
pub fn th(seed: U256, adrs: U256, input: U256) -> U256 {
    mask_n(keccak_3x32(seed, adrs, input))
}

/// ThPair(seed, adrs, left, right) → 128-bit (masked)
#[inline(always)]
pub fn th_pair(seed: U256, adrs: U256, left: U256, right: U256) -> U256 {
    mask_n(keccak_4x32(seed, adrs, left, right))
}

/// ThMulti(seed, adrs, values...) → 128-bit (masked)
pub fn th_multi(seed: U256, adrs: U256, values: &[U256]) -> U256 {
    let mut data = Vec::with_capacity(64 + values.len() * 32);
    data.extend_from_slice(&to_bytes32(seed));
    data.extend_from_slice(&to_bytes32(adrs));
    for v in values {
        data.extend_from_slice(&to_bytes32(*v));
    }
    mask_n(keccak256(&data))
}

/// Domain separator for H_msg: all 0xFF.
pub const HMSG_DOMAIN: U256 = [u64::MAX; 4];

/// H_msg(seed, root, R, message, domain) → full 256-bit digest.
/// Domain-separated: hashes 160 bytes (5 words) vs 128 for ThPair/wotsDigest.
pub fn h_msg(seed: U256, root: U256, r: U256, message: U256) -> U256 {
    let mut buf = [0u8; 160];
    buf[0..32].copy_from_slice(&to_bytes32(seed));
    buf[32..64].copy_from_slice(&to_bytes32(root));
    buf[64..96].copy_from_slice(&to_bytes32(r));
    buf[96..128].copy_from_slice(&to_bytes32(message));
    buf[128..160].copy_from_slice(&to_bytes32(HMSG_DOMAIN));
    keccak256(&buf)
}

/// Chain hash: iterate th from start_pos for `steps` applications.
///
/// FIPS WOTS_HASH: `hash_address` is **word3** (bytes 28..32, low 32 bits of val[3]).
/// We only mutate that slot per step; everything else (layer, tree, type=0,
/// kp, chain_address) stays fixed by the caller.
pub fn chain_hash(seed: U256, adrs: U256, mut val: U256, start_pos: u32, steps: u32) -> U256 {
    let mut a = adrs;
    for step in 0..steps {
        let pos = start_pos + step;
        a[3] = (a[3] & 0xFFFFFFFF_00000000) | (pos as u64);
        val = mask_n(keccak_3x32(seed, a, val));
    }
    val
}

/// Set chain_address in ADRS.
///
/// FIPS WOTS_HASH: `chain_address` is **word2** (bytes 24..28, high 32 bits of val[3]).
pub fn set_chain_index(adrs: U256, idx: u32) -> U256 {
    let mut a = adrs;
    a[3] = (a[3] & 0x00000000_FFFFFFFF) | ((idx as u64) << 32);
    a
}

/// Extract a u32 from U256 bytes at a given position.
pub fn u256_shr(val: &U256, bits: usize) -> u64 {
    // Reconstruct as big integer shift
    let total_bits = 256;
    if bits >= total_bits { return 0; }
    let word_idx = bits / 64;
    let bit_idx = bits % 64;
    // Words are in big-endian order: val[0] is bits 255..192
    let be_word_idx = 3 - word_idx;
    if bit_idx == 0 {
        val[be_word_idx]
    } else if be_word_idx == 0 {
        val[0] >> bit_idx
    } else {
        (val[be_word_idx] >> bit_idx) | (val[be_word_idx - 1] << (64 - bit_idx))
    }
}

/// Convert u32 to U256 (in big-endian position, value in least significant word).
pub fn u256_from_u32(val: u32) -> U256 {
    [0, 0, 0, val as u64]
}
