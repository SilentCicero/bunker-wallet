//! WOTS+C signing for C10: w=8, l=43, target_sum=205.

use crate::hash::{self, U256};
use crate::params::*;

/// Derive WOTS secret key for chain i.
pub fn wots_secret(sk_seed: U256, layer: u32, tree: u64, kp: u32, chain_idx: u32) -> U256 {
    let mut data = Vec::with_capacity(32 + 4 + 4 + 32 + 4 + 4);
    data.extend_from_slice(&hash::to_bytes32(sk_seed));
    data.extend_from_slice(b"wots");
    data.extend_from_slice(&layer.to_be_bytes());
    let mut tree_bytes = [0u8; 32];
    tree_bytes[24..32].copy_from_slice(&tree.to_be_bytes());
    data.extend_from_slice(&tree_bytes);
    data.extend_from_slice(&kp.to_be_bytes());
    data.extend_from_slice(&chain_idx.to_be_bytes());
    hash::mask_n(hash::keccak256(&data))
}

/// Compute WOTS digest: keccak256(seed || hashAdrs || msgHash || count).
pub fn wots_digest(seed: U256, layer: u32, tree: u64, kp: u32, msg_hash: U256, count: u32) -> U256 {
    let adrs = hash::make_adrs(layer, tree, 0, kp, 0, 0, 0);
    hash::keccak_4x32(seed, adrs, msg_hash, hash::u256_from_u32(count))
}

/// Extract L base-w digits from the 256-bit digest.
/// Each digit is LOG_W bits; for w=8 (LOG_W=3) digits straddle bytes,
/// so this uses big-integer bit shifts (matches the Solidity verifier's
/// `shr(mul(i, LOG_W), d)` and the Python signer's `(d >> (i*log_w)) & w_mask`).
pub fn extract_digits(d: &U256) -> [u8; L] {
    let mut digits = [0u8; L];
    for i in 0..L {
        digits[i] = (hash::u256_shr(d, i * LOG_W) & W_MASK) as u8;
    }
    digits
}

/// Find counter such that digit sum = TARGET_SUM.
pub fn find_count(seed: U256, layer: u32, tree: u64, kp: u32, msg_hash: U256) -> Result<(u32, U256, [u8; L]), String> {
    for count in 0..10_000_000u32 {
        let d = wots_digest(seed, layer, tree, kp, msg_hash, count);
        let digits = extract_digits(&d);
        let sum: usize = digits.iter().map(|&x| x as usize).sum();
        if sum == TARGET_SUM {
            return Ok((count, d, digits));
        }
    }
    Err("WOTS+C count grinding failed".into())
}

/// Full WOTS+C keygen: returns (secret_keys, wots_pk).
pub fn keygen(seed: U256, sk_seed: U256, layer: u32, tree: u64, kp: u32) -> (Vec<U256>, U256) {
    let base_adrs = hash::make_adrs(layer, tree, 0, kp, 0, 0, 0);
    let mut sks = Vec::with_capacity(L);
    let mut pk_elements = Vec::with_capacity(L);

    for i in 0..L {
        let sk_i = wots_secret(sk_seed, layer, tree, kp, i as u32);
        sks.push(sk_i);
        let chain_adrs = hash::set_chain_index(base_adrs, i as u32);
        let pk_i = hash::chain_hash(seed, chain_adrs, sk_i, 0, (W - 1) as u32);
        pk_elements.push(pk_i);
    }

    let pk_adrs = hash::make_adrs(layer, tree, 1, kp, 0, 0, 0); // type=WOTS_PK
    let wots_pk = hash::th_multi(seed, pk_adrs, &pk_elements);
    (sks, wots_pk)
}

/// WOTS+C keygen returning only the public key (fast path for tree building).
pub fn keygen_pk_only(seed: U256, sk_seed: U256, layer: u32, tree: u64, kp: u32) -> U256 {
    keygen(seed, sk_seed, layer, tree, kp).1
}

/// Sign: produce (sigma, count).
pub fn sign(seed: U256, sks: &[U256], layer: u32, tree: u64, kp: u32, msg_hash: U256) -> Result<(Vec<U256>, u32), String> {
    let (count, _d, digits) = find_count(seed, layer, tree, kp, msg_hash)?;
    let base_adrs = hash::make_adrs(layer, tree, 0, kp, 0, 0, 0);
    let mut sigma = Vec::with_capacity(L);

    for i in 0..L {
        let chain_adrs = hash::set_chain_index(base_adrs, i as u32);
        let sigma_i = hash::chain_hash(seed, chain_adrs, sks[i], 0, digits[i] as u32);
        sigma.push(sigma_i);
    }

    Ok((sigma, count))
}
