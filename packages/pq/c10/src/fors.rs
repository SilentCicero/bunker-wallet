//! FORS+C for C10: k=13 trees of height a=11, last tree forced-zero via R grinding.

use crate::hash::{self, U256};
use crate::merkle;
use crate::params::*;

/// Derive FORS secret for (tree_idx, leaf_idx) under hypertree leaf `ht_idx`.
///
/// `ht_idx` binds the secret to the per-message hypertree leaf, so each leaf
/// uses an independent FORS instance (standard SLH-DSA few-time behaviour). It
/// is folded into the PRF preimage here and into the ADRS by `build_fors_tree`.
pub fn fors_secret(sk_seed: U256, tree_idx: u32, leaf_idx: u32, ht_idx: u32) -> U256 {
    let mut data = Vec::with_capacity(32 + 4 + 4 + 4 + 4);
    data.extend_from_slice(&hash::to_bytes32(sk_seed));
    data.extend_from_slice(b"fors");
    data.extend_from_slice(&ht_idx.to_be_bytes());
    data.extend_from_slice(&tree_idx.to_be_bytes());
    data.extend_from_slice(&leaf_idx.to_be_bytes());
    hash::mask_n(hash::keccak256(&data))
}

/// Build a single FORS tree bound to hypertree leaf `ht_idx`. Returns
/// (tree_nodes, root).
///
/// Exact FIPS 205 FORS field split: bind to the bottom hypertree subtree
/// (idx_tree0 → tree address) and leaf (idx_leaf0 → kp); the FORS tree number
/// is folded into tree_index as (tree_idx << (A-height)) | node, with
/// tree_height in word2 (FIPS 205 Alg. 17). Matches the C10-FIPS verifier and
/// C12 / SLH-DSA field semantics.
fn build_fors_tree(seed: U256, sk_seed: U256, tree_idx: u32, ht_idx: u32) -> (Vec<Vec<U256>>, U256) {
    let idx_leaf0 = ht_idx & ((1u32 << SUBTREE_H) - 1);
    let idx_tree0 = (ht_idx >> SUBTREE_H) as u64;
    let n_leaves = 1usize << A;
    let mut leaves = Vec::with_capacity(n_leaves);
    for j in 0..n_leaves {
        let secret = fors_secret(sk_seed, tree_idx, j as u32, ht_idx);
        // leaf (height 0): tree_index = (tree_idx << A) | j
        let leaf_adrs = hash::make_adrs(0, idx_tree0, 3, idx_leaf0, 0, 0, (tree_idx << A) | j as u32);
        leaves.push(hash::th(seed, leaf_adrs, secret));
    }

    // Build Merkle tree over FORS leaves
    let mut nodes = vec![leaves];
    for h in 0..A {
        let prev = &nodes[h];
        let mut level = Vec::with_capacity(prev.len() / 2);
        for idx in (0..prev.len()).step_by(2) {
            let parent_idx = idx / 2;
            // height h+1: tree_index = (tree_idx << (A-1-h)) | parent_idx
            let ti = (tree_idx << (A - 1 - h)) | parent_idx as u32;
            let adrs = hash::make_adrs(0, idx_tree0, 3, idx_leaf0, 0, (h + 1) as u32, ti);
            level.push(hash::th_pair(seed, adrs, prev[idx], prev[idx + 1]));
        }
        nodes.push(level);
    }
    let root = nodes[A][0];
    (nodes, root)
}

/// Grind R until the last FORS index is zero (FORS+C forced-zero).
///
/// SECRET-KEYED randomizer (upstream review C13-X-f2). `R` is bound to the secret
/// `sk_seed` and the message:
///   `R = mask_n(keccak256(sk_seed ‖ "R_grind" ‖ message ‖ nonce))`,
/// grinding `nonce` until the forced-zero predicate holds. Binding `R` to
/// `sk_seed` removes the previous public-grindability: an attacker can no
/// longer offline-search `(message, R)` to steer the FORS index map / hypertree
/// leaf onto previously-revealed instances, restoring the standard
/// secret-randomizer few-time model. It stays fully deterministic per
/// `(key, message)`. The preimage layout MUST match `script/signer.py`'s
/// `grind_R_fors` byte-for-byte (sk_seed[32] ‖ "R_grind" ‖ message[32] ‖
/// nonce[32]) or the Rust↔Python cross-check (and on-chain digest) diverge.
/// The verifier is unaffected — it only reads `R` from the signature.
pub fn grind_r(seed: U256, sk_seed: U256, root: U256, message: U256) -> Result<(U256, U256), String> {
    let a_mask = (1u64 << A) - 1;
    let last_shift = (K - 1) * A; // C10: bit 132 = (13-1)*11

    for nonce in 0..10_000_000u32 {
        let mut r_input = Vec::with_capacity(32 + 7 + 32 + 32);
        r_input.extend_from_slice(&hash::to_bytes32(sk_seed));
        r_input.extend_from_slice(b"R_grind");
        r_input.extend_from_slice(&hash::to_bytes32(message));
        r_input.extend_from_slice(&hash::to_bytes32(hash::u256_from_u32(nonce)));
        let r = hash::mask_n(hash::keccak256(&r_input));
        let digest = hash::h_msg(seed, root, r, message);

        // Check last index = 0
        let last_idx = hash::u256_shr(&digest, last_shift) & a_mask;
        if last_idx == 0 {
            return Ok((r, digest));
        }
    }
    Err("R grinding failed".into())
}

/// Sign FORS+C: returns (secrets, auth_paths, fors_pk).
pub fn sign_fors(seed: U256, sk_seed: U256, digest: U256)
    -> Result<(Vec<U256>, Vec<Vec<U256>>, U256), String>
{
    let a_mask = (1u64 << A) - 1;

    // Extract indices
    let mut indices = Vec::with_capacity(K);
    for i in 0..K {
        indices.push((hash::u256_shr(&digest, i * A) & a_mask) as usize);
    }

    // Verify forced-zero
    if indices[K - 1] != 0 {
        return Err("FORS+C forced-zero violated".into());
    }

    // Exact FIPS 205 FORS field split: key the FORS instance by the per-message
    // hypertree leaf. htIdx = (digest >> K*A) & (2^H - 1) — the same value
    // sphincs::sign and the verifier derive — split into the bottom subtree
    // (idx_tree0 → tree address) and leaf (idx_leaf0 → kp).
    let ht_idx = (hash::u256_shr(&digest, K * A) & ((1u64 << H) - 1)) as u32;
    let idx_leaf0 = ht_idx & ((1u32 << SUBTREE_H) - 1);
    let idx_tree0 = (ht_idx >> SUBTREE_H) as u64;

    let mut secrets = Vec::with_capacity(K);
    let mut auth_paths = Vec::with_capacity(K - 1);
    let mut roots = Vec::with_capacity(K);

    // k-1 normal trees
    for t in 0..(K - 1) {
        let (tree_nodes, root) = build_fors_tree(seed, sk_seed, t as u32, ht_idx);
        secrets.push(fors_secret(sk_seed, t as u32, indices[t] as u32, ht_idx));
        auth_paths.push(merkle::get_auth_path(&tree_nodes, indices[t], A));
        roots.push(root);
    }

    // Last tree: forced-zero, reveal root. Hashed as leaf node 0 of tree K-1:
    // tree_index = (K-1) << A, kp=idx_leaf0, tree=idx_tree0.
    let (_, root_last) = build_fors_tree(seed, sk_seed, (K - 1) as u32, ht_idx);
    let last_adrs = hash::make_adrs(0, idx_tree0, 3, idx_leaf0, 0, 0, ((K - 1) as u32) << A);
    secrets.push(root_last);
    roots.push(hash::th(seed, last_adrs, root_last));

    // Compress K roots: FORS_ROOTS ADRS bound to the hypertree leaf (tree=idx_tree0, kp=idx_leaf0)
    let roots_adrs = hash::make_adrs(0, idx_tree0, 4, idx_leaf0, 0, 0, 0); // type=FORS_ROOTS
    let fors_pk = hash::th_multi(seed, roots_adrs, &roots);

    Ok((secrets, auth_paths, fors_pk))
}
