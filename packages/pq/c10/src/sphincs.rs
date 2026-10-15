//! Full SPHINCS+ C10 signing: FORS+C → hypertree → packed signature.

use crate::hash::{self, U256};
use crate::params::*;
use crate::wots;
use crate::fors;
use crate::merkle;

/// Sign a message with SPHINCS+ C10.
/// Returns the raw signature bytes (SIG_SIZE = 4008 bytes).
pub fn sign(seed: U256, sk_seed: U256, pk_root: U256, message: U256) -> Result<Vec<u8>, String> {
    // Step 1: Grind R for FORS+C forced-zero (R is secret-keyed on sk_seed; upstream review C13-X-f2)
    let (r, digest) = fors::grind_r(seed, sk_seed, pk_root, message)?;

    // Step 2: Extract hypertree index
    let ht_shift = K * A; // 128
    let ht_mask = (1u64 << H) - 1;
    let ht_idx = (hash::u256_shr(&digest, ht_shift) & ht_mask) as usize;

    // Step 3: Sign FORS+C
    let (fors_secrets, fors_auth_paths, fors_pk) = fors::sign_fors(seed, sk_seed, digest)?;

    // Step 4: Sign hypertree (D=2 layers)
    let mut ht_layers: Vec<(Vec<U256>, u32, Vec<U256>)> = Vec::with_capacity(D);
    let mut current_node = fors_pk;
    let mut idx_tree = ht_idx;

    for layer in 0..D {
        let idx_leaf = idx_tree & ((1 << SUBTREE_H) - 1);
        idx_tree >>= SUBTREE_H;

        let (all_sks, tree_nodes, _) = merkle::build_subtree_full(
            seed, sk_seed, layer as u32, idx_tree as u64,
        );

        let (sigma, count) = wots::sign(
            seed, &all_sks[idx_leaf], layer as u32, idx_tree as u64,
            idx_leaf as u32, current_node,
        )?;

        let auth_path = merkle::get_auth_path(&tree_nodes, idx_leaf, SUBTREE_H);

        // Verify: recompute what verifier would get
        let d_val = wots::wots_digest(
            seed, layer as u32, idx_tree as u64, idx_leaf as u32, current_node, count,
        );
        let digits = wots::extract_digits(&d_val);
        let base_adrs = hash::make_adrs(layer as u32, idx_tree as u64, 0, idx_leaf as u32, 0, 0, 0);
        let mut pk_elements = Vec::with_capacity(L);
        for i in 0..L {
            let ca = hash::set_chain_index(base_adrs, i as u32);
            pk_elements.push(hash::chain_hash(
                seed, ca, sigma[i], digits[i] as u32, (W - 1 - digits[i] as usize) as u32,
            ));
        }
        let pk_adrs = hash::make_adrs(layer as u32, idx_tree as u64, 1, idx_leaf as u32, 0, 0, 0);
        let wots_pk = hash::th_multi(seed, pk_adrs, &pk_elements);

        let mut node = wots_pk;
        let mut m_idx = idx_leaf;
        for h in 0..SUBTREE_H {
            let sib = auth_path[h];
            let pi = m_idx >> 1;
            let adrs = hash::make_adrs(layer as u32, idx_tree as u64, 2, 0, 0, (h + 1) as u32, pi as u32);
            node = if m_idx & 1 == 0 {
                hash::th_pair(seed, adrs, node, sib)
            } else {
                hash::th_pair(seed, adrs, sib, node)
            };
            m_idx >>= 1;
        }
        current_node = node;

        ht_layers.push((sigma, count, auth_path));
    }

    if current_node != pk_root {
        return Err("root mismatch after signing".into());
    }

    // Step 5: Pack signature
    let mut sig = Vec::with_capacity(SIG_SIZE);

    // R (N bytes)
    sig.extend_from_slice(&hash::to_bytes32(r)[..N]);

    // FORS secrets (K * N bytes)
    for s in &fors_secrets {
        sig.extend_from_slice(&hash::to_bytes32(*s)[..N]);
    }

    // FORS auth paths ((K-1) * A * N bytes)
    for path in &fors_auth_paths {
        for node in path {
            sig.extend_from_slice(&hash::to_bytes32(*node)[..N]);
        }
    }

    // HT layers (D * LAYER_SIZE bytes)
    for (sigma, count, auth_path) in &ht_layers {
        for s in sigma {
            sig.extend_from_slice(&hash::to_bytes32(*s)[..N]);
        }
        sig.extend_from_slice(&count.to_be_bytes());
        for node in auth_path {
            sig.extend_from_slice(&hash::to_bytes32(*node)[..N]);
        }
    }

    assert_eq!(sig.len(), SIG_SIZE, "signature size mismatch");
    Ok(sig)
}
