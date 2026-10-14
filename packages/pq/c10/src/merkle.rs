//! Merkle tree construction and auth path extraction.

use crate::hash::{self, U256};
use crate::wots;
use crate::params::*;

/// Build a Merkle tree from leaves. Returns nodes[level][index].
pub fn build_tree(seed: U256, layer: u32, tree: u64, leaves: &[U256], height: usize) -> Vec<Vec<U256>> {
    let mut nodes = vec![leaves.to_vec()];
    for h in 0..height {
        let prev = &nodes[h];
        let mut level = Vec::with_capacity(prev.len() / 2);
        for j in (0..prev.len()).step_by(2) {
            let parent_idx = j / 2;
            let adrs = hash::make_adrs(layer, tree, 2, 0, 0, (h + 1) as u32, parent_idx as u32);
            level.push(hash::th_pair(seed, adrs, prev[j], prev[j + 1]));
        }
        nodes.push(level);
    }
    nodes
}

/// Extract authentication path for a given leaf index.
pub fn get_auth_path(tree_nodes: &[Vec<U256>], leaf_idx: usize, height: usize) -> Vec<U256> {
    let mut path = Vec::with_capacity(height);
    let mut idx = leaf_idx;
    for h in 0..height {
        path.push(tree_nodes[h][idx ^ 1]);
        idx >>= 1;
    }
    path
}

/// Build a full subtree and return just the root.
pub fn build_subtree_root(seed: U256, sk_seed: U256, layer: u32, tree: u64) -> U256 {
    let n_leaves = 1 << SUBTREE_H;
    let mut leaves = Vec::with_capacity(n_leaves);
    for kp in 0..n_leaves {
        leaves.push(wots::keygen_pk_only(seed, sk_seed, layer, tree, kp as u32));
    }
    let nodes = build_tree(seed, layer, tree, &leaves, SUBTREE_H);
    nodes[SUBTREE_H][0]
}

/// Build a full subtree returning (wots_sks, tree_nodes, root).
pub fn build_subtree_full(seed: U256, sk_seed: U256, layer: u32, tree: u64)
    -> (Vec<Vec<U256>>, Vec<Vec<U256>>, U256)
{
    let n_leaves = 1 << SUBTREE_H;
    let mut all_sks = Vec::with_capacity(n_leaves);
    let mut leaves = Vec::with_capacity(n_leaves);
    for kp in 0..n_leaves {
        let (sks, pk) = wots::keygen(seed, sk_seed, layer, tree, kp as u32);
        all_sks.push(sks);
        leaves.push(pk);
    }
    let nodes = build_tree(seed, layer, tree, &leaves, SUBTREE_H);
    let root = nodes[SUBTREE_H][0];
    (all_sks, nodes, root)
}
