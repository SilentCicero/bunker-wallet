//! Dedicated C10-FIPS parameters, not the upstream wrapper's C13 target.
pub const N: usize = 16;
pub const H: usize = 18;
pub const D: usize = 2;
pub const SUBTREE_H: usize = H / D;
pub const A: usize = 11;
pub const K: usize = 13;
pub const W: usize = 8;
pub const LOG_W: usize = 3;
pub const L: usize = 43;
pub const TARGET_SUM: usize = 205;
pub const W_MASK: u64 = 0x7;
pub const FORS_START: usize = N;
pub const AUTH_START: usize = N + K * N;
pub const HT_START: usize = AUTH_START + (K - 1) * A * N;
pub const LAYER_SIZE: usize = L * N + 4 + SUBTREE_H * N;
pub const SIG_SIZE: usize = HT_START + D * LAYER_SIZE;
