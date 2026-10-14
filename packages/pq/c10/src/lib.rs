//! Dedicated experimental C10-FIPS build; upstream pin and changes documented in README.
pub mod hash;
pub mod params;
pub mod wots;
pub mod fors;
pub mod merkle;
pub mod sphincs;
// Single-threaded, no-import WASM ABI: exports cannot re-enter or run concurrently.
static mut INPUT: [u8; 48] = [0; 48];
static mut OUTPUT: [u8; 4008] = [0; 4008];
static mut KEYS: [[u64; 4]; 3] = [[0; 4]; 3];
static mut READY: bool = false;
fn word(bytes: &[u8]) -> [u64; 4] {
    let mut out = [0; 4];
    for i in 0..4 { out[i] = u64::from_be_bytes(bytes[i*8..i*8+8].try_into().unwrap()); }
    out
}
#[no_mangle]
pub extern "C" fn input() -> *mut u8 { std::ptr::addr_of_mut!(INPUT).cast() }
#[no_mangle]
pub extern "C" fn output() -> *const u8 { std::ptr::addr_of!(OUTPUT).cast() }
/// Input: independent HKDF output, pkSeed16 || skSeed32. Output: pkSeed16 || root16.
#[no_mangle]
pub unsafe extern "C" fn keygen() {
    let mut seed = [0; 32]; seed[..16].copy_from_slice(&INPUT[..16]);
    KEYS[0] = word(&seed); KEYS[1] = word(&INPUT[16..48]);
    KEYS[2] = merkle::build_subtree_root(KEYS[0], KEYS[1], 1, 0);
    OUTPUT[..16].copy_from_slice(&seed[..16]);
    OUTPUT[16..32].copy_from_slice(&hash::to_bytes32(KEYS[2])[..16]);
    INPUT = [0;48]; READY = true;
}
#[no_mangle]
pub unsafe extern "C" fn sign() -> u32 {
    if !READY { return 0; }
    let msg = word(&INPUT[..32]); INPUT = [0;48];
    match sphincs::sign(KEYS[0], KEYS[1], KEYS[2], msg) {
        Ok(sig) => { OUTPUT = sig.try_into().unwrap(); 4008 },
        Err(_) => 0,
    }
}
pub fn u256_from_be(bytes: &[u8;32]) -> [u64;4] { word(bytes) }
pub fn u256_to_be(value: &[u64;4]) -> [u8;32] {
    let mut out = [0;32]; for i in 0..4 { out[i*8..i*8+8].copy_from_slice(&value[i].to_be_bytes()); } out
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn python_c10_fips_differential() { unsafe {
        INPUT = [1;48]; keygen();
        INPUT = [2;48]; assert_eq!(sign(),4008);
        let output = OUTPUT;
        assert_eq!(output.as_slice(), include_bytes!("../../test-vectors/c10-public-test.sig"));
    }}
}
