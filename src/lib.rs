mod hasher;

use std::ffi::CString;
use std::os::raw::c_void;
use umash_sys as ffi;

pub use hasher::Hasher;

#[derive(Copy, Clone)]
pub struct Params(ffi::umash_params);

// Some helpful wrappers for the FFI interface.
impl Params {
    pub fn new() -> Self {
        unsafe { std::mem::zeroed() }
    }
    pub fn derive(bits: u64, key: &str) -> Self {
        let mut params = Self::new();
        // Ensure the string is at least 32 bytes (zero-filled), required by the C interface.
        let mut key_vec: Vec<u8> = key.into();
        (key_vec.len()..32).for_each(|i| key_vec.insert(i, 0));
        let key_str = unsafe { CString::from_vec_unchecked(key_vec) };
        let key_ptr: *const c_void = key_str.as_c_str() as *const _ as *const c_void;
        unsafe {
            ffi::umash_params_derive(&mut params.0, bits, key_ptr);
        }
        params
    }
}

impl Default for Params {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Copy, Clone)]
pub struct State(ffi::umash_state);

impl State {
    pub fn new() -> Self {
        unsafe { std::mem::zeroed() }
    }
    pub fn init(params: &Params, seed: u64, which: i32) -> Self {
        let mut state = Self::new();
        unsafe {
            ffi::umash_init(&mut state.0, &params.0, seed, which);
        }
        state
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Fingerprint {
    pub hash: [u64; 2],
}

impl Fingerprint {
    pub fn generate(params: &Params, seed: u64, input: &[u8]) -> Self {
        let input_len = input.len() as u64;
        let input_ptr = input.as_ptr() as *const c_void;
        let fprint = unsafe { ffi::umash_fprint(&params.0, seed, input_ptr, input_len) };

        Self {
            hash: [fprint.hash[0], fprint.hash[1]],
        }
    }
}

pub fn full_str(params: &Params, seed: u64, which: i32, input_str: &str) -> u64 {
    full(params, seed, which, input_str.as_bytes())
}

pub fn full(params: &Params, seed: u64, which: i32, input: &[u8]) -> u64 {
    let input_len = input.len() as u64;
    let input_ptr: *const c_void = input.as_ptr() as *const c_void;
    unsafe { ffi::umash_full(&params.0, seed, which, input_ptr, input_len) }
}

#[cfg(test)]
mod tests {
    use crate::{Fingerprint, Params};

    #[test]
    fn test_example_case() {
        let key = "hello example.c";
        let input = "the quick brown fox";
        let seed = 42u64;
        let my_params = Params::derive(0, key);
        let fprint = Fingerprint::generate(&my_params, seed, input.as_bytes());
        assert_eq!(fprint.hash, [0x398c5bb5cc113d03, 0x3a52693519575aba]);
    }

    #[test]
    fn test_fingerprint_hash_cmp() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::Hash;
        use std::hash::Hasher;

        let hash = |x: &Fingerprint| {
            let mut hasher = DefaultHasher::new();

            x.hash(&mut hasher);
            hasher.finish()
        };

        let fp1 = Fingerprint { hash: [1, 2] };
        let fp2 = Fingerprint { hash: [1, 2] };
        let fp3 = Fingerprint { hash: [2, 2] };

        assert_eq!(fp1, fp2);
        assert_ne!(fp2, fp3);
        assert_eq!(hash(&fp1), hash(&fp2));
        assert_ne!(hash(&fp2), hash(&fp3));

        assert!(fp1 == fp2);
        assert!(fp2 < fp3);
    }
}
