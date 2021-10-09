mod hasher;

use std::os::raw::c_void;
use umash_sys as ffi;

pub use hasher::Hasher;

/// A `Params` struct wraps a set of hashing parameters.
///
/// There are 38 such u64 parameters, so while a `Params` struct does
/// not own any resource, they should be passed by reference rather
/// than copied as much as possible.
#[derive(Clone)]
pub struct Params(ffi::umash_params);

impl Params {
    /// Returns a new pseudo-unique `Params` value.
    pub fn new() -> Self {
        use std::cell::Cell;

        // Each thread has 32 random bytes and a 64-bit counter.
        //
        // We let umash derive new parameters from the random bytes
        // and the counter (with chacha20).  The parameters should be
        // unique and independently distributed, until we generate
        // 2^64 `Params` on the same thread.
        thread_local!(static RANDOM_STATE: ([u8; 32], Cell<u64>) = {
            let mut slice = [0u8; 32];

            getrandom::getrandom(&mut slice).expect("failed to generate 32 random bytes");
            (slice, Cell::new(0))
        });

        RANDOM_STATE.with(|state| {
            let counter = state.1.get();
            state.1.set(counter.wrapping_add(1));

            Params::derive(counter, &state.0)
        })
    }

    /// Returns a fresh set of `Params` derived deterministically from
    /// `bits` and the first 32 bytes in `key`.
    ///
    /// The umash function defined by the resulting `Params` will
    /// remain the same for all versions of UMASH and umash-rs.
    pub fn derive(bits: u64, key: &[u8]) -> Self {
        let mut params: Self = unsafe { std::mem::zeroed() };

        // Pass a pointer to exactly 32 bytes of key material.
        let mut key_vec = [0u8; 32];
        let to_copy = key.len().min(key_vec.len());

        (&mut key_vec[..to_copy]).copy_from_slice(key);
        unsafe {
            ffi::umash_params_derive(&mut params.0, bits, key_vec.as_ptr() as *const _);
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
        let my_params = Params::derive(0, key.as_bytes());
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
