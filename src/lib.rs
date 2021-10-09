use std::marker::PhantomData;
use std::os::raw::c_void;
use umash_sys as ffi;

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

/// A `Hasher` wraps umash's incremental hashing state, and
/// refers to a `Params` struct.
#[derive(Clone)]
pub struct Hasher<'params>(ffi::umash_state, PhantomData<&'params Params>);

pub enum UmashComponent {
    Hash = 0,
    Secondary = 1,
}

impl<'a> Hasher<'a> {
    /// Returns a new empty hashing state for the umash function
    /// described by `params`.  The `which` argument determines
    /// whether the primary hash or the secondary disambiguation
    /// value will be computed.
    ///
    /// Passing different values for `seed` will yield different hash
    /// values, albeit without any statistical bound on collisions.
    pub fn with_params(params: &'a Params, seed: u64, which: UmashComponent) -> Self {
        let mut state = Hasher(unsafe { std::mem::zeroed() }, PhantomData);

        unsafe {
            ffi::umash_init(&mut state.0, &params.0, seed, which as i32);
        }

        state
    }
}

impl<'a> From<&'a Params> for Hasher<'a> {
    fn from(params: &'a Params) -> Hasher<'a> {
        Hasher::with_params(params, 0, UmashComponent::Hash)
    }
}

impl<'a> std::hash::Hasher for Hasher<'a> {
    fn finish(&self) -> u64 {
        unsafe { ffi::umash_digest(&self.0) }
    }

    fn write(&mut self, bytes: &[u8]) {
        unsafe {
            ffi::umash_sink_update(
                &mut self.0.sink,
                bytes.as_ptr() as *const _,
                bytes.len() as u64,
            );
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Fingerprint {
    pub hash: [u64; 2],
}

/// A `Fingerprinter` wraps umash's incremental fingerprinting state,
/// and refers to a `Params` struct.
#[derive(Clone)]
pub struct Fingerprinter<'params>(ffi::umash_fp_state, PhantomData<&'params Params>);

impl<'a> Fingerprinter<'a> {
    /// Returns a new empty fingerprinting state for the umash
    /// function described by `params`.
    ///
    /// Passing different values for `seed` will yield different hash
    /// values, albeit without any statistical bound on collisions.
    pub fn with_params(params: &'a Params, seed: u64) -> Self {
        let mut state = Self(unsafe { std::mem::zeroed() }, PhantomData);

        unsafe {
            ffi::umash_fp_init(&mut state.0, &params.0, seed);
        }

        state
    }

    pub fn digest(&self) -> Fingerprint {
        let fprint = unsafe { ffi::umash_fp_digest(&self.0) };

        Fingerprint {
            hash: [fprint.hash[0], fprint.hash[1]],
        }
    }
}

impl<'a> From<&'a Params> for Fingerprinter<'a> {
    fn from(params: &'a Params) -> Fingerprinter<'a> {
        Fingerprinter::with_params(params, 0)
    }
}

impl<'a> std::hash::Hasher for Fingerprinter<'a> {
    fn finish(&self) -> u64 {
        self.digest().hash[0]
    }

    fn write(&mut self, bytes: &[u8]) {
        unsafe {
            ffi::umash_sink_update(
                &mut self.0.sink,
                bytes.as_ptr() as *const _,
                bytes.len() as u64,
            );
        }
    }
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
    use crate::{Fingerprint, Fingerprinter, Hasher, Params, UmashComponent};

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
    fn test_example_case_hashers() {
        use std::hash::Hasher as StdHasher;

        let key = "hello example.c";
        let input = "the quick brown fox";
        let seed = 42u64;
        let my_params = Params::derive(0, key.as_bytes());

        let mut hasher = Hasher::with_params(&my_params, seed, UmashComponent::Hash);
        let mut secondary = Hasher::with_params(&my_params, seed, UmashComponent::Secondary);
        let mut fprint = Fingerprinter::with_params(&my_params, seed);

        hasher.write(input.as_bytes());
        secondary.write(input.as_bytes());
        fprint.write(input.as_bytes());

        assert_eq!(hasher.finish(), 0x398c5bb5cc113d03);
        assert_eq!(secondary.finish(), 0x3a52693519575aba);
        assert_eq!(
            fprint.digest().hash,
            [0x398c5bb5cc113d03, 0x3a52693519575aba]
        );
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

    #[test]
    fn test_example_case_with_separate_params() {
        use std::hash::Hasher as StdHasher;

        let params = Params::derive(0, "hello example.c".as_bytes());
        let mut h = Hasher::with_params(&params, 42u64, UmashComponent::Hash);
        h.write(b"the quick brown fox");
        assert_eq!(h.finish(), 0x398c5bb5cc113d03);
    }

    #[test]
    fn test_another_case_with_separate_params() {
        use std::hash::Hasher as StdHasher;

        let params = Params::derive(0, "backtrace".as_bytes());
        let mut h = Hasher::with_params(&params, 0xcd03, UmashComponent::Hash);
        h.write(b"the quick brown fox");
        assert_eq!(h.finish(), 0x931972393b291c81);
    }
}
