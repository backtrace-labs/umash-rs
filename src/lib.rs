//! UMASH defines an almost-universal family of hash functions.  Each
//! [`Params`] struct defines a specific hash function; when the
//! parameters are generated pseudorandomly the probability that two
//! different inputs of up to `s` bytes collide is at most `ceil(s /
//! 4096) 2^-55` for the 64-bit hash.  The 128-bit fingerprint reduces
//! that probability to less than `2^-70` for inputs of 1 GB or less.
//!
//! See the [reference repo](https://github.com/backtrace-labs/umash)
//! for more details and proofs.

use std::marker::PhantomData;
use umash_sys as ffi;

/// A [`Params`] stores a set of hashing parameters.
///
/// By default, each [`Params`] is generated independently with unique
/// pseudorandom parameters.  Call `Params::derive` to generate
/// repeatable parameters that will compute the same hash and
/// fingerprint values across processes, programs, and architectures.
///
/// This struct consists of 38 `u64` parameters, so while [`Params`]
/// do not own any resource, they should be passed by reference rather
/// than copied, as much as possible.
///
/// [`Params`] implements [`std::hash::BuildHasher`]: pass a `&'static
/// Params` to, e.g., [`std::collections::HashMap::with_hasher`], and
/// the hash values will be computed with as the primary UMASH value
/// for these [`Params`], and `seed = 0`.
#[derive(Clone)]
pub struct Params(ffi::umash_params);

/// A given [`Params`] struct defines a pair of 64-bit hash functions.
/// The [`UmashComponent::Hash`] is the primary hash value; we find a
/// 128-bit fingerprint by combining that primary value with the
/// [`UmashComponent::Secondary`] hash (in practice, it's more
/// efficient to compute both hash values concurrently, when one knows
/// they want a fingerprint).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UmashComponent {
    /// Compute the primary 64 bit hash (the first `u64` in a
    /// [`Fingerprint`])
    Hash = 0,

    /// Compute the secondary 64-bit value (the second `u64` in a
    /// [`Fingerprint`]).  This secondary value is slightly less well
    /// distributed and collision resistant than the primary, but
    /// combines efficiently with the primary to compute a reasonably
    /// strong 128-bit [`Fingerprint`].
    Secondary = 1,
}

/// A 128-bit [`Fingerprint`] is constructed by UMASH as if we had
/// computed the [`UmashComponent::Hash`] and
/// [`UmashComponent::Secondary`] functions, and stored them in the
/// [`Fingerprint::hash`] array in order.
///
/// This makes it possible to check a document against a
/// [`Fingerprint`] by only computing the 64-bit
/// [`UmashComponent::Hash`], and comparing that with
/// `Fingerprint::hash[0]`: the comparison gives us less confidence,
/// but is faster to compute.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Fingerprint {
    pub hash: [u64; 2],
}

impl Fingerprint {
    #[inline(always)]
    pub fn new(hash: u64, secondary: u64) -> Self {
        Fingerprint {
            hash: [hash, secondary],
        }
    }

    /// Returns the [`UmashComponent::Hash` component of the fingerprint.
    #[inline(always)]
    pub fn hash(&self) -> u64 {
        self.hash[0]
    }

    /// Returns the [`UmashComponent::Secondary`] component of the
    /// fingerprint.
    #[inline(always)]
    pub fn secondary(&self) -> u64 {
        self.hash[1]
    }

    /// Returns the `which` component of the fingerprint.
    pub fn component(&self, which: UmashComponent) -> u64 {
        self.hash[which as usize]
    }
}

/// A [`Hasher`] implements one of the two hash 64-bit functions
/// defined by a specific [`Params`] struct, further tweaked by a
/// seed.  Construct [`Hasher`]s with [`Params::hasher`],
/// [`Params::secondary_hasher`], or [`Params::component_hasher`].
///
/// The hash value is a function of the [`Params`], the
/// [`UmashComponent`], the seed, and of the bytes written to the
/// [`Hasher`], but independent of the size of the individual slices
/// written to the hasher.
///
/// In other words, it doesn't matter how we partition an input, the
/// [`Hasher`] computes the same hash value as a one-shot UMASH call
/// for the parameters and the concatenated input bytes.
#[derive(Clone)]
pub struct Hasher<'params>(ffi::umash_state, PhantomData<&'params Params>);

/// A [`Fingerprinter` implements the 128-bit fingerprinting function
/// defined by a specific [`Params`] struct, further tweaked by a seed.
/// Construct [`Fingerprinter`]s with [`Params::fingerprinter`].
///
/// The fingerprint value is a function of the [`Params`], the seed,
/// and of the bytes written to the [`Fingerprinter`, but independent
/// of the size of the individual slices written to the hasher.
///
/// In other words, it doesn't matter how we partition an input, the
/// [`Fingerprinter`] computes the same fingerprint as a one-shot
/// UMASH call for the parameters and the concatenated input bytes.
///
/// The two 64-bit value in the resulting fingerprint are equivalent
/// to the value computed by the 64-bit UMASH functions for the same
/// [`Params`], seed, and inputs, with [`UmashComponent::Hash`] for the
/// `Fingerprint::hash[0]`, and with [`UmashComponent::Secondary`] for
/// `Fingerprint::hash[1]`.
///
/// When used as a [`std::hash::Hasher`], the hash value computed by a
/// [`Fingerprinter`] is equivalent to the [`Hasher`] for
/// [`UmashComponent::Hash`].  That's not useful in itself, but it
/// makes sense to pass a [`Fingerprinter`] to a `std::hash::Hash`,
/// and extract a [`Fingerprint`] for the input data with
/// [`Fingerprinter::digest`].
#[derive(Clone)]
pub struct Fingerprinter<'params>(ffi::umash_fp_state, PhantomData<&'params Params>);

impl Params {
    /// Returns a new pseudo-unique [`Params`] value.
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

    /// Returns a fresh set of [`Params`] derived deterministically
    /// from `bits` and the first 32 bytes in `key`.
    ///
    /// The UMASH function defined by the resulting [`Params`] will
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

    /// Returns a [`Hasher`] for the primary UMASH function.
    ///
    /// The `seed` tweaks the hash value without any proven impact on
    /// collision rates for different seed values.
    #[inline(always)]
    pub fn hasher(&self, seed: u64) -> Hasher {
        self.component_hasher(seed, UmashComponent::Hash)
    }

    /// Returns a [`Hasher`] for the secondary UMASH function.
    ///
    /// The `seed` tweaks the hash value without any proven impact on
    /// collision rates for different seed values.
    #[inline(always)]
    pub fn secondary_hasher(&self, seed: u64) -> Hasher {
        self.component_hasher(seed, UmashComponent::Secondary)
    }

    /// Returns a [`Hasher`] for the desired UMASH component (primary
    /// hash or secondary function).
    ///
    /// The `seed` tweaks the hash value without any proven impact on
    /// collision rates for different seed values.
    #[inline(always)]
    pub fn component_hasher(&self, seed: u64, which: UmashComponent) -> Hasher {
        Hasher::with_params(self, seed, which)
    }

    /// Returns a [`Fingerprinter`] for the UMASH function.
    ///
    /// The `seed` tweaks the hash value without any proven impact on
    /// collision rates for different seed values.
    #[inline(always)]
    pub fn fingerprinter(&self, seed: u64) -> Fingerprinter {
        Fingerprinter::with_params(self, seed)
    }

    /// Computes the [`UmashComponent::Hash`] value defined by this
    /// set of UMASH params for `object` and `seed = 0`.
    pub fn hash(&self, object: impl std::hash::Hash) -> u64 {
        let mut hasher = self.hasher(0);
        object.hash(&mut hasher);
        hasher.digest()
    }

    /// Computes the [`UmashComponent::Secondary`] hash value defined
    /// by this set of UMASH params for `object` and `seed = 0`.
    pub fn secondary(&self, object: impl std::hash::Hash) -> u64 {
        let mut hasher = self.secondary_hasher(0);
        object.hash(&mut hasher);
        hasher.digest()
    }

    /// Computes the fingerprint value defined by this set of UMASH
    /// params for `object` and `seed = 0`.
    pub fn fingerprint(&self, object: impl std::hash::Hash) -> Fingerprint {
        let mut hasher = self.fingerprinter(0);
        object.hash(&mut hasher);
        hasher.digest()
    }
}

impl Default for Params {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> std::hash::BuildHasher for &'a Params {
    type Hasher = Hasher<'a>;

    fn build_hasher(&self) -> Hasher<'a> {
        (*self).into()
    }
}

impl<'a> Hasher<'a> {
    /// Returns a fresh hashing state for the UMASH function described
    /// by `params`.  The `which` argument determines whether the
    /// primary hash or the secondary disambiguation value will be
    /// computed.
    ///
    /// Passing different values for `seed` will yield different hash
    /// values, albeit without any statistical bound on collisions.
    #[inline(always)]
    fn with_params(params: &'a Params, seed: u64, which: UmashComponent) -> Self {
        let mut state = Hasher(unsafe { std::mem::zeroed() }, PhantomData);

        unsafe {
            ffi::umash_init(&mut state.0, &params.0, seed, which as i32);
        }

        state
    }

    /// Updates the hash state by conceptually concatenating `bytes`
    /// to the hash input.
    #[inline(always)]
    pub fn write(&mut self, bytes: &[u8]) -> &mut Self {
        unsafe {
            ffi::umash_sink_update(
                &mut self.0.sink,
                bytes.as_ptr() as *const _,
                bytes.len() as u64,
            );
        }

        self
    }

    /// Returns the 64-bit hash value for the [`Hasher`]'s [`Params`]
    /// and the bytes passed to [`Hasher::write`] so far.
    #[inline(always)]
    pub fn digest(&self) -> u64 {
        unsafe { ffi::umash_digest(&self.0) }
    }
}

impl<'a> From<&'a Params> for Hasher<'a> {
    #[inline(always)]
    fn from(params: &'a Params) -> Hasher<'a> {
        params.hasher(0)
    }
}

impl std::hash::Hasher for Hasher<'_> {
    #[inline(always)]
    fn finish(&self) -> u64 {
        self.digest()
    }

    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) {
        Self::write(self, bytes);
    }
}

impl std::io::Write for Hasher<'_> {
    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        Self::write(self, bytes);
        Ok(bytes.len())
    }

    #[inline(always)]
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> Fingerprinter<'a> {
    /// Returns a fresh fingerprinting state for the UMASH function
    /// described by `params`.
    ///
    /// Passing different values for `seed` will yield different
    /// fingerprint values, albeit without any statistical bound on
    /// collisions.
    #[inline(always)]
    fn with_params(params: &'a Params, seed: u64) -> Self {
        let mut state = Self(unsafe { std::mem::zeroed() }, PhantomData);

        unsafe {
            ffi::umash_fp_init(&mut state.0, &params.0, seed);
        }

        state
    }

    /// Updates the fingerprinting state by conceptually concatenating
    /// `bytes` to the fingerprint input.
    #[inline(always)]
    pub fn write(&mut self, bytes: &[u8]) -> &mut Self {
        unsafe {
            ffi::umash_sink_update(
                &mut self.0.sink,
                bytes.as_ptr() as *const _,
                bytes.len() as u64,
            );
        }

        self
    }

    /// Returns the 128-bit fingerprint value for the
    /// [`Fingerprinter`]'s [`Params`] and the bytes passed to
    /// [`Fingerprinter::write`] so far.
    #[inline(always)]
    pub fn digest(&self) -> Fingerprint {
        let fprint = unsafe { ffi::umash_fp_digest(&self.0) };

        Fingerprint { hash: fprint.hash }
    }
}

impl<'a> From<&'a Params> for Fingerprinter<'a> {
    #[inline(always)]
    fn from(params: &'a Params) -> Fingerprinter<'a> {
        params.fingerprinter(0)
    }
}

impl std::hash::Hasher for Fingerprinter<'_> {
    #[inline(always)]
    fn finish(&self) -> u64 {
        self.digest().hash()
    }

    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) {
        Self::write(self, bytes);
    }
}

impl std::io::Write for Fingerprinter<'_> {
    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        Self::write(self, bytes);
        Ok(bytes.len())
    }

    #[inline(always)]
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{Fingerprint, Fingerprinter, Params, UmashComponent};

    #[test]
    fn test_example_case() {
        let key = b"hello example.c";
        let input = b"the quick brown fox";
        let seed = 42u64;
        let my_params = Params::derive(0, key);
        let fprint = my_params.fingerprinter(seed).write(input).digest();

        assert_eq!(
            fprint,
            Fingerprint::new(0x398c5bb5cc113d03, 0x3a52693519575aba)
        );

        assert_eq!(fprint.hash(), 0x398c5bb5cc113d03);
        assert_eq!(fprint.secondary(), 0x3a52693519575aba);
        assert_eq!(fprint.component(UmashComponent::Hash), 0x398c5bb5cc113d03);
        assert_eq!(
            fprint.component(UmashComponent::Secondary),
            0x3a52693519575aba
        );
    }

    #[test]
    fn test_example_case_hashers() {
        use std::hash::Hasher as StdHasher;

        let key = b"hello example.c";
        let input = b"the quick brown fox";
        let seed = 42u64;
        let params = Params::derive(0, key);

        let mut hasher = params.hasher(seed);
        let mut secondary = params.secondary_hasher(seed);
        let mut fprint = params.fingerprinter(seed);

        hasher.write(input);
        secondary.write(input);
        fprint.write(input);

        assert_eq!(hasher.finish(), 0x398c5bb5cc113d03);
        assert_eq!(secondary.finish(), 0x3a52693519575aba);
        assert_eq!(
            fprint.digest(),
            Fingerprint::new(0x398c5bb5cc113d03, 0x3a52693519575aba)
        );
    }

    #[test]
    fn test_example_case_with_separate_params() {
        use std::hash::Hasher as StdHasher;

        let params = Params::derive(0, b"hello example.c");
        let mut h = params.component_hasher(42, UmashComponent::Hash);

        StdHasher::write(&mut h, b"the quick brown fox");
        assert_eq!(h.finish(), 0x398c5bb5cc113d03);
    }

    #[test]
    fn test_secondary_example_case_with_separate_params() {
        use std::io::Write;

        let params = Params::derive(0, b"hello example.c");
        let mut h = params.component_hasher(42, UmashComponent::Secondary);

        let message = b"the quick brown fox";
        assert_eq!(
            Write::write(&mut h, message).expect("must succeed"),
            message.len()
        );

        assert_eq!(h.digest(), 0x3a52693519575aba);
        h.flush().expect("must succeed");
        assert_eq!(h.digest(), 0x3a52693519575aba);
    }

    #[test]
    fn test_another_case_with_separate_params() {
        use std::hash::Hasher as StdHasher;

        let params = Params::derive(0, b"backtrace");
        let mut h = params.fingerprinter(0xcd03);
        StdHasher::write(&mut h, b"the quick brown fox");
        assert_eq!(h.finish(), 0x931972393b291c81);
    }

    #[test]
    fn test_another_case_with_separate_params_as_write() {
        use std::io::Write;

        let params = Params::derive(0, b"backtrace");
        let mut h = params.fingerprinter(0xcd03);

        let message = b"the quick brown fox";
        assert_eq!(
            Write::write(&mut h, message).expect("must succeed"),
            message.len()
        );

        assert_eq!(
            h.digest(),
            Fingerprint::new(10599628788124425345, 10827422672915900785)
        );
        h.flush().expect("must succeed");
        assert_eq!(
            h.digest(),
            Fingerprint::new(10599628788124425345, 10827422672915900785)
        );
    }

    #[test]
    fn test_into_fingerprinter_as_hasher() {
        use std::hash::Hasher as StdHasher;

        let params = Params::derive(0, b"backtrace");
        let mut h: Fingerprinter = (&params).into();
        StdHasher::write(&mut h, b"the quick brown fox");
        assert_eq!(h.finish(), 3130985775916891977);
    }

    #[test]
    fn test_simple_hashes() {
        let params: Params = Default::default();
        let hash = params.hash(100i32);
        let secondary = params.secondary(100i32);
        let fingerprint = params.fingerprint(100i32);

        assert_ne!(hash, secondary);
        assert_eq!(fingerprint, Fingerprint::new(hash, secondary));
    }

    #[test]
    fn test_hash_map() {
        use std::collections::HashMap;

        let params = Params::new();
        let mut map: HashMap<i32, i32, _> = HashMap::with_hasher(&params);

        map.insert(1, 2);
        assert_eq!(map.get(&1), Some(&2));
    }
}
