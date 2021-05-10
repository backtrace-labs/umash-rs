use std::hash;
use std::marker::PhantomData;
use std::os::raw::c_void;

use crate::{ffi, Params, State};

lazy_static::lazy_static! {
    static ref DEFAULT_PARAMS: Params = Params::derive(0, "hello example.c");
}

pub struct Hasher<'a> {
    params: PhantomData<&'a Params>,
    state: State,
}

impl<'a> Hasher<'a> {
    pub fn with_params(params: &'a Params, seed: u64) -> Self {
        Self {
            params: PhantomData,
            state: State::init(&params, seed, 0),
        }
    }

    pub fn new() -> Self {
        Self::with_params(&DEFAULT_PARAMS, 42u64)
    }
}

impl hash::Hasher for Hasher<'_> {
    fn finish(&self) -> u64 {
        unsafe { ffi::umash_digest(&self.state.0) }
    }

    fn write(&mut self, bytes: &[u8]) {
        let bytes_ptr: *const c_void = bytes.as_ptr() as *const _ as *const c_void;
        unsafe {
            ffi::umash_sink_update(&mut self.state.0.sink, bytes_ptr, bytes.len() as u64);
        }
    }
}

impl Default for Hasher<'_> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::Params;
    use std::hash::Hasher;

    #[test]
    fn test_example_case() {
        let mut h = super::Hasher::new();
        h.write(b"the quick brown fox");
        assert_eq!(h.finish(), 0x398c5bb5cc113d03);
    }

    #[test]
    fn test_example_case_with_separate_params() {
        let params = Params::derive(0, "hello example.c");
        let mut h = super::Hasher::with_params(&params, 42u64);
        h.write(b"the quick brown fox");
        assert_eq!(h.finish(), 0x398c5bb5cc113d03);
    }

    #[test]
    fn test_another_case_with_separate_params() {
        let params = Params::derive(0, "backtrace");
        let mut h = super::Hasher::with_params(&params, 0xcd03);
        h.write(b"the quick brown fox");
        assert_eq!(h.finish(), 0x931972393b291c81);
    }
}
