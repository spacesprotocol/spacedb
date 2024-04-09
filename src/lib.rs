#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

pub mod path;
#[cfg(test)]
pub mod path_test;
pub mod subtree;

#[cfg(feature = "std")]
pub mod node;

#[cfg(feature = "std")]
pub mod db;

#[cfg(feature = "std")]
pub mod tx;

#[cfg(feature = "std")]
pub mod fs;

#[cfg(feature = "std")]
pub(crate) const ZERO_HASH: Hash = [0; 32];

use core::marker::PhantomData;
use sha2::{Digest as _, Sha256};

pub type Hash = [u8; 32];

const LEAF_TAG: u8 = 0x00;
const INTERNAL_TAG: u8 = 0x01;

#[derive(Clone)]
pub struct Sha256Hasher;

const DEFAULT_CACHE_SIZE: usize = 1024 * 1024 * 1024; /* 1GB */

#[derive(Clone, Debug)]
pub struct Configuration<Hasher: NodeHasher> {
    pub cache_size: usize,
    _marker: PhantomData<Hasher>,
}

impl<Hasher: NodeHasher> Configuration<Hasher> {
    pub fn new() -> Self {
        Self {
            cache_size: DEFAULT_CACHE_SIZE,
            _marker: PhantomData,
        }
    }

    pub fn with_cache_size(mut self, size: usize) -> Self {
        self.cache_size = size;
        self
    }
}

pub trait NodeHasher: Clone {
    fn hash(data: &[u8]) -> Hash;
    fn hash_leaf(key: &[u8], value_hash: &[u8]) -> Hash;
    fn hash_internal(prefix: &[u8], left: &[u8], right: &[u8]) -> Hash;
}

impl Configuration<Sha256Hasher> {
    pub fn standard() -> Self {
        Self::new().with_cache_size(DEFAULT_CACHE_SIZE)
    }
}

impl NodeHasher for Sha256Hasher {
    fn hash(data: &[u8]) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().as_slice().try_into().unwrap()
    }

    fn hash_leaf(key: &[u8], value_hash: &[u8]) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update([LEAF_TAG]);
        hasher.update(&key);
        hasher.update(&value_hash);
        hasher.finalize().as_slice().try_into().unwrap()
    }

    fn hash_internal(prefix: &[u8], left: &[u8], right: &[u8]) -> Hash {
        let mut hasher = Sha256::new();

        hasher.update([INTERNAL_TAG]);
        let bit_len = prefix[0];
        hasher.update([bit_len]);
        hasher.update(&prefix[1..]);
        hasher.update(left);
        hasher.update(right);

        hasher.finalize().as_slice().try_into().unwrap()
    }
}
