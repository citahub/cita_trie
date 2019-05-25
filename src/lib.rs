//! ## Usage
//!
//! ```rust
//! use std::sync::Arc;

//! use cita_trie::MemoryDB;
//! use cita_trie::{PatriciaTrie, Trie};
//! use cita_trie::Keccak256Hash;

//! fn main() {
//!     let memdb = Arc::new(MemoryDB::new(true));
//!
//!     let key = "test-key".as_bytes();
//!     let value = "test-value".as_bytes();
//!
//!     let root = {
//!         let mut trie = PatriciaTrie::<_, Keccak256Hash>::new(Arc::clone(&memdb));
//!         trie.insert(key.to_vec(), value.to_vec()).unwrap();
//!
//!         let v = trie.get(key).unwrap();
//!         assert_eq!(Some(value.to_vec()), v);
//!         trie.root().unwrap()
//!     };
//!
//!     let mut trie = PatriciaTrie::<_, Keccak256Hash>::from(Arc::clone(&memdb), &root).unwrap();
//!     let exists = trie.contains(key).unwrap();
//!     assert_eq!(exists, true);
//!     let removed = trie.remove(key).unwrap();
//!     assert_eq!(removed, true);
//!     let new_root = trie.root().unwrap();
//!     println!("new root = {:?}", new_root);
//!
//! }
//! ```

mod nibbles;
mod node;
mod tests;

mod db;
mod errors;
mod trie;

pub use db::{MemoryDB, DB};
pub use errors::{MemDBError, TrieError};
pub use trie::{PatriciaTrie, Trie};

pub trait Hasher {
    const LENGTH: usize;

    fn digest(data: &[u8]) -> Vec<u8>;
}

pub struct Keccak256Hash;

impl Hasher for Keccak256Hash {
    const LENGTH: usize = 32;

    fn digest(data: &[u8]) -> Vec<u8> {
        tiny_keccak::keccak256(data).to_vec()
    }
}
