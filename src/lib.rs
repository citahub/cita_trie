//! ## Usage
//!
//! ```rust
//! use std::sync::Arc;
//!
//! use hasher::{Hasher, HasherKeccak}; // https://crates.io/crates/hasher
//!
//! use cita_trie::MemoryDB;
//! use cita_trie::{PatriciaTrie, Trie};

//! fn main() {
//!     let memdb = Arc::new(MemoryDB::new(true));
//!     let hasher = Arc::new(HasherKeccak::new());
//!
//!     let key = "test-key".as_bytes();
//!     let value = "test-value".as_bytes();
//!
//!     let root = {
//!         let mut trie = PatriciaTrie::new(Arc::clone(&memdb), Arc::clone(&hasher));
//!         trie.insert(key.to_vec(), value.to_vec()).unwrap();
//!
//!         let v = trie.get(key).unwrap();
//!         assert_eq!(Some(value.to_vec()), v);
//!         trie.root().unwrap()
//!     };
//!
//!     let mut trie = PatriciaTrie::from(Arc::clone(&memdb), Arc::clone(&hasher), &root).unwrap();
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
