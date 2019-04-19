## CITA-Trie

[![Latest Version](https://img.shields.io/crates/v/cita_trie.svg)](https://crates.io/crates/cita_trie)
[![](https://travis-ci.org/cryptape/cita-trie.svg?branch=master)](https://travis-ci.org/cryptape/cita-trie)
[![](https://img.shields.io/hexpm/l/plug.svg)](https://github.com/cryptape/cita-trie/blob/master/LICENSE)

Rust implementation of the Modified Patricia Tree (aka Trie),

The implementation is strongly inspired by [go-ethereum trie](https://github.com/ethereum/go-ethereum/tree/master/trie)

## Features

- Implementation of the Modified Patricia Tree
- Custom decoder (RLP is provided by default)
- Custom storage interface

## Interfaces

### DB

```rust
pub trait DB: Send + Sync {
    type Error: Error;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;
    fn insert(&self, key: &[u8], value: &[u8]) -> Result<(), Self::Error>;
    fn contains(&self, key: &[u8]) -> Result<bool, Self::Error>;
    fn remove(&self, key: &[u8]) -> Result<(), Self::Error>;
}
```

### Decoder

```rust
pub trait NodeCodec: Sized + Clone {
    type Error: ::std::error::Error;

    const HASH_LENGTH: usize;

    type Hash: AsRef<[u8]>
        + AsMut<[u8]>
        + Default
        + PartialEq
        + Eq
        + hash::Hash
        + Send
        + Sync
        + Clone;

    fn decode<F, T>(&self, data: &[u8], f: F) -> Result<T, Self::Error>
    where
        F: Fn(DataType) -> Result<T, Self::Error>;

    fn encode_empty(&self) -> Vec<u8>;
    fn encode_pair(&self, key: &[u8], value: &[u8]) -> Vec<u8>;
    fn encode_values(&self, values: &[Vec<u8>]) -> Vec<u8>;
    fn encode_raw(&self, raw: &[u8]) -> Vec<u8>;

    fn decode_hash(&self, data: &[u8], is_hash: bool) -> Self::Hash;
}
```

## Example

### Use the RLP decoder

```rust
use std::sync::Arc;
use cita_trie::codec::RLPNodeCodec;
use cita_trie::db::MemoryDB;
use cita_trie::trie::{PatriciaTrie, Trie};

fn main() {
    let memdb = Arc::new(MemoryDB::new(true));
    let key = "test-key".as_bytes();
    let value = "test-value".as_bytes();

    let root = {
        let mut trie = PatriciaTrie::new(Arc::clone(&memdb), RLPNodeCodec::default());
        trie.insert(key, value).unwrap();

        let v = trie.get(key).unwrap();
        assert_eq!(Some(value.to_vec()), v);
        trie.root().unwrap()
    };

    let mut trie = PatriciaTrie::from(Arc::clone(memdb), RLPNodeCodec::default(), &root).unwrap();
    let exists = trie.contains(key).unwrap();
    assert_eq!(exists, true);
    let removed = trie.remove(key).unwrap();
    assert_eq!(removed, true);
    let new_root = trie.root().unwrap();
    println!("new root = {:?}", new_root);

}

```

### Custom decoder

Refer to RLPCodec in `src/codec.rs`

## Why not use parity/trie

Because the `parity/trie` code is too difficult to understand, and the user needs to know the details of the trie to implement the decoder.

`CITA-trie` is more user-friendly, users can easily implement custom decoders without paying attention to trie implementation details, and provide an implementation of RLP by default.

However, this project is currently not perfect, stability and performance testing has not been done, it is not recommended to use in production environments
