## CITA-Trie

Rust implementation of the Modified Patricia Tree (aka Trie),

The implementation is strongly inspired by [go-ethereum trie](https://github.com/ethereum/go-ethereum/tree/master/trie)

## Features

- Implementation of the Modified Patricia Tree
- Custom decoder (RLP is provided by default)
- Custom storage interface

## Interfaces

### DB

```rust
pub trait DB: Send + Sync + Debug {
    type Error: Error;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;
    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), Self::Error>;
    fn contains(&self, key: &[u8]) -> Result<bool, Self::Error>;
    fn remove(&mut self, key: &[u8]) -> Result<(), Self::Error>;
}
```

### Decoder

```rust
pub trait NodeCodec: Sized + Debug {
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
        + Clone
        + Copy;

    fn decode<F, T>(&self, data: &[u8], f: F) -> Result<T, Self::Error>
    where
        F: Fn(DataType) -> Result<T, Self::Error>;

    fn encode_empty(&self) -> Vec<u8>;
    fn encode_pair(&self, key: &[u8], value: &[u8]) -> Vec<u8>;
    fn encode_values(&self, values: &[Vec<u8>]) -> Vec<u8>;

    fn decode_hash(&self, data: &[u8], is_hash: bool) -> Self::Hash;
}
```

## Example

### Use the RLP decoder

```rust
use cita_trie::codec::RLPNodeCodec;
use cita_trie::db::MemoryDB;
use cita_trie::trie::{PatriciaTrie, Trie};

fn main() {
    let mut memdb = MemoryDB::new();
    let key = "test-key".as_bytes();
    let value = "test-value".as_bytes();

    let root = {
        let mut trie = PatriciaTrie::new(&mut memdb, RLPNodeCodec::default());
        trie.insert(key, value).unwrap();

        let v = trie.get(key).unwrap();
        assert_eq!(Some(value.to_vec()), v);
        trie.root().unwrap()
    };

    let mut trie = PatriciaTrie::from(&mut memdb, RLPNodeCodec::default(), root).unwrap();
    let exists = trie.contains(key).unwrap();
    assert_eq!(exists, true);
    let removed = trie.remove(key).unwrap();
    assert_eq!(removed, true);
    let new_root = trie.root().unwrap();
    println!("new root = {:?}", new_root);

}

```

### Custom

```rust
use std::hash;

use rlp::{Prototype, Rlp, RlpStream};
use sha3::{Digest, Sha3_256};

#[derive(Default, Debug)]
pub struct RLPNodeCodec {}

impl NodeCodec for RLPNodeCodec {
    type Error = RLPCodecError;

    const HASH_LENGTH: usize = 32;

    type Hash = [u8; 32];

    fn decode<F, T>(&self, data: &[u8], f: F) -> Result<T, Self::Error>
    where
        F: Fn(DataType) -> Result<T, Self::Error>,
    {
        let r = Rlp::new(data);
        match r.prototype()? {
            Prototype::Data(0) => Ok(f(DataType::Empty)?),
            Prototype::List(2) => {
                let key = r.at(0)?.data()?;
                let value = r.at(1)?.data()?;

                Ok(f(DataType::Pair(&key, &value))?)
            }
            _ => Ok(f(DataType::Values(&r.as_list()?))?),
        }
    }

    fn encode_empty(&self) -> Vec<u8> {
        let mut stream = RlpStream::new();
        stream.append_empty_data();
        stream.out()
    }

    fn encode_pair(&self, key: &[u8], value: &[u8]) -> Vec<u8> {
        let mut stream = RlpStream::new_list(2);
        stream.append(&key);
        stream.append(&value);
        stream.out()
    }

    fn encode_values(&self, values: &[Vec<u8>]) -> Vec<u8> {
        let mut stream = RlpStream::new_list(values.len());
        for data in values {
            stream.append(data);
        }
        stream.out()
    }

    fn decode_hash(&self, data: &[u8], is_hash: bool) -> Self::Hash {
        let mut out = [0u8; Self::HASH_LENGTH];
        if is_hash {
            out.copy_from_slice(data);
        } else {
            out.copy_from_slice(&Sha3_256::digest(data));
        }
        out
    }
}
```
