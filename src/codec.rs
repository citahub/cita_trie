use std::fmt::Debug;
use std::hash;

use rlp::{Prototype, Rlp, RlpStream};
use sha3::{Digest, Sha3_256};

use crate::errors::RLPCodecError;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DataType<'a> {
    Empty,
    Pair(&'a [u8], &'a [u8]),
    Values(&'a [Vec<u8>]),
}

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
        + Clone;

    fn decode<F, T>(&self, data: &[u8], f: F) -> Result<T, Self::Error>
    where
        F: Fn(DataType) -> Result<T, Self::Error>;

    fn encode_empty(&self) -> Vec<u8>;
    fn encode_pair(&self, key: &[u8], value: &[u8]) -> Vec<u8>;
    fn encode_values(&self, values: &[Vec<u8>]) -> Vec<u8>;

    fn decode_hash(&self, data: &[u8], is_hash: bool) -> Self::Hash;
}

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
