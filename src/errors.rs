use std::error::Error;
use std::fmt;

use rlp::DecoderError;

#[derive(Debug)]
pub enum TrieError {
    DB(String),
    Decoder(DecoderError),
    InvalidData,
    InvalidStateRoot,
    InvalidProof,
    Invariant(String),
}

impl Error for TrieError {}

impl fmt::Display for TrieError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let printable = match *self {
            TrieError::DB(ref err) => format!("trie error: {:?}", err),
            TrieError::Decoder(ref err) => format!("trie error: {:?}", err),
            TrieError::InvalidData => "trie error: invali data".to_owned(),
            TrieError::InvalidStateRoot => "trie error: invali state root".to_owned(),
            TrieError::InvalidProof => "trie error: invali proof".to_owned(),
        };
        write!(f, "{}", printable)
    }
}

impl From<DecoderError> for TrieError {
    fn from(error: DecoderError) -> Self {
        TrieError::Decoder(error)
    }
}

#[derive(Debug)]
pub enum MemDBError {}

impl Error for MemDBError {}

impl fmt::Display for MemDBError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "error")
    }
}
