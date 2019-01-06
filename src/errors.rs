use std::error::Error;
use std::fmt;

use crate::codec::NodeCodec;
use crate::db::DB;

#[derive(Debug)]
pub enum TrieError<C: NodeCodec, D: DB> {
    NodeCodec(C::Error),
    DB(D::Error),
    InvalidStateRoot,
}

impl<C, D> Error for TrieError<C, D>
where
    C: NodeCodec,
    D: DB,
{
    fn description(&self) -> &str {
        match *self {
            TrieError::NodeCodec(_) => "node codec error",
            TrieError::DB(_) => "db error",
            TrieError::InvalidStateRoot => "invalid state root",
        }
    }
}

impl<C, D> fmt::Display for TrieError<C, D>
where
    C: NodeCodec,
    D: DB,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let printable = match *self {
            TrieError::NodeCodec(ref err) => format!("node codec err: {:?}", err),
            TrieError::DB(ref err) => format!("db err: {:?}", err),
            TrieError::InvalidStateRoot => format!("invalid state root"),
        };
        write!(f, "{}", printable)
    }
}

// impl<C, D> From<C> for TrieError<C, D>
// where
//     C: NodeCodec,
//     D: DB,
// {
//     fn from(error: C::Error) -> Self {
//         TrieError::NodeCodec(error)
//     }
// }
//
// impl<C, D> From<C> for TrieError<C, D>
// where
//     C: NodeCodec,
//     D: DB,
// {
//     fn from(error: D::Error) -> Self {
//         TrieError::DB(error)
//     }
// }

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MemDBError {}

impl Error for MemDBError {
    fn description(&self) -> &str {
        "mem db error"
    }
}

impl fmt::Display for MemDBError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "error")
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RLPCodecError {
    Decode(rlp::DecoderError),
    InvalidData,
}

impl Error for RLPCodecError {
    fn description(&self) -> &str {
        "mem db error"
    }
}

impl fmt::Display for RLPCodecError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let printable = match *self {
            RLPCodecError::Decode(ref err) => format!("rlp decode {}", err),
            RLPCodecError::InvalidData => "invalid data".to_string(),
        };
        write!(f, "{}", printable)
    }
}

impl From<rlp::DecoderError> for RLPCodecError {
    fn from(error: rlp::DecoderError) -> Self {
        RLPCodecError::Decode(error)
    }
}
