use std::collections::HashMap;
use std::error::Error;
use std::fmt::Debug;
use std::sync::RwLock;

use crate::errors::MemDBError;

pub trait DB: Send + Sync + Debug {
    type Error: Error;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;
    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), Self::Error>;
    fn contains(&self, key: &[u8]) -> Result<bool, Self::Error>;
    fn remove(&mut self, key: &[u8]) -> Result<(), Self::Error>;
}

#[derive(Default, Debug)]
pub struct MemoryDB {
    storage: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
}

impl MemoryDB {
    pub fn new() -> Self {
        MemoryDB {
            storage: RwLock::new(HashMap::new()),
        }
    }
}

impl DB for MemoryDB {
    type Error = MemDBError;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        if let Some(value) = self.storage.read().unwrap().get(key) {
            Ok(Some(value.clone()))
        } else {
            Ok(None)
        }
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        self.storage
            .write()
            .unwrap()
            .insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn contains(&self, key: &[u8]) -> Result<bool, Self::Error> {
        Ok(self.storage.read().unwrap().contains_key(key))
    }

    fn remove(&mut self, key: &[u8]) -> Result<(), Self::Error> {
        self.storage.write().unwrap().remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memdb_get() {
        let mut memdb = MemoryDB::new();
        memdb.insert(b"test-key", b"test-value").unwrap();
        let v = memdb.get(b"test-key").unwrap().unwrap();

        assert_eq!(v, b"test-value")
    }

    #[test]
    fn test_memdb_contains() {
        let mut memdb = MemoryDB::new();
        memdb.insert(b"test", b"test").unwrap();

        let contains = memdb.contains(b"test").unwrap();
        assert_eq!(contains, true)
    }

    #[test]
    fn test_memdb_remove() {
        let mut memdb = MemoryDB::new();
        memdb.insert(b"test", b"test").unwrap();

        memdb.remove(b"test").unwrap();
        let contains = memdb.contains(b"test").unwrap();
        assert_eq!(contains, false)
    }
}
