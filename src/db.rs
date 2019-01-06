use std::collections::HashMap;
use std::error::Error;
use std::sync::RwLock;
use std::fmt::Debug;

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
        if let Some(value) = self.storage.read().unwrap().get(&key.to_vec()) {
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
        Ok(self.storage.read().unwrap().contains_key(&key.to_vec()))
    }

    fn remove(&mut self, key: &[u8]) -> Result<(), Self::Error> {
        self.storage.write().unwrap().remove(&key.to_vec());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memdb_get() {
        let mut memdb = MemoryDB::new();
        memdb
            .insert("test-key".as_bytes(), "test-value".as_bytes())
            .unwrap();
        let v = memdb.get("test-key".as_bytes()).unwrap().unwrap();

        assert_eq!(v, "test-value".as_bytes())
    }

    #[test]
    fn test_memdb_contains() {
        let mut memdb = MemoryDB::new();
        memdb.insert("test".as_bytes(), "test".as_bytes()).unwrap();

        let contains = memdb.contains("test".as_bytes()).unwrap();
        assert_eq!(contains, true)
    }

    #[test]
    fn test_memdb_remove() {
        let mut memdb = MemoryDB::new();
        memdb.insert("test".as_bytes(), "test".as_bytes()).unwrap();

        memdb.remove("test".as_bytes()).unwrap();
        let contains = memdb.contains("test".as_bytes()).unwrap();
        assert_eq!(contains, false)
    }
}
