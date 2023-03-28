use std::collections::HashMap;
use std::io::Error;
use std::sync::Arc;

use parking_lot::RwLock;

/// "DB" defines the "trait" of trie and database interaction.
/// You should first write the data to the cache and write the data
/// to the database in bulk after the end of a set of operations.
pub trait DB {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error>;

    fn contains(&self, key: &[u8]) -> Result<bool, Error>;

    /// Insert data into the cache.
    fn insert(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), Error>;

    /// Insert data into the cache.
    fn remove(&self, key: &[u8]) -> Result<(), Error>;

    /// Insert a batch of data into the cache.
    fn insert_batch(&self, keys: Vec<Vec<u8>>, values: Vec<Vec<u8>>) -> Result<(), Error> {
        for i in 0..keys.len() {
            let key = keys[i].clone();
            let value = values[i].clone();
            self.insert(key, value)?;
        }
        Ok(())
    }

    /// Remove a batch of data into the cache.
    fn remove_batch(&self, keys: &[Vec<u8>]) -> Result<(), Error> {
        for key in keys {
            self.remove(key)?;
        }
        Ok(())
    }

    /// Flush data to the DB from the cache.
    fn flush(&self) -> Result<(), Error>;

    #[cfg(test)]
    fn len(&self) -> Result<usize, Error>;
    #[cfg(test)]
    fn is_empty(&self) -> Result<bool, Error>;
}

// cross DB is raw DB
pub trait CDB: DB + Sync + Send {}

#[derive(Default, Clone, Debug)]
pub struct MemoryDB {
    // If "light" is true, the data is deleted from the database at the time of submission.
    light: bool,
    storage: Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>,
}

impl MemoryDB {
    pub fn new(light: bool) -> Self {
        MemoryDB {
            light,
            storage: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Creates a of the instance.
    pub fn deep_clone(&self) -> Self {
        let storage = self.storage.read();

        Self {
            light: self.light,
            storage: Arc::new(RwLock::new(storage.clone())),
        }
    }
}

impl DB for MemoryDB {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        if let Some(value) = self.storage.read().get(key) {
            Ok(Some(value.clone()))
        } else {
            Ok(None)
        }
    }

    fn insert(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), Error> {
        self.storage.write().insert(key, value);
        Ok(())
    }

    fn contains(&self, key: &[u8]) -> Result<bool, Error> {
        Ok(self.storage.read().contains_key(key))
    }

    fn remove(&self, key: &[u8]) -> Result<(), Error> {
        if self.light {
            self.storage.write().remove(key);
        }
        Ok(())
    }

    fn flush(&self) -> Result<(), Error> {
        Ok(())
    }

    #[cfg(test)]
    fn len(&self) -> Result<usize, Error> {
        Ok(self.storage.try_read().unwrap().len())
    }
    #[cfg(test)]
    fn is_empty(&self) -> Result<bool, Error> {
        Ok(self.storage.try_read().unwrap().is_empty())
    }
}

impl CDB for MemoryDB {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memdb_deep_clone() {
        const KEY: &[u8] = b"test-key";
        const VALUE: &[u8] = b"test-value";

        let memdb1 = MemoryDB::new(true);
        memdb1.insert(KEY.to_vec(), VALUE.to_vec()).unwrap();

        let memdb2 = memdb1.deep_clone();

        let v1 = memdb1.get(KEY).unwrap().unwrap();
        let v2 = memdb2.get(KEY).unwrap().unwrap();

        assert_eq!(v1, v2);

        memdb2.remove(KEY).unwrap();

        assert_eq!(memdb1.get(KEY).unwrap().unwrap(), VALUE);
        assert!(memdb2.get(KEY).unwrap().is_none());
    }

    #[test]
    fn test_memdb_get() {
        let memdb = MemoryDB::new(true);
        memdb
            .insert(b"test-key".to_vec(), b"test-value".to_vec())
            .unwrap();
        let v = memdb.get(b"test-key").unwrap().unwrap();

        assert_eq!(v, b"test-value")
    }

    #[test]
    fn test_memdb_contains() {
        let memdb = MemoryDB::new(true);
        memdb.insert(b"test".to_vec(), b"test".to_vec()).unwrap();

        let contains = memdb.contains(b"test").unwrap();
        assert!(contains)
    }

    #[test]
    fn test_memdb_remove() {
        let memdb = MemoryDB::new(true);
        memdb.insert(b"test".to_vec(), b"test".to_vec()).unwrap();

        memdb.remove(b"test").unwrap();
        let contains = memdb.contains(b"test").unwrap();
        assert!(!contains)
    }
}
