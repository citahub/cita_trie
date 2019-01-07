use std::collections::HashMap;

use crate::codec::{DataType, NodeCodec};
use crate::db::DB;
use crate::errors::TrieError;
use crate::nibbles::Nibbles;
use crate::node::{BranchNode, ExtensionNode, HashNode, LeafNode, Node};

pub type TrieResult<T, C, D> = Result<T, TrieError<C, D>>;

pub trait Trie<C: NodeCodec, D: DB> {
    /// returns the value for key stored in the trie.
    fn get(&self, key: &[u8]) -> TrieResult<Option<Vec<u8>>, C, D>;

    /// check that the key is present in the trie
    fn contains(&self, key: &[u8]) -> TrieResult<bool, C, D>;

    /// inserts value into trie and modifies it if it exists
    fn insert(&mut self, key: &[u8], value: &[u8]) -> TrieResult<(), C, D>;

    /// removes any existing value for key from the trie.
    fn remove(&mut self, key: &[u8]) -> TrieResult<bool, C, D>;

    /// returns the root hash of the trie.
    fn root(&mut self) -> TrieResult<C::Hash, C, D>;
}

#[derive(Debug)]
pub struct PatriciaTrie<'db, C, D>
where
    C: NodeCodec,
    D: DB,
{
    root: Node,
    db: &'db mut D,
    codec: C,

    pub cache: HashMap<C::Hash, Vec<u8>>,
}

impl<'db, C, D> Trie<C, D> for PatriciaTrie<'db, C, D>
where
    C: NodeCodec,
    D: DB,
{
    fn get(&self, key: &[u8]) -> TrieResult<Option<Vec<u8>>, C, D> {
        self.get_at(&self.root, &Nibbles::from_raw(key, true))
    }

    fn contains(&self, key: &[u8]) -> TrieResult<bool, C, D> {
        Ok(self
            .get_at(&self.root, &Nibbles::from_raw(key, true))?
            .map_or(false, |_| true))
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> TrieResult<(), C, D> {
        let root = self.insert_at(self.root.clone(), &Nibbles::from_raw(key, true), value)?;
        self.root = root;
        Ok(())
    }

    fn remove(&mut self, key: &[u8]) -> TrieResult<bool, C, D> {
        let (n, removed) = self.delete_at(self.root.clone(), &Nibbles::from_raw(key, true))?;
        self.root = n;
        Ok(removed)
    }

    fn root(&mut self) -> TrieResult<C::Hash, C, D> {
        self.commit()
    }
}

impl<'db, C, D> PatriciaTrie<'db, C, D>
where
    C: NodeCodec,
    D: DB,
{
    pub fn new(db: &'db mut D, codec: C) -> Self {
        PatriciaTrie {
            root: Node::Empty,
            db,
            codec,

            cache: HashMap::new(),
        }
    }

    pub fn from(db: &'db mut D, codec: C, root: C::Hash) -> TrieResult<Self, C, D> {
        match db.get(root.as_ref()).map_err(TrieError::DB)? {
            Some(data) => {
                let mut trie = PatriciaTrie {
                    root: Node::Empty,
                    db,
                    codec,

                    cache: HashMap::new(),
                };

                trie.root = trie.decode_node(&data).map_err(TrieError::NodeCodec)?;
                Ok(trie)
            }
            None => Err(TrieError::InvalidStateRoot),
        }
    }

    fn get_at<'a>(&self, n: &'a Node, partial: &Nibbles) -> TrieResult<Option<Vec<u8>>, C, D> {
        match n {
            Node::Empty => Ok(None),
            Node::Leaf(ref leaf) => {
                if partial == leaf.get_key() {
                    Ok(Some(leaf.get_value().to_vec()))
                } else {
                    Ok(None)
                }
            }
            Node::Branch(ref branch) => {
                if partial.is_empty() || partial.at(0) == 16 {
                    Ok(branch.get_value().and_then(|v| Some(v.to_vec())))
                } else {
                    let index = partial.at(0) as usize;
                    let node = branch.at_children(index);
                    self.get_at(node, &partial.slice(1, partial.len()))
                }
            }
            Node::Extension(extension) => {
                let prefix = extension.get_prefix();
                let match_len = partial.common_prefix(prefix);
                if match_len == prefix.len() {
                    self.get_at(
                        extension.get_node(),
                        &partial.slice(match_len, partial.len()),
                    )
                } else {
                    Ok(None)
                }
            }
            Node::Hash(hash) => {
                let n = self.get_node_from_hash(hash.get_hash())?;
                self.get_at(&n, partial)
            }
        }
    }

    fn delete_at(&mut self, n: Node, partial: &Nibbles) -> TrieResult<(Node, bool), C, D> {
        match n {
            Node::Empty => Ok((Node::Empty, false)),
            Node::Leaf(leaf) => {
                if leaf.get_key() == partial {
                    Ok((Node::Empty, true))
                } else {
                    Ok((leaf.into_node(), false))
                }
            }
            Node::Branch(mut branch) => {
                if partial.is_empty() || partial.at(0) == 16 {
                    branch.set_value(None);
                    Ok((branch.into_node(), true))
                } else {
                    let index = partial.at(0) as usize;
                    let node = branch.at_children(index);
                    self.delete_at(node.clone(), &partial.slice(1, partial.len()))
                }
            }
            Node::Extension(extension) => {
                let prefix = extension.get_prefix();
                let match_len = partial.common_prefix(prefix);
                if match_len == prefix.len() {
                    self.delete_at(
                        extension.get_node().clone(),
                        &partial.slice(match_len, partial.len()),
                    )
                } else {
                    Ok((extension.into_node(), false))
                }
            }
            Node::Hash(hash) => {
                let n = self.get_node_from_hash(hash.get_hash())?;
                self.delete_at(n, partial)
            }
        }
    }

    fn insert_at(&mut self, n: Node, partial: &Nibbles, value: &[u8]) -> TrieResult<Node, C, D> {
        match n {
            Node::Empty => Ok(LeafNode::new(partial, value).into_node()),
            Node::Leaf(leaf) => {
                let old_partial = leaf.get_key();
                let match_index = partial.common_prefix(old_partial);
                if match_index == old_partial.len() {
                    // replace leaf value
                    return Ok(LeafNode::new(old_partial, value).into_node());
                }

                // create branch node
                let mut branch = BranchNode::new();
                let n = LeafNode::new(&partial.slice(match_index + 1, partial.len()), value)
                    .into_node();
                branch.insert(partial.at(match_index) as usize, n);

                let n = LeafNode::new(
                    &old_partial.slice(match_index + 1, old_partial.len()),
                    leaf.get_value(),
                )
                .into_node();
                branch.insert(old_partial.at(match_index) as usize, n);

                if match_index == 0 {
                    return Ok(branch.into_node());
                }

                // if include a common prefix
                Ok(
                    ExtensionNode::new(&partial.slice(0, match_index), branch.into_node())
                        .into_node(),
                )
            }
            Node::Branch(mut branch) => {
                if partial.is_empty() {
                    branch.set_value(Some(value.to_vec()));
                    Ok(branch.into_node())
                } else {
                    let index = partial.at(0) as usize;
                    let new_n = self.insert_at(
                        branch.at_children(index).clone(),
                        &partial.slice(1, partial.len()),
                        value,
                    )?;
                    branch.insert(index, new_n);
                    Ok(branch.into_node())
                }
            }
            Node::Extension(extension) => {
                let prefix = extension.get_prefix();
                let match_index = partial.common_prefix(&prefix);

                if match_index == 0 {
                    // Don't match, create a branch node.
                    self.insert_at(Node::Empty, partial, value)
                } else if match_index == prefix.len() {
                    let new_node = self.insert_at(
                        extension.get_node().clone(),
                        &partial.slice(match_index, partial.len()),
                        value,
                    )?;

                    Ok(ExtensionNode::new(prefix, new_node).into_node())
                } else {
                    let new_ext = ExtensionNode::new(
                        &prefix.slice(match_index, prefix.len()),
                        extension.get_node().clone(),
                    );

                    let new_n = self.insert_at(
                        new_ext.into_node(),
                        &partial.slice(match_index, partial.len()),
                        value,
                    )?;

                    Ok(ExtensionNode::new(&prefix.slice(0, match_index), new_n).into_node())
                }
            }
            Node::Hash(hash) => {
                let n = self.get_node_from_hash(hash.get_hash())?;
                self.insert_at(n, partial, value)
            }
        }
    }

    fn commit(&mut self) -> TrieResult<C::Hash, C, D> {
        let root = &self.root.clone();
        let encoded = self.encode_node(&root);
        let root_hash = if encoded.len() < C::HASH_LENGTH {
            let hash = self.codec.decode_hash(&encoded, false);
            self.cache.insert(hash, encoded);
            hash
        } else {
            self.codec.decode_hash(&encoded, true)
        };
        for key in self.cache.keys() {
            let value = &self.cache[key];
            self.db
                .insert(key.as_ref(), &value)
                .map_err(TrieError::DB)?;
        }

        Ok(root_hash)
    }

    fn decode_node(&self, data: &[u8]) -> Result<Node, C::Error> {
        self.codec.decode(data, |dp| match dp {
            DataType::Empty => Ok(Node::Empty),
            DataType::Pair(key, value) => {
                let nibble = Nibbles::from_compact(key);
                if nibble.is_leaf() {
                    Ok(LeafNode::new(&nibble, value).into_node())
                } else {
                    let n = self.try_decode_hash_node(value)?;;
                    Ok(ExtensionNode::new(&nibble, n).into_node())
                }
            }
            DataType::Values(values) => {
                let mut branch = BranchNode::new();
                for (index, item) in values.iter().enumerate().take(16) {
                    let n = self.try_decode_hash_node(item)?;
                    branch.insert(index, n);
                }

                if self.codec.encode_empty() == values[16] {
                    branch.set_value(None)
                } else {
                    branch.set_value(Some(values[16].to_vec()))
                }
                Ok(branch.into_node())
            }
        })
    }

    fn encode_node(&mut self, n: &Node) -> Vec<u8> {
        let data = match n {
            Node::Empty => self.codec.encode_empty(),
            Node::Leaf(ref leaf) => self
                .codec
                .encode_pair(&leaf.get_key().encode_compact(), leaf.get_value()),
            Node::Branch(branch) => {
                let mut values = vec![];
                for index in 0..16 {
                    let data = self.encode_node(branch.at_children(index));
                    values.push(data);
                }
                match branch.get_value() {
                    Some(v) => values.push(v.to_vec()),
                    None => values.push(self.codec.encode_empty()),
                }
                self.codec.encode_values(&values)
            }
            Node::Extension(extension) => {
                let key = extension.get_prefix().encode_compact();
                let value = self.encode_node(extension.get_node());

                self.codec.encode_pair(&key, &value)
            }
            Node::Hash(hash) => hash.get_hash().to_vec(),
        };

        // Nodes smaller than 32 bytes are stored inside their parent,
        // Nodes equal to 32 bytes are returned directly
        if data.len() < C::HASH_LENGTH || data.len() == C::HASH_LENGTH {
            data
        } else {
            let hash = self.codec.decode_hash(&data, false);
            self.cache.insert(hash, data);
            Vec::from(hash.as_ref())
        }
    }

    fn try_decode_hash_node(&self, data: &[u8]) -> Result<Node, C::Error> {
        if data.len() == C::HASH_LENGTH {
            Ok(HashNode::new(data).into_node())
        } else {
            self.decode_node(data)
        }
    }

    fn get_node_from_hash(&self, hash: &[u8]) -> TrieResult<Node, C, D> {
        match self.db.get(hash).map_err(TrieError::DB)? {
            Some(data) => self.decode_node(&data).map_err(TrieError::NodeCodec),
            None => Ok(Node::Empty),
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};

    use super::{PatriciaTrie, Trie};
    use crate::codec::{NodeCodec, RLPNodeCodec};
    use crate::db::MemoryDB;

    #[test]
    fn test_trie_insert() {
        let mut memdb = MemoryDB::new();
        let mut trie = PatriciaTrie::new(&mut memdb, RLPNodeCodec::default());
        trie.insert(b"test", b"test").unwrap();
    }

    #[test]
    fn test_trie_get() {
        let mut memdb = MemoryDB::new();
        let mut trie = PatriciaTrie::new(&mut memdb, RLPNodeCodec::default());
        trie.insert(b"test", b"test").unwrap();
        let v = trie.get(b"test").unwrap().map(|v| v.to_vec());

        assert_eq!(Some(b"test".to_vec()), v)
    }

    #[test]
    fn test_trie_random_insert() {
        let mut memdb = MemoryDB::new();
        let mut trie = PatriciaTrie::new(&mut memdb, RLPNodeCodec::default());

        for _ in 0..1000 {
            let rand_str: String = thread_rng().sample_iter(&Alphanumeric).take(30).collect();
            let val = rand_str.as_bytes();
            trie.insert(val, val).unwrap();

            let v = trie.get(val).unwrap();
            assert_eq!(v.map(|v| v.to_vec()), Some(val.to_vec()));
        }
    }

    #[test]
    fn test_trie_contains() {
        let mut memdb = MemoryDB::new();
        let mut trie = PatriciaTrie::new(&mut memdb, RLPNodeCodec::default());
        trie.insert(b"test", b"test").unwrap();
        assert_eq!(true, trie.contains(b"test").unwrap());
        assert_eq!(false, trie.contains(b"test2").unwrap());
    }

    #[test]
    fn test_trie_remove() {
        let mut memdb = MemoryDB::new();
        let mut trie = PatriciaTrie::new(&mut memdb, RLPNodeCodec::default());
        trie.insert(b"test", b"test").unwrap();
        let removed = trie.remove(b"test").unwrap();
        assert_eq!(true, removed)
    }

    #[test]
    fn test_trie_random_remove() {
        let mut memdb = MemoryDB::new();
        let mut trie = PatriciaTrie::new(&mut memdb, RLPNodeCodec::default());

        for _ in 0..1000 {
            let rand_str: String = thread_rng().sample_iter(&Alphanumeric).take(30).collect();
            let val = rand_str.as_bytes();
            trie.insert(val, val).unwrap();

            let removed = trie.remove(val).unwrap();
            assert_eq!(true, removed);
        }
    }

    #[test]
    fn test_trie_empty_commit() {
        let mut memdb = MemoryDB::new();
        let mut trie = PatriciaTrie::new(&mut memdb, RLPNodeCodec::default());

        let codec = RLPNodeCodec::default();
        let empty_node_data = codec.decode_hash(&codec.encode_empty(), false);
        let root = trie.commit().unwrap();

        assert_eq!(hex::encode(root), hex::encode(empty_node_data))
    }

    #[test]
    fn test_trie_commit() {
        let mut memdb = MemoryDB::new();
        let mut trie = PatriciaTrie::new(&mut memdb, RLPNodeCodec::default());
        trie.insert(b"test", b"test").unwrap();
        let root = trie.commit().unwrap();

        let codec = RLPNodeCodec::default();
        let empty_node_data = codec.decode_hash(&codec.encode_empty(), false);
        assert_ne!(hex::encode(root), hex::encode(empty_node_data))
    }

    #[test]
    fn test_trie_from_root() {
        let mut memdb = MemoryDB::new();
        let root = {
            let mut trie = PatriciaTrie::new(&mut memdb, RLPNodeCodec::default());
            trie.insert(b"test", b"test").unwrap();
            trie.insert(b"test1", b"test").unwrap();
            trie.insert(b"test2", b"test").unwrap();
            trie.insert(b"test23", b"test").unwrap();
            trie.insert(b"test33", b"test").unwrap();
            trie.insert(b"test44", b"test").unwrap();
            trie.root().unwrap()
        };

        let mut trie = PatriciaTrie::from(&mut memdb, RLPNodeCodec::default(), root).unwrap();
        let v1 = trie.get(b"test33").unwrap();
        assert_eq!(Some(b"test".to_vec()), v1);
        let v2 = trie.get(b"test44").unwrap();
        assert_eq!(Some(b"test".to_vec()), v2);
        let root2 = trie.commit().unwrap();
        assert_eq!(hex::encode(root), hex::encode(root2));
    }

    #[test]
    fn test_trie_from_root_and_insert() {
        let mut memdb = MemoryDB::new();
        let root = {
            let mut trie = PatriciaTrie::new(&mut memdb, RLPNodeCodec::default());
            trie.insert(b"test", b"test").unwrap();
            trie.insert(b"test1", b"test").unwrap();
            trie.insert(b"test2", b"test").unwrap();
            trie.insert(b"test23", b"test").unwrap();
            trie.insert(b"test33", b"test").unwrap();
            trie.insert(b"test44", b"test").unwrap();
            trie.commit().unwrap()
        };

        let mut trie = PatriciaTrie::from(&mut memdb, RLPNodeCodec::default(), root).unwrap();
        trie.insert(b"test55", b"test55").unwrap();
        let v = trie.get(b"test55").unwrap();
        assert_eq!(Some(b"test55".to_vec()), v);
    }

    #[test]
    fn test_trie_from_root_and_delete() {
        let mut memdb = MemoryDB::new();
        let root = {
            let mut trie = PatriciaTrie::new(&mut memdb, RLPNodeCodec::default());
            trie.insert(b"test", b"test").unwrap();
            trie.insert(b"test1", b"test").unwrap();
            trie.insert(b"test2", b"test").unwrap();
            trie.insert(b"test23", b"test").unwrap();
            trie.insert(b"test33", b"test").unwrap();
            trie.insert(b"test44", b"test").unwrap();
            trie.commit().unwrap()
        };

        let mut trie = PatriciaTrie::from(&mut memdb, RLPNodeCodec::default(), root).unwrap();
        let removed = trie.remove(b"test44").unwrap();
        assert_eq!(true, removed);
    }
}
