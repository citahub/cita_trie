use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use hashbrown::{HashMap, HashSet};
use hasher::Hasher;
use rlp::{Prototype, Rlp, RlpStream};

use crate::db::{MemoryDB, DB};
use crate::errors::TrieError;
use crate::nibbles::Nibbles;
use crate::node::{empty_children, BranchNode, Node};

pub type TrieResult<T> = Result<T, TrieError>;

pub trait Trie<D: DB, H: Hasher> {
    /// Returns the value for key stored in the trie.
    fn get(&self, key: &[u8]) -> TrieResult<Option<Vec<u8>>>;

    /// Checks that the key is present in the trie
    fn contains(&self, key: &[u8]) -> TrieResult<bool>;

    /// Inserts value into trie and modifies it if it exists
    fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) -> TrieResult<()>;

    /// Removes any existing value for key from the trie.
    fn remove(&mut self, key: &[u8]) -> TrieResult<bool>;

    /// Saves all the nodes in the db, clears the cache data, recalculates the root.
    /// Returns the root hash of the trie.
    fn root(&mut self) -> TrieResult<Vec<u8>>;

    /// Prove constructs a merkle proof for key. The result contains all encoded nodes
    /// on the path to the value at key. The value itself is also included in the last
    /// node and can be retrieved by verifying the proof.
    ///
    /// If the trie does not contain a value for key, the returned proof contains all
    /// nodes of the longest existing prefix of the key (at least the root node), ending
    /// with the node that proves the absence of the key.
    fn get_proof(&self, key: &[u8]) -> TrieResult<Vec<Vec<u8>>>;

    /// return value if key exists, None if key not exist, Error if proof is wrong
    fn verify_proof(
        &self,
        root_hash: Vec<u8>,
        key: &[u8],
        proof: Vec<Vec<u8>>,
    ) -> TrieResult<Option<Vec<u8>>>;
}

#[derive(Debug)]
pub struct PatriciaTrie<D, H>
where
    D: DB,
    H: Hasher,
{
    root: Node,
    root_hash: Vec<u8>,

    db: Arc<D>,
    hasher: Arc<H>,

    cache: RefCell<HashMap<Vec<u8>, Vec<u8>>>,
    passing_keys: RefCell<HashSet<Vec<u8>>>,
    gen_keys: RefCell<HashSet<Vec<u8>>>,
}

#[derive(Clone, Debug)]
enum TraceStatus {
    Start,
    Doing,
    Child(u8),
    End,
}

#[derive(Clone, Debug)]
struct TraceNode {
    node: Node,
    status: TraceStatus,
}

impl TraceNode {
    fn advance(&mut self) {
        self.status = match &self.status {
            TraceStatus::Start => TraceStatus::Doing,
            TraceStatus::Doing => match self.node {
                Node::Branch(_) => TraceStatus::Child(0),
                _ => TraceStatus::End,
            },
            TraceStatus::Child(i) if *i < 15 => TraceStatus::Child(i + 1),
            _ => TraceStatus::End,
        }
    }
}

impl From<Node> for TraceNode {
    fn from(node: Node) -> TraceNode {
        TraceNode {
            node,
            status: TraceStatus::Start,
        }
    }
}

pub struct TrieIterator<'a, D, H>
where
    D: DB,
    H: Hasher,
{
    trie: &'a PatriciaTrie<D, H>,
    nibble: Nibbles,
    nodes: Vec<TraceNode>,
}

impl<'a, D, H> Iterator for TrieIterator<'a, D, H>
where
    D: DB,
    H: Hasher,
{
    type Item = (Vec<u8>, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let mut now = self.nodes.last().cloned();
            if let Some(ref mut now) = now {
                self.nodes.last_mut().unwrap().advance();

                match (now.status.clone(), &now.node) {
                    (TraceStatus::End, node) => {
                        match *node {
                            Node::Leaf(ref leaf) => {
                                let cur_len = self.nibble.len();
                                self.nibble.truncate(cur_len - leaf.borrow().key.len());
                            }

                            Node::Extension(ref ext) => {
                                let cur_len = self.nibble.len();
                                self.nibble.truncate(cur_len - ext.borrow().prefix.len());
                            }

                            Node::Branch(_) => {
                                self.nibble.pop();
                            }
                            _ => {}
                        }
                        self.nodes.pop();
                    }

                    (TraceStatus::Doing, Node::Extension(ref ext)) => {
                        self.nibble.extend(&ext.borrow().prefix);
                        self.nodes.push((ext.borrow().node.clone()).into());
                    }

                    (TraceStatus::Doing, Node::Leaf(ref leaf)) => {
                        self.nibble.extend(&leaf.borrow().key);
                        return Some((self.nibble.encode_raw().0, leaf.borrow().value.clone()));
                    }

                    (TraceStatus::Doing, Node::Branch(ref branch)) => {
                        let value_option = branch.borrow().value.clone();
                        if let Some(value) = value_option {
                            return Some((self.nibble.encode_raw().0, value));
                        }
                        else {
                            continue;
                        }
                    }

                    (TraceStatus::Doing, Node::Hash(ref hash_node)) => {
                        if let Ok(n) = self.trie.recover_from_db(&hash_node.borrow().hash.clone()) {
                            self.nodes.pop();
                            self.nodes.push(n.into());
                        } else {
                            //error!();
                            return None;
                        }
                    }

                    (TraceStatus::Child(i), Node::Branch(ref branch)) => {
                        if i == 0 {
                            self.nibble.push(0);
                        } else {
                            self.nibble.pop();
                            self.nibble.push(i);
                        }
                        self.nodes
                            .push((branch.borrow().children[i as usize].clone()).into());
                    }

                    (_, Node::Empty) => {
                        self.nodes.pop();
                    }
                    _ => {}
                }
            } else {
                return None;
            }
        }
    }
}

impl<D, H> PatriciaTrie<D, H>
where
    D: DB,
    H: Hasher,
{
    pub fn iter(&self) -> TrieIterator<D, H> {
        let nodes = vec![(self.root.clone()).into()];
        TrieIterator {
            trie: self,
            nibble: Nibbles::from_raw(vec![], false),
            nodes,
        }
    }
    pub fn new(db: Arc<D>, hasher: Arc<H>) -> Self {
        Self {
            root: Node::Empty,
            root_hash: hasher.digest(&rlp::NULL_RLP.to_vec()),

            cache: RefCell::new(HashMap::new()),
            passing_keys: RefCell::new(HashSet::new()),
            gen_keys: RefCell::new(HashSet::new()),

            db,
            hasher,
        }
    }

    pub fn from(db: Arc<D>, hasher: Arc<H>, root: &[u8]) -> TrieResult<Self> {
        match db.get(root).map_err(|e| TrieError::DB(e.to_string()))? {
            Some(data) => {
                let mut trie = Self {
                    root: Node::Empty,
                    root_hash: root.to_vec(),

                    cache: RefCell::new(HashMap::new()),
                    passing_keys: RefCell::new(HashSet::new()),
                    gen_keys: RefCell::new(HashSet::new()),

                    db,
                    hasher,
                };

                trie.root = trie.decode_node(&data)?;
                Ok(trie)
            }
            None => Err(TrieError::InvalidStateRoot),
        }
    }
}

impl<D, H> Trie<D, H> for PatriciaTrie<D, H>
where
    D: DB,
    H: Hasher,
{
    /// Returns the value for key stored in the trie.
    fn get(&self, key: &[u8]) -> TrieResult<Option<Vec<u8>>> {
        let root = self.root.clone();
        let nibbles = &Nibbles::from_raw(key.to_vec(), true);
        // TODO convert traversal error (MissingTraversalNode in py-trie) to lookup error
        //  (MissingTrieNode)
        self._get(root, nibbles)
    }

    /// Checks that the key is present in the trie
    fn contains(&self, key: &[u8]) -> TrieResult<bool> {
        Ok(self
            .get_at(self.root.clone(), &Nibbles::from_raw(key.to_vec(), true))?
            .map_or(false, |_| true))
    }

    /// Inserts value into trie and modifies it if it exists
    fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) -> TrieResult<()> {
        if value.is_empty() {
            self.remove(&key)?;
            return Ok(());
        }
        let root = self.root.clone();
        self.root = self.insert_at(root, Nibbles::from_raw(key, true), value.to_vec())?;
        Ok(())
    }

    /// Removes any existing value for key from the trie.
    fn remove(&mut self, key: &[u8]) -> TrieResult<bool> {
        let (n, removed) =
            self.delete_at(self.root.clone(), &Nibbles::from_raw(key.to_vec(), true))?;
        self.root = n;
        Ok(removed)
    }

    /// Saves all the nodes in the db, clears the cache data, recalculates the root.
    /// Returns the root hash of the trie.
    fn root(&mut self) -> TrieResult<Vec<u8>> {
        self.commit()
    }

    /// Prove constructs a merkle proof for key. The result contains all encoded nodes
    /// on the path to the value at key. The value itself is also included in the last
    /// node and can be retrieved by verifying the proof.
    ///
    /// If the trie does not contain a value for key, the returned proof contains all
    /// nodes of the longest existing prefix of the key (at least the root node), ending
    /// with the node that proves the absence of the key.
    fn get_proof(&self, key: &[u8]) -> TrieResult<Vec<Vec<u8>>> {
        let mut path =
            self.get_path_at(self.root.clone(), &Nibbles::from_raw(key.to_vec(), true))?;
        match self.root {
            Node::Empty => {}
            _ => path.push(self.root.clone()),
        }
        Ok(path.into_iter().rev().map(|n| self.encode_raw(n)).collect())
    }

    /// return value if key exists, None if key not exist, Error if proof is wrong
    fn verify_proof(
        &self,
        root_hash: Vec<u8>,
        key: &[u8],
        proof: Vec<Vec<u8>>,
    ) -> TrieResult<Option<Vec<u8>>> {
        let memdb = Arc::new(MemoryDB::new(true));
        for node_encoded in proof.into_iter() {
            let hash = self.hasher.digest(&node_encoded);

            if root_hash.eq(&hash) || node_encoded.len() >= H::LENGTH {
                memdb.insert(hash, node_encoded).unwrap();
            }
        }
        let trie = PatriciaTrie::from(memdb, Arc::clone(&self.hasher), &root_hash)
            .or(Err(TrieError::InvalidProof))?;
        trie.get(key).or(Err(TrieError::InvalidProof))
    }
}

impl<D, H> PatriciaTrie<D, H>
where
    D: DB,
    H: Hasher,
{
    fn get_at(&self, n: Node, partial: &Nibbles) -> TrieResult<Option<Vec<u8>>> {
        match n {
            Node::Empty => Ok(None),
            Node::Leaf(leaf) => {
                let borrow_leaf = leaf.borrow();

                if &borrow_leaf.key == partial {
                    Ok(Some(borrow_leaf.value.clone()))
                } else {
                    Ok(None)
                }
            }
            Node::Branch(branch) => {
                let borrow_branch = branch.borrow();

                if partial.is_empty() || partial.at(0) == 16 {
                    Ok(borrow_branch.value.clone())
                } else {
                    let index = partial.at(0);
                    self.get_at(borrow_branch.children[index].clone(), &partial.offset(1))
                }
            }
            Node::Extension(extension) => {
                let extension = extension.borrow();

                let prefix = &extension.prefix;
                let match_len = partial.common_prefix(prefix);
                if match_len == prefix.len() {
                    self.get_at(extension.node.clone(), &partial.offset(match_len))
                } else {
                    Ok(None)
                }
            }
            Node::Hash(hash_node) => {
                let borrow_hash_node = hash_node.borrow();
                let n = self.recover_from_db(&borrow_hash_node.hash)?;
                self.get_at(n, partial)
            }
        }
    }

    fn _get(&self, source_node: Node, full_key: &Nibbles) -> TrieResult<Option<Vec<u8>>> {
        let (node, partial) = self._traverse_from(source_node, full_key); // TODO add ? when this can raise errors
        // partial is the remaining (unconsumed) key, after navigating to the given node

        match node {
            Node::Empty => Ok(None),
            Node::Leaf(leaf) => {
                let borrow_leaf = leaf.borrow();

                if &borrow_leaf.key == partial {
                    Ok(Some(borrow_leaf.value.clone()))
                } else {
                    Ok(None)
                }
            }
            Node::Branch(branch) => {
                let borrow_branch = branch.borrow();

                // TODO drop this weird bonus nibble of 16
                if partial.is_empty() || partial.at(0) == 16 {
                    Ok(borrow_branch.value.clone())
                } else {
                    TrieError::Invariant("Traversal must not return a branch node with any path remaining")
                }
            }
            Node::Extension(_) => {
                if partial.is_empty() {
                    Ok(None)
                } else {
                    TrieError::Invariant("Traversal must not return an extension node with any path remaining")
                }
            }
            Node::Hash(hash_node) => {
                TrieError::Invariant("Traversal must not return a hash node")
            }
            _ => {
                TrieError::Invariant("Traversal must not return any other type of node")
            }
        }
    }

    fn _traverse_from(&self, n: Node, key: &Nibbles) -> TrieResult<(Node, Nibbles)> {
        // TODO reduce memory churn by changing Nibbles to support borrowing a slice,
        //  and/or tracking the offset id and indexing into the remaining key while looping.
        let remaining_key = key.offset(0);
        while !remaining_key.is_empty() {
            match n {
                Node::Empty => (n, Nibbles::empty()),
                Node::Leaf(leaf) => {
                    let borrow_leaf = leaf.borrow();

                    if &borrow_leaf.key == partial {
                        Ok(Some(borrow_leaf.value.clone()))
                    } else {
                        Ok(None)
                    }
                }
                Node::Branch(branch) => {
                    let borrow_branch = branch.borrow();

                    if partial.is_empty() || partial.at(0) == 16 {
                        Ok(borrow_branch.value.clone())
                    } else {
                        let index = partial.at(0);
                        self.get_at(borrow_branch.children[index].clone(), &partial.offset(1))
                    }
                }
                Node::Extension(extension) => {
                    let extension = extension.borrow();

                    let prefix = &extension.prefix;
                    let match_len = partial.common_prefix(prefix);
                    if match_len == prefix.len() {
                        self.get_at(extension.node.clone(), &partial.offset(match_len))
                    } else {
                        Ok(None)
                    }
                }
                Node::Hash(hash_node) => {
                    let borrow_hash_node = hash_node.borrow();
                    let n = self.recover_from_db(&borrow_hash_node.hash)?;
                    self.get_at(n, partial)
                }
            }
        }
    }

    fn insert_at(&self, n: Node, partial: Nibbles, value: Vec<u8>) -> TrieResult<Node> {
        match n {
            Node::Empty => Ok(Node::from_leaf(partial, value)),
            Node::Leaf(leaf) => {
                let mut borrow_leaf = leaf.borrow_mut();

                let old_partial = &borrow_leaf.key;
                let match_index = partial.common_prefix(old_partial);
                if match_index == old_partial.len() {
                    // replace leaf value
                    borrow_leaf.value = value;
                    return Ok(Node::Leaf(leaf.clone()));
                }

                let mut branch = BranchNode {
                    children: empty_children(),
                    value: None,
                };

                let n = Node::from_leaf(
                    old_partial.offset(match_index + 1),
                    borrow_leaf.value.clone(),
                );
                branch.insert(old_partial.at(match_index), n);

                let n = Node::from_leaf(partial.offset(match_index + 1), value);
                branch.insert(partial.at(match_index), n);

                if match_index == 0 {
                    return Ok(Node::Branch(Rc::new(RefCell::new(branch))));
                }

                // if include a common prefix
                Ok(Node::from_extension(
                    partial.slice(0, match_index),
                    Node::Branch(Rc::new(RefCell::new(branch))),
                ))
            }
            Node::Branch(branch) => {
                let mut borrow_branch = branch.borrow_mut();

                if partial.at(0) == 0x10 {
                    borrow_branch.value = Some(value);
                    return Ok(Node::Branch(branch.clone()));
                }

                let child = borrow_branch.children[partial.at(0)].clone();
                let new_child = self.insert_at(child, partial.offset(1), value)?;
                borrow_branch.children[partial.at(0)] = new_child;
                Ok(Node::Branch(branch.clone()))
            }
            Node::Extension(ext) => {
                let mut borrow_ext = ext.borrow_mut();

                let prefix = &borrow_ext.prefix;
                let sub_node = borrow_ext.node.clone();
                let match_index = partial.common_prefix(prefix);

                if match_index == 0 {
                    let mut branch = BranchNode {
                        children: empty_children(),
                        value: None,
                    };
                    branch.insert(
                        prefix.at(0),
                        if prefix.len() == 1 {
                            sub_node
                        } else {
                            Node::from_extension(prefix.offset(1), sub_node)
                        },
                    );
                    let node = Node::Branch(Rc::new(RefCell::new(branch)));

                    return self.insert_at(node, partial, value);
                }

                if match_index == prefix.len() {
                    let new_node = self.insert_at(sub_node, partial.offset(match_index), value)?;
                    return Ok(Node::from_extension(prefix.clone(), new_node));
                }

                let new_ext = Node::from_extension(prefix.offset(match_index), sub_node);
                let new_node = self.insert_at(new_ext, partial.offset(match_index), value)?;
                borrow_ext.prefix = prefix.slice(0, match_index);
                borrow_ext.node = new_node;
                Ok(Node::Extension(ext.clone()))
            }
            Node::Hash(hash_node) => {
                let borrow_hash_node = hash_node.borrow();

                self.passing_keys
                    .borrow_mut()
                    .insert(borrow_hash_node.hash.to_vec());
                let n = self.recover_from_db(&borrow_hash_node.hash)?;
                self.insert_at(n, partial, value)
            }
        }
    }

    fn delete_at(&self, n: Node, partial: &Nibbles) -> TrieResult<(Node, bool)> {
        let (new_n, deleted) = match n {
            Node::Empty => Ok((Node::Empty, false)),
            Node::Leaf(leaf) => {
                let borrow_leaf = leaf.borrow();

                if &borrow_leaf.key == partial {
                    return Ok((Node::Empty, true));
                }
                Ok((Node::Leaf(leaf.clone()), false))
            }
            Node::Branch(branch) => {
                let mut borrow_branch = branch.borrow_mut();

                if partial.at(0) == 0x10 {
                    borrow_branch.value = None;
                    return Ok((Node::Branch(branch.clone()), true));
                }

                let index = partial.at(0);
                let node = borrow_branch.children[index].clone();

                let (new_n, deleted) = self.delete_at(node, &partial.offset(1))?;
                if deleted {
                    borrow_branch.children[index] = new_n;
                }

                Ok((Node::Branch(branch.clone()), deleted))
            }
            Node::Extension(ext) => {
                let mut borrow_ext = ext.borrow_mut();

                let prefix = &borrow_ext.prefix;
                let match_len = partial.common_prefix(prefix);

                if match_len == prefix.len() {
                    let (new_n, deleted) =
                        self.delete_at(borrow_ext.node.clone(), &partial.offset(match_len))?;

                    if deleted {
                        borrow_ext.node = new_n;
                    }

                    Ok((Node::Extension(ext.clone()), deleted))
                } else {
                    Ok((Node::Extension(ext.clone()), false))
                }
            }
            Node::Hash(hash_node) => {
                let hash = hash_node.borrow().hash.clone();
                self.passing_keys.borrow_mut().insert(hash.clone());

                let n = self.recover_from_db(&hash)?;
                self.delete_at(n, partial)
            }
        }?;

        if deleted {
            Ok((self.degenerate(new_n)?, deleted))
        } else {
            Ok((new_n, deleted))
        }
    }

    fn degenerate(&self, n: Node) -> TrieResult<Node> {
        match n {
            Node::Branch(branch) => {
                let borrow_branch = branch.borrow();

                let mut used_indexs = vec![];
                for (index, node) in borrow_branch.children.iter().enumerate() {
                    match node {
                        Node::Empty => continue,
                        _ => used_indexs.push(index),
                    }
                }

                // if only a value node, transmute to leaf.
                if used_indexs.is_empty() && borrow_branch.value.is_some() {
                    let key = Nibbles::from_raw([].to_vec(), true);
                    let value = borrow_branch.value.clone().unwrap();
                    Ok(Node::from_leaf(key, value))
                // if only one node. make an extension.
                } else if used_indexs.len() == 1 && borrow_branch.value.is_none() {
                    let used_index = used_indexs[0];
                    let n = borrow_branch.children[used_index].clone();

                    let new_node =
                        Node::from_extension(Nibbles::from_hex(vec![used_index as u8]), n);
                    self.degenerate(new_node)
                } else {
                    Ok(Node::Branch(branch.clone()))
                }
            }
            Node::Extension(ext) => {
                let borrow_ext = ext.borrow();

                let prefix = &borrow_ext.prefix;
                match borrow_ext.node.clone() {
                    Node::Extension(sub_ext) => {
                        let borrow_sub_ext = sub_ext.borrow();

                        let new_prefix = prefix.join(&borrow_sub_ext.prefix);
                        let new_n = Node::from_extension(new_prefix, borrow_sub_ext.node.clone());
                        self.degenerate(new_n)
                    }
                    Node::Leaf(leaf) => {
                        let borrow_leaf = leaf.borrow();

                        let new_prefix = prefix.join(&borrow_leaf.key);
                        Ok(Node::from_leaf(new_prefix, borrow_leaf.value.clone()))
                    }
                    // try again after recovering node from the db.
                    Node::Hash(hash_node) => {
                        let hash = hash_node.borrow().hash.clone();
                        self.passing_keys.borrow_mut().insert(hash.clone());

                        let new_node = self.recover_from_db(&hash)?;

                        let n = Node::from_extension(borrow_ext.prefix.clone(), new_node);
                        self.degenerate(n)
                    }
                    _ => Ok(Node::Extension(ext.clone())),
                }
            }
            _ => Ok(n),
        }
    }

    // Get nodes path along the key, only the nodes whose encode length is greater than
    // hash length are added.
    // For embedded nodes whose data are already contained in their parent node, we don't need to
    // add them in the path.
    // In the code below, we only add the nodes get by `get_node_from_hash`, because they contains
    // all data stored in db, including nodes whose encoded data is less than hash length.
    fn get_path_at(&self, n: Node, partial: &Nibbles) -> TrieResult<Vec<Node>> {
        match n {
            Node::Empty | Node::Leaf(_) => Ok(vec![]),
            Node::Branch(branch) => {
                let borrow_branch = branch.borrow();

                if partial.is_empty() || partial.at(0) == 16 {
                    Ok(vec![])
                } else {
                    let node = borrow_branch.children[partial.at(0)].clone();
                    self.get_path_at(node, &partial.offset(1))
                }
            }
            Node::Extension(ext) => {
                let borrow_ext = ext.borrow();

                let prefix = &borrow_ext.prefix;
                let match_len = partial.common_prefix(prefix);

                if match_len == prefix.len() {
                    self.get_path_at(borrow_ext.node.clone(), &partial.offset(match_len))
                } else {
                    Ok(vec![])
                }
            }
            Node::Hash(hash_node) => {
                let n = self.recover_from_db(&hash_node.borrow().hash.clone())?;
                let mut rest = self.get_path_at(n.clone(), partial)?;
                rest.push(n);
                Ok(rest)
            }
        }
    }

    fn commit(&mut self) -> TrieResult<Vec<u8>> {
        let encoded = self.encode_node(self.root.clone());
        let root_hash = if encoded.len() < H::LENGTH {
            let hash = self.hasher.digest(&encoded);
            self.cache.borrow_mut().insert(hash.clone(), encoded);
            hash
        } else {
            encoded
        };

        let mut keys = Vec::with_capacity(self.cache.borrow().len());
        let mut values = Vec::with_capacity(self.cache.borrow().len());
        for (k, v) in self.cache.borrow_mut().drain() {
            keys.push(k.to_vec());
            values.push(v);
        }

        self.db
            .insert_batch(keys, values)
            .map_err(|e| TrieError::DB(e.to_string()))?;

        let removed_keys: Vec<Vec<u8>> = self
            .passing_keys
            .borrow()
            .iter()
            .filter(|h| !self.gen_keys.borrow().contains(&h.to_vec()))
            .map(|h| h.to_vec())
            .collect();

        self.db
            .remove_batch(&removed_keys)
            .map_err(|e| TrieError::DB(e.to_string()))?;

        self.root_hash = root_hash.to_vec();
        self.gen_keys.borrow_mut().clear();
        self.passing_keys.borrow_mut().clear();
        self.root = self.recover_from_db(&root_hash)?;
        Ok(root_hash)
    }

    fn encode_node(&self, n: Node) -> Vec<u8> {
        // Returns the hash value directly to avoid double counting.
        if let Node::Hash(hash_node) = n {
            return hash_node.borrow().hash.clone();
        }

        let data = self.encode_raw(n.clone());
        // Nodes smaller than 32 bytes are stored inside their parent,
        // Nodes equal to 32 bytes are returned directly
        if data.len() < H::LENGTH {
            data
        } else {
            let hash = self.hasher.digest(&data);
            self.cache.borrow_mut().insert(hash.clone(), data);

            self.gen_keys.borrow_mut().insert(hash.clone());
            hash
        }
    }

    fn encode_raw(&self, n: Node) -> Vec<u8> {
        match n {
            Node::Empty => rlp::NULL_RLP.to_vec(),
            Node::Leaf(leaf) => {
                let borrow_leaf = leaf.borrow();

                let mut stream = RlpStream::new_list(2);
                stream.append(&borrow_leaf.key.encode_compact());
                stream.append(&borrow_leaf.value);
                stream.out()
            }
            Node::Branch(branch) => {
                let borrow_branch = branch.borrow();

                let mut stream = RlpStream::new_list(17);
                for i in 0..16 {
                    let n = borrow_branch.children[i].clone();
                    let data = self.encode_node(n);
                    if data.len() == H::LENGTH {
                        stream.append(&data);
                    } else {
                        stream.append_raw(&data, 1);
                    }
                }

                match &borrow_branch.value {
                    Some(v) => stream.append(v),
                    None => stream.append_empty_data(),
                };
                stream.out()
            }
            Node::Extension(ext) => {
                let borrow_ext = ext.borrow();

                let mut stream = RlpStream::new_list(2);
                stream.append(&borrow_ext.prefix.encode_compact());
                let data = self.encode_node(borrow_ext.node.clone());
                if data.len() == H::LENGTH {
                    stream.append(&data);
                } else {
                    stream.append_raw(&data, 1);
                }
                stream.out()
            }
            Node::Hash(_hash) => unreachable!(),
        }
    }

    fn decode_node(&self, data: &[u8]) -> TrieResult<Node> {
        let r = Rlp::new(data);

        match r.prototype()? {
            Prototype::Data(0) => Ok(Node::Empty),
            Prototype::List(2) => {
                let key = r.at(0)?.data()?;
                let key = Nibbles::from_compact(key.to_vec());

                if key.is_leaf() {
                    Ok(Node::from_leaf(key, r.at(1)?.data()?.to_vec()))
                } else {
                    let n = self.decode_node(r.at(1)?.as_raw())?;

                    Ok(Node::from_extension(key, n))
                }
            }
            Prototype::List(17) => {
                let mut nodes = empty_children();
                #[allow(clippy::needless_range_loop)]
                for i in 0..nodes.len() {
                    let rlp_data = r.at(i)?;
                    let n = self.decode_node(rlp_data.as_raw())?;
                    nodes[i] = n;
                }

                // The last element is a value node.
                let value_rlp = r.at(16)?;
                let value = if value_rlp.is_empty() {
                    None
                } else {
                    Some(value_rlp.data()?.to_vec())
                };

                Ok(Node::from_branch(nodes, value))
            }
            _ => {
                if r.is_data() && r.size() == H::LENGTH {
                    Ok(Node::from_hash(r.data()?.to_vec()))
                } else {
                    Err(TrieError::InvalidData)
                }
            }
        }
    }

    fn recover_from_db(&self, key: &[u8]) -> TrieResult<Node> {
        match self.db.get(key).map_err(|e| TrieError::DB(e.to_string()))? {
            Some(value) => Ok(self.decode_node(&value)?),
            None => Ok(Node::Empty),
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::distributions::Alphanumeric;
    use rand::seq::SliceRandom;
    use rand::{thread_rng, Rng};
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

    use ethereum_types;
    use hasher::{Hasher, HasherKeccak};

    use super::{PatriciaTrie, Trie};
    use crate::db::{MemoryDB, DB};

    #[test]
    fn test_trie_insert() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = PatriciaTrie::new(memdb, Arc::new(HasherKeccak::new()));
        trie.insert(b"test".to_vec(), b"test".to_vec()).unwrap();
    }

    #[test]
    fn test_trie_get() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = PatriciaTrie::new(memdb, Arc::new(HasherKeccak::new()));
        trie.insert(b"test".to_vec(), b"test".to_vec()).unwrap();
        let v = trie.get(b"test").unwrap();

        assert_eq!(Some(b"test".to_vec()), v)
    }

    #[test]
    fn test_trie_random_insert() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = PatriciaTrie::new(memdb, Arc::new(HasherKeccak::new()));

        for _ in 0..1000 {
            let rand_str: String = thread_rng().sample_iter(&Alphanumeric).take(30).collect();
            let val = rand_str.as_bytes();
            trie.insert(val.to_vec(), val.to_vec()).unwrap();

            let v = trie.get(val).unwrap();
            assert_eq!(v.map(|v| v.to_vec()), Some(val.to_vec()));
        }
    }

    #[test]
    fn test_trie_contains() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = PatriciaTrie::new(memdb, Arc::new(HasherKeccak::new()));
        trie.insert(b"test".to_vec(), b"test".to_vec()).unwrap();
        assert_eq!(true, trie.contains(b"test").unwrap());
        assert_eq!(false, trie.contains(b"test2").unwrap());
    }

    #[test]
    fn test_trie_remove() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = PatriciaTrie::new(memdb, Arc::new(HasherKeccak::new()));
        trie.insert(b"test".to_vec(), b"test".to_vec()).unwrap();
        let removed = trie.remove(b"test").unwrap();
        assert_eq!(true, removed)
    }

    #[test]
    fn test_trie_random_remove() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = PatriciaTrie::new(memdb, Arc::new(HasherKeccak::new()));

        for _ in 0..1000 {
            let rand_str: String = thread_rng().sample_iter(&Alphanumeric).take(30).collect();
            let val = rand_str.as_bytes();
            trie.insert(val.to_vec(), val.to_vec()).unwrap();

            let removed = trie.remove(val).unwrap();
            assert_eq!(true, removed);
        }
    }

    #[test]
    fn test_trie_from_root() {
        let memdb = Arc::new(MemoryDB::new(true));
        let root = {
            let mut trie = PatriciaTrie::new(Arc::clone(&memdb), Arc::new(HasherKeccak::new()));
            trie.insert(b"test".to_vec(), b"test".to_vec()).unwrap();
            trie.insert(b"test1".to_vec(), b"test".to_vec()).unwrap();
            trie.insert(b"test2".to_vec(), b"test".to_vec()).unwrap();
            trie.insert(b"test23".to_vec(), b"test".to_vec()).unwrap();
            trie.insert(b"test33".to_vec(), b"test".to_vec()).unwrap();
            trie.insert(b"test44".to_vec(), b"test".to_vec()).unwrap();
            trie.root().unwrap()
        };

        let mut trie =
            PatriciaTrie::from(Arc::clone(&memdb), Arc::new(HasherKeccak::new()), &root).unwrap();
        let v1 = trie.get(b"test33").unwrap();
        assert_eq!(Some(b"test".to_vec()), v1);
        let v2 = trie.get(b"test44").unwrap();
        assert_eq!(Some(b"test".to_vec()), v2);
        let root2 = trie.root().unwrap();
        assert_eq!(hex::encode(root), hex::encode(root2));
    }

    #[test]
    fn test_trie_from_root_and_insert() {
        let memdb = Arc::new(MemoryDB::new(true));
        let root = {
            let mut trie = PatriciaTrie::new(Arc::clone(&memdb), Arc::new(HasherKeccak::new()));
            trie.insert(b"test".to_vec(), b"test".to_vec()).unwrap();
            trie.insert(b"test1".to_vec(), b"test".to_vec()).unwrap();
            trie.insert(b"test2".to_vec(), b"test".to_vec()).unwrap();
            trie.insert(b"test23".to_vec(), b"test".to_vec()).unwrap();
            trie.insert(b"test33".to_vec(), b"test".to_vec()).unwrap();
            trie.insert(b"test44".to_vec(), b"test".to_vec()).unwrap();
            trie.commit().unwrap()
        };

        let mut trie =
            PatriciaTrie::from(Arc::clone(&memdb), Arc::new(HasherKeccak::new()), &root).unwrap();
        trie.insert(b"test55".to_vec(), b"test55".to_vec()).unwrap();
        trie.commit().unwrap();
        let v = trie.get(b"test55").unwrap();
        assert_eq!(Some(b"test55".to_vec()), v);
    }

    #[test]
    fn test_trie_from_root_and_delete() {
        let memdb = Arc::new(MemoryDB::new(true));
        let root = {
            let mut trie = PatriciaTrie::new(Arc::clone(&memdb), Arc::new(HasherKeccak::new()));
            trie.insert(b"test".to_vec(), b"test".to_vec()).unwrap();
            trie.insert(b"test1".to_vec(), b"test".to_vec()).unwrap();
            trie.insert(b"test2".to_vec(), b"test".to_vec()).unwrap();
            trie.insert(b"test23".to_vec(), b"test".to_vec()).unwrap();
            trie.insert(b"test33".to_vec(), b"test".to_vec()).unwrap();
            trie.insert(b"test44".to_vec(), b"test".to_vec()).unwrap();
            trie.commit().unwrap()
        };

        let mut trie =
            PatriciaTrie::from(Arc::clone(&memdb), Arc::new(HasherKeccak::new()), &root).unwrap();
        let removed = trie.remove(b"test44").unwrap();
        assert_eq!(true, removed);
        let removed = trie.remove(b"test33").unwrap();
        assert_eq!(true, removed);
        let removed = trie.remove(b"test23").unwrap();
        assert_eq!(true, removed);
    }

    #[test]
    fn test_multiple_trie_roots() {
        let k0: ethereum_types::H256 = 0.into();
        let k1: ethereum_types::H256 = 1.into();
        let v: ethereum_types::H256 = 0x1234.into();

        let root1 = {
            let memdb = Arc::new(MemoryDB::new(true));
            let mut trie = PatriciaTrie::new(memdb, Arc::new(HasherKeccak::new()));
            trie.insert(k0.as_bytes().to_vec(), v.as_bytes().to_vec())
                .unwrap();
            trie.root().unwrap()
        };

        let root2 = {
            let memdb = Arc::new(MemoryDB::new(true));
            let mut trie = PatriciaTrie::new(memdb, Arc::new(HasherKeccak::new()));
            trie.insert(k0.as_bytes().to_vec(), v.as_bytes().to_vec())
                .unwrap();
            trie.insert(k1.as_bytes().to_vec(), v.as_bytes().to_vec())
                .unwrap();
            trie.root().unwrap();
            trie.remove(k1.as_ref()).unwrap();
            trie.root().unwrap()
        };

        let root3 = {
            let memdb = Arc::new(MemoryDB::new(true));
            let mut trie1 = PatriciaTrie::new(Arc::clone(&memdb), Arc::new(HasherKeccak::new()));
            trie1
                .insert(k0.as_bytes().to_vec(), v.as_bytes().to_vec())
                .unwrap();
            trie1
                .insert(k1.as_bytes().to_vec(), v.as_bytes().to_vec())
                .unwrap();
            trie1.root().unwrap();
            let root = trie1.root().unwrap();
            let mut trie2 =
                PatriciaTrie::from(Arc::clone(&memdb), Arc::new(HasherKeccak::new()), &root)
                    .unwrap();
            trie2.remove(&k1.as_bytes().to_vec()).unwrap();
            trie2.root().unwrap()
        };

        assert_eq!(root1, root2);
        assert_eq!(root2, root3);
    }

    #[test]
    fn test_delete_stale_keys_with_random_insert_and_delete() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = PatriciaTrie::new(memdb, Arc::new(HasherKeccak::new()));

        let mut rng = rand::thread_rng();
        let mut keys = vec![];
        for _ in 0..100 {
            let random_bytes: Vec<u8> = (0..rng.gen_range(2, 30))
                .map(|_| rand::random::<u8>())
                .collect();
            trie.insert(random_bytes.clone(), random_bytes.clone())
                .unwrap();
            keys.push(random_bytes.clone());
        }
        trie.commit().unwrap();
        let slice = &mut keys;
        slice.shuffle(&mut rng);

        for key in slice.iter() {
            trie.remove(key).unwrap();
        }
        trie.commit().unwrap();

        let empty_node_key = HasherKeccak::new().digest(&rlp::NULL_RLP);
        let value = trie.db.get(empty_node_key.as_ref()).unwrap().unwrap();
        assert_eq!(value, &rlp::NULL_RLP)
    }

    #[test]
    fn insert_full_branch() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = PatriciaTrie::new(memdb, Arc::new(HasherKeccak::new()));

        trie.insert(b"test".to_vec(), b"test".to_vec()).unwrap();
        trie.insert(b"test1".to_vec(), b"test".to_vec()).unwrap();
        trie.insert(b"test2".to_vec(), b"test".to_vec()).unwrap();
        trie.insert(b"test23".to_vec(), b"test".to_vec()).unwrap();
        trie.insert(b"test33".to_vec(), b"test".to_vec()).unwrap();
        trie.insert(b"test44".to_vec(), b"test".to_vec()).unwrap();
        trie.root().unwrap();

        let v = trie.get(b"test").unwrap();
        assert_eq!(Some(b"test".to_vec()), v);
    }

    #[test]
    fn iterator_trie() {
        let memdb = Arc::new(MemoryDB::new(true));
        let root1;
        let mut kv = HashMap::new();
        kv.insert(b"test".to_vec(), b"test".to_vec());
        kv.insert(b"test1".to_vec(), b"test1".to_vec());
        kv.insert(b"test11".to_vec(), b"test2".to_vec());
        kv.insert(b"test14".to_vec(), b"test3".to_vec());
        kv.insert(b"test16".to_vec(), b"test4".to_vec());
        kv.insert(b"test18".to_vec(), b"test5".to_vec());
        kv.insert(b"test2".to_vec(), b"test6".to_vec());
        kv.insert(b"test23".to_vec(), b"test7".to_vec());
        kv.insert(b"test9".to_vec(), b"test8".to_vec());
        {
            let mut trie = PatriciaTrie::new(memdb.clone(), Arc::new(HasherKeccak::new()));
            let mut kv = kv.clone();
            kv.iter().for_each(|(k, v)| {
                trie.insert(k.clone(), v.clone()).unwrap();
            });
            root1 = trie.root().unwrap();

            trie.iter()
                .for_each(|(k, v)| assert_eq!(kv.remove(&k).unwrap(), v));
            assert!(kv.is_empty());
        }

        {
            let mut trie = PatriciaTrie::new(memdb.clone(), Arc::new(HasherKeccak::new()));
            let mut kv2 = HashMap::new();
            kv2.insert(b"test".to_vec(), b"test11".to_vec());
            kv2.insert(b"test1".to_vec(), b"test12".to_vec());
            kv2.insert(b"test14".to_vec(), b"test13".to_vec());
            kv2.insert(b"test22".to_vec(), b"test14".to_vec());
            kv2.insert(b"test9".to_vec(), b"test15".to_vec());
            kv2.insert(b"test16".to_vec(), b"test16".to_vec());
            kv2.insert(b"test2".to_vec(), b"test17".to_vec());
            kv2.iter().for_each(|(k, v)| {
                trie.insert(k.clone(), v.clone()).unwrap();
            });

            trie.root().unwrap();

            let mut kv_delete = HashSet::new();
            kv_delete.insert(b"test".to_vec());
            kv_delete.insert(b"test1".to_vec());
            kv_delete.insert(b"test14".to_vec());

            kv_delete.iter().for_each(|k| {
                trie.remove(&k).unwrap();
            });

            kv2.retain(|k, _| !kv_delete.contains(k));

            trie.root().unwrap();
            trie.iter()
                .for_each(|(k, v)| assert_eq!(kv2.remove(&k).unwrap(), v));
            assert!(kv2.is_empty());
        }

        let trie = PatriciaTrie::from(memdb, Arc::new(HasherKeccak::new()), &root1).unwrap();
        trie.iter()
            .for_each(|(k, v)| assert_eq!(kv.remove(&k).unwrap(), v));
        assert!(kv.is_empty());
    }
}
