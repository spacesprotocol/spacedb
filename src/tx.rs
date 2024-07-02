use crate::{Result, path::{Direction, Path}, subtree::ValueOrHash, Error};

use bincode::config;
use core::marker::PhantomData;
use std::{io, sync::MutexGuard};

use crate::{
    db::{Database, Record, SavePoint, EMPTY_RECORD, CHUNK_SIZE},
    node::{Node, NodeInner},
    path::{BitLength, PathUtils},
    subtree::{SubTree, SubTreeNode},
    Hash, NodeHasher,
};

use crate::{db::DatabaseHeader, fs::WriteBuffer};

use crate::{
    path::{PathSegment, PathSegmentInner},
};

const BUFFER_SIZE: usize = 16 * 64 * 1024;

#[derive(Copy, Clone, PartialEq)]
pub enum ProofType {
    Standard,
    Extended,
}

pub struct WriteTransaction<'db, H: NodeHasher> {
    pub db: &'db Database<H>,
    pub(crate) state: Option<Node>,
    header: MutexGuard<'db, DatabaseHeader>,
    metadata: Option<Vec<u8>>,
}

#[derive(Clone)]
pub struct ReadTransaction<H: NodeHasher> {
    db: Database<H>,
    savepoint: SavePoint,
    cache: Cache,
}

#[derive(Clone)]
pub struct Cache {
    pub node: Option<Node>,
    pub len: usize,
    pub max_len: usize,
}

struct CacheEntry<'n> {
    node: &'n mut Node,
    clean: bool,
}

struct SubTreeNodeInfo {
    node: SubTreeNode,
    value_node: bool,
}

impl<H: NodeHasher> ReadTransaction<H> {
    pub(crate) fn new(db: Database<H>, savepoint: SavePoint) -> Self {
        let cache_size = db.config.cache_size;
        let root = savepoint.root;

        Self {
            db,
            savepoint,
            cache: Cache::new(root, cache_size),
        }
    }

    pub fn iter(&self) -> KeyIterator<H> {
        KeyIterator::new(self.db.clone(), self.savepoint.root)
    }

    pub fn rollback(&self) -> Result<()> {
        let mut header = self.db.header.lock().expect("acquire lock");
        header.savepoint = self.savepoint.clone();
        self.db.write_header(&header)?;
        self.db.file.set_len(header.len())?;
        Ok(())
    }

    pub fn metadata(&self) -> &[u8] {
        match &self.savepoint.metadata {
            None => &[],
            Some(meta) => meta.as_slice()
        }
    }

    pub fn get(&mut self, key: &Hash) -> Result<Option<Vec<u8>>> {
        if self.is_empty() {
            return Ok(None)
        }

        let mut node = self.cache.node.take().unwrap();
        let result = Self::get_node(&self.db, &mut self.cache, &mut node, Path(key), 0);
        self.cache.node = Some(node);
        result
    }

    pub fn root(&mut self) -> Result<Hash> {
        if self.is_empty() {
            return Ok(H::hash(&[]));
        }

        let mut n = self.cache.node.take().unwrap();
        let h = {
            let entry = Self::hash_node(&self.db, &mut self.cache, &mut n)?;
            entry.node.hash_cache.clone().unwrap()
        };
        self.cache.node = Some(n);
        Ok(h)
    }

    pub fn prove(&mut self, keys: &[Hash], proof_type: ProofType) -> Result<SubTree<H>> {
        if self.is_empty() {
            return Ok(SubTree::<H>::empty());
        }

        let mut node = self.cache.node.take().unwrap();
        let mut key_paths = keys.iter().map(|k| Path(k)).collect::<Vec<_>>();
        key_paths.sort();

        match Self::prove_nodes(&self.db, &mut self.cache, &mut node, key_paths.as_slice(), 0, proof_type) {
            Ok(info) => {
                self.cache.node = Some(node);
                Ok(SubTree::<H> {
                    root: info.node,
                    _marker: PhantomData::<H>,
                })
            }
            Err(e) => {
                self.cache.node = Some(node);
                Err(e)
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.savepoint.root == EMPTY_RECORD
    }

    fn prove_nodes(
        db: &Database<H>,
        cache: &mut Cache,
        node: &mut Node,
        keys: &[Path<&Hash>],
        depth: usize,
        proof_type: ProofType,
    ) -> Result<SubTreeNodeInfo> {
        let entry = cache.load_node(db, node)?;
        match entry.node.inner.as_mut().unwrap() {
            NodeInner::Leaf {
                key: node_key,
                value,
            } => {
                let include_value = keys.iter().any(|k| *k.0 == node_key.0);
                let value_or_hash = if include_value {
                    ValueOrHash::Value(value.clone())
                } else {
                    ValueOrHash::Hash(H::hash(value))
                };
                Ok(SubTreeNodeInfo {
                    node: SubTreeNode::Leaf {
                        key: node_key.clone(),
                        value_or_hash,
                    },
                    value_node: include_value,
                })
            }
            NodeInner::Internal {
                prefix,
                left,
                right,
            } => {
                // Exclude keys that are not in this subtree.
                let end = keys.partition_point(|key| key.split_point(depth, *prefix).is_none());
                let keys = &keys[..end];

                // Keys are split based on their direction at the current depth.
                let depth = depth + prefix.bit_len();

                let split = keys.partition_point(|key| key.direction(depth) == Direction::Left);
                let (left_keys, right_keys) = keys.split_at(split);

                let mut left_subtree = if left_keys.is_empty() { None } else {
                    Some(Self::prove_nodes(db, cache, left, left_keys, depth + 1, proof_type)?)
                };
                let mut right_subtree = if right_keys.is_empty() { None } else {
                    Some(Self::prove_nodes(db, cache, right, right_keys, depth + 1, proof_type)?)
                };

                // Include extended hash of the sibling if its subtree isn't already part of the proof
                if proof_type == ProofType::Extended && left_subtree.is_none() &&
                    right_subtree.is_some() && right_subtree.as_ref().unwrap().value_node {
                    left_subtree = Some(SubTreeNodeInfo {
                        node: Self::hash_node_extended(db, cache, left)?,
                        value_node: false,
                    })
                }
                if proof_type == ProofType::Extended && right_subtree.is_none() &&
                    left_subtree.is_some() && left_subtree.as_ref().unwrap().value_node {
                    right_subtree = Some(SubTreeNodeInfo {
                        node: Self::hash_node_extended(db, cache, right)?,
                        value_node: false,
                    })
                }

                // If extended hashes aren't needed, include basic ones
                if left_subtree.is_none() {
                    let left_entry = Self::hash_node(db, cache, left)?;
                    let left_hash = left_entry.node.hash_cache.clone().unwrap();
                    left_subtree = Some(SubTreeNodeInfo {
                        node: SubTreeNode::Hash(left_hash),
                        value_node: false,
                    });
                }
                if right_subtree.is_none() {
                    let right_entry = Self::hash_node(db, cache, right)?;
                    let right_hash = right_entry.node.hash_cache.clone().unwrap();
                    right_subtree = Some(SubTreeNodeInfo {
                        node: SubTreeNode::Hash(right_hash),
                        value_node: false,
                    });
                }

                // if left and right subtrees are value leafs, we need to include the sibling of this node
                let value_node = left_subtree.as_ref().unwrap().value_node &&
                    right_subtree.as_ref().unwrap().value_node;

                Ok(SubTreeNodeInfo {
                    node: SubTreeNode::Internal {
                        prefix: prefix.clone(),
                        left: Box::new(left_subtree.unwrap().node),
                        right: Box::new(right_subtree.unwrap().node),
                    },
                    value_node,
                })
            }
        }
    }


    fn hash_node<'c>(
        db: &Database<H>,
        cache: &mut Cache,
        node: &'c mut Node,
    ) -> Result<CacheEntry<'c>> {
        if node.hash_cache.is_some() {
            return Ok(CacheEntry::new(node, false));
        }

        let entry = cache.load_node(db, node)?;
        match entry.node.inner.as_mut().unwrap() {
            NodeInner::Leaf { key, value } => {
                let hash = H::hash(value);
                entry.node.hash_cache = Some(H::hash_leaf(&key.0, &hash));
            }
            NodeInner::Internal {
                prefix,
                left,
                right,
            } => {
                let left_entry = Self::hash_node(db, cache, left)?;
                let left_hash = left_entry.node.hash_cache.as_ref().unwrap();
                let right_entry = Self::hash_node(db, cache, right)?;
                let right_hash = right_entry.node.hash_cache.as_ref().unwrap();
                entry.node.hash_cache =
                    Some(H::hash_internal(prefix.as_bytes(), left_hash, right_hash));
            }
        }
        Ok(entry)
    }

    /// Creates an extended hash of a node
    /// For internal nodes, it would be the prefix value, left and right hashes.
    /// For leaf nodes, it's the key and value hashes.
    ///
    /// Note: This is different from regular hashing as it converts a [Node] into either
    /// a [SubTreeNode::Internal] or [SubTreeNode::Leaf]
    /// while `hash_node` converts any [Node] into a [SubTreeNode::Hash]
    fn hash_node_extended(
        db: &Database<H>,
        cache: &mut Cache,
        node: &mut Node,
    ) -> Result<SubTreeNode> {
        let entry = cache.load_node(db, node)?;
        match entry.node.inner.as_mut().unwrap() {
            NodeInner::Leaf { key, value } => {
                let hash = H::hash(value);
                Ok(SubTreeNode::Leaf {
                    key: key.clone(),
                    value_or_hash: ValueOrHash::Hash(hash),
                })
            }
            NodeInner::Internal {
                prefix,
                left,
                right,
            } => {
                let left_hash = Self::hash_node(db, cache, left)?.node.hash_cache.as_ref().unwrap().clone();
                let right_hash = Self::hash_node(db, cache, right)?.node.hash_cache.as_ref().unwrap().clone();
                Ok(SubTreeNode::Internal {
                    prefix: prefix.clone(),
                    left: Box::new(SubTreeNode::Hash(left_hash)),
                    right: Box::new(SubTreeNode::Hash(right_hash)),
                })
            }
        }
    }

    fn get_node<'c>(
        db: &Database<H>,
        cache: &mut Cache,
        node: &'c mut Node,
        key: Path<&Hash>,
        depth: usize,
    ) -> Result<Option<Vec<u8>>> {
        let entry = cache.load_node(db, node)?;
        match entry.node.inner.as_mut().unwrap() {
            NodeInner::Leaf {
                value,
                key: node_key,
            } => {
                if node_key.0 == *key.0 {
                    return Ok(Some(value.clone()));
                }
                return Ok(None);
            }
            NodeInner::Internal {
                prefix,
                left,
                right,
            } => {
                if key.split_point(depth, *prefix).is_some() {
                    return Ok(None);
                }
                let depth = depth + prefix.bit_len();
                match key.direction(depth) {
                    Direction::Right => Self::get_node(db, cache, right, key, depth + 1),
                    Direction::Left => Self::get_node(db, cache, left, key, depth + 1),
                }
            }
        }
    }
}


impl<'db, H: NodeHasher> WriteTransaction<'db, H> {
    pub(crate) fn new(db: &'db Database<H>) -> Self {
        let head = db.header.lock().unwrap();
        let state = if head.savepoint.root == EMPTY_RECORD {
            None
        } else {
            Some(Node::from_id(head.savepoint.root))
        };

        Self {
            db,
            state,
            header: head,
            metadata: None,
        }
    }

    pub fn metadata(&mut self, metadata: Vec<u8>) -> Result<()> {
        if metadata.len() > 512 {
            return Err(io::Error::new(io::ErrorKind::Other, "metadata must not exceed 512 bytes").into());
        }

        self.metadata = Some(metadata);
        Ok(())
    }

    pub fn insert(&mut self, key: Hash, value: Vec<u8>) -> Result<()> {
        if self.state.is_none() {
            self.state = Some(Node::from_leaf(Path(key), value));
            return Ok(());
        }

        let mut state = self.state.take().unwrap();
        state = self.insert_into_node(state, Path(key), value, 0)?;
        self.state = Some(state);
        Ok(())
    }

    pub fn delete(&mut self, key: Hash) -> Result<Option<Vec<u8>>> {
        if self.state.is_none() {
            return Ok(None);
        }

        let state = self.state.take().unwrap();
        let (node, value) = self.delete_node(state, Path(key), 0)?;
        self.state = node;

        Ok(value)
    }

    fn insert_into_node(
        &mut self,
        node: Node,
        key: Path<Hash>,
        value: Vec<u8>,
        depth: usize,
    ) -> Result<Node> {
        let inner = self.read_inner(node)?;
        match inner {
            NodeInner::Leaf {
                key: node_key,
                value: node_value,
            } => self.insert_leaf(node_key, node_value, key, value, depth),
            NodeInner::Internal {
                prefix,
                left,
                right,
            } => self.insert_internal(prefix, left, right, key, value, depth),
        }
    }

    #[inline]
    fn insert_internal(
        &mut self,
        prefix: PathSegment<PathSegmentInner>,
        left: Box<Node>,
        right: Box<Node>,
        key: Path<Hash>,
        value: Vec<u8>,
        depth: usize,
    ) -> Result<Node> {
        let point = key.split_point(depth, prefix);
        if point.is_none() {
            let depth = depth + prefix.bit_len();
            // Traverse further based on the direction
            return match key.direction(depth) {
                Direction::Right => {
                    let new_node =
                        Box::new(self.insert_into_node(*right, key, value, depth + 1)?);
                    Ok(Node::from_internal(prefix, left, new_node))
                }
                Direction::Left => {
                    let new_node = Box::new(self.insert_into_node(*left, key, value, depth + 1)?);
                    Ok(Node::from_internal(prefix, new_node, right))
                }
            };
        }

        // A split point exists: compress common path into an internal node
        let point = point.unwrap();

        // Prefix paths are relative to the depth
        // Parent will be from 0th bit of the prefix (inclusive) to split point (exclusive)
        let parent_prefix = PathSegment::from_path(prefix, 0, point);

        // Since current node is going down one level, we need to copy from split point+1 i.e. skipping 1 bit.
        let prefix = PathSegment::from_path(prefix, point + 1, prefix.bit_len());

        let current_node = Node::from_internal(prefix, left, right);
        let new_node = Node::from_leaf(key, value);

        let depth = depth + parent_prefix.bit_len();
        let (left, right) = match key.direction(depth) {
            Direction::Right => (current_node, new_node),
            Direction::Left => (new_node, current_node),
        };

        Ok(Node::from_internal(
            parent_prefix,
            Box::new(left),
            Box::new(right),
        ))
    }

    #[inline]
    fn insert_leaf(
        &mut self,
        current_key: Path<Hash>,
        current_value: Vec<u8>,
        key: Path<Hash>,
        value: Vec<u8>,
        depth: usize,
    ) -> Result<Node> {
        // Same key: update value
        if current_key == key {
            return Ok(Node::from_leaf(key, value));
        }

        // A split point must exist: compress common path into an internal node
        let point = current_key.split_point(0, key).unwrap();
        let prefix = PathSegment::from_path(current_key, depth, point);

        let depth = depth + prefix.bit_len();
        let node_direction = key.direction(depth);
        let current_node = Node::from_leaf(current_key, current_value);
        let node = Node::from_leaf(key, value);

        let (left, right) = match node_direction {
            Direction::Right => (current_node, node),
            Direction::Left => (node, current_node),
        };

        Ok(Node::from_internal(prefix, Box::new(left), Box::new(right)))
    }

    fn delete_node(
        &mut self,
        node: Node,
        key: Path<Hash>,
        depth: usize,
    ) -> Result<(Option<Node>, Option<Vec<u8>>)> {
        let inner = self.read_inner(node)?;
        return match inner {
            NodeInner::Leaf {
                key: node_key, value
            } => {
                if node_key != key {
                    let node = Node::from_leaf(node_key, value);
                    return Ok((Some(node), None));
                }
                Ok((None, Some(value)))
            }
            NodeInner::Internal {
                prefix,
                left,
                right,
            } => {
                let depth = depth + prefix.bit_len();
                // Traverse further based on the direction
                match key.direction(depth) {
                    Direction::Right => {
                        let (right_subtree, value) = self.delete_node(*right, key, depth + 1)?;
                        match right_subtree {
                            None => {
                                // Right subtree was deleted, move left subtree up
                                let left_subtree = self.read_inner(*left)?;
                                Ok((Some(self.lift_node(prefix, left_subtree, Direction::Left)), value))
                            }
                            Some(right_subtree) => {
                                Ok((Some(
                                    Node::from_internal(prefix, left, Box::new(right_subtree))
                                ), value))
                            }
                        }
                    }
                    Direction::Left => {
                        let (left_subtree, value) = self.delete_node(*left, key, depth + 1)?;
                        return match left_subtree {
                            None => {
                                // Left subtree was deleted, move right subtree up
                                let right_subtree = self.read_inner(*right)?;
                                Ok((Some(self.lift_node(prefix, right_subtree, Direction::Right)), value))
                            }
                            Some(left_subtree) => {
                                Ok((Some(
                                    Node::from_internal(prefix, Box::new(left_subtree), right)
                                ), value))
                            }
                        };
                    }
                }
            }
        };
    }

    #[inline(always)]
    fn lift_node(
        &self,
        mut parent_prefix: PathSegment<PathSegmentInner>,
        node: NodeInner,
        direction: Direction,
    ) -> Node {
        match node {
            NodeInner::Leaf { key: leaf_key, value: leaf_value } => {
                Node::from_leaf(leaf_key, leaf_value)
            }
            NodeInner::Internal {
                prefix:
                child_prefix,
                left: child_left,
                right: child_right
            } => {

                // Since this node is being lifted one level append a single bit
                // based on its direction
                match direction {
                    Direction::Left => parent_prefix.extend_from_byte(0, 1),
                    Direction::Right => parent_prefix.extend_from_byte(0b1000_0000, 1)
                }

                // Extend the parent's prefix with the node prefix being lifted
                parent_prefix.extend(child_prefix);
                Node::from_internal(parent_prefix, child_left, child_right)
            }
        }
    }

    fn read_inner(&self, node: Node) -> Result<NodeInner> {
        Ok(match node.inner {
            Some(node) => node,
            None => {
                if node.id == EMPTY_RECORD {
                    return Err(io::Error::new(io::ErrorKind::NotFound, "Node not found").into());
                }
                let raw = self.db.file.read(node.id.offset, node.id.size as usize)?;
                let config = config::standard();
                let (inner, _): (NodeInner, usize) =
                    bincode::decode_from_slice(&raw, config).unwrap();
                inner
            }
        })
    }

    fn write_all(
        &mut self,
        buf: &mut WriteBuffer<BUFFER_SIZE>,
        node: &mut Node,
    ) -> Result<Record> {
        match &mut node.inner {
            Some(NodeInner::Leaf { .. }) => {
                node.id = buf.write_node(node)?;
            }
            Some(NodeInner::Internal { left, right, .. }) => {
                self.write_all(buf, left)?;
                self.write_all(buf, right)?;
                node.id = buf.write_node(node)?;
            }
            None => {
                if node.id != EMPTY_RECORD {
                    return Ok(node.id);
                }
                return Err(Error::from(io::ErrorKind::NotFound));
            }
        }

        Ok(node.id)
    }


    pub fn commit(mut self) -> Result<()> {
        if self.state.is_none() && self.metadata.is_none() {
            return Ok(());
        }

        let write_len = self.header.len();
        assert_eq!(
            write_len % CHUNK_SIZE,
            0,
            "Database length is not a multiple of chunk size {}",
            write_len
        );

        let file_length = self.db.file.len()?;
        if file_length != write_len {
            // truncate/extend file to expected length
            self.db.file.set_len(write_len)?;
        }

        let mut buf: WriteBuffer<BUFFER_SIZE> = WriteBuffer::new(&self.db.file, file_length);

        let root = match self.state.take() {
            None => self.header.savepoint.root,
            Some(mut state) => {
                self.write_all(&mut buf, &mut state)?
            }
        };

        let previous_savepoint = buf.write_save_point(&self.header.savepoint)?;
        buf.flush()?;
        self.db.file.sync_data()?;

        self.header.savepoint = SavePoint {
            root,
            previous_savepoint,
            metadata: self.metadata,
        };

        self.db.write_header(&self.header)?;
        Ok(())
    }
}

pub struct KeyIterator<H: NodeHasher> {
    db: Database<H>,
    stack: Vec<Record>,
}

impl<H: NodeHasher> KeyIterator<H> {
    fn new(db: Database<H>, root: Record) -> Self {
        let stack = vec![root];
        Self { db, stack }
    }
}

impl<'db, H: NodeHasher> Iterator for KeyIterator<H> {
    type Item = Result<(Hash, Vec<u8>)>;

    fn next(&mut self) -> Option<Self::Item> {
        let record = self.stack.pop()?;
        if record == EMPTY_RECORD {
            return None;
        }

        match self.db.load_node(record) {
            Ok(inner) => match inner {
                NodeInner::Leaf { key, value } => Some(Ok((key.0, value))),
                NodeInner::Internal { left, right, .. } => {
                    self.stack.push(left.id);
                    self.stack.push(right.id);
                    self.next()
                }
            },
            Err(e) => Some(Err(Error::from(e))),
        }
    }
}

impl<'n> CacheEntry<'n> {
    fn new(node: &'n mut Node, clean: bool) -> Self {
        Self { node, clean }
    }
}

impl Drop for CacheEntry<'_> {
    fn drop(&mut self) {
        if self.clean {
            self.node.inner = None;
        }
    }
}

impl Cache {
    fn new(record: Record, capacity: usize) -> Self {
        Self {
            node: Some(Node::from_id(record)),
            len: 0,
            max_len: capacity,
        }
    }

    fn is_full(&self) -> bool {
        self.len > self.max_len
    }

    fn load_node<'c, H: NodeHasher>(&mut self, db: &Database<H>, node: &'c mut Node) -> Result<CacheEntry<'c>> {
        if node.inner.is_some() {
            return Ok(CacheEntry { node, clean: false });
        }
        assert_ne!(node.id, EMPTY_RECORD, "Attempted to read empty record");
        let is_full = self.is_full();

        let inner = db.load_node(node.id)?;

        let empty_len = node.mem_size();
        node.inner = Some(inner);
        let new_len = node.mem_size();
        if !is_full {
            self.len += new_len - empty_len;
        }

        Ok(CacheEntry {
            node,
            clean: is_full,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::db::Database;
    use crate::subtree::SubTreeNode;
    use crate::tx::ProofType;

    #[test]
    fn test_extended_proofs() {
        let db = Database::memory().unwrap();
        let mut tx = db.begin_write().unwrap();
        tx.insert([0b1000_0000u8; 32], vec![1]).unwrap();
        tx.insert([0b1100_0000u8; 32], vec![2]).unwrap();
        tx.insert([0b0000_0000u8; 32], vec![3]).unwrap();
        tx.commit().unwrap();

        let mut snapshot = db.begin_read().unwrap();
        let standard_subtree = snapshot.prove(&[[0u8; 32]], ProofType::Standard).unwrap();

        match standard_subtree.root {
            SubTreeNode::Internal { left, right, .. } => {
                assert!(left.is_value_leaf(), "expected a value leaf on left");
                assert!(matches!(*right, SubTreeNode::Hash(_)), "expected a hash node on the right");
            }
            _ => panic!("invalid result")
        }

        let extended_subtree = snapshot.prove(&[[0u8; 32]], ProofType::Extended).unwrap();
        match extended_subtree.root {
            SubTreeNode::Internal { left, right, .. } => {
                assert!(left.is_value_leaf(), "expected a value leaf on left");
                // Extended proof includes the sibling with terminal child hashes if any
                match *right {
                    SubTreeNode::Internal { left: left_left, right: left_right, .. } => {
                        assert!(matches!(*left_left, SubTreeNode::Hash(_)), "expected a hash node");
                        assert!(matches!(*left_right, SubTreeNode::Hash(_)), "expected a hash node");
                    }
                    _ => panic!("expected internal node")
                }
            }
            _ => panic!("invalid result")
        }
    }
}
