use crate::{Result, path::{Direction, Path}, subtree::ValueOrHash, Error};

use bincode::config;
use core::marker::PhantomData;
use std::{io, sync::MutexGuard};

use crate::{
    db::{Database, Record, SavePoint, EMPTY_RECORD, PAGE_SIZE},
    node::{Node, NodeInner},
    path::{BitLength, PathUtils},
    subtree::{SubTree, SubTreeNode},
    Configuration, Hash, NodeHasher,
};

use crate::{db::DatabaseHeader, fs::WriteBuffer};

use crate::{
    path::{PathSegment, PathSegmentInner},
    ZERO_HASH,
};

const BUFFER_SIZE: usize = 16 * 64 * 1024;

pub struct WriteTransaction<'db, H: NodeHasher> {
    pub db: &'db Database<H>,
    pub(crate) state: Option<Node>,
    header: MutexGuard<'db, DatabaseHeader>,
}

pub struct ReadTransaction<'db, H: NodeHasher> {
    pub db: &'db Database<H>,
    pub root: Record,
    pub cache: Cache<'db, H>,
    pub config: Configuration<H>,
}

pub struct Cache<'db, H: NodeHasher> {
    db: &'db Database<H>,
    pub node: Option<Node>,
    pub len: usize,
    pub max_len: usize,
}

struct CacheEntry<'n> {
    node: &'n mut Node,
    clean: bool,
}

impl<'db, H: NodeHasher + 'db> ReadTransaction<'db, H> {
    pub(crate) fn new(db: &'db Database<H>, savepoint: SavePoint) -> Self {
        Self {
            db,
            root: savepoint.root,
            cache: Cache::new(db, savepoint.root, db.config.cache_size),
            config: db.config.clone(),
        }
    }

    pub fn iter(&self) -> KeyIterator<H> {
        KeyIterator::new(self.db, self.root)
    }

    pub fn get(&mut self, key: &Hash) -> Result<Option<Vec<u8>>> {
        let mut node = self.cache.node.take().unwrap();
        let result = Self::get_node(&mut self.cache, &mut node, Path(key), 0);
        self.cache.node = Some(node);
        result
    }

    pub fn root(&mut self) -> Result<Hash> {
        let mut n = self.cache.node.take().unwrap();
        if n.id == EMPTY_RECORD {
            self.cache.node = Some(n);
            return Ok(H::hash(&[]));
        }

        let h = {
            let entry = Self::load_hash(&mut self.cache, &mut n)?;
            entry.node.hash_cache.clone().unwrap()
        };
        self.cache.node = Some(n);
        Ok(h)
    }

    pub fn prove(&mut self, keys: &[Hash]) -> Result<SubTree<H>> {
        let mut node = self.cache.node.take().unwrap();
        if node.id == EMPTY_RECORD {
            self.cache.node = Some(node);
            return Ok(SubTree::<H>::empty());
        }

        let mut key_paths = keys.iter().map(|k| Path(k)).collect::<Vec<_>>();
        key_paths.sort();

        let subtree = Self::prove_nodes(&mut self.cache, &mut node, key_paths.as_slice(), 0);
        self.cache.node = Some(node);
        if subtree.is_ok() {
            Ok(SubTree::<H> {
                root: subtree.unwrap(),
                _marker: PhantomData::<H>,
            })
        } else {
            Err(subtree.unwrap_err())
        }
    }

    fn prove_nodes(
        cache: &mut Cache<H>,
        node: &mut Node,
        keys: &[Path<&Hash>],
        depth: usize,
    ) -> Result<SubTreeNode> {
        let entry = cache.load_node(node)?;
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
                Ok(SubTreeNode::Leaf {
                    key: node_key.clone(),
                    value_or_hash,
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

                let left_subtree = if left_keys.is_empty() {
                    let left_entry = Self::load_hash(cache, left)?;
                    let left_hash = left_entry.node.hash_cache.clone().unwrap();
                    SubTreeNode::Hash(left_hash)
                } else {
                    Self::prove_nodes(cache, left, left_keys, depth + 1)?
                };

                let right_subtree = if right_keys.is_empty() {
                    let right_entry = Self::load_hash(cache, right)?;
                    let right_hash = right_entry.node.hash_cache.clone().unwrap();
                    SubTreeNode::Hash(right_hash)
                } else {
                    Self::prove_nodes(cache, right, right_keys, depth + 1)?
                };

                Ok(SubTreeNode::Internal {
                    prefix: prefix.clone(),
                    left: Box::new(left_subtree),
                    right: Box::new(right_subtree),
                })
            }
        }
    }

    fn load_hash<'c>(
        cache: &mut Cache<H>,
        node: &'c mut Node,
    ) -> Result<CacheEntry<'c>> {
        if node.hash_cache.is_some() {
            return Ok(CacheEntry::new(node, false));
        }

        let entry = cache.load_node(node)?;
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
                let left_entry = Self::load_hash(cache, left)?;
                let left_hash = left_entry.node.hash_cache.as_ref().unwrap();
                let right_entry = Self::load_hash(cache, right)?;
                let right_hash = right_entry.node.hash_cache.as_ref().unwrap();
                entry.node.hash_cache =
                    Some(H::hash_internal(prefix.as_bytes(), left_hash, right_hash));
            }
        }
        Ok(entry)
    }

    fn get_node<'c>(
        cache: &mut Cache<H>,
        node: &'c mut Node,
        key: Path<&Hash>,
        depth: usize,
    ) -> Result<Option<Vec<u8>>> {
        let entry = cache.load_node(node)?;
        match entry.node.inner.as_mut().unwrap() {
            NodeInner::Leaf {
                value,
                key: node_key,
            } => {
                if node_key.0 == *key.0 {
                    return Ok(Some(value.clone()))
                }
                return Ok(None)
            }
            NodeInner::Internal {
                prefix,
                left,
                right,
            } => {
                if key.split_point(depth, *prefix).is_some() {
                    return Ok(None)
                }
                let depth = depth + prefix.bit_len();
                match key.direction(depth) {
                    Direction::Right => Self::get_node(cache, right, key, depth + 1),
                    Direction::Left => Self::get_node(cache, left, key, depth + 1),
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
        }
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

    fn insert_into_node(
        &mut self,
        node: Node,
        key: Path<Hash>,
        value: Vec<u8>,
        depth: usize,
    ) -> Result<Node> {
        let inner = match node.inner {
            Some(node) => node,
            None => {
                if node.id == EMPTY_RECORD {
                    return Err(io::ErrorKind::NotFound.into());
                }
                let raw = self.db.file.read(node.id.offset, node.id.size as usize)?;
                let config = config::standard();
                let (inner, _): (NodeInner, usize) =
                    bincode::decode_from_slice(&raw, config).unwrap();
                inner
            }
        };

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
        // Empty root: leaf becomes root
        if current_key == Path(ZERO_HASH) {
            return Ok(Node::from_leaf(key, value));
        }

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
        if self.state.is_none() {
            return Ok(());
        }

        let expected_file_length = self.header.len();
        assert_eq!(
            expected_file_length % PAGE_SIZE as u64,
            0,
            "Database length is not a multiple of page size {}",
            expected_file_length
        );

        let file_length = self.db.file.len()?;
        if file_length != expected_file_length {
            // truncate/extend file to expected length
            self.db.file.set_len(expected_file_length)?;
        }

        let mut buf: WriteBuffer<BUFFER_SIZE> = WriteBuffer::new(&self.db.file, file_length);
        let mut state = self.state.take().unwrap();
        let root = self.write_all(&mut buf, &mut state)?;

        let previous_save_point = buf.write_save_point(&self.header.savepoint)?;
        buf.flush()?;
        self.db.file.sync_data()?;

        self.header.savepoint = SavePoint {
            root,
            previous_save_point,
        };

        self.db.write_header(&self.header)?;
        Ok(())
    }
}

pub struct KeyIterator<'db, H: NodeHasher> {
    db: &'db Database<H>,
    stack: Vec<Record>,
}

impl<'db, H: NodeHasher> KeyIterator<'db, H> {
    fn new(db: &'db Database<H>, root: Record) -> Self {
        let stack = vec![root];
        Self { db, stack }
    }
}

impl<'db, H: NodeHasher> Iterator for KeyIterator<'db, H> {
    type Item = Result<(Hash, Vec<u8>)>;

    fn next(&mut self) -> Option<Self::Item> {
        let record = self.stack.pop()?;
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

impl<'db, H: NodeHasher> Cache<'db, H> {
    fn new(db: &'db Database<H>, record: Record, capacity: usize) -> Self {
        Self {
            node: Some(Node::from_id(record)),
            len: 0,
            max_len: capacity,
            db,
        }
    }

    fn is_full(&self) -> bool {
        self.len > self.max_len
    }

    fn load_node<'c>(&mut self, node: &'c mut Node) -> Result<CacheEntry<'c>> {
        if node.inner.is_some() {
            return Ok(CacheEntry { node, clean: false });
        }
        assert_ne!(node.id, EMPTY_RECORD, "Attempted to read empty record");
        let is_full = self.is_full();

        let inner = self.db.load_node(node.id)?;

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
