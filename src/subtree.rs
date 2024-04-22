use crate::{Result, path::{BitLength, Direction, Path, PathSegment, PathSegmentInner, PathUtils}, Hash, NodeHasher, VerifyError};

use alloc::{boxed::Box, vec, vec::Vec};
use bincode::{
    de::Decoder,
    enc::Encoder,
    error::{DecodeError, EncodeError},
    impl_borrow_decode, Decode, Encode,
};

#[derive(Clone, Debug)]
pub struct SubTree<H: NodeHasher> {
    pub root: SubTreeNode,
    pub _marker: core::marker::PhantomData<H>,
}

#[derive(Clone, Debug)]
pub enum SubTreeNode {
    Leaf {
        key: Path<Hash>,
        value_or_hash: ValueOrHash,
    },
    Internal {
        prefix: PathSegment<PathSegmentInner>,
        left: Box<SubTreeNode>,
        right: Box<SubTreeNode>,
    },
    Hash(Hash),
    None,
}

#[derive(Clone, Debug)]
pub enum ValueOrHash {
    Value(Vec<u8>),
    Hash(Hash),
}


impl<H: NodeHasher> SubTree<H> {
    pub fn empty() -> Self {
        Self {
            root: SubTreeNode::None,
            _marker: core::marker::PhantomData,
        }
    }

    pub fn root(&self) -> Result<Hash> {
        if self.is_empty() {
            return Ok(H::hash(&[]));
        }
        Self::hash_node(&self.root)
    }

    #[inline(always)]
    pub fn hash(&self, value: &[u8]) -> Hash {
        H::hash(value)
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        match self.root {
            SubTreeNode::None => true,
            _ => false,
        }
    }

    pub fn insert(&mut self, key: Hash, value_or_hash: ValueOrHash) -> Result<()> {
        if self.is_empty() {
            self.root = SubTreeNode::Leaf {
                key: Path(key),
                value_or_hash,
            };
            return Ok(());
        }

        let mut node = &mut self.root;
        let key = Path(key);
        let mut depth = 0;
        loop {
            match node {
                SubTreeNode::Leaf { key: node_key, .. } => {
                    // Same key
                    if key.0 == node_key.0 {
                        return Err(VerifyError::KeyExists.into());
                    }

                    //  A split point must exist: compress common path into an internal node
                    let point = node_key.split_point(0, key).unwrap();
                    let prefix = PathSegment::from_path(*node_key, depth, point);
                    let depth = depth + prefix.bit_len() as usize;
                    let direction = key.direction(depth);
                    let current_node = core::mem::take(node);
                    let new_node = SubTreeNode::Leaf { key, value_or_hash };
                    let (left, right) = match direction {
                        Direction::Right => (Box::new(current_node), Box::new(new_node)),
                        Direction::Left => (Box::new(new_node), Box::new(current_node)),
                    };
                    *node = SubTreeNode::Internal {
                        prefix,
                        left,
                        right,
                    };
                    return Ok(());
                }
                SubTreeNode::Internal {
                    prefix,
                    left,
                    right,
                } => {
                    let point = key.split_point(depth, *prefix);
                    if point.is_none() {
                        depth = depth + prefix.bit_len() as usize;
                        match key.direction(depth) {
                            Direction::Right => node = right,
                            Direction::Left => node = left,
                        }
                        depth += 1;
                        continue;
                    }

                    //  A split point exists: compress common path into an internal node
                    let point = point.unwrap();
                    let parent_prefix = PathSegment::from_path(*prefix, 0, point);
                    let current_node_prefix =
                        PathSegment::from_path(*prefix, point + 1, prefix.bit_len());

                    let current_node = SubTreeNode::Internal {
                        prefix: current_node_prefix,
                        left: core::mem::take(left),
                        right: core::mem::take(right),
                    };

                    depth = depth + parent_prefix.bit_len();

                    let new_node = SubTreeNode::Leaf { key, value_or_hash };
                    let (lefty, righty) = match key.direction(depth) {
                        Direction::Right => (Box::new(current_node), Box::new(new_node)),
                        Direction::Left => (Box::new(new_node), Box::new(current_node)),
                    };

                    *prefix = parent_prefix;
                    *left = lefty;
                    *right = righty;

                    return Ok(());
                }
                SubTreeNode::Hash(_hash) => {
                    return Err(VerifyError::IncompleteProof.into());
                }
                SubTreeNode::None => {
                    unreachable!("Unexpected None node")
                }
            }
        }
    }

    pub fn contains(&self, key: &Hash) -> Result<bool> {
        if self.is_empty() {
            return Ok(false);
        }

        let mut node = &self.root;
        let key = Path(key);
        let mut depth = 0;
        loop {
            match node {
                SubTreeNode::Leaf { key: node_key, .. } => {
                    return Ok(*key.0 == node_key.0);
                }
                SubTreeNode::Internal {
                    prefix,
                    left,
                    right,
                } => {
                    depth = depth + prefix.bit_len() as usize;
                    match key.direction(depth) {
                        Direction::Left => node = left,
                        Direction::Right => node = right,
                    }
                    depth += 1;
                }
                SubTreeNode::Hash(_hash) => {
                    return Err(VerifyError::IncompleteProof.into());
                }
                SubTreeNode::None => {
                    unreachable!("None should not be inserted")
                }
            }
        }
    }

    fn hash_node(node: &SubTreeNode) -> Result<Hash> {
        match node {
            SubTreeNode::Leaf { key, value_or_hash } => match value_or_hash {
                ValueOrHash::Value(value) => {
                    let hash = H::hash(value);
                    Ok(H::hash_leaf(&key.0, &hash))
                }
                ValueOrHash::Hash(hash) => Ok(H::hash_leaf(&key.0, hash)),
            },
            SubTreeNode::Internal {
                prefix,
                left,
                right,
            } => {
                let left_hash = Self::hash_node(left)?;
                let right_hash = Self::hash_node(right)?;
                Ok(H::hash_internal(prefix.as_bytes(), &left_hash, &right_hash))
            }
            SubTreeNode::Hash(hash) => Ok(hash.clone()),
            SubTreeNode::None => {
                unreachable!("None should not be inserted")
            }
        }
    }

    pub fn iter(&self) -> SubtreeIter {
        if self.is_empty() || !value_node(&self.root) {
            return SubtreeIter { stack: vec![] };
        }
        SubtreeIter {
            stack: vec![(&self.root, 0)],
        }
    }

    pub fn iter_mut(&mut self) -> SubtreeIterMut {
        if self.is_empty() || !value_node(&self.root) {
            return SubtreeIterMut { stack: vec![] };
        }
        SubtreeIterMut {
            stack: vec![(&mut self.root, 0)],
        }
    }
}

impl<H: NodeHasher> Encode for SubTree<H> {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> core::result::Result<(), EncodeError> {
        Encode::encode(&self.root, encoder)
    }
}

impl<H: NodeHasher> Decode for SubTree<H> {
    fn decode<D: Decoder>(decoder: &mut D) -> core::result::Result<Self, DecodeError> {
        let root = Decode::decode(decoder)?;
        Ok(Self {
            root,
            _marker: core::marker::PhantomData,
        })
    }
}

impl Encode for SubTreeNode {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> core::result::Result<(), EncodeError> {
        match self {
            SubTreeNode::Leaf { key, value_or_hash } => {
                Encode::encode(&0u8, encoder)?;
                Encode::encode(&key.0, encoder)?;
                Encode::encode(value_or_hash, encoder)?;
            }
            SubTreeNode::Internal {
                prefix,
                left,
                right,
            } => {
                Encode::encode(&1u8, encoder)?;
                Encode::encode(&prefix.0, encoder)?;
                Encode::encode(left, encoder)?;
                Encode::encode(right, encoder)?;
            }
            SubTreeNode::Hash(hash) => {
                Encode::encode(&2u8, encoder)?;
                Encode::encode(hash, encoder)?;
            }
            SubTreeNode::None => {
                unreachable!("None should not be encoded")
            }
        }
        Ok(())
    }
}

impl Decode for SubTreeNode {
    fn decode<D: Decoder>(decoder: &mut D) -> core::result::Result<Self, DecodeError> {
        let tag: u8 = Decode::decode(decoder)?;
        match tag {
            0 => {
                let key_raw: Hash = Decode::decode(decoder)?;
                let key = Path(key_raw);
                let value_or_hash = Decode::decode(decoder)?;
                Ok(SubTreeNode::Leaf { key, value_or_hash })
            }
            1 => {
                let seg: [u8; 33] = Decode::decode(decoder)?;
                let prefix = PathSegment(seg);
                let left: Box<SubTreeNode> = Decode::decode(decoder)?;
                let right: Box<SubTreeNode> = Decode::decode(decoder)?;
                Ok(SubTreeNode::Internal {
                    prefix,
                    left,
                    right,
                })
            }
            2 => {
                let hash: Hash = Decode::decode(decoder)?;
                Ok(SubTreeNode::Hash(hash))
            }
            _ => Err(DecodeError::Other("Invalid tag subtree node")),
        }
    }
}

impl_borrow_decode!(SubTreeNode);

impl Encode for ValueOrHash {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> core::result::Result<(), EncodeError> {
        match self {
            ValueOrHash::Value(value) => {
                Encode::encode(&0u8, encoder)?;
                Encode::encode(value, encoder)?;
            }
            ValueOrHash::Hash(hash) => {
                Encode::encode(&1u8, encoder)?;
                Encode::encode(hash, encoder)?;
            }
        }
        Ok(())
    }
}

impl Decode for ValueOrHash {
    fn decode<D: Decoder>(decoder: &mut D) -> core::result::Result<Self, DecodeError> {
        let tag: u8 = Decode::decode(decoder)?;
        match tag {
            0 => {
                let value: Vec<u8> = Decode::decode(decoder)?;
                Ok(ValueOrHash::Value(value))
            }
            1 => {
                let hash: Hash = Decode::decode(decoder)?;
                Ok(ValueOrHash::Hash(hash))
            }
            _ => Err(DecodeError::Other("Invalid tag")),
        }
    }
}

impl_borrow_decode!(ValueOrHash);

impl Default for SubTreeNode {
    fn default() -> Self {
        SubTreeNode::None
    }
}

pub struct SubtreeIter<'a> {
    stack: Vec<(&'a SubTreeNode, usize)>,
}

impl<'a> Iterator for SubtreeIter<'a> {
    type Item = (&'a Hash, &'a Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (node, depth) = match self.stack.pop() {
                Some(x) => x,
                None => return None,
            };

            match node {
                SubTreeNode::Leaf { key, value_or_hash } => {
                    if let ValueOrHash::Value(value) = value_or_hash {
                        return Some((&key.0, value));
                    }
                    unreachable!("Hashes of leaf nodes must not be in the stack")
                }
                SubTreeNode::Internal {
                    prefix,
                    left,
                    right,
                } => {
                    let depth = depth + prefix.bit_len() + 1;
                    if value_node(right.as_ref()) {
                        self.stack.push((right, depth));
                    }
                    if value_node(left.as_ref()) {
                        self.stack.push((left, depth));
                    }
                }
                SubTreeNode::Hash(_hash) => {
                    unreachable!("Hashes must not be in the stack")
                }
                SubTreeNode::None => {
                    unreachable!("None should not be inserted")
                }
            }
        }
    }
}

pub struct SubtreeIterMut<'a> {
    stack: Vec<(&'a mut SubTreeNode, usize)>,
}

impl<'a> Iterator for SubtreeIterMut<'a> {
    // The Item type now is a tuple of an immutable reference to Hash and a mutable reference to Vec<u8>
    type Item = (&'a Hash, &'a mut Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (node, depth) = self.stack.pop()?;

            match node {
                SubTreeNode::Leaf { key, value_or_hash } => match value_or_hash {
                    ValueOrHash::Value(value) => {
                        return Some((&key.0, value));
                    }
                    ValueOrHash::Hash(_) => {
                        unreachable!("Hash of leaf node must not be in the stack");
                    }
                },
                SubTreeNode::Internal {
                    prefix,
                    left,
                    right,
                } => {
                    let depth = depth + prefix.bit_len() + 1;
                    if value_node(right.as_ref()) {
                        self.stack.push((right, depth));
                    }
                    if value_node(left.as_ref()) {
                        self.stack.push((left, depth));
                    }
                }
                SubTreeNode::Hash(_) => {
                    unreachable!("Hashes must not be in the stack")
                }
                SubTreeNode::None => {
                    unreachable!("None should not be inserted")
                }
            }
        }
    }
}

#[inline(always)]
fn value_node(node: &SubTreeNode) -> bool {
    match node {
        SubTreeNode::Leaf { value_or_hash, .. } => matches!(value_or_hash, ValueOrHash::Value(_)),
        SubTreeNode::Internal { .. } => true,
        SubTreeNode::Hash(_) => false,
        SubTreeNode::None => {
            unreachable!("None should not be inserted")
        }
    }
}
