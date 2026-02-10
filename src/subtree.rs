use crate::{
    path::{BitLength, Direction, Path, PathSegment, PathSegmentInner, PathUtils},
    Result, Hash, NodeHasher, VerifyError
};

use alloc::{boxed::Box, vec, vec::Vec};
use core::marker::PhantomData;
use borsh::{BorshDeserialize, BorshSerialize, io::{Read, Write}};

#[derive(Clone, Debug)]
pub struct SubTree<H: NodeHasher> {
    pub root: SubTreeNode,
    pub _marker: PhantomData<H>,
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

    pub fn to_vec(&self) -> Result<Vec<u8>> {
        borsh::to_vec(self).map_err(|_| crate::Error::Encode(crate::EncodeError::InvalidData("serialization failed")))
    }

    pub fn from_slice(buf: &[u8]) -> Result<Self> {
        borsh::from_slice(buf).map_err(|_| crate::Error::Encode(crate::EncodeError::InvalidData("deserialization failed")))
    }

    pub fn compute_root(&self) -> Result<Hash> {
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

    /// Inserts a key-value pair. Returns error if key already exists.
    pub fn insert(&mut self, key: Hash, value_or_hash: ValueOrHash) -> Result<()> {
        match self.update(key, value_or_hash)? {
            Some(_) => Err(VerifyError::KeyExists.into()),
            None => Ok(()),
        }
    }

    /// Sets a key-value pair, replacing any existing value.
    /// Returns the previous value if the key existed.
    pub fn update(&mut self, key: Hash, value_or_hash: ValueOrHash) -> Result<Option<ValueOrHash>> {
        if self.is_empty() {
            self.root = SubTreeNode::Leaf {
                key: Path(key),
                value_or_hash,
            };
            return Ok(None);
        }

        let mut node = &mut self.root;
        let key = Path(key);
        let mut depth = 0;
        loop {
            match node {
                SubTreeNode::Leaf { key: node_key, value_or_hash: existing } => {
                    // Same key - replace value
                    if key.0 == node_key.0 {
                        let old = core::mem::replace(existing, value_or_hash);
                        return Ok(Some(old));
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
                    return Ok(None);
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

                    return Ok(None);
                }
                SubTreeNode::Hash(_hash) => {
                    return Err(VerifyError::IncompleteProof.into());
                }
                SubTreeNode::None => {
                    return Err(VerifyError::IncompleteProof.into());
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
                    // Check if key matches the prefix - if not, key is not in this subtree
                    if key.split_point(depth, *prefix).is_some() {
                        return Ok(false);
                    }
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
                    return Err(VerifyError::IncompleteProof.into());
                }
            }
        }
    }

    pub fn delete(self, key: &Hash) -> Result<SubTree<H>> {
        let key = Path(key);
        Ok(SubTree::<H> {
            root: Self::delete_node(self.root, &key, 0)?,
            _marker: PhantomData::<H>,
        })
    }

    fn delete_node(node: SubTreeNode, key: &Path<&Hash>, depth: usize) -> Result<SubTreeNode> {
        match node {
            SubTreeNode::Leaf { key : node_key, .. } => {
                if node_key.0 != *key.0 {
                    return Err(VerifyError::KeyNotFound.into());
                }
                Ok(SubTreeNode::None)
            }
            SubTreeNode::Internal { prefix, left, right } => {
                let depth = depth + prefix.bit_len();
                match key.direction(depth) {
                    Direction::Right => {
                        let right_subtree = Self::delete_node(*right, key, depth + 1)?;
                        match right_subtree {
                            SubTreeNode::None => {
                                // Right subtree was deleted, move left subtree up
                                Ok(Self::lift_node(prefix, *left, Direction::Left)?)
                            },
                            SubTreeNode::Hash(_) => {
                                return Err(VerifyError::IncompleteProof.into())
                            },
                            other  => {
                                // Right node was updated
                                Ok(SubTreeNode::Internal {
                                    prefix,
                                    left,
                                    right: Box::new(other),
                                })
                            }
                        }
                    }
                    Direction::Left => {
                        let left_subtree = Self::delete_node(*left, key, depth + 1)?;
                        match left_subtree {
                            SubTreeNode::None => {
                                // left subtree was deleted, move right subtree up
                                Ok(Self::lift_node(prefix, *right, Direction::Right)?)
                            },
                            SubTreeNode::Hash(_) => {
                                return Err(VerifyError::IncompleteProof.into())
                            },
                            other  => {
                                // left node was updated
                                Ok(SubTreeNode::Internal {
                                    prefix,
                                    right,
                                    left: Box::new(other),
                                })
                            }
                        }
                    }
                }
            }
            SubTreeNode::Hash(_) => Err(VerifyError::IncompleteProof.into()),
            SubTreeNode::None => Err(VerifyError::KeyNotFound.into()),
        }
    }

    fn lift_node(mut parent_prefix: PathSegment<PathSegmentInner>, node: SubTreeNode, direction: Direction) -> Result<SubTreeNode> {
        match node {
            SubTreeNode::Leaf { .. } => {
                Ok(node.clone())
            }
            SubTreeNode::Internal { prefix, left, right } => {
                match direction {
                    Direction::Left => parent_prefix.extend_from_byte(0, 1),
                    Direction::Right => parent_prefix.extend_from_byte(0b1000_0000, 1)
                }
                parent_prefix.extend(prefix.clone());

                Ok(SubTreeNode::Internal {
                    prefix: parent_prefix,
                    left,
                    right,
                })
            }
            SubTreeNode::Hash(_) => {
                 Err(VerifyError::IncompleteProof.into())
            }
            SubTreeNode::None => {
                 Err(VerifyError::IncompleteProof.into())
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
                return Err(VerifyError::IncompleteProof.into())
            }
        }
    }

    pub fn iter(&self) -> SubtreeIter<'_> {
        if self.is_empty() || !value_node(&self.root) {
            return SubtreeIter { stack: vec![] };
        }
        SubtreeIter {
            stack: vec![(&self.root, 0)],
        }
    }

    pub fn iter_mut(&mut self) -> SubtreeIterMut<'_> {
        if self.is_empty() || !value_node(&self.root) {
            return SubtreeIterMut { stack: vec![] };
        }
        SubtreeIterMut {
            stack: vec![(&mut self.root, 0)],
        }
    }
}

#[cfg(feature = "extras")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofType {
    /// Standard proof - includes only the nodes needed to verify the requested keys
    Standard,
    /// Extended proof - includes sibling leaf keys (with hashed values) for deletion support
    Extended,
}

#[cfg(feature = "extras")]
struct ProveNodeInfo {
    node: SubTreeNode,
    value_node: bool,
}

#[cfg(feature = "extras")]
impl<H: NodeHasher> SubTree<H> {
    /// Creates a new proof (SubTree) containing only the nodes necessary to prove
    /// the specified keys. This mirrors the prove() method on the main tree.
    pub fn prove(&self, keys: &[Hash], proof_type: ProofType) -> Result<SubTree<H>> {
        if self.is_empty() {
            return Ok(SubTree::<H>::empty());
        }

        let mut key_paths: Vec<Path<&Hash>> = keys.iter().map(|k| Path(k)).collect();
        key_paths.sort_by(|a, b| a.0.cmp(b.0));

        let info = Self::prove_node(&self.root, key_paths.as_slice(), 0, proof_type)?;
        Ok(SubTree::<H> {
            root: info.node,
            _marker: PhantomData::<H>,
        })
    }

    fn prove_node(
        node: &SubTreeNode,
        keys: &[Path<&Hash>],
        depth: usize,
        proof_type: ProofType,
    ) -> Result<ProveNodeInfo> {
        match node {
            SubTreeNode::Leaf { key: node_key, value_or_hash } => {
                let include_value = keys.iter().any(|k| *k.0 == node_key.0);
                let new_value_or_hash = match value_or_hash {
                    ValueOrHash::Value(value) => {
                        if include_value {
                            ValueOrHash::Value(value.clone())
                        } else {
                            ValueOrHash::Hash(H::hash(value))
                        }
                    }
                    // If already a hash, keep it as is
                    ValueOrHash::Hash(hash) => ValueOrHash::Hash(hash.clone()),
                };
                Ok(ProveNodeInfo {
                    node: SubTreeNode::Leaf {
                        key: node_key.clone(),
                        value_or_hash: new_value_or_hash,
                    },
                    value_node: include_value,
                })
            }
            SubTreeNode::Internal { prefix, left, right } => {
                // Exclude keys that don't match this prefix
                let end = keys.partition_point(|key| key.split_point(depth, *prefix).is_none());
                let keys = &keys[..end];

                // Split keys by direction at current depth
                let depth = depth + prefix.bit_len();
                let split = keys.partition_point(|key| key.direction(depth) == Direction::Left);
                let (left_keys, right_keys) = keys.split_at(split);

                let mut left_info = if left_keys.is_empty() {
                    None
                } else {
                    Some(Self::prove_node(left, left_keys, depth + 1, proof_type)?)
                };
                let mut right_info = if right_keys.is_empty() {
                    None
                } else {
                    Some(Self::prove_node(right, right_keys, depth + 1, proof_type)?)
                };

                // For extended proofs, include sibling leaf structure (with hashed values)
                if proof_type == ProofType::Extended {
                    if left_info.is_none() && right_info.as_ref().map_or(false, |r| r.value_node) {
                        left_info = Some(ProveNodeInfo {
                            node: Self::hash_node_extended(left)?,
                            value_node: false,
                        });
                    }
                    if right_info.is_none() && left_info.as_ref().map_or(false, |l| l.value_node) {
                        right_info = Some(ProveNodeInfo {
                            node: Self::hash_node_extended(right)?,
                            value_node: false,
                        });
                    }
                }

                // If not included yet, hash the subtrees
                if left_info.is_none() {
                    let hash = Self::hash_node(left)?;
                    left_info = Some(ProveNodeInfo {
                        node: SubTreeNode::Hash(hash),
                        value_node: false,
                    });
                }
                if right_info.is_none() {
                    let hash = Self::hash_node(right)?;
                    right_info = Some(ProveNodeInfo {
                        node: SubTreeNode::Hash(hash),
                        value_node: false,
                    });
                }

                let value_node = left_info.as_ref().unwrap().value_node
                    && right_info.as_ref().unwrap().value_node;

                Ok(ProveNodeInfo {
                    node: SubTreeNode::Internal {
                        prefix: prefix.clone(),
                        left: Box::new(left_info.unwrap().node),
                        right: Box::new(right_info.unwrap().node),
                    },
                    value_node,
                })
            }
            SubTreeNode::Hash(_) => Err(VerifyError::IncompleteProof.into()),
            SubTreeNode::None => Err(VerifyError::IncompleteProof.into()),
        }
    }

    /// Creates an extended hash of a node - keeps leaf structure but hashes values
    fn hash_node_extended(node: &SubTreeNode) -> Result<SubTreeNode> {
        match node {
            SubTreeNode::Leaf { key, value_or_hash } => {
                let hash = match value_or_hash {
                    ValueOrHash::Value(value) => H::hash(value),
                    ValueOrHash::Hash(h) => h.clone(),
                };
                Ok(SubTreeNode::Leaf {
                    key: key.clone(),
                    value_or_hash: ValueOrHash::Hash(hash),
                })
            }
            SubTreeNode::Internal { prefix, left, right } => {
                let left_hash = Self::hash_node(left)?;
                let right_hash = Self::hash_node(right)?;
                Ok(SubTreeNode::Internal {
                    prefix: prefix.clone(),
                    left: Box::new(SubTreeNode::Hash(left_hash)),
                    right: Box::new(SubTreeNode::Hash(right_hash)),
                })
            }
            SubTreeNode::Hash(h) => Ok(SubTreeNode::Hash(h.clone())),
            SubTreeNode::None => Err(VerifyError::IncompleteProof.into()),
        }
    }

    /// Returns hashes for 2^bits buckets based on key prefix.
    /// Bucket i contains all keys where the first `bits` bits equal i.
    /// Returns None for empty buckets or buckets that can't be computed (hash nodes).
    pub fn bucket_hashes(&self, bits: usize) -> Vec<Option<Hash>> {
        self.bucket_hashes_at_prefix(&[], bits)
    }

    /// Returns hashes for 2^bits buckets starting from a given prefix.
    /// First navigates to the subtree at `prefix`, then returns bucket hashes
    /// for `bits` additional levels.
    /// Returns None for empty buckets or buckets that can't be computed (hash nodes).
    pub fn bucket_hashes_at_prefix(&self, prefix: &[bool], bits: usize) -> Vec<Option<Hash>> {
        if bits == 0 {
            if prefix.is_empty() {
                return vec![self.compute_root().ok()];
            }
            // Navigate to prefix and return its hash
            let hash = Self::hash_at_prefix(&self.root, prefix, 0);
            return vec![hash];
        }

        let num_buckets = 1usize << bits;
        let mut result = vec![None; num_buckets];

        if !self.is_empty() {
            Self::collect_bucket_hashes_at_prefix(&self.root, prefix, 0, 0, bits, &mut result);
        }

        result
    }

    fn hash_at_prefix(node: &SubTreeNode, prefix: &[bool], depth: usize) -> Option<Hash> {
        if depth >= prefix.len() {
            return Self::hash_node(node).ok();
        }

        match node {
            SubTreeNode::None => None,
            SubTreeNode::Hash(_) => None, // Can't navigate through hash node
            SubTreeNode::Leaf { key, .. } => {
                // Check if leaf matches prefix
                let key_path = Path(&key.0);
                for i in depth..prefix.len() {
                    let key_bit = matches!(key_path.direction(i), Direction::Right);
                    if key_bit != prefix[i] {
                        return None;
                    }
                }
                Self::hash_node(node).ok()
            }
            SubTreeNode::Internal { prefix: seg, left, right } => {
                let seg_len = seg.bit_len();
                let mut current_depth = depth;

                // Check segment against prefix
                for i in 0..seg_len {
                    if current_depth >= prefix.len() {
                        // Prefix ends within segment
                        return Self::hash_node(node).ok();
                    }
                    let seg_bit = matches!(seg.direction(i), Direction::Right);
                    if seg_bit != prefix[current_depth] {
                        return None; // Divergence
                    }
                    current_depth += 1;
                }

                if current_depth >= prefix.len() {
                    return Self::hash_node(node).ok();
                }

                // Recurse into appropriate child
                if prefix[current_depth] {
                    Self::hash_at_prefix(right, prefix, current_depth + 1)
                } else {
                    Self::hash_at_prefix(left, prefix, current_depth + 1)
                }
            }
        }
    }

    fn collect_bucket_hashes_at_prefix(
        node: &SubTreeNode,
        prefix: &[bool],
        prefix_idx: usize,
        bucket_bits: usize,
        target_bits: usize,
        result: &mut Vec<Option<Hash>>,
    ) {
        // First, navigate to the prefix
        if prefix_idx < prefix.len() {
            match node {
                SubTreeNode::None | SubTreeNode::Hash(_) => return,
                SubTreeNode::Leaf { key, .. } => {
                    // Check if leaf matches remaining prefix
                    let key_path = Path(&key.0);
                    for i in prefix_idx..prefix.len() {
                        let key_bit = matches!(key_path.direction(i), Direction::Right);
                        if key_bit != prefix[i] {
                            return;
                        }
                    }
                    // Leaf matches prefix - determine its bucket
                    let mut bucket = 0usize;
                    for i in 0..target_bits {
                        bucket <<= 1;
                        if matches!(key_path.direction(prefix.len() + i), Direction::Right) {
                            bucket |= 1;
                        }
                    }
                    if let Ok(hash) = Self::hash_node(node) {
                        result[bucket] = Some(hash);
                    }
                }
                SubTreeNode::Internal { prefix: seg, left, right } => {
                    let seg_len = seg.bit_len();
                    let mut current_prefix_idx = prefix_idx;

                    // Match segment against prefix
                    for i in 0..seg_len {
                        if current_prefix_idx >= prefix.len() {
                            // Prefix consumed within segment - collect from here
                            let remaining_seg_bits = seg_len - i;
                            Self::collect_from_segment_point(
                                node, seg, i, remaining_seg_bits,
                                bucket_bits, target_bits, result
                            );
                            return;
                        }
                        let seg_bit = matches!(seg.direction(i), Direction::Right);
                        if seg_bit != prefix[current_prefix_idx] {
                            return; // Divergence
                        }
                        current_prefix_idx += 1;
                    }

                    // Segment matched, recurse into child
                    if current_prefix_idx >= prefix.len() {
                        // Prefix exactly consumed - collect buckets from children
                        Self::collect_bucket_hashes(left, bucket_bits << 1, 0, target_bits, result);
                        Self::collect_bucket_hashes(right, (bucket_bits << 1) | 1, 0, target_bits, result);
                    } else if prefix[current_prefix_idx] {
                        Self::collect_bucket_hashes_at_prefix(
                            right, prefix, current_prefix_idx + 1,
                            bucket_bits, target_bits, result
                        );
                    } else {
                        Self::collect_bucket_hashes_at_prefix(
                            left, prefix, current_prefix_idx + 1,
                            bucket_bits, target_bits, result
                        );
                    }
                }
            }
        } else {
            // Prefix fully consumed - collect bucket hashes from here
            Self::collect_bucket_hashes(node, bucket_bits, 0, target_bits, result);
        }
    }

    fn collect_from_segment_point(
        node: &SubTreeNode,
        seg: &PathSegment<PathSegmentInner>,
        seg_start: usize,
        remaining_seg_bits: usize,
        bucket_bits: usize,
        target_bits: usize,
        result: &mut Vec<Option<Hash>>,
    ) {
        let mut current_bucket = bucket_bits;
        let mut bits_collected = 0;

        // Collect bits from remaining segment
        for i in seg_start..(seg_start + remaining_seg_bits) {
            if bits_collected >= target_bits {
                break;
            }
            current_bucket <<= 1;
            if matches!(seg.direction(i), Direction::Right) {
                current_bucket |= 1;
            }
            bits_collected += 1;
        }

        if bits_collected >= target_bits {
            // Target reached within segment
            if let Ok(hash) = Self::hash_node(node) {
                result[current_bucket] = Some(hash);
            }
        } else {
            // Need to continue into children
            if let SubTreeNode::Internal { left, right, .. } = node {
                let remaining_bits = target_bits - bits_collected;
                Self::collect_bucket_hashes(left, current_bucket << 1, 0, remaining_bits, result);
                Self::collect_bucket_hashes(right, (current_bucket << 1) | 1, 0, remaining_bits, result);
            }
        }
    }

    fn collect_bucket_hashes(
        node: &SubTreeNode,
        prefix_bits: usize,
        depth: usize,
        target_depth: usize,
        result: &mut Vec<Option<Hash>>,
    ) {
        if depth == target_depth {
            if let Ok(hash) = Self::hash_node(node) {
                result[prefix_bits] = Some(hash);
            }
            return;
        }

        match node {
            SubTreeNode::None => {}
            SubTreeNode::Hash(_) => {
                // Can't drill into hash node - leave as None
            }
            SubTreeNode::Leaf { key, .. } => {
                // Determine which bucket this leaf belongs to
                let key_path = Path(&key.0);
                let mut bucket = 0usize;
                for i in 0..target_depth {
                    bucket <<= 1;
                    if matches!(key_path.direction(i), Direction::Right) {
                        bucket |= 1;
                    }
                }
                if let Ok(hash) = Self::hash_node(node) {
                    result[bucket] = Some(hash);
                }
            }
            SubTreeNode::Internal { prefix, left, right } => {
                let seg_len = prefix.bit_len();
                let mut current_prefix = prefix_bits;
                let mut current_depth = depth;

                // Process segment bits
                for i in 0..seg_len {
                    if current_depth >= target_depth {
                        break;
                    }
                    current_prefix <<= 1;
                    if matches!(prefix.direction(i), Direction::Right) {
                        current_prefix |= 1;
                    }
                    current_depth += 1;
                }

                if current_depth >= target_depth {
                    // Reached target depth within this node's prefix
                    if let Ok(hash) = Self::hash_node(node) {
                        result[current_prefix] = Some(hash);
                    }
                } else {
                    // Need to recurse into children
                    Self::collect_bucket_hashes(
                        left,
                        current_prefix << 1,
                        current_depth + 1,
                        target_depth,
                        result,
                    );
                    Self::collect_bucket_hashes(
                        right,
                        (current_prefix << 1) | 1,
                        current_depth + 1,
                        target_depth,
                        result,
                    );
                }
            }
        }
    }

    /// Get a subtree containing all keys that start with the given bit prefix.
    /// Returns a proper subtree with paths from the root - siblings not on the
    /// path are replaced with their hashes.
    /// The prefix is specified as a slice of bools (true = 1, false = 0).
    pub fn get_prefix(&self, prefix: &[bool]) -> Result<SubTree<H>> {
        if self.is_empty() {
            return Ok(self.clone());
        }
        if prefix.is_empty() {
            return Ok(self.clone());
        }

        let node = Self::extract_prefix_node(&self.root, prefix, 0)?;
        Ok(SubTree {
            root: node,
            _marker: PhantomData,
        })
    }

    fn extract_prefix_node(
        node: &SubTreeNode,
        prefix: &[bool],
        depth: usize,
    ) -> Result<SubTreeNode> {
        match node {
            SubTreeNode::None => Ok(SubTreeNode::None),

            SubTreeNode::Hash(_) => Err(VerifyError::IncompleteProof.into()),

            SubTreeNode::Leaf { key, .. } => {
                // Check if leaf's key matches the prefix
                let key_path = Path(&key.0);
                for i in depth..prefix.len() {
                    let key_bit = matches!(key_path.direction(i), Direction::Right);
                    if key_bit != prefix[i] {
                        // Leaf doesn't match prefix - hash it
                        let hash = Self::hash_node(node)?;
                        return Ok(SubTreeNode::Hash(hash));
                    }
                }
                // Leaf matches prefix - keep it
                Ok(node.clone())
            }

            SubTreeNode::Internal { prefix: seg, left, right } => {
                let seg_len = seg.bit_len();
                let mut current_depth = depth;

                // Check each bit in the segment against our target prefix
                for i in 0..seg_len {
                    if current_depth >= prefix.len() {
                        // Prefix ends within this segment - keep entire subtree
                        return Ok(node.clone());
                    }

                    let seg_bit = matches!(seg.direction(i), Direction::Right);
                    if seg_bit != prefix[current_depth] {
                        // Divergence - no keys match this prefix, hash entire node
                        let hash = Self::hash_node(node)?;
                        return Ok(SubTreeNode::Hash(hash));
                    }
                    current_depth += 1;
                }

                // Passed the segment - check if we've consumed the prefix
                if current_depth >= prefix.len() {
                    // Prefix ends at this node - keep entire subtree
                    return Ok(node.clone());
                }

                // Need to recurse - keep the path, hash the sibling
                if prefix[current_depth] {
                    // Going right - hash left sibling
                    let left_hash = Self::hash_node(left)?;
                    let right_node = Self::extract_prefix_node(right, prefix, current_depth + 1)?;
                    Ok(SubTreeNode::Internal {
                        prefix: seg.clone(),
                        left: Box::new(SubTreeNode::Hash(left_hash)),
                        right: Box::new(right_node),
                    })
                } else {
                    // Going left - hash right sibling
                    let right_hash = Self::hash_node(right)?;
                    let left_node = Self::extract_prefix_node(left, prefix, current_depth + 1)?;
                    Ok(SubTreeNode::Internal {
                        prefix: seg.clone(),
                        left: Box::new(left_node),
                        right: Box::new(SubTreeNode::Hash(right_hash)),
                    })
                }
            }
        }
    }

    /// Merges two subtrees into one. Both subtrees must have the same root hash.
    /// This is useful for combining proofs that cover different keys.
    pub fn merge(self, other: SubTree<H>) -> Result<SubTree<H>> {
        if self.is_empty() {
            return Ok(other);
        }
        if other.is_empty() {
            return Ok(self);
        }

        let merged_root = Self::merge_nodes(self.root, other.root, 0)?;
        Ok(SubTree::<H> {
            root: merged_root,
            _marker: PhantomData::<H>,
        })
    }

    fn merge_nodes(a: SubTreeNode, b: SubTreeNode, depth: usize) -> Result<SubTreeNode> {
        match (a, b) {
            // If either is None, return the other
            (SubTreeNode::None, other) | (other, SubTreeNode::None) => Ok(other),

            // Two hash nodes - if they're equal, keep one; otherwise can't merge
            (SubTreeNode::Hash(h1), SubTreeNode::Hash(h2)) => {
                if h1 == h2 {
                    Ok(SubTreeNode::Hash(h1))
                } else {
                    Err(VerifyError::RootMismatch.into())
                }
            }

            // Hash + non-hash: the non-hash provides more detail, but we need to verify
            // they represent the same subtree by checking the hash matches
            (SubTreeNode::Hash(h), other) | (other, SubTreeNode::Hash(h)) => {
                let other_hash = Self::hash_node(&other)?;
                if h == other_hash {
                    Ok(other)
                } else {
                    Err(VerifyError::RootMismatch.into())
                }
            }

            // Two leaves
            (
                SubTreeNode::Leaf { key: k1, value_or_hash: v1 },
                SubTreeNode::Leaf { key: k2, value_or_hash: v2 },
            ) => {
                if k1.0 == k2.0 {
                    // Same key - prefer value over hash
                    let merged_value = match (v1, v2) {
                        (ValueOrHash::Value(val), _) => ValueOrHash::Value(val),
                        (_, ValueOrHash::Value(val)) => ValueOrHash::Value(val),
                        (ValueOrHash::Hash(h1), ValueOrHash::Hash(h2)) => {
                            if h1 == h2 {
                                ValueOrHash::Hash(h1)
                            } else {
                                return Err(VerifyError::RootMismatch.into());
                            }
                        }
                    };
                    Ok(SubTreeNode::Leaf {
                        key: k1,
                        value_or_hash: merged_value,
                    })
                } else {
                    // Different keys - this shouldn't happen if roots match
                    Err(VerifyError::RootMismatch.into())
                }
            }

            // Leaf + Internal: shouldn't happen if roots match
            (SubTreeNode::Leaf { .. }, SubTreeNode::Internal { .. })
            | (SubTreeNode::Internal { .. }, SubTreeNode::Leaf { .. }) => {
                Err(VerifyError::RootMismatch.into())
            }

            // Two internal nodes
            (
                SubTreeNode::Internal { prefix: p1, left: l1, right: r1 },
                SubTreeNode::Internal { prefix: p2, left: l2, right: r2 },
            ) => {
                // Prefixes must match for valid merge
                if p1.0 != p2.0 {
                    return Err(VerifyError::RootMismatch.into());
                }

                let new_depth = depth + p1.bit_len() + 1;
                let merged_left = Self::merge_nodes(*l1, *l2, new_depth)?;
                let merged_right = Self::merge_nodes(*r1, *r2, new_depth)?;

                Ok(SubTreeNode::Internal {
                    prefix: p1,
                    left: Box::new(merged_left),
                    right: Box::new(merged_right),
                })
            }
        }
    }

    /// Returns all (key, value_hash) entries under the given prefix.
    /// This is bandwidth-efficient for sync - just the leaf data, no merkle paths.
    pub fn entries_at_prefix(&self, prefix: &[bool]) -> Vec<(Hash, Hash)> {
        let mut result = Vec::new();
        if !self.is_empty() {
            Self::collect_entries_at_prefix(&self.root, prefix, 0, &mut result);
        }
        result
    }

    fn collect_entries_at_prefix(
        node: &SubTreeNode,
        prefix: &[bool],
        depth: usize,
        result: &mut Vec<(Hash, Hash)>,
    ) {
        match node {
            SubTreeNode::None | SubTreeNode::Hash(_) => {}

            SubTreeNode::Leaf { key, value_or_hash } => {
                // Check if leaf matches prefix
                let key_path = Path(&key.0);
                for i in depth..prefix.len() {
                    let key_bit = matches!(key_path.direction(i), Direction::Right);
                    if key_bit != prefix[i] {
                        return; // Doesn't match
                    }
                }
                // Matches - add to result
                let value_hash = match value_or_hash {
                    ValueOrHash::Value(v) => H::hash(v),
                    ValueOrHash::Hash(h) => *h,
                };
                result.push((key.0, value_hash));
            }

            SubTreeNode::Internal { prefix: seg, left, right } => {
                let seg_len = seg.bit_len();
                let mut current_depth = depth;

                // Check segment against prefix
                for i in 0..seg_len {
                    if current_depth >= prefix.len() {
                        // Prefix consumed - collect all entries in this subtree
                        Self::collect_all_entries(node, result);
                        return;
                    }
                    let seg_bit = matches!(seg.direction(i), Direction::Right);
                    if seg_bit != prefix[current_depth] {
                        return; // Divergence
                    }
                    current_depth += 1;
                }

                if current_depth >= prefix.len() {
                    // Prefix consumed - collect all entries
                    Self::collect_all_entries(left, result);
                    Self::collect_all_entries(right, result);
                } else {
                    // Recurse into matching child
                    if prefix[current_depth] {
                        Self::collect_entries_at_prefix(right, prefix, current_depth + 1, result);
                    } else {
                        Self::collect_entries_at_prefix(left, prefix, current_depth + 1, result);
                    }
                }
            }
        }
    }

    fn collect_all_entries(node: &SubTreeNode, result: &mut Vec<(Hash, Hash)>) {
        match node {
            SubTreeNode::None | SubTreeNode::Hash(_) => {}
            SubTreeNode::Leaf { key, value_or_hash } => {
                let value_hash = match value_or_hash {
                    ValueOrHash::Value(v) => H::hash(v),
                    ValueOrHash::Hash(h) => *h,
                };
                result.push((key.0, value_hash));
            }
            SubTreeNode::Internal { left, right, .. } => {
                Self::collect_all_entries(left, result);
                Self::collect_all_entries(right, result);
            }
        }
    }
}

#[cfg(feature = "extras")]
#[derive(Clone, Debug)]
pub enum DiffRequest {
    /// Request bucket hashes at a prefix with given bit depth
    BucketHashes { prefix: Vec<bool>, bits: usize },
    /// Request all entries at a prefix
    Entries { prefix: Vec<bool> },
}

/// Response types for the diff state machine
#[cfg(feature = "extras")]
#[derive(Clone, Debug)]
pub enum DiffResponse {
    BucketHashes(Vec<Option<Hash>>),
    Entries(Vec<(Hash, Hash)>),
}

/// State machine for diffing a local tree against a remote tree.
/// Returns entries that differ: missing locally OR have different values.
#[cfg(feature = "extras")]
pub struct DiffSession<'a, H: NodeHasher> {
    local: &'a SubTree<H>,
    bits_per_round: usize,
    target_depth: usize,
    pending_prefixes: Vec<Vec<bool>>,
    pending_entries: Vec<Vec<bool>>,
    current_request: Option<DiffRequest>,
    differing_entries: Vec<(Hash, Hash)>,
}

#[cfg(feature = "extras")]
impl<'a, H: NodeHasher> DiffSession<'a, H> {
    pub fn new(local: &'a SubTree<H>) -> Self {
        Self::with_config(local, 4, 12)
    }

    pub fn with_config(local: &'a SubTree<H>, bits_per_round: usize, target_depth: usize) -> Self {
        Self {
            local,
            bits_per_round,
            target_depth,
            pending_prefixes: vec![vec![]],
            pending_entries: Vec::new(),
            current_request: None,
            differing_entries: Vec::new(),
        }
    }

    /// Get the next request to send to the remote peer.
    /// Returns None when the diff is complete.
    pub fn next_request(&mut self) -> Option<DiffRequest> {
        // First, drain pending entry requests
        if let Some(prefix) = self.pending_entries.pop() {
            let request = DiffRequest::Entries { prefix };
            self.current_request = Some(request.clone());
            return Some(request);
        }

        // Then, drain pending prefix comparisons
        if let Some(prefix) = self.pending_prefixes.pop() {
            let request = DiffRequest::BucketHashes {
                prefix,
                bits: self.bits_per_round,
            };
            self.current_request = Some(request.clone());
            return Some(request);
        }

        None
    }

    /// Process a response from the remote peer.
    pub fn process_response(&mut self, response: DiffResponse) {
        let request = self.current_request.take();

        match (request, response) {
            (Some(DiffRequest::BucketHashes { prefix, bits }), DiffResponse::BucketHashes(remote_hashes)) => {
                let local_hashes = self.local.bucket_hashes_at_prefix(&prefix, bits);

                for (i, (local_h, remote_h)) in local_hashes.iter().zip(remote_hashes.iter()).enumerate() {
                    if local_h != remote_h {
                        let new_prefix = extend_prefix(&prefix, i, bits);
                        if new_prefix.len() >= self.target_depth {
                            self.pending_entries.push(new_prefix);
                        } else {
                            self.pending_prefixes.push(new_prefix);
                        }
                    }
                }
            }
            (Some(DiffRequest::Entries { prefix }), DiffResponse::Entries(remote_entries)) => {
                let local_entries = self.local.entries_at_prefix(&prefix);
                let local_map: alloc::collections::BTreeMap<Hash, Hash> =
                    local_entries.into_iter().collect();

                for (key, value_hash) in remote_entries {
                    match local_map.get(&key) {
                        None => {
                            // Missing locally
                            self.differing_entries.push((key, value_hash));
                        }
                        Some(local_hash) if *local_hash != value_hash => {
                            // Different value
                            self.differing_entries.push((key, value_hash));
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    /// Consume the session and return all differing entries (key, value_hash).
    /// These are entries that the remote has but local doesn't, or has with different values.
    pub fn result(self) -> Vec<(Hash, Hash)> {
        self.differing_entries
    }
}

#[cfg(feature = "extras")]
fn extend_prefix(prefix: &[bool], bucket: usize, bits: usize) -> Vec<bool> {
    let mut result = prefix.to_vec();
    for i in (0..bits).rev() {
        result.push((bucket >> i) & 1 == 1);
    }
    result
}

impl<H: NodeHasher> BorshSerialize for SubTree<H> {
    fn serialize<W: Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        crate::encode::serialize_node(&self.root, writer)
    }
}

impl<H: NodeHasher> BorshDeserialize for SubTree<H> {
    fn deserialize_reader<R: Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let root = crate::encode::deserialize_node(reader)?;
        Ok(Self {
            root,
            _marker: core::marker::PhantomData,
        })
    }
}

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

impl SubTreeNode {
    pub fn is_value_leaf(&self) -> bool {
        matches!(self, SubTreeNode::Leaf {  value_or_hash: ValueOrHash::Value(_), ..})
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
