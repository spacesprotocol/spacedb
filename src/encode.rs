use alloc::boxed::Box;
use alloc::vec;
use crate::{EncodeError, Error, NodeHasher, Result};
use crate::path::{BitLength, Path, PathSegment};
use crate::subtree::{SubTree, SubTreeNode, ValueOrHash};

const NODE_LEAF: u8 = 0;
const NODE_INTERNAL: u8 = 1;
const NODE_HASH: u8 = 2;
const NODE_NONE: u8 = 3;
const LEAF_VALUE: u8 = 0;
const LEAF_HASH: u8 = 1;

pub trait SubTreeEncoder {
    fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize>;
    fn from_slice(buf: &[u8]) -> Result<Self> where Self: Sized;
}

impl<H : NodeHasher> SubTreeEncoder for SubTree<H> {
    fn write_to_slice(&self, buf: &mut [u8]) -> Result<usize> {
        let initial_len = buf.len();
        let remaining = serialize_node(&self.root, buf)?;
        Ok(initial_len - remaining.len())
    }

    fn from_slice(mut buf:&[u8]) -> Result<Self> {
        Ok(Self {
            root: deserialize_node(&mut buf)?,
            _marker: Default::default(),
        })
    }
}

/// Serializes a `SubTreeNode` into the provided buffer, advancing the buffer slice.
fn serialize_node<'a>(node: &SubTreeNode, mut buf: &'a mut [u8]) -> Result<&'a mut [u8]> {
    match node {
        SubTreeNode::Leaf { key, value_or_hash } => {
            buf = write_bytes(buf, &[NODE_LEAF])?;
            buf = write_bytes(buf, &key.0)?;
            match value_or_hash {
                ValueOrHash::Value(value) => {
                    buf = write_bytes(buf, &[LEAF_VALUE])?;
                    buf = write_bytes(buf, &[value.len() as u8])?;
                    buf = write_bytes(buf, value)?;
                }
                ValueOrHash::Hash(hash) => {
                    buf = write_bytes(buf, &[LEAF_HASH])?;
                    buf = write_bytes(buf, hash)?;
                }
            }
        }
        SubTreeNode::Internal { prefix, left, right } => {
            buf = write_bytes(buf, &[NODE_INTERNAL])?;
            buf = write_bytes(buf, prefix.as_bytes())?;
            buf = serialize_node(left, buf)?;
            buf = serialize_node(right, buf)?;
        }
        SubTreeNode::Hash(hash) => {
            buf = write_bytes(buf, &[NODE_HASH])?;
            buf = write_bytes(buf, hash)?;
        }
        SubTreeNode::None => {
            buf = write_bytes(buf, &[NODE_NONE])?;
        }
    }
    Ok(buf)
}

/// Deserializes a `SubTreeNode` from the provided buffer, advancing the slice.
fn deserialize_node(buf: &mut &[u8]) -> Result<SubTreeNode> {
    let mut tag_buf = [0u8; 1];
    read_bytes(buf, &mut tag_buf)?;
    match tag_buf[0] {
        NODE_LEAF => {
            let mut key = [0u8; 32];
            read_bytes(buf, &mut key)?;
            let mut subtag_buf = [0u8; 1];
            read_bytes(buf, &mut subtag_buf)?;
            let value_or_hash = match subtag_buf[0] {
                LEAF_HASH => {
                    let mut hash = [0u8; 32];
                    read_bytes(buf, &mut hash)?;
                    ValueOrHash::Hash(hash)
                }
                LEAF_VALUE => {
                    let mut len_buf = [0u8; 1];
                    read_bytes(buf, &mut len_buf)?;
                    let len = len_buf[0] as usize;
                    let mut bytes = vec![0u8; len];
                    read_bytes(buf, &mut bytes)?;
                    ValueOrHash::Value(bytes)
                }
                _ => return Err(Error::Encode(EncodeError::InvalidData("unknown leaf tag"))),
            };
            Ok(SubTreeNode::Leaf {
                key: Path(key),
                value_or_hash,
            })
        }
        NODE_INTERNAL => {
            let mut prefix_body = [0u8; 33];
            read_bytes(buf, &mut prefix_body[..1])?;
            let byte_count = (prefix_body[0] as usize + 7) / 8;
            read_bytes(buf, &mut prefix_body[1..byte_count + 1])?;
            let prefix = PathSegment(prefix_body);
            let left = Box::new(deserialize_node(buf)?);
            let right = Box::new(deserialize_node(buf)?);
            Ok(SubTreeNode::Internal { prefix, left, right })
        }
        NODE_HASH => {
            let mut hash = [0u8; 32];
            read_bytes(buf, &mut hash)?;
            Ok(SubTreeNode::Hash(hash))
        }
        NODE_NONE => Ok(SubTreeNode::None),
        _ => Err(Error::Encode(EncodeError::InvalidData("unknown node tag"))),
    }
}

fn write_bytes<'a>(buf: &'a mut [u8], data: &[u8]) -> Result<&'a mut [u8]> {
    if buf.len() < data.len() {
        return Err(Error::Encode(EncodeError::BufferTooSmall));
    }
    let (head, tail) = buf.split_at_mut(data.len());
    head.copy_from_slice(data);
    Ok(tail)
}

fn read_bytes<'a>(buf: &mut &'a [u8], out: &mut [u8]) -> Result<()> {
    if buf.len() < out.len() {
        return Err(Error::Encode(EncodeError::BufferTooSmall));
    }
    let (head, tail) = buf.split_at(out.len());
    out.copy_from_slice(head);
    *buf = tail;
    Ok(())
}
