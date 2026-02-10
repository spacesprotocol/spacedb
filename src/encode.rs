use alloc::boxed::Box;
use alloc::vec;
use borsh::io::{Error as IoError, ErrorKind, Read, Write};
use crate::path::{BitLength, Path, PathSegment};
use crate::subtree::{SubTreeNode, ValueOrHash};

const NODE_LEAF: u8 = 0;
const NODE_INTERNAL: u8 = 1;
const NODE_HASH: u8 = 2;
const NODE_NONE: u8 = 3;
const LEAF_VALUE: u8 = 0;
const LEAF_HASH: u8 = 1;

/// Serializes a `SubTreeNode` into a writer.
pub(crate) fn serialize_node<W: Write>(node: &SubTreeNode, writer: &mut W) -> borsh::io::Result<()> {
    match node {
        SubTreeNode::Leaf { key, value_or_hash } => {
            writer.write_all(&[NODE_LEAF])?;
            writer.write_all(&key.0)?;
            match value_or_hash {
                ValueOrHash::Value(value) => {
                    writer.write_all(&[LEAF_VALUE])?;
                    writer.write_all(&(value.len() as u16).to_le_bytes())?;
                    writer.write_all(value)?;
                }
                ValueOrHash::Hash(hash) => {
                    writer.write_all(&[LEAF_HASH])?;
                    writer.write_all(hash)?;
                }
            }
        }
        SubTreeNode::Internal { prefix, left, right } => {
            writer.write_all(&[NODE_INTERNAL])?;
            writer.write_all(prefix.as_bytes())?;
            serialize_node(left, writer)?;
            serialize_node(right, writer)?;
        }
        SubTreeNode::Hash(hash) => {
            writer.write_all(&[NODE_HASH])?;
            writer.write_all(hash)?;
        }
        SubTreeNode::None => {
            writer.write_all(&[NODE_NONE])?;
        }
    }
    Ok(())
}

/// Deserializes a `SubTreeNode` from a reader.
pub(crate) fn deserialize_node<R: Read>(reader: &mut R) -> borsh::io::Result<SubTreeNode> {
    let mut tag = [0u8; 1];
    reader.read_exact(&mut tag)?;
    match tag[0] {
        NODE_LEAF => {
            let mut key = [0u8; 32];
            reader.read_exact(&mut key)?;
            let mut subtag = [0u8; 1];
            reader.read_exact(&mut subtag)?;
            let value_or_hash = match subtag[0] {
                LEAF_HASH => {
                    let mut hash = [0u8; 32];
                    reader.read_exact(&mut hash)?;
                    ValueOrHash::Hash(hash)
                }
                LEAF_VALUE => {
                    let mut len_buf = [0u8; 2];
                    reader.read_exact(&mut len_buf)?;
                    let len = u16::from_le_bytes(len_buf) as usize;
                    let mut bytes = vec![0u8; len];
                    reader.read_exact(&mut bytes)?;
                    ValueOrHash::Value(bytes)
                }
                _ => return Err(IoError::new(ErrorKind::InvalidData, "unknown leaf tag")),
            };
            Ok(SubTreeNode::Leaf {
                key: Path(key),
                value_or_hash,
            })
        }
        NODE_INTERNAL => {
            let mut bit_len = [0u8; 1];
            reader.read_exact(&mut bit_len)?;
            let byte_count = (bit_len[0] as usize + 7) / 8;
            let mut seg = [0u8; 33];
            seg[0] = bit_len[0];
            reader.read_exact(&mut seg[1..byte_count + 1])?;
            let prefix = PathSegment(seg);
            let left = Box::new(deserialize_node(reader)?);
            let right = Box::new(deserialize_node(reader)?);
            Ok(SubTreeNode::Internal { prefix, left, right })
        }
        NODE_HASH => {
            let mut hash = [0u8; 32];
            reader.read_exact(&mut hash)?;
            Ok(SubTreeNode::Hash(hash))
        }
        NODE_NONE => Ok(SubTreeNode::None),
        _ => Err(IoError::new(ErrorKind::InvalidData, "unknown node tag")),
    }
}
