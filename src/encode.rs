use crate::path::{BitLength, Path, PathSegment};
use crate::subtree::{SubTreeNode, ValueOrHash};
use alloc::boxed::Box;
use alloc::vec;
use borsh::io::{Error as IoError, ErrorKind, Read, Write};

const NODE_LEAF: u8 = 0;
const NODE_INTERNAL: u8 = 1;
const NODE_HASH: u8 = 2;
const NODE_NONE: u8 = 3;
const LEAF_VALUE: u8 = 0;
const LEAF_HASH: u8 = 1;

// Keys are 256-bit hashes. Every Internal node's prefix plus the
// discriminating bit that follows must fit within that budget, so the
// effective depth after entering an Internal node is bounded by 255.
const KEY_BITS: usize = 256;

/// Serializes a `SubTreeNode` into a writer.
pub(crate) fn serialize_node<W: Write>(
    node: &SubTreeNode,
    writer: &mut W,
) -> borsh::io::Result<()> {
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
        SubTreeNode::Internal {
            prefix,
            left,
            right,
        } => {
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
    deserialize_node_at(reader, 0)
}

fn deserialize_node_at<R: Read>(reader: &mut R, depth: usize) -> borsh::io::Result<SubTreeNode> {
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
            let byte_count = (bit_len[0] as usize).div_ceil(8);
            let mut seg = [0u8; 33];
            seg[0] = bit_len[0];
            reader.read_exact(&mut seg[1..byte_count + 1])?;
            let prefix = PathSegment(seg);

            // Reject prefixes that would push the discriminating bit past
            // the end of a 256-bit key. Without this, traversal would feed
            // an out-of-range index to Path::direction (panic) or to
            // split_point (assert).
            let next_depth = depth
                .checked_add(prefix.bit_len())
                .and_then(|d| d.checked_add(1))
                .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "subtree depth overflow"))?;
            if next_depth > KEY_BITS {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    "subtree internal node exceeds key length",
                ));
            }

            let left = Box::new(deserialize_node_at(reader, next_depth)?);
            let right = Box::new(deserialize_node_at(reader, next_depth)?);
            Ok(SubTreeNode::Internal {
                prefix,
                left,
                right,
            })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Sha256Hasher, subtree::SubTree};

    /// A crafted subtree where two nested Internal nodes claim cumulative
    /// prefixes longer than 256 bits should be rejected by the
    /// deserializer rather than producing a structure that can later
    /// panic during traversal.
    #[test]
    fn deserialize_rejects_oversized_prefix_chain() {
        // Root: Internal { prefix bit_len = 130 }, descending into
        // another Internal { prefix bit_len = 130 }. After the root we
        // are at depth 131; the child would push us to 262, past the
        // 256-bit key.
        let mut bytes = alloc::vec::Vec::new();
        // Root tag + prefix (bit_len 130 -> 17 bytes of payload + 1 length byte)
        bytes.push(NODE_INTERNAL);
        bytes.push(130);
        bytes.extend(core::iter::repeat_n(0xFFu8, 17));
        // Left child: another oversized Internal
        bytes.push(NODE_INTERNAL);
        bytes.push(130);
        bytes.extend(core::iter::repeat_n(0xFFu8, 17));
        // Two trivial Hash leaves under the inner Internal so the structure
        // is at least syntactically complete.
        bytes.push(NODE_HASH);
        bytes.extend(core::iter::repeat_n(0u8, 32));
        bytes.push(NODE_HASH);
        bytes.extend(core::iter::repeat_n(0u8, 32));
        // Right child of root
        bytes.push(NODE_HASH);
        bytes.extend(core::iter::repeat_n(0u8, 32));

        let result = SubTree::<Sha256Hasher>::from_slice(&bytes);
        assert!(
            result.is_err(),
            "deserializer must reject a subtree whose nested prefixes overrun the key length"
        );
    }
}
