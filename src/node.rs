use crate::{
    db::{Record, EMPTY_RECORD},
    path::{Path, PathSegment, PathSegmentInner},
    Hash,
};
use bincode::{
    de::Decoder,
    enc::Encoder,
    error::{DecodeError, EncodeError},
    impl_borrow_decode, Decode, Encode,
};

#[derive(Clone, Debug)]
pub struct Node {
    pub id: Record,
    pub inner: Option<NodeInner>,
    pub(crate) hash_cache: Option<Hash>,
}

#[derive(Clone, Debug)]
pub enum NodeInner {
    Leaf {
        key: Path<Hash>,
        value: Vec<u8>,
    },
    Internal {
        prefix: PathSegment<PathSegmentInner>,
        left: Box<Node>,
        right: Box<Node>,
    },
}

impl Node {
    #[inline]
    pub fn from_internal(
        prefix: PathSegment<PathSegmentInner>,
        left: Box<Node>,
        right: Box<Node>,
    ) -> Self {
        Self {
            id: EMPTY_RECORD,
            inner: Some(NodeInner::Internal {
                prefix,
                left,
                right,
            }),
            hash_cache: None,
        }
    }

    #[inline]
    pub fn from_leaf(key: Path<Hash>, value: Vec<u8>) -> Self {
        Self {
            id: EMPTY_RECORD,
            inner: Some(NodeInner::Leaf { key, value }),
            hash_cache: None,
        }
    }

    #[inline]
    pub(crate) fn from_id(id: Record) -> Self {
        Self {
            id,
            inner: None,
            hash_cache: None,
        }
    }

    #[inline]
    pub fn mem_size(&self) -> usize {
        let base_size = std::mem::size_of_val(&self);
        let inner_size = std::mem::size_of_val(&self.inner)
            + match &self.inner {
                Some(NodeInner::Leaf { value, .. }) => value.capacity(),
                Some(NodeInner::Internal { left, right, .. }) => left.mem_size() + right.mem_size(),
                None => 0,
            };

        base_size
            + inner_size
            + std::mem::size_of_val(&self.hash_cache)
            + std::mem::size_of_val(&self.id)
            - 1
    }
}

impl Encode for NodeInner {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        match self {
            NodeInner::Leaf { key, value } => {
                Encode::encode(&0u8, encoder)?;
                Encode::encode(&key.0, encoder)?;
                Encode::encode(value, encoder)?;
            }
            NodeInner::Internal {
                prefix,
                left,
                right,
            } => {
                Encode::encode(&1u8, encoder)?;
                Encode::encode(&prefix.0, encoder)?;
                Encode::encode(left, encoder)?;
                Encode::encode(right, encoder)?;
            }
        }
        Ok(())
    }
}

impl Decode for NodeInner {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let tag: u8 = Decode::decode(decoder)?;
        match tag {
            0 => {
                let key = Path(Decode::decode(decoder)?);
                let value = Decode::decode(decoder)?;
                Ok(NodeInner::Leaf { key, value })
            }
            1 => {
                let seg: [u8; 33] = Decode::decode(decoder)?;
                let prefix = PathSegment(seg);
                let left: Node = Decode::decode(decoder)?;
                let right: Node = Decode::decode(decoder)?;
                Ok(NodeInner::Internal {
                    prefix,
                    left: Box::new(left),
                    right: Box::new(right),
                })
            }
            _ => Err(DecodeError::Other("Invalid tag")),
        }
    }
}

impl<'a> Encode for &'a mut NodeInner {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        match self {
            NodeInner::Leaf { key, value } => {
                Encode::encode(&0u8, encoder)?;
                Encode::encode(&key.0, encoder)?;
                Encode::encode(value, encoder)?;
            }
            NodeInner::Internal {
                prefix,
                left,
                right,
            } => {
                Encode::encode(&1u8, encoder)?;
                Encode::encode(&prefix.0, encoder)?;
                Encode::encode(left, encoder)?;
                Encode::encode(right, encoder)?;
            }
        }
        Ok(())
    }
}

impl Encode for Node {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        if self.id == EMPTY_RECORD {
            return Err(EncodeError::Other("Node id is zero"));
        }
        Encode::encode(&self.id, encoder)
    }
}

impl Decode for Node {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let id = Decode::decode(decoder)?;
        Ok(Node::from_id(id))
    }
}

impl_borrow_decode!(Node);
impl_borrow_decode!(NodeInner);
