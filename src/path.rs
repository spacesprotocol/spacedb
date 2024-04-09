pub(crate) type PathSegmentInner = [u8; 33];

const BIT_MASK: [u8; 8] = [128, 64, 32, 16, 8, 4, 2, 1];

#[derive(PartialEq)]
pub enum Direction {
    Left,
    Right,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Path<T>(pub T);

#[derive(Clone, Copy, Debug)]
pub struct PathSegment<T>(pub T);

pub trait PathUtils {
    /// Returns the direction at a specified index within a path in the binary trie.
    ///
    /// # Parameters
    /// - `index`: The index of the bit within the path.
    ///
    /// # Returns
    /// - `Direction::Right` if the bit at the specified index is set.
    /// - `Direction::Left` if the bit at the specified index is unset.
    ///
    /// # Note
    /// - The function uses MSB ordering, where the most significant bit is at index 0.
    fn direction(&self, index: usize) -> Direction;

    /// Returns the first point of divergence relative to `start` .
    /// The comparison begins at `start` index within `self` and proceeds until the end of the shortest segment.
    ///
    /// # Parameters
    /// - `start`: The index within `self` from which the comparison should start. Must be within the bounds of `self`.
    /// - `segment`: The segment to compare against `self`. Must implement `BitLength` and `PathUtils`.
    ///
    /// # Panics
    /// - If `start` + `segment.bit_len()` is greater than the length of `self`.
    ///
    /// # Returns
    /// - `None` if the paths are identical up to the length of the shortest segment.
    /// - `Some(index)` where `index` is the first point of divergence relative to `start` in `self`.
    ///
    /// # Note
    /// - The comparison stops at the end of the shortest segment.
    /// - The function uses MSB ordering, where the most significant bit is at index 0.
    fn split_point<S: BitLength + PathUtils>(
        &self,
        segment_start: usize,
        segment: S,
    ) -> Option<usize>;
}

impl<T: AsMut<[u8]>> PathSegment<T> {
    /// Copies all bits from `src` into `self` starting and ending at the specified bit indices.
    /// `self` must be able to accommodate the copied bits within its length.
    ///
    /// # Parameters
    /// - `src`: The source path from which bits will be copied. Must implement `BitLength` and `PathUtils`.
    /// - `start`: The starting bit index in the `src` path (inclusive)
    /// - `end`: The ending bit index in `src` path (exclusive)
    ///
    /// # Panics
    /// - The function panics if `start` > `end`.
    pub fn copy<A: BitLength + PathUtils>(&mut self, src: A, start: usize, end: usize) {
        if start == end {
            return;
        }
        assert!(start < end, "start {} must be less than end {}", start, end);
        let bit_len = end - start;
        self.set_len(bit_len);

        let (src, src_start, start_bit) = (src.inner(), start / 8, start % 8);
        let (dst_slice, dst_end_idx, dst_end_bit) =
            (self.as_mut_inner(), (bit_len - 1) / 8, bit_len % 8);

        // If aligned on byte boundary, use direct slice copy.
        if start_bit == 0 {
            dst_slice[..dst_end_idx + 1]
                .copy_from_slice(&src[src_start..src_start + dst_end_idx + 1]);
        } else {
            // For non-aligned bits, copy bits with shifting.
            for (i, j) in (src_start..src_start + dst_end_idx + 1).zip(0..) {
                dst_slice[j] = src[i] << start_bit;
                if i + 1 < src.len() {
                    dst_slice[j] |= src[i + 1] >> (8 - start_bit);
                }
            }
        }

        // Handle the case where the last byte in dst_slice is copied
        // but not all bits are needed.
        if dst_end_bit != 0 {
            // zero out the unused bits.
            dst_slice[dst_end_idx] &= 0xFF << (8 - dst_end_bit);
        }
    }

    #[inline(always)]
    pub fn set_len(&mut self, len: usize) {
        assert!(len <= 255, "PathSegment length must be <= 255");
        self.0.as_mut()[0] = len as u8;
    }

    #[inline(always)]
    pub fn as_mut_inner(&mut self) -> &mut [u8] {
        &mut self.0.as_mut()[1..]
    }
}

impl<T: BitLength + AsRef<[u8]>> PathUtils for T {
    #[inline(always)]
    fn direction(&self, index: usize) -> Direction {
        if self.inner()[index / 8] & BIT_MASK[index % 8] != 0 {
            return Direction::Right;
        }
        Direction::Left
    }

    /// Returns the first differing bit of `self`, from `start` bit of `self`(inclusive).
    /// If all bits are the same, returns None instead.
    fn split_point<S: BitLength + PathUtils>(&self, start: usize, b: S) -> Option<usize> {
        assert!(self.bit_len() >= start);
        let max_bit_len = core::cmp::min(self.bit_len() - start, b.bit_len());
        let (src_start_byte, src_start_bit, seg_end_byte) =
            (start / 8, start % 8, (max_bit_len + 7) / 8);
        let mut count = 0;

        // Aligned on byte boundary
        if src_start_bit == 0 {
            let (a, b) = (&self.inner()[src_start_byte..], &b.inner()[..seg_end_byte]);
            for (a_byte, b_byte) in a.iter().zip(b.iter()) {
                if *a_byte != *b_byte {
                    count += (a_byte ^ b_byte).leading_zeros();
                    break;
                }
                count += 8;
            }
        } else {
            // Non-aligned: we need to align self and then compare (b is already aligned)
            let (a, b) = (&self.inner()[src_start_byte..], &b.inner()[..seg_end_byte]);
            for (i, b_byte) in b.iter().enumerate() {
                // Remove bits we don't care about at the start by shifiting
                let mut a_byte = a[i] << src_start_bit;
                // We made room for some bits from the next byte
                if i < a.len() {
                    a_byte |= a[i + 1] >> (8 - src_start_bit);
                }

                // We now have an aligned a_byte
                if a_byte != *b_byte {
                    count += (a_byte ^ b_byte).leading_zeros();
                    break;
                }
                count += 8;
            }
        }

        let count = core::cmp::min(count as usize, max_bit_len);
        if count == max_bit_len {
            return None;
        } else {
            return Some(count);
        }
    }
}

impl PathSegment<[u8; 33]> {
    #[inline(always)]
    pub fn from_path<A: BitLength + PathUtils>(src: A, from: usize, to: usize) -> Self {
        let mut a = PathSegment([0; 33]);
        a.copy(src, from, to);
        a
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Path<T> {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<T: AsMut<[u8]>> AsMut<[u8]> for Path<T> {
    #[inline(always)]
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for PathSegment<T> {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<T: AsMut<[u8]>> AsMut<[u8]> for PathSegment<T> {
    #[inline(always)]
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl<T: AsRef<[u8]>> BitLength for Path<T> {
    #[inline(always)]
    fn bit_len(&self) -> usize {
        256
    }

    #[inline(always)]
    fn inner(&self) -> &[u8] {
        &self.0.as_ref()
    }

    #[inline(always)]
    fn as_bytes(&self) -> &[u8] {
        &self.0.as_ref()
    }
}

impl<T: AsRef<[u8]>> BitLength for PathSegment<T> {
    #[inline(always)]
    fn bit_len(&self) -> usize {
        self.0.as_ref()[0] as usize
    }

    #[inline(always)]
    fn inner(&self) -> &[u8] {
        &self.0.as_ref()[1..]
    }

    #[inline(always)]
    fn as_bytes(&self) -> &[u8] {
        let byte_len = (self.bit_len() + 7) / 8;
        &self.0.as_ref()[..(byte_len + 1)]
    }
}

#[cfg(feature = "std")]
impl<T: PartialOrd> PartialOrd for Path<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

#[cfg(feature = "std")]
impl<T: Ord> Ord for Path<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

pub trait BitLength {
    fn bit_len(&self) -> usize;
    fn inner(&self) -> &[u8];
    fn as_bytes(&self) -> &[u8];
}
