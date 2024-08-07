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

    /// Extend from another path segment
    pub fn extend<A: BitLength + PathUtils>(&mut self, other: A) {
        let inner = other.inner();

        let mut remaining_bits = other.bit_len();
        let mut index = 0;

        while remaining_bits >= 8 {
            self.extend_from_byte(inner[index], 8);
            remaining_bits -= 8;
            index += 1;
        }

        if remaining_bits > 0 {
            self.extend_from_byte(inner[index], remaining_bits as u8);
        }
    }

    /// Extends the current path with bits from a single byte.
    ///
    /// This function takes a byte `bits` and a length `len` and extends the current path with the specified
    /// number of bits.
    ///
    /// # Arguments
    ///
    /// * `bits` - The byte containing the bits to extend.
    /// * `len` - The number of bits to extend from the byte (must be less than or equal to 8).
    ///
    /// # Panics
    ///
    /// This function panics if `len` is greater than 8 or not enough space
    /// to accommodate the new bits.
    pub fn extend_from_byte(&mut self, bits: u8, len: u8) {
        assert!(len <= 8, "invalid bit length");

        let raw = self.as_mut();
        let current_bit_len = raw[0];
        let new_bit_len = current_bit_len + len;

        raw[0] = new_bit_len;
        let inner = &mut raw[1..];
        let unfilled_bits = 8 - (current_bit_len % 8);

        // If multiple of 8, index will point to the next unfilled byte,
        // otherwise it will point to the last partially filled byte.
        let mut index = (current_bit_len / 8) as usize;

        if len <= unfilled_bits {
            // All new bits fit in the current byte
            inner[index] |= bits >> (8 - len) << (unfilled_bits - len);
        } else {
            // New bits span over two bytes
            inner[index] |= bits >> (8 - unfilled_bits);

            // carry over any remaining bits to a new byte
            index += 1;
            assert!(inner.len() > index, "could not fit all bits");
            inner[index] = bits << unfilled_bits;
        }

        // Clear any trailing bits in the last byte
        let last_byte_bits = new_bit_len % 8;
        if last_byte_bits != 0 {
            inner[index] &= 0xFF << (8 - last_byte_bits);
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

    fn split_point<S: BitLength + PathUtils>(&self, start: usize, b: S) -> Option<usize> {
        let max_bit_len = core::cmp::min(self.bit_len(), b.bit_len());
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


#[cfg(test)]
mod tests {
    use core::fmt::Display;
    use crate::path::{BitLength, Direction, PathSegment, PathUtils};

    impl<T: AsRef<[u8]>> Display for PathSegment<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            for i in 0..self.bit_len() {
                if self.direction(i) == Direction::Right {
                    write!(f, "1")?;
                } else {
                    write!(f, "0")?;
                }
            }
            Ok(())
        }
    }

    #[test]
    fn test_extend() {
        let mut parent = PathSegment([0u8;33]);
        parent.set_len(5);

        let mut child = PathSegment([0u8;33]);
        child.set_len(10);
        child.0[1] = 0b1111_1010;

        parent.extend(child);
        assert_eq!(parent.to_string(), "000001111101000");
    }

    #[test]
    fn test_extend_from_byte() {
        let mut segment = PathSegment([0u8;33]);
        segment.set_len(2);

        let inner = segment.as_mut_inner();
        inner[0] = 0b1100_0000;

        segment.extend_from_byte(0b1000_1000,3);
        assert_eq!(segment.to_string(), "11100");

        segment.extend_from_byte(0b1111_1111, 8);
        assert_eq!(segment.to_string(), "1110011111111");

        segment.extend_from_byte(0b0011_1111, 2);
        assert_eq!(segment.to_string(), "111001111111100");

        segment.extend_from_byte(0b1111_1111, 8);
        assert_eq!(segment.to_string(), "11100111111110011111111");

        segment.extend_from_byte(0b0000_1111, 4);
        assert_eq!(segment.to_string(), "111001111111100111111110000");

        segment.set_len(segment.bit_len() + 2);
        assert_eq!(segment.to_string(),  "11100111111110011111111000000",
                   "trailing bits must be cleared");
    }
}
