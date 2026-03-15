use crate::path::{BitLength, Path, PathSegment};
use crate::ZERO_HASH;

#[test]
fn path_bit_len() {
    let current_key = Path(ZERO_HASH);
    for depth in 0..256 {
        for point in depth..256 {
            let seg = PathSegment::from_path(current_key, depth, point);
            assert_eq!(
                seg.bit_len(),
                point - depth,
                "depth:{} point:{}",
                depth,
                point
            );
        }
    }
}
