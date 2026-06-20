//! Private, panic-free bit/byte helpers shared by the header codecs.

use crate::error::ProtocolError;

/// Copy the first `N` bytes of `data` into a fixed array, or report truncation.
///
/// No panics and no indexing: `get(..N)` bounds-checks, and `try_into` on the resulting
/// exactly-`N`-length slice is infallible (the `and_then` collapses the impossible error into the
/// truncation case).
pub(crate) fn take_array<const N: usize>(data: &[u8]) -> Result<[u8; N], ProtocolError> {
    data.get(..N)
        .and_then(|s| s.try_into().ok())
        .ok_or(ProtocolError::Truncated {
            needed: N,
            have: data.len(),
        })
}

/// Pack `(value, left_shift)` pairs into one byte by OR-ing each value shifted left.
///
/// Every caller passes constant shifts `<= 6` and pre-ranged small values, so no shift overflows and
/// no bits collide. `wrapping_shl` is used purely to stay clear of the `arithmetic_side_effects` lint;
/// for these in-range constant shifts it is exactly equivalent to `<<`.
pub(crate) fn bitpack(parts: &[(u8, u32)]) -> u8 {
    let mut out = 0u8;
    for &(value, shift) in parts {
        out |= value.wrapping_shl(shift);
    }
    out
}
