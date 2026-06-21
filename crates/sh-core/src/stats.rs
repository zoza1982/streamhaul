//! Shared percentile statistics helpers for latency harnesses.

/// Compute percentile statistics over a **sorted** `u64` slice.
///
/// Returns `(min, median, p95, max)`. All four values are `0` for an empty slice.
///
/// # Rounding
///
/// Median for an even-length slice uses integer averaging:
/// `lo/2 + hi/2 + (lo%2 + hi%2)/2` to avoid overflow.
///
/// The p95 index formula is `ceil(len * 95 / 100) - 1`, computed entirely with
/// saturating integer arithmetic to avoid any overflow on large slices.
#[allow(clippy::arithmetic_side_effects)]
pub(crate) fn percentiles(sorted: &[u64]) -> (u64, u64, u64, u64) {
    let len = sorted.len();
    if len == 0 {
        return (0, 0, 0, 0);
    }
    let min = sorted.first().copied().unwrap_or(0);
    let max = sorted.last().copied().unwrap_or(0);

    let median = if len % 2 == 1 {
        sorted.get(len / 2).copied().unwrap_or(0)
    } else {
        let lo = sorted.get(len / 2 - 1).copied().unwrap_or(0);
        let hi = sorted.get(len / 2).copied().unwrap_or(0);
        lo / 2 + hi / 2 + (lo % 2 + hi % 2) / 2
    };

    let p95_idx = len
        .saturating_mul(95)
        .saturating_add(99)
        .saturating_div(100)
        .saturating_sub(1)
        .min(len.saturating_sub(1));
    let p95 = sorted.get(p95_idx).copied().unwrap_or(0);

    (min, median, p95, max)
}

#[cfg(test)]
mod tests {
    use super::percentiles;

    #[test]
    fn empty_slice_is_all_zero() {
        assert_eq!(percentiles(&[]), (0, 0, 0, 0));
    }

    #[test]
    fn single_element_collapses() {
        assert_eq!(percentiles(&[42]), (42, 42, 42, 42));
    }

    #[test]
    fn odd_length_median_is_middle() {
        // sorted: [1, 2, 3] → median 2
        let (min, median, _p95, max) = percentiles(&[1, 2, 3]);
        assert_eq!((min, median, max), (1, 2, 3));
    }

    #[test]
    fn even_length_median_is_integer_average() {
        // sorted: [2, 4] → (2+4)/2 = 3
        assert_eq!(percentiles(&[2, 4]).1, 3);
        // odd operands: [3, 4] → 3/2 + 4/2 + (1+0)/2 = 1 + 2 + 0 = 3
        assert_eq!(percentiles(&[3, 4]).1, 3);
    }

    #[test]
    fn even_median_no_overflow_near_u64_max() {
        // Both near u64::MAX: naive (lo+hi)/2 would overflow; the split formula must not.
        let lo = u64::MAX - 1;
        let hi = u64::MAX;
        // lo/2 + hi/2 + (lo%2 + hi%2)/2
        let expected = lo / 2 + hi / 2 + (lo % 2 + hi % 2) / 2;
        assert_eq!(percentiles(&[lo, hi]).1, expected);
    }

    #[test]
    fn p95_index_picks_high_tail() {
        // 0..=99 (100 elements): ceil(100*95/100)-1 = 94
        let data: Vec<u64> = (0..100).collect();
        let (min, _median, p95, max) = percentiles(&data);
        assert_eq!((min, p95, max), (0, 94, 99));
    }

    #[test]
    fn p95_clamps_for_tiny_slices() {
        // len=2: ceil(2*95/100)-1 = ceil(1.9)-1 = 2-1 = 1, clamped to len-1=1 → max element
        assert_eq!(percentiles(&[10, 20]).2, 20);
    }
}
