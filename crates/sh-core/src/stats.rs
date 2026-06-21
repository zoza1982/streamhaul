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
