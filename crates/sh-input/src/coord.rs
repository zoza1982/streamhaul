//! Coordinate mapping from normalized `0..=65535` pointer values to absolute host pixels.
//!
//! # Design
//!
//! The Streamhaul wire protocol transmits pointer coordinates as `u16` values in the range
//! `0..=65535`, resolution-independent across the client's source surface (`LLD.md` §3.1).
//! The host must map these to absolute pixels in its own virtual-desktop coordinate space
//! before synthesizing an OS pointer event.
//!
//! [`CoordMapper`] encapsulates this mapping and the [`TargetRect`] that describes the
//! host display (or virtual-desktop spanning multiple monitors).
//!
//! # Multi-monitor support
//!
//! A Windows/Linux multi-monitor virtual desktop has a single coordinate space where the
//! primary display's top-left is typically `(0, 0)`, and secondary displays can extend into
//! negative X or Y territory (e.g. a monitor to the left of primary has negative X origin).
//! [`TargetRect`] uses `i32` origins to cover this case.
//!
//! # Mapping formula
//!
//! For a single axis with normalized input `norm` (range `0..=65535`) and target
//! extent `n` pixels:
//!
//! ```text
//! pixel_offset = round(norm × (n − 1) / 65535)
//! ```
//!
//! Implemented with integer half-up rounding and no floating-point:
//!
//! ```text
//! pixel_offset = (norm as u64 × (n − 1) as u64 + 32767) / 65535
//! ```
//!
//! Adding `32767` (⌊65535/2⌋) before integer division achieves **half-up rounding**
//! (round half toward positive infinity). `n` (the axis extent) is accepted up to `u32::MAX`,
//! so the maximum intermediate value is
//! `65535 × (u32::MAX − 1) + 32767 = 281_470_681_645_057`, which fits comfortably in a `u64`
//! (~65000× below `u64::MAX`).
//!
//! Edge-case invariants (verified by the test suite and the proptest):
//!
//! | Input `norm` | `n = 1` | `n > 1` |
//! |---|---|---|
//! | `0`     | origin     | origin (top-left pixel)          |
//! | `65535` | origin     | origin + n − 1 (bottom-right pixel) |
//! | `32767` | origin     | origin + ⌊(n−1)/2⌋               |
//!
//! A zero-extent axis (`n = 0`) is rejected at [`TargetRect`] construction time with
//! [`crate::InputError::ZeroSizeAxis`].

use crate::InputError;

/// The virtual-desktop bounds of the injection target.
///
/// `origin_x` / `origin_y` are the top-left corner in the host's virtual-desktop coordinate
/// space. They may be **negative** when a secondary monitor lies to the left of or above the
/// primary monitor. `width` / `height` must be non-zero; use [`TargetRect::new`] to validate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetRect {
    /// X coordinate of the left edge of the target area in host virtual-desktop space.
    /// May be negative (secondary monitor left of primary).
    pub origin_x: i32,
    /// Y coordinate of the top edge of the target area in host virtual-desktop space.
    /// May be negative (secondary monitor above primary).
    pub origin_y: i32,
    /// Width of the target area in pixels. Must be ≥ 1.
    pub width: u32,
    /// Height of the target area in pixels. Must be ≥ 1.
    pub height: u32,
}

impl TargetRect {
    /// Construct a [`TargetRect`], validating that neither axis has zero extent.
    ///
    /// # Errors
    ///
    /// Returns [`InputError::ZeroSizeAxis`] when `width = 0` or `height = 0`.
    pub fn new(origin_x: i32, origin_y: i32, width: u32, height: u32) -> Result<Self, InputError> {
        if width == 0 || height == 0 {
            return Err(InputError::ZeroSizeAxis { width, height });
        }
        Ok(Self {
            origin_x,
            origin_y,
            width,
            height,
        })
    }
}

/// An absolute pixel coordinate in the host's virtual-desktop space.
///
/// Origins may be negative for multi-monitor setups where a display extends to the left of or
/// above the primary monitor's origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappedPoint {
    /// Absolute X pixel in host virtual-desktop space.
    pub x: i32,
    /// Absolute Y pixel in host virtual-desktop space.
    pub y: i32,
}

/// Maps normalized pointer coordinates (`0..=65535`) to absolute host pixels.
///
/// Construct once per session (or on display-layout change) and call [`CoordMapper::map`]
/// for every [`sh_protocol::InputEvent`] that carries pointer data.
///
/// See the [module-level documentation](self) for the full mapping formula and
/// edge-case behaviour.
#[derive(Debug, Clone, Copy)]
pub struct CoordMapper {
    rect: TargetRect,
}

impl CoordMapper {
    /// Create a mapper for the given target rectangle.
    ///
    /// # Errors
    ///
    /// Returns [`InputError::ZeroSizeAxis`] when the rect has `width = 0` or `height = 0`.
    pub fn new(rect: TargetRect) -> Result<Self, InputError> {
        // TargetRect::new already validated; accept a pre-validated rect directly.
        // Re-validate here as a defence in depth: TargetRect has public fields, so a caller
        // can construct it directly without going through TargetRect::new — this guards that path.
        if rect.width == 0 || rect.height == 0 {
            return Err(InputError::ZeroSizeAxis {
                width: rect.width,
                height: rect.height,
            });
        }
        Ok(Self { rect })
    }

    /// Map a normalized pointer position to an absolute host pixel.
    ///
    /// `norm_x` and `norm_y` are in `0..=65535` (the full range of [`sh_protocol::InputEvent`]
    /// `pointer_x` / `pointer_y`). The result is always within the [`TargetRect`] bounds.
    ///
    /// # Rounding
    ///
    /// Uses **half-up integer rounding** (see module documentation for the exact formula).
    /// No floating-point operations are used; the intermediate is a `u64`.
    ///
    /// # Panics
    ///
    /// Never panics for any input in `0..=u16::MAX` and any non-zero `TargetRect`.
    #[must_use]
    pub fn map(&self, norm_x: u16, norm_y: u16) -> MappedPoint {
        MappedPoint {
            x: self
                .rect
                .origin_x
                .saturating_add(map_axis(norm_x, self.rect.width)),
            y: self
                .rect
                .origin_y
                .saturating_add(map_axis(norm_y, self.rect.height)),
        }
    }

    /// The target rectangle this mapper was built for.
    #[must_use]
    pub fn target_rect(&self) -> TargetRect {
        self.rect
    }
}

/// Map a single normalized axis value to a pixel offset within `[0, extent - 1]`.
///
/// Formula: `round_half_up(norm × (extent - 1) / 65535)` using integer arithmetic.
///
/// `extent` must be ≥ 1 (enforced by [`CoordMapper::new`]).
///
/// # Arithmetic bounds proof (justifies the `arithmetic_side_effects` allow)
///
/// - `extent ≥ 2` (checked by early return for `extent == 1`), so `extent - 1 ≥ 1`.
/// - `n ≤ 65535`, `e ≤ u32::MAX − 1 = 4_294_967_294`.
/// - `n * e ≤ 65535 × 4_294_967_294 = 281_470_681_612_290`, well within `u64::MAX`.
/// - `n * e + 32767 ≤ 281_470_681_645_057`, still well within `u64::MAX` (~65000× below it).
/// - Division by 65535 is unconditionally safe (constant, non-zero).
/// - `offset ≤ (65535 × e + 32767) / 65535 ≤ e ≤ u32::MAX − 1`.
///   `i32::try_from` saturates at `i32::MAX` for pathological extents > 2 GiB
///   (no real display is that large).
#[allow(clippy::arithmetic_side_effects)]
fn map_axis(norm: u16, extent: u32) -> i32 {
    debug_assert!(extent >= 1, "extent must be ≥ 1");

    if extent == 1 {
        // Only one pixel; every normalized value maps to offset 0.
        return 0;
    }

    // extent ≥ 2, so (extent - 1) ≥ 1.
    let n = norm as u64;
    let e = (extent - 1) as u64;
    // Half-up rounding: add ⌊65535/2⌋ = 32767 before dividing.
    // Maximum intermediate: 65535 × (u32::MAX − 1) + 32767 fits in u64 (see proof above).
    let offset = (n * e + 32767) / 65535;

    // offset ≤ e ≤ u32::MAX − 1; saturate defensively for pathological extents.
    i32::try_from(offset).unwrap_or(i32::MAX)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn mapper(w: u32, h: u32) -> CoordMapper {
        CoordMapper::new(TargetRect::new(0, 0, w, h).unwrap()).unwrap()
    }

    fn mapper_at(ox: i32, oy: i32, w: u32, h: u32) -> CoordMapper {
        CoordMapper::new(TargetRect::new(ox, oy, w, h).unwrap()).unwrap()
    }

    // ── Zero-size rejection ────────────────────────────────────────────────

    #[test]
    fn zero_width_rejected() {
        assert_eq!(
            TargetRect::new(0, 0, 0, 100),
            Err(InputError::ZeroSizeAxis {
                width: 0,
                height: 100
            })
        );
    }

    #[test]
    fn zero_height_rejected() {
        assert_eq!(
            TargetRect::new(0, 0, 100, 0),
            Err(InputError::ZeroSizeAxis {
                width: 100,
                height: 0
            })
        );
    }

    #[test]
    fn zero_size_rejected_via_coord_mapper() {
        let rect = TargetRect {
            origin_x: 0,
            origin_y: 0,
            width: 0,
            height: 1,
        };
        assert!(matches!(
            CoordMapper::new(rect),
            Err(InputError::ZeroSizeAxis { .. })
        ));
    }

    // ── Edge cases: 1×1 target ────────────────────────────────────────────

    #[test]
    fn one_by_one_target_all_norms_map_to_origin() {
        let m = mapper_at(7, -3, 1, 1);
        // Every norm value must map to the single pixel (7, -3).
        for norm in [0u16, 1, 32767, 32768, 65534, 65535] {
            let pt = m.map(norm, norm);
            assert_eq!(pt, MappedPoint { x: 7, y: -3 }, "norm={norm}");
        }
    }

    // ── Edge cases: norm=0 → top-left, norm=65535 → bottom-right ─────────

    #[test]
    fn norm_zero_maps_to_top_left() {
        let m = mapper(1920, 1080);
        assert_eq!(m.map(0, 0), MappedPoint { x: 0, y: 0 });
    }

    #[test]
    fn norm_max_maps_to_bottom_right() {
        let m = mapper(1920, 1080);
        assert_eq!(m.map(65535, 65535), MappedPoint { x: 1919, y: 1079 });
    }

    #[test]
    fn norm_zero_maps_to_top_left_with_offset() {
        let m = mapper_at(-1920, -1080, 1920, 1080);
        assert_eq!(m.map(0, 0), MappedPoint { x: -1920, y: -1080 });
    }

    #[test]
    fn norm_max_maps_to_bottom_right_with_offset() {
        let m = mapper_at(-1920, -1080, 1920, 1080);
        assert_eq!(
            m.map(65535, 65535),
            MappedPoint {
                x: -1920 + 1919,
                y: -1080 + 1079
            }
        );
    }

    // ── Midpoint rounding ─────────────────────────────────────────────────

    #[test]
    fn midpoint_rounding_1080p() {
        // 1080p: extent = 1920 × 1080.
        // norm = 32767: expected offset = round(32767 × 1919 / 65535)
        // = round(959.985...) = 960 (half-up: 32767 × 1919 = 62,880,673; +32767 = 62,913,440; /65535 = 959.99... → 959)
        // Let's compute explicitly:
        // 32767 * 1919 = 62,878,673
        // + 32767     = 62,911,440
        // / 65535     = 959.95... → 959
        // So norm=32767 on 1920-wide → offset 959.
        let m = mapper(1920, 1080);
        let pt = m.map(32767, 32767);
        // Verify pixel is within bounds.
        assert!(pt.x >= 0 && pt.x < 1920);
        assert!(pt.y >= 0 && pt.y < 1080);
        // Exact: (32767 × 1919 + 32767) / 65535 = 62_911_440 / 65535 = 959 (floor, ≈0.999)
        assert_eq!(pt.x, 959, "midpoint x on 1920 px wide");
        // Exact: (32767 × 1079 + 32767) / 65535 = 35_388_360 / 65535 = 539 (floor, ≈0.992)
        assert_eq!(pt.y, 539, "midpoint y on 1080 px tall");
    }

    #[test]
    fn norm_32768_midpoint_rounding() {
        // norm=32768 on a 2-pixel axis: (32768 * 1 + 32767) / 65535 = 65535 / 65535 = 1.
        let m = mapper(2, 2);
        let pt = m.map(32768, 32768);
        assert_eq!(pt, MappedPoint { x: 1, y: 1 });
    }

    #[test]
    fn norm_32767_on_two_pixel_axis() {
        // (32767 * 1 + 32767) / 65535 = 65534 / 65535 = 0.
        let m = mapper(2, 2);
        let pt = m.map(32767, 32767);
        assert_eq!(pt, MappedPoint { x: 0, y: 0 });
    }

    // ── Negative origins (multi-monitor) ──────────────────────────────────

    #[test]
    fn negative_origin_x() {
        let m = mapper_at(-3840, 0, 1920, 1080);
        let pt = m.map(65535, 0);
        assert_eq!(pt.x, -3840 + 1919);
        assert_eq!(pt.y, 0);
    }

    #[test]
    fn negative_origin_both_axes() {
        let m = mapper_at(-500, -300, 800, 600);
        let pt = m.map(0, 0);
        assert_eq!(pt, MappedPoint { x: -500, y: -300 });
        let pt2 = m.map(65535, 65535);
        assert_eq!(
            pt2,
            MappedPoint {
                x: -500 + 799,
                y: -300 + 599
            }
        );
    }

    // ── Max extents (large display) ───────────────────────────────────────

    #[test]
    fn max_norm_on_large_display() {
        // 8K display 7680×4320
        let m = mapper(7680, 4320);
        let pt = m.map(65535, 65535);
        assert_eq!(pt, MappedPoint { x: 7679, y: 4319 });
    }

    // ── target_rect accessor ──────────────────────────────────────────────

    #[test]
    fn target_rect_accessor() {
        let rect = TargetRect::new(-100, 200, 1920, 1080).unwrap();
        let m = CoordMapper::new(rect).unwrap();
        assert_eq!(m.target_rect(), rect);
    }

    // ── Proptest: mapped coords always within target bounds ───────────────

    proptest! {
        #[test]
        fn mapped_point_always_in_bounds(
            norm_x in any::<u16>(),
            norm_y in any::<u16>(),
            origin_x in -100_000i32..=100_000i32,
            origin_y in -100_000i32..=100_000i32,
            // Keep dimensions realistic (1..=32768) to avoid i32 overflow in origin + offset.
            width in 1u32..=32_768,
            height in 1u32..=32_768,
        ) {
            let rect = TargetRect::new(origin_x, origin_y, width, height).unwrap();
            let m = CoordMapper::new(rect).unwrap();
            let pt = m.map(norm_x, norm_y);

            prop_assert!(pt.x >= origin_x, "x={} < origin_x={}", pt.x, origin_x);
            prop_assert!(
                pt.x <= origin_x.saturating_add((width - 1) as i32),
                "x={} > origin_x + width - 1 = {}",
                pt.x,
                origin_x.saturating_add((width - 1) as i32)
            );
            prop_assert!(pt.y >= origin_y, "y={} < origin_y={}", pt.y, origin_y);
            prop_assert!(
                pt.y <= origin_y.saturating_add((height - 1) as i32),
                "y={} > origin_y + height - 1 = {}",
                pt.y,
                origin_y.saturating_add((height - 1) as i32)
            );
        }
    }
}
