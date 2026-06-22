//! Re-export of [`Bitrate`] from `sh-types`.
//!
//! The canonical definition lives in `sh-types` (the workspace leaf crate) so that
//! `sh-transport`'s pacer can use it without depending on `sh-adaptive`. This module
//! re-exports it for backward compatibility.

pub use sh_types::Bitrate;

#[cfg(test)]
mod tests {
    #[allow(clippy::wildcard_imports)]
    use super::*;

    #[test]
    fn from_bps_roundtrips() {
        let b = Bitrate::from_bps(1_234_567);
        assert_eq!(b.as_bps(), 1_234_567);
    }

    #[test]
    fn kbps_conversion() {
        let b = Bitrate::from_kbps(5_000);
        assert_eq!(b.as_bps(), 5_000_000);
        assert_eq!(b.as_kbps(), 5_000);
    }

    #[test]
    fn mbps_conversion() {
        let b = Bitrate::from_mbps(10);
        assert_eq!(b.as_bps(), 10_000_000);
        assert_eq!(b.as_mbps(), 10);
    }

    #[test]
    fn from_bps_f64_finite() {
        let b = Bitrate::from_bps_f64(2_000_000.0);
        assert_eq!(b.as_bps(), 2_000_000);
    }

    #[test]
    fn from_bps_f64_nan_gives_zero() {
        assert_eq!(Bitrate::from_bps_f64(f64::NAN), Bitrate::ZERO);
    }

    #[test]
    fn from_bps_f64_neg_gives_zero() {
        assert_eq!(Bitrate::from_bps_f64(-1.0), Bitrate::ZERO);
    }

    #[test]
    fn from_bps_f64_pos_inf_saturates() {
        assert_eq!(Bitrate::from_bps_f64(f64::INFINITY), Bitrate(u64::MAX));
    }

    #[test]
    fn from_bps_f64_neg_inf_gives_zero() {
        assert_eq!(Bitrate::from_bps_f64(f64::NEG_INFINITY), Bitrate::ZERO);
    }

    #[test]
    fn clamp_within() {
        let b = Bitrate::from_kbps(500);
        assert_eq!(
            b.clamp(Bitrate::from_kbps(100), Bitrate::from_kbps(1_000)),
            b
        );
    }

    #[test]
    fn clamp_below_min() {
        let b = Bitrate::from_kbps(50);
        let min = Bitrate::from_kbps(100);
        assert_eq!(b.clamp(min, Bitrate::from_kbps(1_000)), min);
    }

    #[test]
    fn clamp_above_max() {
        let b = Bitrate::from_kbps(2_000);
        let max = Bitrate::from_kbps(1_000);
        assert_eq!(b.clamp(Bitrate::from_kbps(100), max), max);
    }

    #[test]
    fn display_bps() {
        assert_eq!(format!("{}", Bitrate::from_bps(500)), "500 bps");
    }

    #[test]
    fn display_kbps() {
        assert_eq!(format!("{}", Bitrate::from_kbps(250)), "250 kbps");
    }

    #[test]
    fn display_mbps() {
        assert_eq!(format!("{}", Bitrate::from_mbps(8)), "8 Mbps");
    }

    #[test]
    fn saturating_add() {
        let a = Bitrate(u64::MAX - 10);
        let b = Bitrate(20);
        assert_eq!(a.saturating_add(b), Bitrate(u64::MAX));
    }

    #[test]
    fn saturating_sub_floors_at_zero() {
        let a = Bitrate::from_kbps(100);
        let b = Bitrate::from_kbps(200);
        assert_eq!(a.saturating_sub(b), Bitrate::ZERO);
    }

    #[test]
    fn ordering() {
        assert!(Bitrate::from_kbps(100) < Bitrate::from_kbps(200));
        assert!(Bitrate::from_mbps(1) > Bitrate::from_kbps(999));
    }

    #[test]
    fn kbps_saturates_on_overflow() {
        // u64::MAX / 1_000 + 1 overflows
        let huge = u64::MAX / 1_000 + 1;
        let b = Bitrate::from_kbps(huge);
        assert_eq!(b, Bitrate(u64::MAX));
    }
}
