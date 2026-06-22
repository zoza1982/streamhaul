//! NACK feedback framing for the SHP receiver-report channel.
//!
//! Implements the 25-byte `NackFeedback` wire message defined in LLD §3.1. This message
//! carries all state a sender needs to react to loss: cumulative counters, jitter, RTT,
//! bandwidth estimate, and a 16-bit NACK bitmap pointing at missing sequence numbers.
//!
//! ## Wire layout (big-endian)
//!
//! | Offset | Size | Field              |
//! |--------|------|--------------------|
//! | 0      | 1    | REPORT_TYPE        |
//! | 1      | 4    | SSRC               |
//! | 5      | 2    | HIGHEST_SEQ        |
//! | 7      | 3    | CUMULATIVE_LOST    |
//! | 10     | 1    | FRACTION_LOST      |
//! | 11     | 4    | JITTER (µs)        |
//! | 15     | 4    | RTT (µs)           |
//! | 19     | 4    | BWE (kbps)         |
//! | 23     | 2    | NACK_BITMAP        |
//!
//! **Total: 25 bytes.**

use crate::bits::take_array;
use crate::error::ProtocolError;

/// Wire size of a [`NackFeedback`] message, in bytes.
pub const NACK_FEEDBACK_LEN: usize = 25;

/// Maximum value of `cumulative_lost` that fits in the 24-bit on-wire field.
pub const MAX_CUMULATIVE_LOST: u32 = 0x00FF_FFFF;

/// A 25-byte NACK feedback message carrying receiver state to the sender.
///
/// The NACK bitmap encodes which of the 16 sequence numbers immediately preceding
/// `highest_seq` are missing: bit `i` = 1 means sequence number `highest_seq - 1 - i`
/// has not been received.
///
/// ## Standard report type
///
/// `report_type = 0` is the "standard feedback" variant. Other values are
/// application-defined; this implementation encodes and decodes them without restriction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NackFeedback {
    /// Application-defined report type; 0 = standard feedback.
    pub report_type: u8,
    /// Synchronization source identifier.
    pub ssrc: u32,
    /// Highest sequence number received so far.
    pub highest_seq: u16,
    /// Total cumulative packets lost since session start.
    ///
    /// Only the low 24 bits travel on the wire; values exceeding [`MAX_CUMULATIVE_LOST`]
    /// are rejected by [`NackFeedback::encode`].
    pub cumulative_lost: u32,
    /// Fraction of packets lost in the last reporting interval (RTCP encoding: 0 = 0%, 255 ≈ 99.6%).
    pub fraction_lost: u8,
    /// Interarrival jitter estimate in microseconds.
    pub jitter_us: u32,
    /// Most recent round-trip time estimate in microseconds.
    pub rtt_us: u32,
    /// Current bandwidth estimate in kilobits per second.
    pub bwe_kbps: u32,
    /// 16-bit NACK bitmap: bit `i` = 1 means sequence number `highest_seq - 1 - i` is missing.
    pub nack_bitmap: u16,
}

impl NackFeedback {
    /// Serialize to the 25-byte big-endian wire representation.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::CumulativeLostTooLarge`] if `cumulative_lost` exceeds
    /// [`MAX_CUMULATIVE_LOST`] (24-bit maximum `0x00FF_FFFF`).
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_protocol::{NackFeedback, NACK_FEEDBACK_LEN};
    /// # fn main() -> Result<(), sh_protocol::ProtocolError> {
    /// let fb = NackFeedback {
    ///     report_type: 0,
    ///     ssrc: 0xDEAD_BEEF,
    ///     highest_seq: 1000,
    ///     cumulative_lost: 42,
    ///     fraction_lost: 5,
    ///     jitter_us: 1500,
    ///     rtt_us: 25_000,
    ///     bwe_kbps: 2048,
    ///     nack_bitmap: 0b0000_0000_0000_0011,
    /// };
    /// let bytes = fb.encode()?;
    /// assert_eq!(bytes.len(), NACK_FEEDBACK_LEN);
    /// assert_eq!(NackFeedback::decode(&bytes), Ok(fb));
    /// # Ok(()) }
    /// ```
    pub fn encode(&self) -> Result<[u8; NACK_FEEDBACK_LEN], ProtocolError> {
        if self.cumulative_lost > MAX_CUMULATIVE_LOST {
            return Err(ProtocolError::CumulativeLostTooLarge(self.cumulative_lost));
        }

        let ssrc = self.ssrc.to_be_bytes();
        let highest_seq = self.highest_seq.to_be_bytes();
        // 24-bit big-endian: take the 3 least-significant bytes of the 32-bit value.
        let cum = self.cumulative_lost.to_be_bytes();
        let jitter = self.jitter_us.to_be_bytes();
        let rtt = self.rtt_us.to_be_bytes();
        let bwe = self.bwe_kbps.to_be_bytes();
        let nack = self.nack_bitmap.to_be_bytes();

        Ok([
            self.report_type,
            ssrc[0],
            ssrc[1],
            ssrc[2],
            ssrc[3],
            highest_seq[0],
            highest_seq[1],
            // cumulative_lost: low 3 bytes of big-endian u32 (index 1, 2, 3)
            cum[1],
            cum[2],
            cum[3],
            self.fraction_lost,
            jitter[0],
            jitter[1],
            jitter[2],
            jitter[3],
            rtt[0],
            rtt[1],
            rtt[2],
            rtt[3],
            bwe[0],
            bwe[1],
            bwe[2],
            bwe[3],
            nack[0],
            nack[1],
        ])
    }

    /// Parse a `NackFeedback` from the start of `data`. Never panics; rejects malformed input.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Truncated`] if `data` is shorter than [`NACK_FEEDBACK_LEN`] bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_protocol::{NackFeedback, ProtocolError};
    /// assert_eq!(
    ///     NackFeedback::decode(&[0u8; 10]),
    ///     Err(ProtocolError::Truncated { needed: 25, have: 10 })
    /// );
    /// ```
    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        let [report_type, s0, s1, s2, s3, h0, h1, c0, c1, c2, fraction_lost, j0, j1, j2, j3, r0, r1, r2, r3, b0, b1, b2, b3, n0, n1] =
            take_array::<NACK_FEEDBACK_LEN>(data)?;

        Ok(Self {
            report_type,
            ssrc: u32::from_be_bytes([s0, s1, s2, s3]),
            highest_seq: u16::from_be_bytes([h0, h1]),
            // Reconstruct 24-bit cumulative_lost as u32 (high byte = 0).
            cumulative_lost: u32::from_be_bytes([0, c0, c1, c2]),
            fraction_lost,
            jitter_us: u32::from_be_bytes([j0, j1, j2, j3]),
            rtt_us: u32::from_be_bytes([r0, r1, r2, r3]),
            bwe_kbps: u32::from_be_bytes([b0, b1, b2, b3]),
            nack_bitmap: u16::from_be_bytes([n0, n1]),
        })
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn sample() -> NackFeedback {
        NackFeedback {
            report_type: 0,
            ssrc: 0xDEAD_BEEF,
            highest_seq: 1000,
            cumulative_lost: 42,
            fraction_lost: 5,
            jitter_us: 1500,
            rtt_us: 25_000,
            bwe_kbps: 2048,
            nack_bitmap: 0b0000_0000_0000_0011,
        }
    }

    #[test]
    fn roundtrip_basic() {
        let fb = sample();
        let bytes = fb.encode().unwrap();
        assert_eq!(bytes.len(), NACK_FEEDBACK_LEN);
        // Verify key byte positions.
        assert_eq!(bytes[0], 0); // report_type
        assert_eq!(bytes[1..5], [0xDE, 0xAD, 0xBE, 0xEF]); // ssrc
        assert_eq!(bytes[5..7], [0x03, 0xE8]); // highest_seq = 1000
        assert_eq!(bytes[7..10], [0x00, 0x00, 0x2A]); // cumulative_lost = 42
        assert_eq!(bytes[10], 5); // fraction_lost
        assert_eq!(NackFeedback::decode(&bytes), Ok(fb));
    }

    #[test]
    fn decode_rejects_truncation() {
        for len in 0..NACK_FEEDBACK_LEN {
            let data = vec![0u8; len];
            assert_eq!(
                NackFeedback::decode(&data),
                Err(ProtocolError::Truncated {
                    needed: NACK_FEEDBACK_LEN,
                    have: len,
                })
            );
        }
    }

    #[test]
    fn cumulative_lost_too_large_rejected() {
        let mut fb = sample();
        fb.cumulative_lost = MAX_CUMULATIVE_LOST.saturating_add(1);
        assert_eq!(
            fb.encode(),
            Err(ProtocolError::CumulativeLostTooLarge(fb.cumulative_lost))
        );
    }

    #[test]
    fn cumulative_lost_max_encodes_correctly() {
        let mut fb = sample();
        fb.cumulative_lost = MAX_CUMULATIVE_LOST;
        let bytes = fb.encode().unwrap();
        // 0x00FF_FFFF → big-endian low 3 bytes = [0xFF, 0xFF, 0xFF]
        assert_eq!(bytes[7..10], [0xFF, 0xFF, 0xFF]);
        assert_eq!(NackFeedback::decode(&bytes), Ok(fb));
    }

    proptest! {
        #[test]
        fn roundtrip_proptest(
            report_type in any::<u8>(),
            ssrc in any::<u32>(),
            highest_seq in any::<u16>(),
            cumulative_lost in 0u32..=MAX_CUMULATIVE_LOST,
            fraction_lost in any::<u8>(),
            jitter_us in any::<u32>(),
            rtt_us in any::<u32>(),
            bwe_kbps in any::<u32>(),
            nack_bitmap in any::<u16>(),
        ) {
            let fb = NackFeedback {
                report_type,
                ssrc,
                highest_seq,
                cumulative_lost,
                fraction_lost,
                jitter_us,
                rtt_us,
                bwe_kbps,
                nack_bitmap,
            };
            let bytes = fb.encode().unwrap();
            prop_assert_eq!(NackFeedback::decode(&bytes), Ok(fb));
        }

        #[test]
        fn decode_never_panics(data in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = NackFeedback::decode(&data);
        }
    }
}
