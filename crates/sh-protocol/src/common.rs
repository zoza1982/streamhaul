//! The 9-byte common header that prefixes every SHP packet on every channel (`LLD.md` §3.1).

use sh_types::{ChannelId, TimestampUs};

use crate::bits::{bitpack, take_array};
use crate::error::ProtocolError;
use crate::{COMMON_HEADER_LEN, SHP_VERSION};

/// The two SHP flag bits in byte 0 of the common header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags {
    /// Set when this packet is a fragment of a larger payload.
    pub fragment: bool,
    /// Set on the final fragment of a fragmented payload.
    pub last_fragment: bool,
}

/// The 9-byte common header that prefixes every SHP packet.
///
/// Layout (big-endian): byte 0 = `VER(2) | CHANNEL(4) | FLAGS(2)`; bytes 1–2 `SEQUENCE`; bytes 3–6
/// `TIMESTAMP`; bytes 7–8 `PAYLOAD_LEN`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommonHeader {
    /// Which logical channel this packet belongs to.
    pub channel: ChannelId,
    /// Fragmentation flags.
    pub flags: Flags,
    /// Per-channel sequence number (wraps at 2^16).
    pub sequence: u16,
    /// Microseconds since the session epoch (monotonic). Only the low 32 bits travel on the wire and
    /// wrap at 2^32 µs (~71 min); higher bits are dropped by [`CommonHeader::encode`].
    pub timestamp_us: TimestampUs,
    /// Length in bytes of the payload following this header.
    pub payload_len: u16,
}

impl CommonHeader {
    /// Serialize the header to its fixed 9-byte big-endian wire form.
    ///
    /// The timestamp is narrowed to its low 32 bits (see [`CommonHeader::timestamp_us`]); all other
    /// fields fit their wire widths exactly, so this cannot fail.
    ///
    /// # Examples
    /// ```
    /// use sh_protocol::{CommonHeader, Flags};
    /// use sh_types::{ChannelId, TimestampUs};
    ///
    /// let h = CommonHeader {
    ///     channel: ChannelId::Input,
    ///     flags: Flags { fragment: true, last_fragment: false },
    ///     sequence: 0x0102,
    ///     timestamp_us: TimestampUs(0x0304_0506),
    ///     payload_len: 0x0708,
    /// };
    /// let bytes = h.encode();
    /// assert_eq!(bytes[0], 0x4A); // VER=01, CHANNEL=Input(2), FLAGS=fragment
    /// assert_eq!(CommonHeader::decode(&bytes), Ok(h));
    /// ```
    #[must_use]
    pub fn encode(&self) -> [u8; COMMON_HEADER_LEN] {
        let flags_bits = bitpack(&[
            (u8::from(self.flags.fragment), 1),
            (u8::from(self.flags.last_fragment), 0),
        ]);
        // byte 0: VER(2) | CHANNEL(4) | FLAGS(2)
        let byte0 = bitpack(&[
            (SHP_VERSION, 6),
            (channel_to_bits(self.channel), 2),
            (flags_bits, 0),
        ]);
        let [s0, s1] = self.sequence.to_be_bytes();
        // Keep only the low 32 bits of the timestamp (wire field is 32-bit).
        let [_, _, _, _, t0, t1, t2, t3] = self.timestamp_us.0.to_be_bytes();
        let [l0, l1] = self.payload_len.to_be_bytes();
        [byte0, s0, s1, t0, t1, t2, t3, l0, l1]
    }

    /// Parse a common header from the start of `data`. Never panics; rejects malformed input.
    ///
    /// # Errors
    /// - [`ProtocolError::Truncated`] if `data` is shorter than [`COMMON_HEADER_LEN`].
    /// - [`ProtocolError::UnsupportedVersion`] if the version bits are not [`SHP_VERSION`].
    /// - [`ProtocolError::InvalidChannel`] if the channel bits do not map to a [`ChannelId`].
    ///
    /// # Examples
    /// ```
    /// use sh_protocol::{CommonHeader, ProtocolError};
    /// assert!(matches!(
    ///     CommonHeader::decode(&[0u8; 4]),
    ///     Err(ProtocolError::Truncated { needed: 9, have: 4 })
    /// ));
    /// ```
    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        let [byte0, s0, s1, t0, t1, t2, t3, l0, l1] = take_array::<COMMON_HEADER_LEN>(data)?;
        let version = byte0 >> 6;
        if version != SHP_VERSION {
            return Err(ProtocolError::UnsupportedVersion(version));
        }
        let channel = channel_from_bits((byte0 >> 2) & 0x0F)?;
        let flags = Flags {
            fragment: (byte0 & 0b10) != 0,
            last_fragment: (byte0 & 0b01) != 0,
        };
        Ok(Self {
            channel,
            flags,
            sequence: u16::from_be_bytes([s0, s1]),
            timestamp_us: TimestampUs(u64::from(u32::from_be_bytes([t0, t1, t2, t3]))),
            payload_len: u16::from_be_bytes([l0, l1]),
        })
    }
}

fn channel_to_bits(channel: ChannelId) -> u8 {
    match channel {
        ChannelId::Video => 0,
        ChannelId::Audio => 1,
        ChannelId::Input => 2,
        ChannelId::Clipboard => 3,
        ChannelId::File => 4,
        ChannelId::Control => 5,
    }
}

fn channel_from_bits(bits: u8) -> Result<ChannelId, ProtocolError> {
    match bits {
        0 => Ok(ChannelId::Video),
        1 => Ok(ChannelId::Audio),
        2 => Ok(ChannelId::Input),
        3 => Ok(ChannelId::Clipboard),
        4 => Ok(ChannelId::File),
        5 => Ok(ChannelId::Control),
        other => Err(ProtocolError::InvalidChannel(other)),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn known_layout_roundtrips() {
        let h = CommonHeader {
            channel: ChannelId::Input,
            flags: Flags {
                fragment: true,
                last_fragment: false,
            },
            sequence: 0x0102,
            timestamp_us: TimestampUs(0x0304_0506),
            payload_len: 0x0708,
        };
        // VER=01, CHANNEL=0010(Input), FLAGS=10 => 0b0100_1010 = 0x4A
        assert_eq!(
            h.encode(),
            [0x4A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
        assert_eq!(CommonHeader::decode(&h.encode()), Ok(h));
    }

    #[test]
    fn every_channel_roundtrips() {
        for channel in [
            ChannelId::Video,
            ChannelId::Audio,
            ChannelId::Input,
            ChannelId::Clipboard,
            ChannelId::File,
            ChannelId::Control,
        ] {
            let h = CommonHeader {
                channel,
                flags: Flags::default(),
                sequence: 0,
                timestamp_us: TimestampUs(0),
                payload_len: 0,
            };
            assert_eq!(CommonHeader::decode(&h.encode()), Ok(h));
        }
    }

    #[test]
    fn timestamp_high_bits_are_dropped() {
        let h = CommonHeader {
            channel: ChannelId::Video,
            flags: Flags::default(),
            sequence: 0,
            timestamp_us: TimestampUs(0xABCD_0000_0000_0001),
            payload_len: 0,
        };
        // Only the low 32 bits survive the wire round-trip.
        let decoded = CommonHeader::decode(&h.encode()).unwrap();
        assert_eq!(decoded.timestamp_us, TimestampUs(1));
    }

    #[test]
    fn rejects_truncation() {
        assert_eq!(
            CommonHeader::decode(&[0u8; 8]),
            Err(ProtocolError::Truncated { needed: 9, have: 8 })
        );
    }

    #[test]
    fn rejects_bad_version() {
        // version bits 11 (0xC0) != SHP_VERSION (01)
        assert_eq!(
            CommonHeader::decode(&[0xC0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(ProtocolError::UnsupportedVersion(0b11))
        );
    }

    #[test]
    fn rejects_unknown_channel() {
        // VER=01, CHANNEL=1111(15), FLAGS=00 => 0b0111_1100 = 0x7C
        assert_eq!(
            CommonHeader::decode(&[0x7C, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(ProtocolError::InvalidChannel(15))
        );
    }

    fn arb_channel() -> impl Strategy<Value = ChannelId> {
        prop_oneof![
            Just(ChannelId::Video),
            Just(ChannelId::Audio),
            Just(ChannelId::Input),
            Just(ChannelId::Clipboard),
            Just(ChannelId::File),
            Just(ChannelId::Control),
        ]
    }

    proptest! {
        #[test]
        fn roundtrips(
            channel in arb_channel(),
            fragment in any::<bool>(),
            last_fragment in any::<bool>(),
            sequence in any::<u16>(),
            timestamp in any::<u32>(),
            payload_len in any::<u16>(),
        ) {
            let h = CommonHeader {
                channel,
                flags: Flags { fragment, last_fragment },
                sequence,
                timestamp_us: TimestampUs(u64::from(timestamp)),
                payload_len,
            };
            prop_assert_eq!(CommonHeader::decode(&h.encode()), Ok(h));
        }

        #[test]
        fn decode_never_panics(data in proptest::collection::vec(any::<u8>(), 0..32)) {
            let _ = CommonHeader::decode(&data);
        }
    }
}
