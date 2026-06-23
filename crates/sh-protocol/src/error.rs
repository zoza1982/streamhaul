//! The crate-wide [`ProtocolError`] type.

use thiserror::Error;

/// Errors produced while decoding (or validating before encoding) SHP wire data.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProtocolError {
    /// The input slice is shorter than the header it should contain.
    #[error("truncated: need {needed} bytes, have {have}")]
    Truncated {
        /// Bytes required to parse the header.
        needed: usize,
        /// Bytes actually available.
        have: usize,
    },
    /// The version bits do not match [`crate::SHP_VERSION`].
    #[error("unsupported SHP version: {0:#04b}")]
    UnsupportedVersion(u8),
    /// The channel bits do not map to a known [`sh_types::ChannelId`].
    #[error("invalid channel id: {0}")]
    InvalidChannel(u8),
    /// The codec bits do not map to a known [`crate::Codec`].
    #[error("invalid codec id: {0}")]
    InvalidCodec(u8),
    /// The frame-type bits do not map to a known [`crate::FrameType`].
    #[error("invalid frame type: {0}")]
    InvalidFrameType(u8),
    /// The priority bits do not map to a known [`crate::Priority`].
    #[error("invalid priority: {0}")]
    InvalidPriority(u8),
    /// A reserved field was non-zero (must be zero; rejected to keep the format unambiguous).
    #[error("reserved bits must be zero")]
    ReservedBitsSet,
    /// The event-type byte does not map to a known [`crate::EventType`].
    #[error("invalid input event type: {0}")]
    InvalidEventType(u8),
    /// A control-frame payload exceeds the 16-bit length field.
    #[error("control payload {0} exceeds 16-bit maximum")]
    ControlPayloadTooLarge(usize),
    /// `frame_id` exceeds [`crate::MAX_FRAME_ID`] (does not fit the 24-bit wire field).
    #[error("frame_id {0} exceeds 24-bit maximum")]
    FrameIdTooLarge(u64),
    /// `monitor_id` exceeds [`crate::MAX_MONITOR_ID`] (does not fit the 4-bit wire field).
    #[error("monitor_id {0} exceeds 4-bit maximum")]
    MonitorIdTooLarge(u8),
    /// `cumulative_lost` exceeds [`crate::MAX_CUMULATIVE_LOST`] (does not fit the 24-bit wire field).
    #[error("cumulative_lost {0} exceeds 24-bit maximum")]
    CumulativeLostTooLarge(u32),
    /// The version byte in a framed payload does not match the expected version.
    ///
    /// Returned by [`crate::transport_caps::decode_transport_caps`] when byte 0 is not `0x01`.
    /// The raw byte is preserved so callers can surface a diagnostic ("got 0x02, expected 0x01").
    #[error("unknown version byte: {0:#04x}")]
    UnknownVersion(u8),
}
