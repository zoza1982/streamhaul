//! Streamhaul Protocol (SHP) wire format.
//!
//! This crate is pure, allocation-light, and does **no I/O**: it turns header structs into byte arrays
//! and parses byte slices back into structs. All multi-byte fields are **big-endian** (network byte
//! order). Decoding treats every input as hostile — it never panics and never indexes out of bounds;
//! malformed input returns [`ProtocolError`]. See `LLD.md` §3.1 for the field layouts.
//!
//! Covers the [`CommonHeader`], [`VideoHeader`], the [`InputEvent`] (P1-2), and control-channel
//! framing ([`encode_control`]/[`decode_control`], P1-2). Audio and feedback message types land with
//! their phases. Each message type lives in its own module; the public surface is re-exported here.

mod bits;
mod common;
mod control;
mod error;
mod input;
mod video;

pub use common::{CommonHeader, Flags};
pub use control::{decode_control, encode_control, ControlFrame, CONTROL_HEADER_LEN};
pub use error::ProtocolError;
pub use input::{EventType, InputEvent, Modifiers};
pub use video::{Codec, FrameType, Priority, VideoHeader};

/// Current SHP protocol version, carried in the top two bits of byte 0 of every packet.
pub const SHP_VERSION: u8 = 0b01;

/// Wire length of the common SHP header, in bytes.
pub const COMMON_HEADER_LEN: usize = 9;

/// Wire length of the video payload header (follows the common header for video packets), in bytes.
pub const VIDEO_HEADER_LEN: usize = 12;

/// Wire length of an SHP input event, in bytes (14 fields + 2 reserved).
pub const INPUT_EVENT_LEN: usize = 16;

/// The largest value a 24-bit on-wire `FRAME_ID` can hold.
pub const MAX_FRAME_ID: u32 = 0x00FF_FFFF;

/// The largest value a 4-bit on-wire `MONITOR_ID` can hold.
pub const MAX_MONITOR_ID: u8 = 0x0F;
