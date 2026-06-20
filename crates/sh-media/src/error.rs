//! The crate-wide [`MediaError`] type.

use thiserror::Error;

/// Errors produced by capture, encode, and decode operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MediaError {
    /// A screen-capture backend failed to produce a frame.
    #[error("capture failed: {0}")]
    Capture(String),
    /// A video encoder failed.
    #[error("encode failed: {0}")]
    Encode(String),
    /// A video decoder failed (e.g. malformed packet).
    #[error("decode failed: {0}")]
    Decode(String),
    /// A requested codec, format, or resolution is not supported by this backend.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// A frame's buffer length does not match its declared format and resolution.
    #[error("frame size mismatch: expected {expected} bytes, got {got}")]
    FrameSize {
        /// Bytes required by the frame's format and resolution.
        expected: usize,
        /// Bytes actually present in the buffer.
        got: usize,
    },
}
