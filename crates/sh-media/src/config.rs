//! Encoder configuration and capability descriptors.

use sh_protocol::Codec;

use crate::frame::{PixelFormat, Resolution};

/// Configuration for constructing a [`VideoEncoder`](crate::VideoEncoder).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderConfig {
    /// Codec to encode with.
    pub codec: Codec,
    /// Frame resolution.
    pub resolution: Resolution,
    /// Target frame rate (frames per second).
    pub target_fps: u32,
    /// Target bitrate in kbps, or `None` for a constant-quality / lossless mode.
    pub target_bitrate_kbps: Option<u32>,
}

/// What a concrete [`VideoEncoder`](crate::VideoEncoder) backend can do, probed at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderCaps {
    /// Codec this encoder produces.
    pub codec: Codec,
    /// Whether encoding is hardware-accelerated (GPU) rather than software/CPU.
    pub hardware: bool,
    /// Largest resolution this encoder supports.
    pub max_resolution: Resolution,
    /// Pixel formats this encoder accepts as input. **An empty slice means "accepts any format"**
    /// (e.g. the raw codec). The pipeline checks whether the capturer's
    /// [`pixel_format`](crate::ScreenCapturer::pixel_format) is in this list and, if not, inserts
    /// color conversion to the first accepted format (e.g. a BGRA capturer feeding an NV12-only NVENC).
    /// A `&'static [..]` rather than a single format because hardware encoders often accept several.
    pub accepted_input_formats: &'static [PixelFormat],
}

/// What a concrete [`VideoDecoder`](crate::VideoDecoder) backend can do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecoderCaps {
    /// Codec this decoder consumes.
    pub codec: Codec,
    /// Whether decoding is hardware-accelerated.
    pub hardware: bool,
}
