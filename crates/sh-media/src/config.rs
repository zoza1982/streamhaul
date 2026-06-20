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
    /// Pixel format this encoder requires as input, or `None` if it accepts any format. The pipeline
    /// compares `Some(fmt)` against the capturer's [`pixel_format`](crate::ScreenCapturer::pixel_format)
    /// and inserts color conversion if they differ (e.g. NVENC needs NV12 while a BGRA capturer feeds
    /// it); `None` (e.g. the raw codec) means no conversion is ever needed.
    pub required_input_format: Option<PixelFormat>,
}

/// What a concrete [`VideoDecoder`](crate::VideoDecoder) backend can do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecoderCaps {
    /// Codec this decoder consumes.
    pub codec: Codec,
    /// Whether decoding is hardware-accelerated.
    pub hardware: bool,
}
