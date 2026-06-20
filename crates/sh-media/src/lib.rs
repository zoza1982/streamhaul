//! Codec-agnostic media traits and types for Streamhaul.
//!
//! This crate defines the seams the capture/encode/decode pipeline is built from — [`ScreenCapturer`],
//! [`VideoEncoder`], [`VideoDecoder`], [`AudioEncoder`], [`AudioDecoder`] — plus the shared
//! [`VideoFrame`] / [`EncodedPacket`] / [`AudioFrame`] / [`AudioEncodedPacket`] types
//! (see `LLD.md` §2, §5, §6). Concrete hardware backends (DXGI capture, NVENC/QSV/VideoToolbox encode,
//! WASAPI/ALSA capture) live in `sh-codec-hw` / `sh-platform-*` and implement these traits.
//!
//! The traits are **synchronous**: capture and encode run on dedicated real-time threads, not on the
//! async runtime (`LLD.md` §1). Portable synthetic sources ([`SyntheticCapturer`],
//! [`SyntheticAudioSource`]) are provided so the Phase-0 pipeline can run and be measured on any
//! machine (including headless CI) without capture hardware.
//!
//! The [`avsync`] module provides the [`AvSync`] controller for aligning audio and video playout
//! times from their shared capture clock (`LLD.md` §6.6).

mod audio_codec;
mod audio_codec_type;
mod audio_frame;
mod audio_packet;
pub mod avsync;
mod config;
mod error;
mod frame;
mod packet;
pub mod sink;
mod synthetic;
mod synthetic_audio;

use std::time::Duration;

pub use audio_codec::{AudioDecoder, AudioDecoderCaps, AudioEncoder, AudioEncoderCaps};
pub use audio_codec_type::AudioCodec;
pub use audio_frame::AudioFrame;
pub use audio_packet::AudioEncodedPacket;
pub use avsync::{AvSync, MonotonicClock};
pub use config::{DecoderCaps, EncoderCaps, EncoderConfig};
pub use error::MediaError;
pub use frame::{PixelFormat, Resolution, VideoFrame};
pub use packet::EncodedPacket;
pub use sink::{CollectingSink, FrameSink, NullSink, RenderError};
pub use synthetic::SyntheticCapturer;
pub use synthetic_audio::{
    SyntheticAudioSource, DEFAULT_CHANNELS, DEFAULT_FRAME_DURATION_US, DEFAULT_SAMPLE_RATE,
};

/// A source of raw video frames (a screen/window/display, or a synthetic generator).
///
/// Implementations run on a dedicated capture thread and are polled by the pipeline.
pub trait ScreenCapturer: Send {
    /// Block up to `timeout` for the next frame.
    ///
    /// Returns `Ok(Some(frame))` when a frame is available, `Ok(None)` if `timeout` elapsed with no
    /// new frame (e.g. the screen did not change).
    ///
    /// # Errors
    /// Returns [`MediaError::Capture`] if the capture backend fails irrecoverably.
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<VideoFrame>, MediaError>;

    /// The resolution this capturer currently produces.
    fn resolution(&self) -> Resolution;

    /// The pixel format this capturer produces.
    fn pixel_format(&self) -> PixelFormat;
}

/// Encodes raw [`VideoFrame`]s into [`EncodedPacket`]s.
pub trait VideoEncoder: Send {
    /// Submit one frame for encoding.
    ///
    /// Returns `Ok(None)` if the encoder buffered the frame internally — hardware encoders (NVENC,
    /// VideoToolbox, VAAPI) pipeline several frames, so a packet may emerge on a later call or from
    /// [`flush`](Self::flush). A purely software encoder typically returns `Ok(Some(_))` every call.
    ///
    /// # Errors
    /// Returns [`MediaError::Encode`] on encoder failure, or [`MediaError::FrameSize`] if the frame's
    /// buffer length is inconsistent with its format and resolution.
    fn encode(&mut self, frame: &VideoFrame) -> Result<Option<EncodedPacket>, MediaError>;

    /// Drain any internally buffered packets. Call once before dropping the encoder so a pipelined
    /// encoder's tail frames are not lost. The default returns nothing (non-buffering encoder).
    ///
    /// # Errors
    /// Returns [`MediaError::Encode`] if the encoder fails while draining.
    fn flush(&mut self) -> Result<Vec<EncodedPacket>, MediaError> {
        Ok(Vec::new())
    }

    /// Request that the next encoded frame be a keyframe (e.g. after packet loss or a new viewer).
    fn request_keyframe(&mut self);

    /// This encoder's capabilities.
    fn caps(&self) -> EncoderCaps;
}

/// Decodes [`EncodedPacket`]s back into raw [`VideoFrame`]s.
pub trait VideoDecoder: Send {
    /// Decode one packet.
    ///
    /// Returns `Ok(None)` if the decoder needs more input before it can emit a frame.
    ///
    /// # Errors
    /// Returns [`MediaError::Decode`] if the packet is malformed or the decoder fails.
    fn decode(&mut self, packet: &EncodedPacket) -> Result<Option<VideoFrame>, MediaError>;

    /// This decoder's capabilities.
    fn caps(&self) -> DecoderCaps;
}
