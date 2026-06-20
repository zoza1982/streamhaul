//! Audio encoder and decoder traits.

use crate::audio_codec_type::AudioCodec;
use crate::audio_frame::AudioFrame;
use crate::audio_packet::AudioEncodedPacket;
use crate::error::MediaError;

/// Capabilities of a concrete [`AudioEncoder`] backend, probed at startup.
///
/// This struct is the pipeline seam for sample-rate and channel-count
/// negotiation. Inspect `sample_rate_hz` and `channels` before wiring
/// an encoder to a capturer to determine whether an intermediate resampler
/// or channel-layout converter is needed.
///
/// # Note — no `request_keyframe`
/// Audio encoders intentionally do **not** expose a `request_keyframe`
/// method. Opus (and PCM) have no keyframe concept; error resilience is
/// handled at the packet level by FEC / PLC, not by forcing an intra-refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioEncoderCaps {
    /// Codec this encoder produces.
    pub codec: AudioCodec,
    /// Output sample rate in Hz (e.g. 48 000).
    pub sample_rate_hz: u32,
    /// Number of interleaved output channels (e.g. 1 for mono, 2 for stereo).
    pub channels: u8,
}

/// Capabilities of a concrete [`AudioDecoder`] backend.
///
/// # Note — no `request_keyframe`
/// Audio decoders intentionally do **not** expose a `request_keyframe`
/// method. See [`AudioEncoderCaps`] for the rationale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioDecoderCaps {
    /// Codec this decoder consumes.
    pub codec: AudioCodec,
}

/// Encodes raw [`AudioFrame`]s into [`AudioEncodedPacket`]s.
///
/// Implementations are synchronous and run on a dedicated audio-capture thread.
/// A concrete backend may buffer internally (e.g. Opus works on fixed-size windows),
/// in which case `encode` may return `Ok(None)` and emit a packet on a later call
/// or from [`flush`](Self::flush).
pub trait AudioEncoder: Send {
    /// Submit one frame for encoding.
    ///
    /// Returns `Ok(None)` if the encoder buffered the frame internally without
    /// producing a packet yet. Returns `Ok(Some(_))` when a packet is ready.
    ///
    /// # Errors
    /// Returns [`MediaError::Encode`] on encoder failure, or
    /// [`MediaError::FrameSize`] if the frame's buffer is inconsistent with its
    /// declared format.
    fn encode(&mut self, frame: &AudioFrame) -> Result<Option<AudioEncodedPacket>, MediaError>;

    /// Drain any internally buffered packets. Call once before dropping the encoder
    /// so pipelined encoders (e.g. a future Opus backend) do not drop tail packets.
    ///
    /// The default implementation returns an empty `Vec` (non-buffering encoder).
    ///
    /// # Errors
    /// Returns [`MediaError::Encode`] if the encoder fails while flushing.
    fn flush(&mut self) -> Result<Vec<AudioEncodedPacket>, MediaError> {
        Ok(Vec::new())
    }

    /// This encoder's capabilities.
    fn caps(&self) -> AudioEncoderCaps;
}

/// Decodes [`AudioEncodedPacket`]s back into raw [`AudioFrame`]s.
///
/// Implementations are synchronous and run on a dedicated audio-decode thread.
pub trait AudioDecoder: Send {
    /// Decode one packet.
    ///
    /// Returns `Ok(None)` if the decoder needs more input before it can emit a
    /// frame (e.g. an Opus decoder that pre-buffers for PLC).
    ///
    /// # Errors
    /// Returns [`MediaError::Decode`] if the packet is malformed or the decoder
    /// fails. Implementations must never panic on malformed input.
    fn decode(&mut self, packet: &AudioEncodedPacket) -> Result<Option<AudioFrame>, MediaError>;

    /// Drain any internally buffered frames. Call once before dropping the decoder
    /// so a buffering decoder does not drop its last pending output.
    ///
    /// The default implementation returns an empty `Vec` (non-buffering decoder).
    ///
    /// # Errors
    /// Returns [`MediaError::Decode`] if the decoder fails while flushing.
    fn flush(&mut self) -> Result<Vec<AudioFrame>, MediaError> {
        Ok(Vec::new())
    }

    /// This decoder's capabilities.
    fn caps(&self) -> AudioDecoderCaps;
}
