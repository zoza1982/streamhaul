//! Audio encoder and decoder traits.

use sh_protocol::Codec;

use crate::audio_frame::AudioFrame;
use crate::audio_packet::AudioEncodedPacket;
use crate::error::MediaError;

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

    /// Drain any internally buffered packet. Call once before dropping the encoder
    /// so pipelined encoders do not drop their last pending output.
    ///
    /// # Errors
    /// Returns [`MediaError::Encode`] if the encoder fails while flushing.
    fn flush(&mut self) -> Result<Option<AudioEncodedPacket>, MediaError>;

    /// The codec this encoder produces.
    fn codec(&self) -> Codec;
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

    /// Drain any internally buffered frame. Call once before dropping the decoder
    /// so a buffering decoder does not drop its last pending output.
    ///
    /// # Errors
    /// Returns [`MediaError::Decode`] if the decoder fails while flushing.
    fn flush(&mut self) -> Result<Option<AudioFrame>, MediaError>;

    /// The codec this decoder consumes.
    fn codec(&self) -> Codec;
}
