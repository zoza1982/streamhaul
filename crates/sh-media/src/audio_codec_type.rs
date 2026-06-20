//! Audio-domain codec identifier.
//!
//! Audio and video travel on separate wire channels, so they have separate codec
//! namespaces. [`AudioCodec`] is intentionally distinct from
//! [`sh_protocol::Codec`] (a **video** codec identifier) to prevent semantic
//! confusion between the two domains.

/// Codec identifier for an audio bitstream.
///
/// This enum lives in the audio domain. There is no overlap with
/// [`sh_protocol::Codec`], which identifies video codecs carried on the
/// video channel. Audio and video already flow on separate logical channels,
/// so there is no wire collision, but using a shared type would be semantically
/// misleading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioCodec {
    /// Uncompressed raw PCM — used by the Phase-0 audio pipeline
    /// (`sh-codec-hw::RawAudioEncoder`/`RawAudioDecoder`). Every encoded
    /// packet is independently decodable (no inter-frame state).
    ///
    /// # Deferred
    /// `Opus` will be added as a variant when libopus/audiopus cmake support
    /// is available. Opus frames are **not** independently decodable; the
    /// pipeline must handle packet-loss concealment (PLC) at that point.
    RawPcm,
}
