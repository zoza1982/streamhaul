//! Video and audio codec backends for Streamhaul.
//!
//! Phase 0 ships portable, dependency-light raw codecs:
//! - [`RawEncoder`] / [`RawDecoder`] for video (uncompressed frames with a self-describing header)
//! - [`RawAudioEncoder`] / [`RawAudioDecoder`] for audio (uncompressed PCM with a self-describing header)
//!
//! These let the capture→encode→transport→decode→render slice run and be measured on any machine —
//! including this Linux/Intel dev laptop and headless CI — without GPU or C build tooling.
//!
//! The hardware backends (NVENC / AMD AMF / Intel QSV / Apple VideoToolbox / VA-API for video;
//! WASAPI / Core Audio / PipeWire for audio, see `LLD.md` §5–§6) implement the same `sh_media`
//! traits and land during the on-hardware session.
//!
//! # Deferred
//! - Opus audio encode/decode: blocked on `libopus`/`audiopus` requiring cmake. Add `Codec::Opus`
//!   variant and `RawOpusEncoder`/`RawOpusDecoder` when cmake is available.

mod raw;
mod raw_audio;

pub use raw::{RawDecoder, RawEncoder, RAW_HEADER_LEN};
pub use raw_audio::{RawAudioDecoder, RawAudioEncoder, RAW_AUDIO_HEADER_LEN};
