//! Video and audio codec backends for Streamhaul.
//!
//! Phase 0 ships portable, dependency-light raw codecs:
//! - [`RawEncoder`] / [`RawDecoder`] for video (uncompressed frames with a self-describing header)
//! - [`RawAudioEncoder`] / [`RawAudioDecoder`] for audio (uncompressed PCM with a self-describing header)
//!
//! These let the capture→encode→transport→decode→render slice run and be measured on any machine —
//! including this Linux/Intel dev laptop and headless CI — without GPU or C build tooling.
//!
//! Phase 2 (P2-4) adds the **glitch-free double-buffered encoder mode switch** ([`mode_switch`]):
//! - [`mode_switch::SessionLimiter`] — NVENC session-slot guard (tracks live encoder count, default max 4)
//! - [`mode_switch::DoubleBufferedEncoder`] — atomic prime→swap→drain→destroy encoder switcher
//! - [`mode_switch::BackpressurePolicy`] — per-[`ContentMode`](sh_adaptive::classifier::ContentMode)
//!   frame-drop policy (Game/Scrolling → drop-oldest; Work → skip-current)
//! - [`mode_switch::EncoderFactory`] — `FnMut` seam so NVENC slots in without changing any
//!   switcher code
//!
//! The hardware backends (NVENC / AMD AMF / Intel QSV / Apple VideoToolbox / VA-API for video;
//! WASAPI / Core Audio / PipeWire for audio, see `LLD.md` §5–§6) implement the same `sh_media`
//! traits and land during the on-hardware session.
//!
//! # Deferred
//! - Opus audio encode/decode: blocked on `libopus`/`audiopus` requiring cmake. Add `AudioCodec::Opus`
//!   variant and `RawOpusEncoder`/`RawOpusDecoder` when cmake is available.
//! - Real NVENC 4:2:0 ↔ 4:4:4 hardware reconfigure: the double-buffer orchestration is portable and
//!   fully tested against [`RawEncoder`]; the real NVENC pixel-format switch lands in the on-hardware
//!   session (see Risk Register R6 in `IMPLEMENTATION_PLAN.md`).

pub mod mode_switch;
mod raw;
mod raw_audio;

pub use raw::{RawDecoder, RawEncoder, RAW_HEADER_LEN};
pub use raw_audio::{RawAudioDecoder, RawAudioEncoder, RAW_AUDIO_HEADER_LEN};
