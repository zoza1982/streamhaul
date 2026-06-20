//! Video codec backends for Streamhaul.
//!
//! Phase 0 ships a single portable, dependency-light [`RawEncoder`] / [`RawDecoder`] (uncompressed
//! frames with a self-describing header) so the capture→encode→transport→decode→render slice runs and
//! is measured on any machine — including this Linux/Intel dev laptop and headless CI — without GPU or
//! C build tooling. The hardware backends (NVENC / AMD AMF / Intel QSV / Apple VideoToolbox / VA-API,
//! see `LLD.md` §5) implement the same `sh_media` traits and land during the on-hardware session.

mod raw;

pub use raw::{RawDecoder, RawEncoder, RAW_HEADER_LEN};
