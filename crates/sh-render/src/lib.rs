//! `sh-render` — client presentation pipeline (wgpu swapchain, deferred to on-hardware session).
//!
//! Frame-sink abstractions have moved to `sh-media`. The real `wgpu`-backed present sink
//! will be implemented here once GPU hardware is available (deferred past P0).
//!
//! Re-exports [`sh_media::FrameSink`] and friends for backward compatibility.
pub use sh_media::{CollectingSink, FrameSink, NullSink, RenderError};
