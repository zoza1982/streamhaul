//! `sh-core` — umbrella facade composing the Streamhaul engine.
//!
//! Re-exports the pipeline, packetization, and harness APIs for Phase-0 latency measurement.

pub mod packetize;
pub mod pipeline;

#[cfg(feature = "harness")]
pub mod harness;

pub use sh_types;

#[cfg(feature = "harness")]
pub use harness::{
    run_loopback_harness, FrameMeasurement, HarnessError, HarnessParams, HarnessReport,
};
pub use packetize::{fragment, PacketizeError, Reassembler};
pub use pipeline::{run_client_pipeline, run_host_pipeline, HostPipelineParams, PipelineError};
