//! `sh-core` — umbrella facade composing the Streamhaul engine.
#![deny(missing_docs)]
//!
//! Re-exports the pipeline, packetization, and harness APIs for Phase-0/Phase-1 latency
//! measurement. The `harness` feature gates the two latency harnesses:
//!
//! - [`run_loopback_harness`] — Phase-0 video one-way latency (unreliable datagrams).
//! - [`run_input_rtt_harness`] — Phase-1 input round-trip latency (reliable Input channel).
//!
//! Phase-4 adds:
//! - [`session`] — P4-6 transport capability negotiation and [`SessionEstablisher`].

pub mod authz;
pub mod packetize;
pub mod pipeline;
pub mod session;

pub use authz::{
    Capabilities, Denied, FreshPresence, InMemoryMinEpochStore, MinEpochStore, PrivilegedAction,
    SessionAuthorizer, Ugc,
};

#[cfg(feature = "harness")]
pub mod harness;

#[cfg(feature = "harness")]
pub mod input_harness;

#[cfg(feature = "harness")]
pub(crate) mod stats;

pub use sh_types;

#[cfg(feature = "harness")]
pub use harness::{
    run_loopback_harness, FrameMeasurement, HarnessError, HarnessParams, HarnessReport,
};
#[cfg(feature = "harness")]
pub use input_harness::{
    run_input_rtt_harness, InputEventMeasurement, InputRttError, InputRttParams, InputRttReport,
};
pub use packetize::{fragment, PacketizeError, Reassembler};
pub use pipeline::{run_client_pipeline, run_host_pipeline, HostPipelineParams, PipelineError};
pub use session::{
    IcePathOutcome, SessionError, SessionEstablisher, SignalingChannel, TransportFactory,
};
