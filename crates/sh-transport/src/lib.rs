//! `sh-transport` — Minimal QUIC datagram transport for Streamhaul.
//!
//! Provides [`ServerEndpoint`] and [`ClientEndpoint`] for accepting and
//! establishing QUIC connections, and a [`Connection`] wrapper that exposes
//! unreliable datagram send/receive via quinn.
//!
//! The optional `insecure-lan` feature enables [`self_signed_server_config`]
//! and [`insecure_client_config`] helpers that skip TLS verification. These
//! are **LAN lab only** and must never be used in production.

// CLAUDE.md §6: library crates must deny missing_docs and document all public items.
#![deny(missing_docs)]

// Hard guard: the LAN-lab insecure TLS path skips certificate verification and must NEVER be compiled
// into an optimized/release artifact. `debug_assertions` is on in dev/test builds and off under
// `--release`, so this turns `cargo build --release --features insecure-lan` into a compile error
// while still allowing the lab and tests in debug builds. (See `insecure.rs`; removed entirely at P4.)
#[cfg(all(feature = "insecure-lan", not(debug_assertions)))]
compile_error!(
    "sh-transport: the `insecure-lan` feature skips TLS verification and must never be enabled in a \
     release build — it is for LAN-lab/debug use only."
);

mod connection;
mod endpoint;
mod error;

#[cfg(feature = "insecure-lan")]
mod insecure;

pub mod channel;
pub mod driver;
pub mod quic_binding;
pub mod webrtc;

pub use channel::{Channel, ChannelSpec, QuicTransport, Reliability, Transport, MAX_FRAME_LEN};
pub use connection::Connection;
pub use driver::{
    spawn_webrtc_driver, AsyncUdpSocket, DriverHandle, SimNetwork, SimUdpSocket, TokioUdpSocket,
};
pub use endpoint::{ClientEndpoint, ServerEndpoint};
pub use error::TransportError;
pub use webrtc::{
    PinnedWebRtcTransport, SdpBridgeBuilder, SdpBridgeError, SdpBridgeResult, WebRtcChannel,
    WebRtcTransportBuilder,
};
// Re-export the str0m fingerprint type so callers of SdpBridgeResult do not need a direct
// str0m dependency to name `local_dtls_fingerprint` or `remote_dtls_fingerprint`.
pub use str0m::crypto::Fingerprint as DtlsFingerprint;

#[cfg(feature = "insecure-lan")]
pub use insecure::{
    insecure_client_config, lan_lab_transport_config, self_signed_server_config, InsecureLanLab,
};
