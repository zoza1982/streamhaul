//! `sh-transport` — Minimal QUIC datagram transport for Streamhaul.
//!
//! Provides [`ServerEndpoint`] and [`ClientEndpoint`] for accepting and
//! establishing QUIC connections, and a [`Connection`] wrapper that exposes
//! unreliable datagram send/receive via quinn.
//!
//! The optional `insecure-lan` feature enables [`self_signed_server_config`]
//! and [`insecure_client_config`] helpers that skip TLS verification. These
//! are **LAN lab only** and must never be used in production.

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

pub use connection::Connection;
pub use endpoint::{ClientEndpoint, ServerEndpoint};
pub use error::TransportError;

#[cfg(feature = "insecure-lan")]
pub use insecure::{insecure_client_config, self_signed_server_config, InsecureLanLab};
