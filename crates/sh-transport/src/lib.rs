//! `sh-transport` — Minimal QUIC datagram transport for Streamhaul.
//!
//! Provides [`ServerEndpoint`] and [`ClientEndpoint`] for accepting and
//! establishing QUIC connections, and a [`Connection`] wrapper that exposes
//! unreliable datagram send/receive via quinn.
//!
//! The optional `insecure-lan` feature enables [`self_signed_server_config`]
//! and [`insecure_client_config`] helpers that skip TLS verification. These
//! are **LAN lab only** and must never be used in production.

mod connection;
mod endpoint;
mod error;

#[cfg(feature = "insecure-lan")]
mod insecure;

pub use connection::Connection;
pub use endpoint::{ClientEndpoint, ServerEndpoint};
pub use error::TransportError;

#[cfg(feature = "insecure-lan")]
pub use insecure::{insecure_client_config, self_signed_server_config};
