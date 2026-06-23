//! `sh-ice` — ICE/STUN/TURN orchestration and P2P-vs-relay path selection.
//!
//! This crate implements the ICE protocol (RFC 8445) subset required for Streamhaul's
//! peer-to-peer remote desktop connectivity.  It handles:
//!
//! - **STUN codec** (RFC 8489): `Binding` request/response, `MESSAGE-INTEGRITY`
//!   (HMAC-SHA1), `FINGERPRINT` (CRC32 XOR `0x5354554E`), and all ICE-relevant
//!   attributes.
//! - **Candidate model** (RFC 8445): host, server-reflexive, and relay candidates;
//!   priority computation; candidate-pair formation and ordering.
//! - **ICE agent state machine**: `New → Gathering → Checking → Connected`,
//!   with restart (`Failed → Restarting → New`) on timeout.
//! - **Relay steering**: probe scoring and TURN credential generation (coturn REST API).
//! - **NAT simulator**: an in-process network fabric with Full Cone, Restricted Cone,
//!   Port-Restricted, and Symmetric NAT models for hermetic integration tests.
//!
//! - **TURN client** (RFC 8656, P4-3): `TurnMessage` codec (Allocate/Refresh/
//!   CreatePermission/ChannelBind/Send/Data), long-term credential authentication
//!   (RFC 8489 §9.2), ChannelData framing, and a simulated TURN server for hermetic
//!   relay tests.
//!
//! # Feature completeness
//!
//! P4-3 ships the TURN client codec and state machine with full in-sim test coverage.
//! Items deferred (R-COTURN-DEPLOY):
//! - Live coturn server deployment and REST credential endpoint integration.
//! - TURNS-on-443 configuration and TLS wrapping.
//! - ICE agent relay candidate gathering wired to a real TURN server.
//! - Live NAT traversal on real internet paths.
//!
//! # Security
//!
//! All untrusted wire input enters through [`stun::StunMessage::decode`] or
//! [`turn::TurnMessage::decode`], both of which bounds-check every field before
//! reading.  Fuzz targets:
//! - `crates/sh-ice/fuzz/fuzz_targets/stun_decode.rs` — STUN codec.
//! - `crates/sh-ice/fuzz/fuzz_targets/turn_decode.rs` — TURN codec + ChannelData.

#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod agent;
pub mod candidate;
pub mod error;
pub mod steering;
pub mod stun;
pub mod transport;
pub mod turn;

pub use error::IceError;
