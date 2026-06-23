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
//! # Feature completeness
//!
//! P4-2 ships a synchronous, test-driven implementation.  Items deferred to P4-3:
//! - Live STUN/TURN server communication.
//! - TURN Allocate / Refresh / CreatePermission / ChannelBind message sequences.
//! - Coturn deployment and REST credential endpoint integration.
//! - Live NAT traversal on real internet paths.
//!
//! # Security
//!
//! All untrusted wire input enters only through [`stun::StunMessage::decode`], which
//! bounds-checks every field before reading.  The fuzz target
//! `crates/sh-ice/fuzz/fuzz_targets/stun_decode.rs` exercises this path with
//! libFuzzer.

#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod agent;
pub mod candidate;
pub mod error;
pub mod steering;
pub mod stun;
pub mod transport;

pub use error::IceError;
