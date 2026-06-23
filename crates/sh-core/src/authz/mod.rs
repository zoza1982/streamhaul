//! Authorization layer: sealed capability mask, UGC verification, epoch-floor revocation,
//! and kill-switch (ADR-0010).
//!
//! # Overview
//!
//! This module implements the host-side authorization layer that decides **what an
//! authenticated peer is allowed to do** — separate from and layered on top of the
//! cryptographic authentication established by the Noise handshake (P3-2) and the
//! per-channel AEAD session (P3-4).
//!
//! # Architecture
//!
//! - **[`Capabilities`]** — a `bitflags` `u32` set of actions a peer may perform.
//! - **[`Ugc`]** — Unattended Grant Certificate: a host-signed, grantee-bound,
//!   time-limited, epoch-versioned bearer token for unattended sessions.
//! - **[`SessionAuthorizer`]** — the sealed, host-authoritative gate: created once at
//!   session start, consulted on every privileged action, irreversibly killed by
//!   [`SessionAuthorizer::kill`].
//! - **[`MinEpochStore`]** — a monotonic revocation floor; bumping it revokes all
//!   sub-epoch UGCs offline, without network.
//!
//! # Security properties
//!
//! - The sealed mask has no widen API: any source can only REMOVE capabilities.
//! - UGC grantee binding (constant-time) defeats stolen-UGC replay.
//! - Kill-switch zeroizes session AEAD keys + bumps epoch floor: irreversible
//!   for the session, defeats same-UGC reconnect.
//! - `ELEVATION` requires a [`FreshPresence`] token (default-deny without it).
//! - Never logs secrets; `Denied` carries only public info safe for audit logs.

#![deny(missing_docs)]

pub mod authorizer;
pub mod capabilities;
pub mod epoch;
pub mod ugc;

pub use authorizer::{Denied, FreshPresence, PrivilegedAction, SessionAuthorizer};
pub use capabilities::Capabilities;
pub use epoch::{InMemoryMinEpochStore, MinEpochStore};
pub use ugc::Ugc;
