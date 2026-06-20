//! `sh-core` — the umbrella facade that composes protocol, transport, media, adaptive, and crypto into
//! the `Session` / `HostEngine` / `ClientEngine` state machines (see `LLD.md` §1).
//!
//! Scaffold stub: the engine is wired up starting in Phase 0 task **P0-9**. For now it only re-exports
//! the shared primitive types so downstream crates have a single import surface.

/// Shared primitive types, re-exported so downstream code can reach them as `sh_core::sh_types::*`
/// without taking a separate direct dependency.
pub use sh_types;
