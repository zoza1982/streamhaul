//! Wall-clock abstraction for `sh-crypto`.
//!
//! The [`Clock`] trait, [`SystemClock`], and [`FixedClock`] live in [`sh_types`] so that
//! crates like `sh-transport` (P3-4 rekey timers) can inject wall-clock time without pulling in
//! the full `sh-crypto` / `snow` dependency tree. This module re-exports them for ergonomics.
//!
//! All time-sensitive code in `sh-crypto` (BindCert validity, handshake timeouts) must
//! call [`Clock::now_unix_secs`] rather than [`std::time::SystemTime::now`]. This
//! allows tests to use a fixed or advancing mock clock without OS calls.

pub use sh_types::{Clock, FixedClock, SystemClock};
