//! Epoch-floor revocation: [`MinEpochStore`] trait and [`InMemoryMinEpochStore`].
//!
//! The epoch floor is a host-local monotonic `u64`. A UGC whose `epoch < min_epoch` is
//! immediately revoked with zero network and zero round-trips. Bumping the floor works
//! offline and survives restart when backed by a durable store.
//!
//! # Durability note (R-EPOCH-PERSIST)
//!
//! [`InMemoryMinEpochStore`] is the portable P3-5 implementation: in-memory only.
//! A UGC's point is unattended access across reboots; a production deployment MUST wire a
//! durable atomic backend (platform config file / OS keystore metadata) before relying on
//! epoch-floor revocation surviving a restart. That backend is a deferred follow-up
//! (R-EPOCH-PERSIST). Until then, callers should treat the in-memory floor as session-scoped
//! only.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// A monotonic floor for UGC epoch revocation.
///
/// A UGC whose `epoch < store.current()` is immediately revoked — no network needed.
/// The floor is **monotonic**: `bump` only ever increases it, so a replayed "un-revoke"
/// message cannot roll it back.
///
/// # Thread safety
///
/// Implementations must be `Send + Sync + 'static` — the store is shared across
/// the session and may be bumped by a kill-switch while another task is verifying a UGC.
pub trait MinEpochStore: Send + Sync + 'static {
    /// Returns the current minimum-epoch floor.
    ///
    /// A UGC with `epoch < current()` fails verification step 5 (`UgcRevoked`).
    fn current(&self) -> u64;

    /// Monotonically raises the floor to `max(current(), new_floor)`.
    ///
    /// Returns the new (possibly unchanged) floor.
    ///
    /// # Panics
    ///
    /// Never panics.
    fn bump(&self, new_floor: u64) -> u64;

    /// Bumps the floor by one: `bump(current() + 1)`.
    ///
    /// Revokes all UGCs at or below the current epoch. Used by the kill-switch.
    ///
    /// # Concurrency note
    ///
    /// This default implementation is **not atomic** across the `current()` read and the
    /// `bump()` write. Between the two calls, another thread may already have raised the
    /// floor. Because `bump` uses `fetch_max`, the floor can never go backward, but two
    /// concurrent `bump_min_epoch` calls may result in the floor advancing by only +1
    /// rather than +2 (if both read the same `current()` before either writes). For the
    /// kill-switch use case (at most one kill call per session) this is safe in practice.
    /// Implementations that require strict +1 per-call atomicity must override this method
    /// with a dedicated atomic `fetch_add` backed by their store.
    ///
    /// # Panics
    ///
    /// Never panics.
    fn bump_min_epoch(&self) -> u64 {
        let cur = self.current();
        self.bump(cur.saturating_add(1))
    }
}

/// An in-memory [`MinEpochStore`] backed by an [`AtomicU64`].
///
/// **Not durable**: the floor is lost on process restart. See the module-level documentation
/// (R-EPOCH-PERSIST) for the follow-up that will wire a persistent backend.
///
/// # Examples
///
/// ```
/// use sh_core::authz::{InMemoryMinEpochStore, MinEpochStore};
///
/// let store = InMemoryMinEpochStore::new(0);
/// assert_eq!(store.current(), 0);
/// store.bump(5);
/// assert_eq!(store.current(), 5);
/// // bump is monotonic — going backward is a no-op:
/// store.bump(3);
/// assert_eq!(store.current(), 5);
/// store.bump_min_epoch();
/// assert_eq!(store.current(), 6);
/// ```
#[derive(Debug, Clone)]
pub struct InMemoryMinEpochStore {
    floor: Arc<AtomicU64>,
}

impl InMemoryMinEpochStore {
    /// Creates a new store with an initial floor of `initial`.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_core::authz::InMemoryMinEpochStore;
    ///
    /// let store = InMemoryMinEpochStore::new(0);
    /// ```
    pub fn new(initial: u64) -> Self {
        Self {
            floor: Arc::new(AtomicU64::new(initial)),
        }
    }
}

impl MinEpochStore for InMemoryMinEpochStore {
    fn current(&self) -> u64 {
        self.floor.load(Ordering::SeqCst)
    }

    fn bump(&self, new_floor: u64) -> u64 {
        // fetch_max returns the OLD value; we return the new effective floor.
        let old = self.floor.fetch_max(new_floor, Ordering::SeqCst);
        old.max(new_floor)
    }
}
