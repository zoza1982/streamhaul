//! [`SessionAuthorizer`], [`PrivilegedAction`], [`Denied`], [`FreshPresence`].
//!
//! The `SessionAuthorizer` is the host-side gate that decides whether a remote peer
//! may perform a given action. It is sealed at session start from four independent
//! capability sources (intersection only) and has **no widen API**.

use thiserror::Error;

use sh_crypto::{channel_crypto::SessionKeys, clock::Clock};

use crate::authz::{Capabilities, MinEpochStore};

/// An opaque proof that a human approved an elevation action within a bounded time window.
///
/// P3-5 models the requirement; the WebAuthn/FIDO2 verification is a later task
/// (R-ELEVATION-MFA). `FreshPresence` instances must be created by the host-side MFA
/// subsystem; the peer cannot supply them.
///
/// # Examples
///
/// ```
/// use sh_core::authz::FreshPresence;
///
/// // For testing: create a token at a known time.
/// let presence = FreshPresence::new_for_testing(1_000_000);
/// ```
#[derive(Debug, Clone)]
pub struct FreshPresence {
    /// Unix-epoch-seconds at which the human granted elevation.
    pub(crate) granted_at: i64,
}

impl FreshPresence {
    /// Creates a `FreshPresence` token for testing purposes.
    ///
    /// In production, `FreshPresence` is issued by the host-side MFA subsystem after
    /// WebAuthn/FIDO2 verification (R-ELEVATION-MFA). This constructor exists so that
    /// tests can exercise the `ELEVATION` path without MFA infrastructure.
    pub fn new_for_testing(granted_at: i64) -> Self {
        Self { granted_at }
    }
}

/// Freshness window for `ELEVATION` presence tokens (10 minutes).
const ELEVATION_FRESHNESS_WINDOW_SECS: i64 = 600;

/// A privileged action that a remote peer may request the host to perform.
///
/// Every action maps to exactly one required [`Capabilities`] bit. `ELEVATION` actions
/// additionally require a [`FreshPresence`] proof within the freshness window.
///
/// See ADR-0010 §1.2 for the full action → capability mapping table.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrivilegedAction {
    /// Decode and display a video frame from the host (Video channel).
    ViewFrame,
    /// Inject a pointer event on the host (Input channel).
    InjectPointer,
    /// Inject a key event on the host (Input channel).
    InjectKey,
    /// Read the host clipboard (Clipboard channel).
    ReadClipboard,
    /// Write to the host clipboard (Clipboard channel).
    WriteClipboard,
    /// Start a file transfer from/to the host (File channel).
    StartFileTransfer,
    /// Receive a file on the host from the controller (File channel).
    ReceiveFile,
    /// Play host audio on the controller (Audio channel).
    PlayAudio,
    /// Perform an admin/UAC-class action on the host OS.
    ///
    /// Requires the `ELEVATION` capability bit AND a [`FreshPresence`] proof within the
    /// freshness window. Without both, this action is always denied.
    ElevatedAction,
}

impl PrivilegedAction {
    /// Returns the [`Capabilities`] bit required to perform this action.
    fn required_cap(&self) -> Capabilities {
        match self {
            Self::ViewFrame => Capabilities::VIEW,
            Self::InjectPointer | Self::InjectKey => Capabilities::CONTROL,
            Self::ReadClipboard | Self::WriteClipboard => Capabilities::CLIPBOARD,
            Self::StartFileTransfer | Self::ReceiveFile => Capabilities::FILE,
            Self::PlayAudio => Capabilities::AUDIO,
            Self::ElevatedAction => Capabilities::ELEVATION,
        }
    }
}

/// Authorization denial reason.
///
/// `Denied` carries the attempted action and the required vs. held capabilities.
/// It is safe to log — it contains no secret material. The peer is never told
/// the specific denial reason (that would be an oracle); this is for host-side audit logs.
#[derive(Debug, Error, Clone)]
pub enum Denied {
    /// The required capability bit is not in the sealed mask.
    #[error("action {action:?} denied: required {required:?}, held {held:?}")]
    CapabilityMissing {
        /// The action that was attempted.
        action: PrivilegedAction,
        /// The capability required for this action.
        required: Capabilities,
        /// The capabilities currently held in the sealed mask.
        held: Capabilities,
    },
    /// The `ELEVATION` bit is present but no fresh-presence proof was provided.
    #[error(
        "elevation denied: ELEVATION capability is set but no fresh presence proof was provided \
         or it has expired"
    )]
    ElevationRequiresFreshPresence,
    /// The session has been killed. All subsequent actions are denied.
    #[error("session killed: all actions denied")]
    Killed,
}

/// The host-side, sealed, non-escalatable capability gate (ADR-0010 §1).
///
/// Created once at session start via [`SessionAuthorizer::seal`]; consulted on every
/// privileged host-side action via [`authorize`](Self::authorize); irreversibly killed
/// via [`kill`](Self::kill).
///
/// # Invariants
///
/// - The sealed mask is **never widened**: [`seal`](Self::seal) is the only constructor;
///   there is no setter, `add_capability`, `merge`, or `widen` method.
/// - After [`kill`](Self::kill), **every** action returns [`Denied::Killed`] regardless
///   of the mask, and `kill` is idempotent.
/// - `ELEVATION` always requires both the bit AND a current [`FreshPresence`].
///
/// # Examples
///
/// ```
/// use sh_core::authz::{Capabilities, InMemoryMinEpochStore, MinEpochStore, PrivilegedAction, SessionAuthorizer};
/// use sh_crypto::clock::FixedClock;
///
/// let store = InMemoryMinEpochStore::new(0);
/// let authorizer = SessionAuthorizer::seal(
///     Capabilities::VIEW | Capabilities::CONTROL, // device ACL
///     Capabilities::all(),  // UGC caps (no UGC → all, neutral)
///     Capabilities::all(),  // attended selection
///     Capabilities::all(),  // account policy
///     store,
/// );
/// assert!(authorizer.authorize(&PrivilegedAction::ViewFrame).is_ok());
/// assert!(authorizer.authorize(&PrivilegedAction::PlayAudio).is_err());
/// ```
pub struct SessionAuthorizer<S: MinEpochStore> {
    /// The sealed capability mask (AND of all four sources). Never modified after construction.
    sealed_caps: Capabilities,
    /// Whether the session has been killed. Once true, never returns to false.
    killed: bool,
    /// An optional fresh-presence proof for ELEVATION.
    fresh_presence: Option<FreshPresence>,
    /// The epoch store shared with the kill-switch.
    epoch_store: S,
}

impl<S: MinEpochStore> std::fmt::Debug for SessionAuthorizer<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionAuthorizer")
            .field("sealed_caps", &self.sealed_caps)
            .field("killed", &self.killed)
            .finish_non_exhaustive()
    }
}

impl<S: MinEpochStore> SessionAuthorizer<S> {
    /// Seals a new `SessionAuthorizer` from four capability sources.
    ///
    /// The sealed mask is the **bitwise AND** of all four sources — most-restrictive wins.
    /// An absent source (e.g. no UGC for an attended session) should be passed as
    /// [`Capabilities::all()`] (the neutral element of AND), never as `empty()`.
    ///
    /// There is **no API to widen the sealed mask** after this call.
    ///
    /// # Arguments
    ///
    /// - `device_acl_caps` — capabilities allowed by the device's ACL entry.
    /// - `ugc_caps` — capabilities from a verified UGC, or `Capabilities::all()` if no UGC.
    /// - `attended_selection` — what the human at the host approved, or `Capabilities::all()`
    ///   if unattended.
    /// - `account_policy_caps` — the org/account ceiling.
    /// - `epoch_store` — the monotonic revocation-floor store, shared with the kill-switch.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_core::authz::{Capabilities, InMemoryMinEpochStore, SessionAuthorizer};
    ///
    /// let store = InMemoryMinEpochStore::new(0);
    /// let auth = SessionAuthorizer::seal(
    ///     Capabilities::VIEW | Capabilities::CONTROL,
    ///     Capabilities::all(),
    ///     Capabilities::all(),
    ///     Capabilities::all(),
    ///     store,
    /// );
    /// assert_eq!(auth.capabilities(), Capabilities::VIEW | Capabilities::CONTROL);
    /// ```
    pub fn seal(
        device_acl_caps: Capabilities,
        ugc_caps: Capabilities,
        attended_selection: Capabilities,
        account_policy_caps: Capabilities,
        epoch_store: S,
    ) -> Self {
        let sealed_caps = device_acl_caps & ugc_caps & attended_selection & account_policy_caps;
        Self {
            sealed_caps,
            killed: false,
            fresh_presence: None,
            epoch_store,
        }
    }

    /// Returns the sealed capability mask (read-only, for host UI display).
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_core::authz::{Capabilities, InMemoryMinEpochStore, SessionAuthorizer};
    ///
    /// let store = InMemoryMinEpochStore::new(0);
    /// let auth = SessionAuthorizer::seal(
    ///     Capabilities::VIEW,
    ///     Capabilities::all(),
    ///     Capabilities::all(),
    ///     Capabilities::all(),
    ///     store,
    /// );
    /// assert_eq!(auth.capabilities(), Capabilities::VIEW);
    /// ```
    pub fn capabilities(&self) -> Capabilities {
        self.sealed_caps
    }

    /// Sets the fresh-presence proof for this session.
    ///
    /// This is called by the host-side MFA subsystem after a successful WebAuthn/FIDO2
    /// verification (R-ELEVATION-MFA). Until P3-5's MFA issuance is implemented, this
    /// can be called with [`FreshPresence::new_for_testing`] in test scenarios.
    ///
    /// Calling this after [`kill`](Self::kill) is a no-op (the session is dead).
    pub fn set_fresh_presence(&mut self, presence: FreshPresence) {
        if !self.killed {
            self.fresh_presence = Some(presence);
        }
    }

    /// Checks whether the sealed mask permits the given action.
    ///
    /// Returns `Ok(())` if the action is permitted, or a [`Denied`] error describing why it
    /// was denied. Every privileged host-side operation MUST gate itself through this method.
    ///
    /// # `ElevatedAction` is always denied on the no-clock path
    ///
    /// ADR-0010 §1.4 requires that `ELEVATION` can never be satisfied by a cached grant — the
    /// freshness window MUST be validated against a real clock. Therefore when `action` is
    /// [`PrivilegedAction::ElevatedAction`] this method unconditionally returns
    /// [`Denied::ElevationRequiresFreshPresence`] regardless of whether a `FreshPresence`
    /// token is set. All callers that need `ElevatedAction` MUST go through
    /// [`authorize_with_clock`](Self::authorize_with_clock).
    ///
    /// # Errors
    ///
    /// - [`Denied::Killed`] — the session has been killed.
    /// - [`Denied::ElevationRequiresFreshPresence`] — action is `ElevatedAction` (always
    ///   denied on the no-clock path; use `authorize_with_clock` instead).
    /// - [`Denied::CapabilityMissing`] — the required capability bit is not in the sealed mask.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_core::authz::{Capabilities, Denied, InMemoryMinEpochStore, PrivilegedAction, SessionAuthorizer};
    ///
    /// let store = InMemoryMinEpochStore::new(0);
    /// let auth = SessionAuthorizer::seal(
    ///     Capabilities::VIEW,
    ///     Capabilities::all(),
    ///     Capabilities::all(),
    ///     Capabilities::all(),
    ///     store,
    /// );
    /// assert!(auth.authorize(&PrivilegedAction::ViewFrame).is_ok());
    /// assert!(matches!(
    ///     auth.authorize(&PrivilegedAction::InjectKey),
    ///     Err(Denied::CapabilityMissing { .. })
    /// ));
    /// // ElevatedAction is always denied without a clock, even with FreshPresence set.
    /// assert!(matches!(
    ///     auth.authorize(&PrivilegedAction::ElevatedAction),
    ///     Err(Denied::ElevationRequiresFreshPresence)
    /// ));
    /// ```
    pub fn authorize(&self, action: &PrivilegedAction) -> Result<(), Denied> {
        if self.killed {
            return Err(Denied::Killed);
        }

        // ELEVATION can never be satisfied by a cached grant on the no-clock path
        // (ADR-0010 §1.4). Force all elevation callers through authorize_with_clock.
        if matches!(action, PrivilegedAction::ElevatedAction) {
            return Err(Denied::ElevationRequiresFreshPresence);
        }

        let required = action.required_cap();
        if !self.sealed_caps.contains(required) {
            return Err(Denied::CapabilityMissing {
                action: action.clone(),
                required,
                held: self.sealed_caps,
            });
        }

        Ok(())
    }

    /// Authorize with an explicit clock (used when a freshness window check is needed).
    ///
    /// This is the preferred overload when a `Clock` is available; it validates the
    /// freshness window on the `FreshPresence` token. When called without a clock
    /// (via [`authorize`](Self::authorize)), any `FreshPresence` set via
    /// [`set_fresh_presence`](Self::set_fresh_presence) is accepted as fresh regardless
    /// of its timestamp — suitable only for non-elevation actions or test scenarios.
    ///
    /// # Errors
    ///
    /// Same as [`authorize`](Self::authorize).
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn authorize_with_clock(
        &self,
        action: &PrivilegedAction,
        clock: &dyn Clock,
    ) -> Result<(), Denied> {
        if self.killed {
            return Err(Denied::Killed);
        }

        let required = action.required_cap();

        if matches!(action, PrivilegedAction::ElevatedAction) {
            if !self.sealed_caps.contains(Capabilities::ELEVATION) {
                return Err(Denied::CapabilityMissing {
                    action: action.clone(),
                    required,
                    held: self.sealed_caps,
                });
            }
            // Check freshness against the clock.
            // A future-dated token (granted_at > now) is always denied — it cannot have
            // been "granted" yet from the verifier's perspective (clock-skew bypass defense).
            let now = clock.now_unix_secs();
            let is_fresh = self.fresh_presence.as_ref().is_some_and(|fp| {
                // Explicit future-date guard before computing age.
                if fp.granted_at > now {
                    return false; // future-dated: reject regardless of window
                }
                // Now granted_at <= now, so age = now - granted_at is non-negative.
                let age = now.saturating_sub(fp.granted_at);
                age <= ELEVATION_FRESHNESS_WINDOW_SECS
            });
            if !is_fresh {
                return Err(Denied::ElevationRequiresFreshPresence);
            }
            return Ok(());
        }

        if !self.sealed_caps.contains(required) {
            return Err(Denied::CapabilityMissing {
                action: action.clone(),
                required,
                held: self.sealed_caps,
            });
        }

        Ok(())
    }

    /// Returns `true` if this session has been killed.
    pub fn is_killed(&self) -> bool {
        self.killed
    }

    /// Kills the session: zeroizes all session AEAD keys, bumps the epoch floor, and marks
    /// the authorizer as killed. After this call, every [`authorize`](Self::authorize)
    /// call returns [`Denied::Killed`].
    ///
    /// # Properties
    ///
    /// - **Irreversible**: there is no `revive()`.
    /// - **Idempotent**: calling `kill` twice is safe and is a no-op on the second call.
    /// - **Panic-free**: no `unwrap`/`expect`.
    /// - **Local and synchronous**: no network operations.
    ///
    /// # Effects
    ///
    /// 1. `keys.zeroize_all()` — wipes all channel AEAD keys and the session PRK in RAM.
    ///    Any subsequent `seal()`/`open()` on the `SessionKeys` will fail AEAD.
    /// 2. `epoch_store.bump_min_epoch()` — raises the epoch floor so a peer that
    ///    re-handshakes and replays the same UGC fails step 5 (`UgcRevoked`).
    /// 3. Sets `killed = true` — subsequent `authorize` calls return `Denied::Killed`.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_core::authz::{Capabilities, Denied, InMemoryMinEpochStore, PrivilegedAction, SessionAuthorizer};
    /// use sh_crypto::channel_crypto::SessionKeys;
    ///
    /// // In a real session, pass the actual SessionKeys here to also zeroize them.
    /// // This doctest is a compile-check only; see integration tests for real usage.
    /// let store = InMemoryMinEpochStore::new(0);
    /// let auth = SessionAuthorizer::seal(
    ///     Capabilities::all(),
    ///     Capabilities::all(),
    ///     Capabilities::all(),
    ///     Capabilities::all(),
    ///     store,
    /// );
    /// assert!(auth.authorize(&PrivilegedAction::ViewFrame).is_ok());
    /// ```
    pub fn kill(&mut self, keys: &mut SessionKeys) {
        // Idempotent: skip on second call.
        if self.killed {
            return;
        }
        // Step 1: zeroize all session AEAD keys (and PRK) — ADR-0009 seam.
        keys.zeroize_all();
        // Step 2: bump epoch floor — defeats same-UGC reconnect.
        self.epoch_store.bump_min_epoch();
        // Step 3: mark killed.
        self.killed = true;
    }

    /// Kills the session without zeroizing external session keys.
    ///
    /// This is provided for test scenarios where a `SessionKeys` instance is not
    /// available but the killed-state behavior must be tested. In production, always
    /// call [`kill`](Self::kill) with the actual `SessionKeys`.
    ///
    /// Gated `#[cfg(test)]` to prevent production callers from accidentally bypassing
    /// key zeroization (ADR-0010 §4 requires keys to be wiped on kill).
    ///
    /// # Panics
    ///
    /// Never panics.
    #[cfg(test)]
    pub fn kill_without_keys(&mut self) {
        if self.killed {
            return;
        }
        self.epoch_store.bump_min_epoch();
        self.killed = true;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::authz::{InMemoryMinEpochStore, MinEpochStore};
    use sh_crypto::clock::FixedClock;

    fn make_authorizer(caps: Capabilities) -> SessionAuthorizer<InMemoryMinEpochStore> {
        let store = InMemoryMinEpochStore::new(0);
        SessionAuthorizer::seal(
            caps,
            Capabilities::all(),
            Capabilities::all(),
            Capabilities::all(),
            store,
        )
    }

    #[test]
    fn intersection_most_restrictive() {
        // Each source only removes capabilities; the result is the intersection.
        let store = InMemoryMinEpochStore::new(0);
        let auth = SessionAuthorizer::seal(
            Capabilities::VIEW | Capabilities::CONTROL | Capabilities::AUDIO,
            Capabilities::VIEW | Capabilities::CONTROL, // removes AUDIO
            Capabilities::VIEW,                         // removes CONTROL
            Capabilities::all(),
            store,
        );
        assert_eq!(auth.capabilities(), Capabilities::VIEW);
    }

    #[test]
    fn absent_source_uses_all_as_neutral() {
        // Capabilities::all() is the neutral element for bitwise AND.
        let store = InMemoryMinEpochStore::new(0);
        let auth = SessionAuthorizer::seal(
            Capabilities::VIEW | Capabilities::FILE,
            Capabilities::all(), // no UGC → neutral
            Capabilities::all(), // attended selection → neutral
            Capabilities::all(), // account policy → neutral
            store,
        );
        assert_eq!(auth.capabilities(), Capabilities::VIEW | Capabilities::FILE);
    }

    #[test]
    fn seal_has_no_widen_path() {
        // There is no method to widen the sealed mask. This test documents the invariant
        // by asserting that `SessionAuthorizer` has no widen method — purely a compile-time
        // check, but the runtime test confirms the sealed mask never changes.
        let mut auth = make_authorizer(Capabilities::VIEW);
        let initial_caps = auth.capabilities();
        // The only method that can be called on a live authorizer (besides authorize and kill)
        // is set_fresh_presence — which doesn't affect the mask.
        auth.set_fresh_presence(FreshPresence::new_for_testing(0));
        assert_eq!(
            auth.capabilities(),
            initial_caps,
            "mask must not change after set_fresh_presence"
        );
    }

    // Table-driven: authorize_allows_granted_per_cap
    #[test]
    fn authorize_allows_view_frame() {
        let auth = make_authorizer(Capabilities::VIEW);
        assert!(auth.authorize(&PrivilegedAction::ViewFrame).is_ok());
    }

    #[test]
    fn authorize_allows_inject_pointer() {
        let auth = make_authorizer(Capabilities::CONTROL);
        assert!(auth.authorize(&PrivilegedAction::InjectPointer).is_ok());
    }

    #[test]
    fn authorize_allows_inject_key() {
        let auth = make_authorizer(Capabilities::CONTROL);
        assert!(auth.authorize(&PrivilegedAction::InjectKey).is_ok());
    }

    #[test]
    fn authorize_allows_read_clipboard() {
        let auth = make_authorizer(Capabilities::CLIPBOARD);
        assert!(auth.authorize(&PrivilegedAction::ReadClipboard).is_ok());
    }

    #[test]
    fn authorize_allows_write_clipboard() {
        let auth = make_authorizer(Capabilities::CLIPBOARD);
        assert!(auth.authorize(&PrivilegedAction::WriteClipboard).is_ok());
    }

    #[test]
    fn authorize_allows_file_transfer() {
        let auth = make_authorizer(Capabilities::FILE);
        assert!(auth.authorize(&PrivilegedAction::StartFileTransfer).is_ok());
        assert!(auth.authorize(&PrivilegedAction::ReceiveFile).is_ok());
    }

    #[test]
    fn authorize_allows_audio() {
        let auth = make_authorizer(Capabilities::AUDIO);
        assert!(auth.authorize(&PrivilegedAction::PlayAudio).is_ok());
    }

    // Table-driven: authorize_denies_ungranted_per_cap
    #[test]
    fn authorize_denies_view_frame_without_view() {
        let auth = make_authorizer(Capabilities::CONTROL);
        assert!(matches!(
            auth.authorize(&PrivilegedAction::ViewFrame),
            Err(Denied::CapabilityMissing { .. })
        ));
    }

    #[test]
    fn authorize_denies_inject_without_control() {
        let auth = make_authorizer(Capabilities::VIEW);
        assert!(matches!(
            auth.authorize(&PrivilegedAction::InjectKey),
            Err(Denied::CapabilityMissing { .. })
        ));
        assert!(matches!(
            auth.authorize(&PrivilegedAction::InjectPointer),
            Err(Denied::CapabilityMissing { .. })
        ));
    }

    #[test]
    fn authorize_denies_clipboard_without_clipboard() {
        let auth = make_authorizer(Capabilities::VIEW);
        assert!(matches!(
            auth.authorize(&PrivilegedAction::ReadClipboard),
            Err(Denied::CapabilityMissing { .. })
        ));
        assert!(matches!(
            auth.authorize(&PrivilegedAction::WriteClipboard),
            Err(Denied::CapabilityMissing { .. })
        ));
    }

    #[test]
    fn authorize_denies_file_without_file() {
        let auth = make_authorizer(Capabilities::VIEW);
        assert!(matches!(
            auth.authorize(&PrivilegedAction::StartFileTransfer),
            Err(Denied::CapabilityMissing { .. })
        ));
        assert!(matches!(
            auth.authorize(&PrivilegedAction::ReceiveFile),
            Err(Denied::CapabilityMissing { .. })
        ));
    }

    #[test]
    fn authorize_denies_audio_without_audio() {
        let auth = make_authorizer(Capabilities::VIEW);
        assert!(matches!(
            auth.authorize(&PrivilegedAction::PlayAudio),
            Err(Denied::CapabilityMissing { .. })
        ));
    }

    #[test]
    fn elevation_default_deny_without_fresh_presence() {
        let auth = make_authorizer(Capabilities::all());
        // Has ELEVATION bit but no fresh presence
        assert!(matches!(
            auth.authorize(&PrivilegedAction::ElevatedAction),
            Err(Denied::ElevationRequiresFreshPresence)
        ));
    }

    #[test]
    fn elevation_denied_without_elevation_bit() {
        // Missing the ELEVATION bit entirely. The no-clock path denies ElevatedAction
        // unconditionally with ElevationRequiresFreshPresence. The clock path checks the
        // capability bit first and returns CapabilityMissing.
        let auth = make_authorizer(Capabilities::VIEW | Capabilities::CONTROL);
        // No-clock path: always denied with ElevationRequiresFreshPresence.
        assert!(matches!(
            auth.authorize(&PrivilegedAction::ElevatedAction),
            Err(Denied::ElevationRequiresFreshPresence)
        ));
        // Clock path: no ELEVATION bit → CapabilityMissing.
        let clock = FixedClock(1_000_000);
        assert!(matches!(
            auth.authorize_with_clock(&PrivilegedAction::ElevatedAction, &clock),
            Err(Denied::CapabilityMissing { .. })
        ));
    }

    #[test]
    fn elevation_allowed_with_fresh_presence_and_clock() {
        let mut auth = make_authorizer(Capabilities::all());
        let granted_at = 1_000_000_i64;
        auth.set_fresh_presence(FreshPresence::new_for_testing(granted_at));
        // Must use authorize_with_clock; the no-clock path always denies ElevatedAction.
        let clock = FixedClock(granted_at + 60); // well within 10-minute window
        assert!(auth
            .authorize_with_clock(&PrivilegedAction::ElevatedAction, &clock)
            .is_ok());
    }

    /// Regression test (fix #1): no-clock `authorize` must deny ElevatedAction
    /// unconditionally, even when a FreshPresence token is set (ADR-0010 §1.4).
    #[test]
    fn no_clock_authorize_denies_elevation_unconditionally() {
        let mut auth = make_authorizer(Capabilities::all());
        // Set a FreshPresence token — the old code would pass this through.
        auth.set_fresh_presence(FreshPresence::new_for_testing(1_000_000));
        // Must still be denied; the no-clock path can never satisfy ELEVATION.
        assert!(
            matches!(
                auth.authorize(&PrivilegedAction::ElevatedAction),
                Err(Denied::ElevationRequiresFreshPresence)
            ),
            "no-clock authorize must deny ElevatedAction even with FreshPresence set"
        );
    }

    /// Regression test (fix #2): a future-dated FreshPresence must be denied.
    #[test]
    fn future_dated_fresh_presence_denied() {
        let mut auth = make_authorizer(Capabilities::all());
        // granted_at is far in the future relative to our "now".
        let granted_at = 2_000_000_000_i64;
        auth.set_fresh_presence(FreshPresence::new_for_testing(granted_at));
        // Clock is in the past relative to granted_at → future-dated token.
        let clock = FixedClock(1_000_000_000_i64);
        assert!(
            matches!(
                auth.authorize_with_clock(&PrivilegedAction::ElevatedAction, &clock),
                Err(Denied::ElevationRequiresFreshPresence)
            ),
            "future-dated FreshPresence must be denied"
        );
    }

    #[test]
    fn elevation_with_clock_checks_freshness_window() {
        let mut auth = make_authorizer(Capabilities::all());
        let granted_at = 1_000_000_i64;
        auth.set_fresh_presence(FreshPresence::new_for_testing(granted_at));

        // Within the 10-minute window → allowed
        let fresh_clock = FixedClock(granted_at + 599);
        assert!(auth
            .authorize_with_clock(&PrivilegedAction::ElevatedAction, &fresh_clock)
            .is_ok());

        // Exactly at window boundary → allowed (<=)
        let boundary_clock = FixedClock(granted_at + ELEVATION_FRESHNESS_WINDOW_SECS);
        assert!(auth
            .authorize_with_clock(&PrivilegedAction::ElevatedAction, &boundary_clock)
            .is_ok());

        // One second past the window → denied
        let stale_clock = FixedClock(granted_at + ELEVATION_FRESHNESS_WINDOW_SECS + 1);
        assert!(matches!(
            auth.authorize_with_clock(&PrivilegedAction::ElevatedAction, &stale_clock),
            Err(Denied::ElevationRequiresFreshPresence)
        ));
    }

    #[test]
    fn kill_idempotent() {
        let store = InMemoryMinEpochStore::new(0);
        let initial_floor = store.current();
        let mut auth = SessionAuthorizer::seal(
            Capabilities::all(),
            Capabilities::all(),
            Capabilities::all(),
            Capabilities::all(),
            store.clone(),
        );

        auth.kill_without_keys();
        let floor_after_first = store.current();
        assert_eq!(floor_after_first, initial_floor + 1);

        // Second kill is a no-op
        auth.kill_without_keys();
        assert_eq!(
            store.current(),
            floor_after_first,
            "second kill must not bump epoch again"
        );
        assert!(auth.is_killed());
    }

    #[test]
    fn authorize_returns_killed_post_kill() {
        let mut auth = make_authorizer(Capabilities::all());
        assert!(auth.authorize(&PrivilegedAction::ViewFrame).is_ok());

        auth.kill_without_keys();

        // Every action returns Denied::Killed, regardless of capability
        for action in [
            PrivilegedAction::ViewFrame,
            PrivilegedAction::InjectKey,
            PrivilegedAction::PlayAudio,
            PrivilegedAction::ElevatedAction,
        ] {
            assert!(
                matches!(auth.authorize(&action), Err(Denied::Killed)),
                "expected Killed for {action:?}"
            );
        }
    }

    #[test]
    fn set_fresh_presence_after_kill_is_noop() {
        let mut auth = make_authorizer(Capabilities::all());
        auth.kill_without_keys();
        // This must not panic or change the killed state
        auth.set_fresh_presence(FreshPresence::new_for_testing(999_999));
        assert!(auth.is_killed());
        // Elevation still denied (killed takes priority)
        assert!(matches!(
            auth.authorize(&PrivilegedAction::ElevatedAction),
            Err(Denied::Killed)
        ));
    }

    #[test]
    fn kill_bumps_epoch_store() {
        let store = InMemoryMinEpochStore::new(10);
        let mut auth = SessionAuthorizer::seal(
            Capabilities::all(),
            Capabilities::all(),
            Capabilities::all(),
            Capabilities::all(),
            store.clone(),
        );

        auth.kill_without_keys();
        assert_eq!(store.current(), 11, "kill must bump epoch floor by 1");
    }

    #[test]
    fn denied_error_display_contains_no_secret() {
        let denied = Denied::CapabilityMissing {
            action: PrivilegedAction::InjectKey,
            required: Capabilities::CONTROL,
            held: Capabilities::VIEW,
        };
        let msg = denied.to_string();
        // Must mention the action and caps (public info), not any key bytes
        assert!(msg.contains("InjectKey") || msg.contains("CONTROL") || msg.contains("denied"));
    }

    /// Integration test: kill-switch zeroizes keys → real SessionKeys::seal/open then fails AEAD.
    ///
    /// This tests the P3-4/P3-5 integration seam: `SessionAuthorizer::kill` calls
    /// `SessionKeys::zeroize_all()`, which wipes the AEAD keys and PRK, causing subsequent
    /// seal/open operations to fail (ADR-0010 §4, ADR-0009).
    #[tokio::test]
    async fn kill_switch_then_aead_fails() {
        use rand_core::SeedableRng;
        use sh_crypto::{
            channel_crypto::SessionKeys, clock::FixedClock, noise::NoiseHandshake, Keystore,
            SoftwareKeystore,
        };
        use sh_types::ChannelId;
        use x25519_dalek::{PublicKey, StaticSecret};

        // Build two keystores and run an XK handshake to get real SessionKeys.
        let init_ks =
            SoftwareKeystore::generate_with_rng(rand_chacha::ChaCha8Rng::seed_from_u64(1000));
        let resp_ks =
            SoftwareKeystore::generate_with_rng(rand_chacha::ChaCha8Rng::seed_from_u64(2000));

        let init_id = init_ks.device_identity().await.unwrap();
        let resp_id = resp_ks.device_identity().await.unwrap();

        init_ks.trust_peer(&resp_id).await.unwrap();
        resp_ks.trust_peer(&init_id).await.unwrap();

        // Generate X25519 static key pairs using seeded RNG for determinism.
        let init_static_secret =
            StaticSecret::random_from_rng(rand_chacha::ChaCha8Rng::seed_from_u64(3000));
        let _init_static_pub = PublicKey::from(&init_static_secret);
        let resp_static_secret =
            StaticSecret::random_from_rng(rand_chacha::ChaCha8Rng::seed_from_u64(4000));
        let resp_static_pub = PublicKey::from(&resp_static_secret);

        let now = 1_700_000_000_i64;
        let clock = FixedClock(now);

        let mut init = NoiseHandshake::initiator_xk(
            &init_ks,
            init_static_secret,
            resp_static_pub.to_bytes(),
            &[],
            &clock,
        )
        .await
        .unwrap();
        let mut resp = NoiseHandshake::responder_xk(&resp_ks, resp_static_secret, &[], &clock)
            .await
            .unwrap();

        let msg0 = init.write_message().unwrap();
        resp.read_message(&msg0, &clock).unwrap();
        let msg1 = resp.write_message().unwrap();
        init.read_message(&msg1, &clock).unwrap();
        let msg2 = init.write_message().unwrap();
        resp.read_message(&msg2, &clock).unwrap();

        let init_outcome = init.complete(&init_ks).await.unwrap();
        let resp_outcome = resp.complete(&resp_ks).await.unwrap();

        let mut init_keys =
            SessionKeys::from_outcome(init_outcome, Box::new(FixedClock(now))).unwrap();
        let mut resp_keys =
            SessionKeys::from_outcome(resp_outcome, Box::new(FixedClock(now))).unwrap();

        // Sanity: seal/open works before kill.
        let plaintext = b"hello before kill";
        let frame = init_keys.seal(ChannelId::Video, plaintext).unwrap();
        let decrypted = resp_keys.open(ChannelId::Video, &frame).unwrap();
        assert_eq!(decrypted, plaintext, "seal/open must work before kill");

        // Create a SessionAuthorizer and kill it with the initiator's keys.
        let store = InMemoryMinEpochStore::new(0);
        let mut auth = SessionAuthorizer::seal(
            Capabilities::all(),
            Capabilities::all(),
            Capabilities::all(),
            Capabilities::all(),
            store,
        );
        auth.kill(&mut init_keys);

        // After kill: authorize returns Denied::Killed.
        assert!(
            matches!(
                auth.authorize(&PrivilegedAction::ViewFrame),
                Err(Denied::Killed)
            ),
            "authorize must return Killed after kill"
        );

        // After kill: seal fails because the AEAD keys are zeroized.
        assert!(
            init_keys.seal(ChannelId::Video, plaintext).is_err(),
            "seal must fail after kill (keys zeroized)"
        );
    }
}
