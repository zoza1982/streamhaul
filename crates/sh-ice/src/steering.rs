//! Relay latency probing, scoring, and TURN credential generation.
//!
//! # Relay steering
//!
//! Given probe results from the ICE initiator and responder for each TURN relay
//! server, [`score_relays`] computes a combined score (lower = better) and sorts
//! the servers accordingly.  [`select_relay`] then picks the best server and an
//! optional standby (within 10 ms of the best).
//!
//! # TURN REST credentials
//!
//! [`TurnCredentials::generate`] implements the coturn REST API credential scheme:
//! `username = "<expiry_unix_secs>:<user_id>"` and
//! `password = base64(HMAC-SHA1(shared_key, username))`.

use std::net::SocketAddr;

use base64::Engine as _;
use hmac::Mac as _;
use sha1::Sha1;

use crate::error::IceError;

// ─── Probe results ────────────────────────────────────────────────────────────

/// RTT measurements from a single relay server probe sequence (3 probes).
#[derive(Debug, Clone)]
pub struct RelayProbeResult {
    /// The relay server address.
    pub server: SocketAddr,
    /// Median RTT across the 3 probes, in microseconds.
    pub rtt_us: u64,
    /// Jitter: `abs(max_rtt - min_rtt)` of the 3 probe RTTs, in microseconds.
    pub jitter_us: u64,
}

// ─── Scoring ─────────────────────────────────────────────────────────────────

/// Combined relay score for one server, in microseconds (lower = better).
#[derive(Debug, Clone)]
pub struct RelayScore {
    /// The relay server address.
    pub server: SocketAddr,
    /// `rtt_initiator + rtt_responder + jitter/2`, all in microseconds.
    pub score: u64,
}

/// Score all relay servers and return them sorted by score ascending (best first).
///
/// The score formula is:
/// `score = rtt_initiator + rtt_responder + (jitter_initiator + jitter_responder) / 2`
///
/// Only servers that appear in **both** `initiator_results` and `responder_results`
/// are included.  Servers with no matching entry in either slice are skipped.
///
/// # Examples
///
/// ```
/// use std::net::SocketAddr;
/// use sh_ice::steering::{RelayProbeResult, score_relays};
///
/// let relay: SocketAddr = "127.0.0.1:3478".parse().unwrap();
/// let init = vec![RelayProbeResult { server: relay, rtt_us: 10_000, jitter_us: 500 }];
/// let resp = vec![RelayProbeResult { server: relay, rtt_us: 12_000, jitter_us: 1_000 }];
/// let scores = score_relays(&init, &resp);
/// assert_eq!(scores.len(), 1);
/// assert_eq!(scores[0].score, 10_000 + 12_000 + (500 + 1_000) / 2);
/// ```
#[must_use]
pub fn score_relays(
    initiator_results: &[RelayProbeResult],
    responder_results: &[RelayProbeResult],
) -> Vec<RelayScore> {
    let mut scores: Vec<RelayScore> = initiator_results
        .iter()
        .filter_map(|init| {
            let resp = responder_results.iter().find(|r| r.server == init.server)?;
            // Division by 2 cannot overflow; allow the arithmetic_side_effects lint.
            #[allow(clippy::arithmetic_side_effects)]
            let jitter_half = init.jitter_us.saturating_add(resp.jitter_us) / 2;
            let score = init
                .rtt_us
                .saturating_add(resp.rtt_us)
                .saturating_add(jitter_half);
            Some(RelayScore {
                server: init.server,
                score,
            })
        })
        .collect();
    scores.sort_by_key(|s| s.score);
    scores
}

// ─── Relay selection ─────────────────────────────────────────────────────────

/// The selected relay servers: a primary and an optional hot-standby.
#[derive(Debug, Clone)]
pub struct RelaySelection {
    /// The best relay (lowest score).
    pub primary: RelayScore,
    /// A standby relay within 10 ms (10 000 µs) of the primary, if one exists.
    pub standby: Option<RelayScore>,
}

/// Select the primary relay and an optional standby from a scored list.
///
/// The list must already be sorted by score ascending (as returned by [`score_relays`]).
/// The standby is the second-lowest-score server if its score is within 10 000 µs of
/// the primary's score.
///
/// Returns `None` if `scores` is empty.
///
/// # Examples
///
/// ```
/// use std::net::SocketAddr;
/// use sh_ice::steering::{RelayScore, select_relay};
///
/// let r1: SocketAddr = "127.0.0.1:3478".parse().unwrap();
/// let r2: SocketAddr = "127.0.0.2:3478".parse().unwrap();
/// let scores = vec![
///     RelayScore { server: r1, score: 20_000 },
///     RelayScore { server: r2, score: 25_000 },
/// ];
/// let sel = select_relay(&scores).unwrap();
/// assert_eq!(sel.primary.server, r1);
/// assert!(sel.standby.is_some()); // within 10 ms
/// ```
#[must_use]
pub fn select_relay(scores: &[RelayScore]) -> Option<RelaySelection> {
    let primary = scores.first()?.clone();
    let standby = scores.get(1).and_then(|s| {
        if s.score.saturating_sub(primary.score) <= 10_000 {
            Some(s.clone())
        } else {
            None
        }
    });
    Some(RelaySelection { primary, standby })
}

// ─── TURN credentials ────────────────────────────────────────────────────────

/// Time-limited TURN credentials generated using the coturn REST API scheme.
///
/// The username is `"<expiry_unix_secs>:<user_id>"` and the password is
/// `base64(HMAC-SHA1(shared_key, username))`.  These credentials are only valid
/// until the expiry timestamp embedded in the username.
///
/// # Security
///
/// The `shared_key` is a symmetric secret shared between the application server
/// and the TURN server.  It must never appear in logs or on the wire.
/// TURN credentials derived from the coturn REST API.
#[derive(Clone)]
pub struct TurnCredentials {
    /// The TURN username in coturn REST format: `"<expiry_unix_secs>:<user_id>"`.
    pub username: String,
    /// The TURN password: `base64(HMAC-SHA1(shared_key, username))`.
    ///
    /// **Not printed by `Debug`** — TURN passwords must not appear in logs.
    pub password: String,
    /// The Unix timestamp (seconds) at which these credentials expire.
    pub expires_at: i64,
}

impl std::fmt::Debug for TurnCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnCredentials")
            .field("username", &self.username)
            .field("password", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl TurnCredentials {
    /// Generate coturn REST API TURN credentials.
    ///
    /// # Arguments
    ///
    /// * `shared_key` — the secret shared with the TURN server.
    /// * `user_id` — an opaque identifier for the user (e.g. session ID or device ID).
    /// * `ttl_secs` — credential lifetime in seconds (e.g. 3600 for 1 hour).
    /// * `now_unix_secs` — current Unix time in seconds.
    ///
    /// # Errors
    ///
    /// Returns [`IceError::TurnCredTimestampOverflow`] if
    /// `now_unix_secs + ttl_secs` overflows `i64`.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_ice::steering::TurnCredentials;
    ///
    /// let key = b"supersecretkey";
    /// // expires_at = 1_700_000_000 + 3600 = 1_700_003_600
    /// let creds = TurnCredentials::generate(key, "user123", 3600, 1_700_000_000).unwrap();
    /// assert!(creds.is_valid(1_700_000_000));           // well within window
    /// assert!(!creds.is_valid(1_700_003_600));          // at expiry boundary — invalid
    /// assert!(!creds.is_valid(1_700_003_700));          // past expiry — invalid
    /// ```
    pub fn generate(
        shared_key: &[u8],
        user_id: &str,
        ttl_secs: u32,
        now_unix_secs: i64,
    ) -> Result<Self, IceError> {
        let expires_at = now_unix_secs
            .checked_add(i64::from(ttl_secs))
            .ok_or(IceError::TurnCredTimestampOverflow)?;
        let username = format!("{expires_at}:{user_id}");
        let password = hmac_sha1_base64(shared_key, username.as_bytes())?;
        Ok(Self {
            username,
            password,
            expires_at,
        })
    }

    /// Check whether the credentials are still valid (and not about to expire) at
    /// `now_unix_secs`.
    ///
    /// A 60-second early-expiry leeway is applied: the credentials are treated as
    /// invalid 60 seconds *before* the embedded `expires_at` timestamp.  This
    /// ensures that a client never presents near-expired credentials that the TURN
    /// server may reject due to clock skew.
    ///
    /// Effective validity window: `now_unix_secs < expires_at - 60`.
    ///
    /// # Examples
    ///
    /// ```
    /// use sh_ice::steering::TurnCredentials;
    ///
    /// let creds = TurnCredentials::generate(b"key", "u", 3600, 1_000_000).unwrap();
    /// // expires_at = 1_003_600
    /// assert!(creds.is_valid(1_000_000));           // well within window
    /// assert!(creds.is_valid(1_003_539));           // 61 s before expiry — still valid
    /// assert!(!creds.is_valid(1_003_540));          // exactly 60 s before expiry — invalid
    /// assert!(!creds.is_valid(1_003_600));          // at the expiry boundary — invalid
    /// assert!(!creds.is_valid(1_003_700));          // past expiry — invalid
    /// ```
    #[must_use]
    pub fn is_valid(&self, now_unix_secs: i64) -> bool {
        // Treat as invalid 60 seconds before the real expiry so clients renew proactively.
        // expires_at - 60 > now  ⟺  now < expires_at - 60
        now_unix_secs < self.expires_at.saturating_sub(60)
    }
}

/// Compute `base64(HMAC-SHA1(key, data))`.
///
/// Returns `Err(IceError::Transport)` if HMAC construction fails (this should never
/// occur in practice since HMAC accepts any key length).
fn hmac_sha1_base64(key: &[u8], data: &[u8]) -> Result<String, IceError> {
    type HmacSha1 = hmac::Hmac<Sha1>;
    // HMAC accepts any key length; this can only fail if the underlying block size is
    // zero, which is impossible for SHA-1. We propagate rather than panic.
    let mut mac = HmacSha1::new_from_slice(key)
        .map_err(|e| IceError::Transport(format!("HMAC-SHA1 key error: {e}")))?;
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::expect_used,
        clippy::panic,
        clippy::arithmetic_side_effects
    )]

    use std::net::SocketAddr;

    use super::*;

    fn relay(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    #[test]
    fn scoring_picks_min_total() {
        let r1 = relay(3478);
        let r2 = relay(3479);
        let init = vec![
            RelayProbeResult {
                server: r1,
                rtt_us: 10_000,
                jitter_us: 1_000,
            },
            RelayProbeResult {
                server: r2,
                rtt_us: 50_000,
                jitter_us: 5_000,
            },
        ];
        let resp = vec![
            RelayProbeResult {
                server: r1,
                rtt_us: 12_000,
                jitter_us: 2_000,
            },
            RelayProbeResult {
                server: r2,
                rtt_us: 40_000,
                jitter_us: 4_000,
            },
        ];
        let scores = score_relays(&init, &resp);
        assert_eq!(scores.len(), 2);
        // r1 score: 10_000 + 12_000 + (1_000 + 2_000)/2 = 23_500
        assert_eq!(scores[0].server, r1);
        assert_eq!(scores[0].score, 23_500);
        // r2 score: 50_000 + 40_000 + (5_000 + 4_000)/2 = 94_500
        assert_eq!(scores[1].server, r2);
        assert_eq!(scores[1].score, 94_500);
    }

    #[test]
    fn standby_within_10ms() {
        let r1 = relay(3478);
        let r2 = relay(3479);
        let r3 = relay(3480);
        let scores = vec![
            RelayScore {
                server: r1,
                score: 20_000,
            },
            RelayScore {
                server: r2,
                score: 25_000,
            }, // within 10 ms of r1
            RelayScore {
                server: r3,
                score: 50_000,
            }, // outside 10 ms
        ];
        let sel = select_relay(&scores).unwrap();
        assert_eq!(sel.primary.server, r1);
        let standby = sel.standby.unwrap();
        assert_eq!(standby.server, r2);
    }

    #[test]
    fn no_standby_when_outside_10ms() {
        let r1 = relay(3478);
        let r2 = relay(3479);
        let scores = vec![
            RelayScore {
                server: r1,
                score: 20_000,
            },
            RelayScore {
                server: r2,
                score: 50_001,
            }, // > 10 ms away
        ];
        let sel = select_relay(&scores).unwrap();
        assert!(sel.standby.is_none());
    }

    #[test]
    fn turn_cred_generate_and_validate() {
        let key = b"shared_secret_for_turn";
        let now = 1_700_000_000i64;
        let ttl = 3600u32;
        let creds = TurnCredentials::generate(key, "user42", ttl, now).unwrap();

        assert_eq!(creds.expires_at, now + i64::from(ttl));
        assert!(creds
            .username
            .starts_with(&format!("{}:", now + i64::from(ttl))));
        // Valid well within the window.
        assert!(creds.is_valid(now));
        // Invalid at the real expiry boundary (early-expiry leeway kicks in 60s before).
        assert!(!creds.is_valid(now + i64::from(ttl)));
        // Valid up to 60 seconds before expiry.
        assert!(creds.is_valid(now + i64::from(ttl) - 61));

        // Verify the HMAC independently.
        let expected_password =
            hmac_sha1_base64(key, creds.username.as_bytes()).expect("hmac_sha1_base64 failed");
        assert_eq!(creds.password, expected_password);
    }

    #[test]
    fn turn_cred_expired() {
        let key = b"key";
        let now = 1_000_000i64;
        let ttl = 3600u32;
        // expires_at = 1_003_600.
        let creds = TurnCredentials::generate(key, "u", ttl, now).unwrap();
        // 61 seconds before real expiry: still valid.
        assert!(creds.is_valid(now + i64::from(ttl) - 61));
        // 60 seconds before real expiry: invalid (early-expiry leeway).
        assert!(!creds.is_valid(now + i64::from(ttl) - 60));
        // At the real expiry boundary: invalid.
        assert!(!creds.is_valid(now + i64::from(ttl)));
        // Past expiry: invalid.
        assert!(!creds.is_valid(now + i64::from(ttl) + 100));
    }

    #[test]
    fn turn_cred_timestamp_overflow() {
        let result = TurnCredentials::generate(b"k", "u", u32::MAX, i64::MAX);
        assert!(matches!(result, Err(IceError::TurnCredTimestampOverflow)));
    }
}
