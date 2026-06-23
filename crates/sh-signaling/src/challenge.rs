//! Server-side challenge generation seam (R-SIG-AUTH, ADR-0016).
//!
//! The signaling server issues a fresh random 32-byte challenge on every connection. The peer must
//! sign it in its `Hello` identity proof, which is what makes a captured proof non-replayable. The
//! [`ChallengeSource`] trait is the injection point for the CSPRNG so that tests can supply a
//! deterministic source while production uses the OS entropy pool.
//!
//! # Security
//!
//! Production deployments MUST use a cryptographically secure source ([`OsChallengeSource`], the
//! default). A predictable challenge would let an attacker pre-sign a proof and defeat the
//! anti-replay guarantee, so deterministic sources are for tests only.

use sh_crypto::peer_auth::PEER_AUTH_CHALLENGE_LEN;

/// Supplies the random per-connection challenge nonce.
///
/// Implementations must be `Send + Sync + 'static` because the server holds the source behind an
/// `Arc` and calls it from many concurrent connection tasks.
pub trait ChallengeSource: Send + Sync + 'static {
    /// Fills `buf` with a fresh challenge nonce.
    ///
    /// Production implementations MUST draw from a cryptographically secure RNG. Each call MUST
    /// produce an unpredictable, effectively-unique value.
    fn fill_challenge(&self, buf: &mut [u8; PEER_AUTH_CHALLENGE_LEN]);
}

/// The production challenge source: the operating system CSPRNG via `getrandom`.
///
/// # Examples
///
/// ```
/// use sh_signaling::challenge::{ChallengeSource, OsChallengeSource};
///
/// let src = OsChallengeSource;
/// let mut a = [0u8; 32];
/// let mut b = [0u8; 32];
/// src.fill_challenge(&mut a);
/// src.fill_challenge(&mut b);
/// // Two draws are overwhelmingly unlikely to collide.
/// assert_ne!(a, b);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct OsChallengeSource;

impl ChallengeSource for OsChallengeSource {
    fn fill_challenge(&self, buf: &mut [u8; PEER_AUTH_CHALLENGE_LEN]) {
        // `OsRng` is a CSPRNG backed by `getrandom`; `fill_bytes` cannot fail for it.
        use rand_core::RngCore as _;
        rand_core::OsRng.fill_bytes(buf);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn os_source_produces_distinct_challenges() {
        let src = OsChallengeSource;
        let mut a = [0u8; PEER_AUTH_CHALLENGE_LEN];
        let mut b = [0u8; PEER_AUTH_CHALLENGE_LEN];
        src.fill_challenge(&mut a);
        src.fill_challenge(&mut b);
        assert_ne!(a, b, "two CSPRNG draws must differ");
        assert_ne!(
            a, [0u8; PEER_AUTH_CHALLENGE_LEN],
            "challenge must not be all-zero"
        );
    }
}
