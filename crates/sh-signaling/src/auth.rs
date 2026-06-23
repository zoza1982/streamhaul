//! Peer authentication seam for the signaling server.
//!
//! [`PeerAuthenticator`] is the injection point for access-control policy. The server calls
//! [`PeerAuthenticator::authenticate`] on the `from_fp` of every `Hello` envelope. A `false`
//! return causes the server to send an `Error` envelope back and drop the connection.
//!
//! # Production use
//!
//! In production, supply an authenticator that verifies the fingerprint against a known-devices
//! list or a pairing token. Never ship [`AcceptAll`] in a production binary.
//!
//! # `insecure-lan` feature
//!
//! [`AcceptAll`] and [`InsecureLanLab`] are exported only when the `insecure-lan` feature is
//! active. Integration tests use these types to start an unauthenticated signaling server on
//! loopback.

/// Decides whether a connecting peer (identified by its fingerprint) is allowed to register.
///
/// The server calls this once per `Hello` envelope. Returning `false` causes the connection to
/// be rejected with an `Error` message.
///
/// # Thread safety
///
/// Implementations must be `Send + Sync + 'static` because the server holds the authenticator
/// behind an `Arc` and calls it from multiple concurrent tasks.
pub trait PeerAuthenticator: Send + Sync + 'static {
    /// Returns `true` if the peer with fingerprint `fp` is allowed to register.
    ///
    /// `fp` is the raw `from_fp` string from the `Hello` envelope — 64-char lowercase hex.
    fn authenticate(&self, fp: &str) -> bool;
}

/// An authenticator that admits every peer without restriction.
///
/// **WARNING**: This is only for local integration tests. Using it in a production deployment
/// allows any unauthenticated peer to register and route messages through your signaling server.
///
/// Available only with the `insecure-lan` feature.
///
/// # Examples
///
/// ```
/// use sh_signaling::auth::AcceptAll;
/// use sh_signaling::PeerAuthenticator;
///
/// let auth = AcceptAll;
/// assert!(auth.authenticate("a".repeat(64).as_str()));
/// ```
#[cfg(feature = "insecure-lan")]
#[derive(Debug, Clone, Copy)]
pub struct AcceptAll;

#[cfg(feature = "insecure-lan")]
impl PeerAuthenticator for AcceptAll {
    fn authenticate(&self, _fp: &str) -> bool {
        true
    }
}

/// Witness type that unlocks the `insecure-lan` server/client path in integration tests.
///
/// Constructing this type is a deliberate act: the caller must name
/// [`i_understand_this_skips_authentication`](InsecureLanLab::i_understand_this_skips_authentication)
/// to obtain it, making it impossible to accidentally use in a production binary.
///
/// # Examples
///
/// ```
/// use sh_signaling::auth::InsecureLanLab;
///
/// let _witness = InsecureLanLab::i_understand_this_skips_authentication();
/// ```
#[cfg(feature = "insecure-lan")]
#[derive(Debug, Clone, Copy)]
pub struct InsecureLanLab(());

#[cfg(feature = "insecure-lan")]
impl InsecureLanLab {
    /// Returns the witness token, acknowledging that authentication is skipped.
    ///
    /// The verbose name is intentional: it must appear literally in calling code as a
    /// self-documenting proof that the caller understands what they are bypassing.
    #[must_use]
    pub fn i_understand_this_skips_authentication() -> Self {
        Self(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    #[cfg(feature = "insecure-lan")]
    use super::*;

    #[cfg(feature = "insecure-lan")]
    #[test]
    fn accept_all_admits_any_fingerprint() {
        let auth = AcceptAll;
        assert!(PeerAuthenticator::authenticate(&auth, &"a".repeat(64)));
        assert!(PeerAuthenticator::authenticate(&auth, &"f".repeat(64)));
        assert!(PeerAuthenticator::authenticate(&auth, ""));
    }

    #[cfg(feature = "insecure-lan")]
    #[test]
    fn insecure_lan_lab_constructs() {
        let _w = InsecureLanLab::i_understand_this_skips_authentication();
    }
}
