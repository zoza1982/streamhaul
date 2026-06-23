//! Peer authentication seam for the signaling server (R-SIG-AUTH, ADR-0016).
//!
//! [`PeerAuthenticator`] is the injection point for access-control policy. On every `Hello`, the
//! server builds an [`AuthContext`] (claimed fingerprint + session id + the challenge it issued +
//! the proof bytes the client supplied) and calls [`PeerAuthenticator::authenticate`]. The
//! production [`IdentityProofAuthenticator`] verifies a possession-of-identity-key proof: the
//! connecting peer must prove it controls the Ed25519 device key behind its claimed `from_fp`,
//! over a fresh server challenge. This stops fingerprint spoofing / impersonation / DoS at the
//! relay.
//!
//! # Authentication is NOT peer trust
//!
//! A passing [`PeerAuthenticator`] check proves the connecting peer **owns** the claimed
//! fingerprint. It does **not** establish end-to-end trust between the two peers — that remains the
//! peers' responsibility via the Noise handshake + `BindCert` + TOFU pairing (P3). Do not read a
//! server-side pass as identity verification between endpoints.
//!
//! # Zero-knowledge preserved
//!
//! The authenticator only ever sees PUBLIC data — the claimed fingerprint, session id, server
//! challenge, and the proof (public key + signature). It never sees session content, and the
//! server's routing remains keyed only on `(session_id, to_fp)`. The proof rides in the opaque
//! `Hello` payload (it does not bloat the 149-byte routing header).
//!
//! # Policy layering
//!
//! [`PeerAuthenticator`] stays a trait so an allow-list, rate-limiter, or token-issuer policy can
//! wrap [`IdentityProofAuthenticator`] (verify possession first, then apply policy).
//!
//! # `insecure-lan` feature
//!
//! [`AcceptAll`] and [`InsecureLanLab`] are exported only when the `insecure-lan` feature is
//! active. Integration tests use these types to start an unauthenticated signaling server on
//! loopback. They MUST NOT ship in a release build (see the `compile_error!` fence below).

// Prevent `insecure-lan` from being compiled into release builds.
// This feature skips all peer authentication and exists solely for local integration tests.
#[cfg(all(feature = "insecure-lan", not(debug_assertions)))]
compile_error!(
    "`insecure-lan` must not be enabled in release builds. \
     This feature skips all peer authentication and is for local integration tests only."
);

use sh_crypto::peer_auth::IdentityProof;
use thiserror::Error;

use crate::envelope::SessionId;

/// The reason a [`PeerAuthenticator`] rejected a connecting peer.
///
/// # Security: no enumeration oracle
///
/// The server maps **every** rejection to a single, uniform `Error` envelope reason
/// (`"authentication failed"`) before sending it on the wire — it never tells the client which
/// specific check failed. The richer variants here exist for **server-side logging and tests**
/// only, so the operator can diagnose failures without handing a probing attacker a
/// fingerprint/proof enumeration oracle. Do not forward the `Display` of these variants to the
/// remote peer.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthError {
    /// The supplied proof bytes were structurally malformed (wrong length / undecodable).
    #[error("authentication failed")]
    MalformedProof,

    /// The proof did not verify: fingerprint mismatch, wrong/replayed challenge, wrong session
    /// binding, or an invalid/forged signature. Uniform on purpose (no oracle).
    #[error("authentication failed")]
    ProofRejected,

    /// An access-control policy layered on top of possession-proof denied this peer (e.g. an
    /// allow-list miss). Distinct variant so policy layers can be tested independently.
    #[error("authentication failed")]
    PolicyDenied,
}

/// The public material the server hands to a [`PeerAuthenticator`] for one `Hello`.
///
/// All fields are PUBLIC (no session content). `proof` is the attacker-controlled opaque payload
/// from the `Hello` envelope; the authenticator MUST treat it as hostile and parse it
/// panic-free / bounds-checked (the production impl decodes it via
/// [`sh_crypto::peer_auth::IdentityProof::decode`]).
#[derive(Debug, Clone, Copy)]
pub struct AuthContext<'a> {
    /// The fingerprint the connecting peer claims as its `from_fp` (64-char lowercase hex).
    pub claimed_fp: &'a str,
    /// The signaling session the peer is joining.
    pub session_id: SessionId,
    /// The exact 32-byte challenge the server issued to THIS connection.
    pub challenge: &'a [u8; sh_crypto::peer_auth::PEER_AUTH_CHALLENGE_LEN],
    /// The raw proof bytes the client supplied in the `Hello` payload (hostile input).
    pub proof: &'a [u8],
}

/// Decides whether a connecting peer is allowed to register, given a possession proof.
///
/// The server calls this once per `Hello`. Returning `Err(_)` causes the connection to be rejected
/// with a uniform `Error` envelope (the specific [`AuthError`] is logged server-side, never sent).
///
/// # Thread safety
///
/// Implementations must be `Send + Sync + 'static` because the server holds the authenticator
/// behind an `Arc` and calls it from multiple concurrent tasks.
pub trait PeerAuthenticator: Send + Sync + 'static {
    /// Returns `Ok(())` if the peer described by `ctx` is allowed to register.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] describing (for server-side logging only) why the peer was
    /// rejected. The server sanitizes this to a uniform wire reason.
    fn authenticate(&self, ctx: &AuthContext<'_>) -> Result<(), AuthError>;
}

/// The production authenticator: verifies an Ed25519 possession-of-identity-key proof.
///
/// It decodes the [`IdentityProof`] from `ctx.proof` and verifies that:
/// 1. the proof echoes the server-issued `ctx.challenge` (anti-replay),
/// 2. the presented public key is a valid, non-weak Ed25519 key,
/// 3. `Fingerprint::from(pubkey) == ctx.claimed_fp` (constant-time), and
/// 4. the signature verifies (`verify_strict`) over the canonical, domain-separated message
///    binding `ctx.session_id`, the key, and the challenge.
///
/// It does **not** consult any trust store — server-side auth proves *ownership*, not *trust*
/// (see the module docs). It is self-contained: no token issuer and no pre-shared secret, so a
/// self-hosted relay can use it as-is.
///
/// # Examples
///
/// ```
/// use sh_signaling::auth::{AuthContext, IdentityProofAuthenticator, PeerAuthenticator};
/// use sh_signaling::SessionId;
/// # use sh_crypto::{SoftwareKeystore, Keystore};
/// # use sh_crypto::peer_auth::IdentityProof;
/// # tokio_test::block_on(async {
/// let ks = SoftwareKeystore::generate();
/// let id = ks.device_identity().await.unwrap();
/// let session = SessionId([7u8; 16]);
/// let challenge = [9u8; 32];
///
/// let proof = IdentityProof::create(&ks, session.as_bytes(), &challenge).await.unwrap();
/// let wire = proof.encode();
///
/// let auth = IdentityProofAuthenticator;
/// let ctx = AuthContext {
///     claimed_fp: id.fingerprint().as_str(),
///     session_id: session,
///     challenge: &challenge,
///     proof: &wire,
/// };
/// assert!(auth.authenticate(&ctx).is_ok());
/// # });
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct IdentityProofAuthenticator;

impl PeerAuthenticator for IdentityProofAuthenticator {
    fn authenticate(&self, ctx: &AuthContext<'_>) -> Result<(), AuthError> {
        // Hostile input: decode bounds-checked, never panic.
        let proof = IdentityProof::decode(ctx.proof).map_err(|_| AuthError::MalformedProof)?;
        // Verify possession: challenge + fingerprint binding + verify_strict signature.
        proof
            .verify(ctx.claimed_fp, ctx.session_id.as_bytes(), ctx.challenge)
            .map_err(|_| AuthError::ProofRejected)
    }
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
/// use sh_signaling::auth::{AcceptAll, AuthContext};
/// use sh_signaling::{PeerAuthenticator, SessionId};
///
/// let auth = AcceptAll;
/// let challenge = [0u8; 32];
/// let ctx = AuthContext {
///     claimed_fp: &"a".repeat(64),
///     session_id: SessionId([0u8; 16]),
///     challenge: &challenge,
///     proof: &[],
/// };
/// assert!(auth.authenticate(&ctx).is_ok());
/// ```
#[cfg(feature = "insecure-lan")]
#[derive(Debug, Clone, Copy)]
pub struct AcceptAll;

#[cfg(feature = "insecure-lan")]
impl PeerAuthenticator for AcceptAll {
    fn authenticate(&self, _ctx: &AuthContext<'_>) -> Result<(), AuthError> {
        Ok(())
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
    use super::*;
    use sh_crypto::{Keystore, SoftwareKeystore};

    const CHALLENGE: [u8; 32] = [0x5a; 32];

    fn ctx<'a>(
        fp: &'a str,
        session: SessionId,
        challenge: &'a [u8; 32],
        proof: &'a [u8],
    ) -> AuthContext<'a> {
        AuthContext {
            claimed_fp: fp,
            session_id: session,
            challenge,
            proof,
        }
    }

    #[tokio::test]
    async fn identity_proof_authenticator_admits_valid_proof() {
        let ks = SoftwareKeystore::generate();
        let id = ks.device_identity().await.unwrap();
        let session = SessionId([1u8; 16]);
        let proof = IdentityProof::create(&ks, session.as_bytes(), &CHALLENGE)
            .await
            .unwrap();
        let wire = proof.encode();
        let auth = IdentityProofAuthenticator;
        let c = ctx(id.fingerprint().as_str(), session, &CHALLENGE, &wire);
        assert!(auth.authenticate(&c).is_ok());
    }

    #[tokio::test]
    async fn identity_proof_authenticator_rejects_malformed_proof() {
        let ks = SoftwareKeystore::generate();
        let id = ks.device_identity().await.unwrap();
        let session = SessionId([1u8; 16]);
        let auth = IdentityProofAuthenticator;
        // Truncated / wrong-length proof bytes → MalformedProof, never a panic.
        for bad in [&b""[..], &[0u8; 10][..], &[0xff; 500][..]] {
            let c = ctx(id.fingerprint().as_str(), session, &CHALLENGE, bad);
            assert!(matches!(
                auth.authenticate(&c),
                Err(AuthError::MalformedProof)
            ));
        }
    }

    #[tokio::test]
    async fn identity_proof_authenticator_rejects_wrong_challenge() {
        let ks = SoftwareKeystore::generate();
        let id = ks.device_identity().await.unwrap();
        let session = SessionId([1u8; 16]);
        // Proof issued for CHALLENGE; server now expects a different challenge (replay).
        let proof = IdentityProof::create(&ks, session.as_bytes(), &CHALLENGE)
            .await
            .unwrap();
        let wire = proof.encode();
        let auth = IdentityProofAuthenticator;
        let fresh = [0u8; 32];
        let c = ctx(id.fingerprint().as_str(), session, &fresh, &wire);
        assert!(matches!(
            auth.authenticate(&c),
            Err(AuthError::ProofRejected)
        ));
    }

    #[tokio::test]
    async fn identity_proof_authenticator_rejects_fp_spoof() {
        let ks = SoftwareKeystore::generate();
        let other = SoftwareKeystore::generate();
        let other_id = other.device_identity().await.unwrap();
        let session = SessionId([1u8; 16]);
        // Proof is for `ks`'s key, but claims `other`'s fingerprint.
        let proof = IdentityProof::create(&ks, session.as_bytes(), &CHALLENGE)
            .await
            .unwrap();
        let wire = proof.encode();
        let auth = IdentityProofAuthenticator;
        let c = ctx(other_id.fingerprint().as_str(), session, &CHALLENGE, &wire);
        assert!(matches!(
            auth.authenticate(&c),
            Err(AuthError::ProofRejected)
        ));
    }

    #[tokio::test]
    async fn identity_proof_authenticator_rejects_wrong_session() {
        let ks = SoftwareKeystore::generate();
        let id = ks.device_identity().await.unwrap();
        let session = SessionId([1u8; 16]);
        let other_session = SessionId([2u8; 16]);
        let proof = IdentityProof::create(&ks, session.as_bytes(), &CHALLENGE)
            .await
            .unwrap();
        let wire = proof.encode();
        let auth = IdentityProofAuthenticator;
        let c = ctx(id.fingerprint().as_str(), other_session, &CHALLENGE, &wire);
        assert!(matches!(
            auth.authenticate(&c),
            Err(AuthError::ProofRejected)
        ));
    }

    #[cfg(feature = "insecure-lan")]
    #[test]
    fn accept_all_admits_any_proof() {
        let auth = AcceptAll;
        let challenge = [0u8; 32];
        let fp = "a".repeat(64);
        let c = ctx(&fp, SessionId([0u8; 16]), &challenge, &[]);
        assert!(auth.authenticate(&c).is_ok());
    }

    #[cfg(feature = "insecure-lan")]
    #[test]
    fn insecure_lan_lab_constructs() {
        let _w = InsecureLanLab::i_understand_this_skips_authentication();
    }
}
