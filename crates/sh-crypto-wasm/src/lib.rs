#![deny(missing_docs)]
//! `sh-crypto-wasm` — WebAssembly crypto bridge for Streamhaul.
//!
//! This crate exposes the cryptographic primitives from [`sh_crypto`] to browser JavaScript
//! via [`wasm_bindgen`].  The source of truth for every algorithm stays in `sh-crypto`; this
//! bridge only marshals between Rust types and JS-friendly representations (`Uint8Array`, strings,
//! `JsError`).
//!
//! # What this crate exposes
//!
//! | JS type / function | Purpose |
//! |--------------------|---------|
//! | [`WasmKeystore`] | Opaque handle owning the device's Ed25519 identity + TOFU trust store. Private keys NEVER cross the JS boundary. |
//! | [`WasmNoiseHandshake`] | In-progress Noise XK or IK handshake. |
//! | [`WasmHandshakeOutcome`] | Completed handshake: peer fingerprint + DTLS pin. |
//! | [`create_identity_proof`] | R-SIG-AUTH: sign a server challenge → 128-byte `IdentityProof`. |
//! | [`verify_identity_proof`] | Verify a received proof against a claimed fingerprint. |
//! | [`decode_identity_proof_pubkey`] | Extract the 32-byte public key from a proof. |
//! | [`fingerprint_from_pubkey`] | Derive the 64-char hex fingerprint from a 32-byte public key. |
//!
//! # Security constraints
//!
//! - **Private keys never leave wasm linear memory.** [`WasmKeystore`] is an opaque JS handle.
//! - **WebCrypto CSPRNG.** `getrandom/js` is the sole entropy source in the wasm sandbox.
//! - **Constant-time operations preserved** (via `subtle::ConstantTimeEq` inside `sh-crypto`).
//! - **Zeroize preserved** (`SoftwareKeystore` zeroizes the Ed25519 scalar on drop).
//! - **No panics / traps.** Every entry point that receives attacker-controlled bytes returns
//!   `Result<_, JsError>`.
//!
//! # Trust model
//!
//! [`WasmKeystore`] provides a TOFU (Trust On First Use) trust store.  A valid
//! [`IdentityProof`] proves possession of the key behind a fingerprint — it does NOT imply
//! the peer is trusted.  Trust is established via Noise + BindCert + TOFU
//! ([`WasmKeystore::trust_peer_by_key`]).
//!
//! # What is deferred
//!
//! - **Encrypted key persistence** (`to_encrypted_bytes` / `from_encrypted_bytes`): deferred.
//! - **Live `RTCPeerConnection` wiring**: the next PR (R-BROWSER-INTEROP).
//!
//! See ADR-0020 for the design rationale.

use sh_crypto::Keystore as _;
use wasm_bindgen::prelude::*;

// ── Wasm-compatible clock ─────────────────────────────────────────────────────

/// A [`sh_types::Clock`] implementation backed by `Date.now()` (milliseconds since epoch)
/// for use on `wasm32-unknown-unknown`, where `std::time::SystemTime::now()` panics.
///
/// `Date.now()` is available in both browser and Node.js environments (where
/// `wasm-pack test --node` runs).  Accuracy is millisecond-level, sufficient for
/// `BindCert` validity checks (seconds granularity).
struct WasmClock;

impl sh_types::Clock for WasmClock {
    fn now_unix_secs(&self) -> i64 {
        // `js_sys::Date::now()` returns ms since Unix epoch as f64 (always finite and >= 0).
        // Dividing by 1000 gives seconds; truncating to i64 is safe for any date in the
        // range our BindCert validity window covers.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let secs = (js_sys::Date::now() / 1000.0) as i64;
        secs
    }
}

// ── Error mapping ────────────────────────────────────────────────────────────

/// Convert a [`sh_crypto::CryptoError`] into a throwable [`JsError`].
fn crypto_err(e: sh_crypto::CryptoError) -> JsError {
    JsError::new(&e.to_string())
}

/// Probe the WebCrypto entropy source, surfacing unavailability as a catchable [`JsError`].
///
/// Any code that draws from `OsRng` (`SoftwareKeystore::generate`, the X25519 static-key draws
/// in the handshake constructors) *panics* — a wasm trap that crashes the tab — if WebCrypto is
/// missing, and `catch_unwind` cannot recover it on `wasm32-unknown-unknown` (no unwinding
/// runtime). `getrandom`'s explicit API instead returns `Err` (never panics), so probing it
/// first turns a would-be trap into a recoverable error before any `OsRng` draw runs.
///
/// # Errors
///
/// Returns a [`JsError`] if the platform CSPRNG (WebCrypto on wasm) is unavailable.
fn probe_entropy() -> Result<(), JsError> {
    let mut probe = [0u8; 32];
    getrandom::getrandom(&mut probe)
        .map_err(|e| JsError::new(&format!("WebCrypto entropy unavailable: {e}")))
}

// ── Async helpers (drive synchronous-under-the-hood SoftwareKeystore async methods) ──

/// Drive `Keystore::device_identity` synchronously via `pollster`.
fn ks_device_identity(
    ks: &sh_crypto::SoftwareKeystore,
) -> Result<sh_crypto::DeviceIdentity, sh_crypto::CryptoError> {
    pollster::block_on(ks.device_identity())
}

/// Drive `Keystore::trust_peer` synchronously.
fn ks_trust_peer(
    ks: &sh_crypto::SoftwareKeystore,
    id: &sh_crypto::DeviceIdentity,
) -> Result<(), sh_crypto::CryptoError> {
    pollster::block_on(ks.trust_peer(id))
}

/// Drive `Keystore::is_trusted` synchronously.
fn ks_is_trusted(
    ks: &sh_crypto::SoftwareKeystore,
    id: &sh_crypto::DeviceIdentity,
) -> Result<bool, sh_crypto::CryptoError> {
    pollster::block_on(ks.is_trusted(id))
}

/// Drive `Keystore::revoke_peer` synchronously.
fn ks_revoke_peer(
    ks: &sh_crypto::SoftwareKeystore,
    id: &sh_crypto::DeviceIdentity,
) -> Result<(), sh_crypto::CryptoError> {
    pollster::block_on(ks.revoke_peer(id))
}

// ── WasmKeystore ─────────────────────────────────────────────────────────────

/// An opaque handle to a Streamhaul device identity and TOFU trust store.
///
/// Create one with [`WasmKeystore::generate`].  The underlying Ed25519 signing key NEVER
/// leaves wasm linear memory — no method exposes raw private-key bytes to JavaScript.
///
/// # Key security properties
///
/// - `generate()` uses `getrandom/js` (WebCrypto) as its CSPRNG — the same source browsers use
///   for `window.crypto.getRandomValues`.
/// - The inner [`sh_crypto::SoftwareKeystore`] is `ZeroizeOnDrop`: the Ed25519 scalar is zeroed
///   when this handle is dropped / GC'd.
/// - No signing-key accessor exists.  The only outward-facing key material is `fingerprint()` (a
///   SHA-256 hex of the public key) and `public_key_bytes()` (the 32-byte Ed25519 public point),
///   both of which are safe to transmit on the wire.
///
/// # Trust store
///
/// The trust store starts empty.  Call [`trust_peer_by_key`](Self::trust_peer_by_key) after a
/// successful Noise handshake + TOFU confirmation.  [`is_trusted_by_key`](Self::is_trusted_by_key)
/// gates subsequent connections.
///
/// # Examples (JavaScript)
///
/// ```js
/// const ks = WasmKeystore.generate(); // throws if WebCrypto unavailable
/// console.log(ks.fingerprint()); // 64-char hex
/// const pk = ks.public_key_bytes(); // Uint8Array(32)
/// ```
#[wasm_bindgen]
pub struct WasmKeystore {
    inner: sh_crypto::SoftwareKeystore,
}

#[wasm_bindgen]
impl WasmKeystore {
    /// Generates a fresh device identity using the browser's WebCrypto CSPRNG.
    ///
    /// Two successive calls always produce distinct identities (collision probability ≈ 1/2^256).
    ///
    /// # Errors
    ///
    /// Returns a `JsError` if the WebCrypto RNG is unavailable in this environment.
    /// On all standards-compliant browsers and Node.js 15+ this always succeeds.
    /// Returning an error is strongly preferable to a wasm trap (browser tab crash).
    #[wasm_bindgen]
    pub fn generate() -> Result<WasmKeystore, JsError> {
        // `SoftwareKeystore::generate()` draws from `OsRng` → `getrandom/js` → WebCrypto, and
        // `OsRng` *panics* (a wasm trap that crashes the tab — `catch_unwind` cannot recover it
        // on `wasm32-unknown-unknown`, which has no unwinding runtime) if WebCrypto is missing.
        // So we PROBE the entropy source first via getrandom's fallible API: it returns `Err`
        // (never panics) when WebCrypto is unavailable, which we surface as a catchable `JsError`.
        // On success, the subsequent `OsRng` draw is guaranteed to have a working source.
        probe_entropy()?;
        Ok(WasmKeystore {
            inner: sh_crypto::SoftwareKeystore::generate(),
        })
    }

    /// Returns this device's fingerprint: a 64-character lowercase hex string.
    ///
    /// The fingerprint is SHA-256(Ed25519 public key).  Safe to log and transmit.
    ///
    /// # Errors
    ///
    /// Returns a `JsError` if the underlying keystore is in an unexpected state.
    #[wasm_bindgen]
    pub fn fingerprint(&self) -> Result<String, JsError> {
        let id = ks_device_identity(&self.inner).map_err(crypto_err)?;
        Ok(id.fingerprint().as_str().to_owned())
    }

    /// Returns the 32-byte compressed Ed25519 public key as a `Uint8Array`.
    ///
    /// Public and safe to transmit — this is the verifying key, not the signing key.
    ///
    /// # Errors
    ///
    /// Returns a `JsError` if the underlying keystore is in an unexpected state.
    #[wasm_bindgen]
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, JsError> {
        let id = ks_device_identity(&self.inner).map_err(crypto_err)?;
        Ok(id.public_key_bytes().to_vec())
    }

    /// Pins the peer identified by `peer_pubkey_bytes` as trusted in the local TOFU store.
    ///
    /// `peer_pubkey_bytes` must be the 32-byte Ed25519 compressed public key (available from
    /// [`WasmHandshakeOutcome::peer_pubkey`] or [`decode_identity_proof_pubkey`]).
    ///
    /// Call this after the user confirms the peer's fingerprint during TOFU pairing.
    ///
    /// # Errors
    ///
    /// Returns a `JsError` if `peer_pubkey_bytes` is not exactly 32 bytes, is an invalid /
    /// small-order key, or if the trust store update fails.
    #[wasm_bindgen]
    pub fn trust_peer_by_key(&self, peer_pubkey_bytes: &[u8]) -> Result<(), JsError> {
        let id = identity_from_pubkey_bytes(peer_pubkey_bytes)?;
        ks_trust_peer(&self.inner, &id).map_err(crypto_err)
    }

    /// Returns `true` if the peer identified by `peer_pubkey_bytes` is currently trusted.
    ///
    /// `peer_pubkey_bytes` must be the 32-byte Ed25519 compressed public key.
    ///
    /// # Errors
    ///
    /// Returns a `JsError` if `peer_pubkey_bytes` is not exactly 32 bytes or is invalid.
    #[wasm_bindgen]
    pub fn is_trusted_by_key(&self, peer_pubkey_bytes: &[u8]) -> Result<bool, JsError> {
        let id = identity_from_pubkey_bytes(peer_pubkey_bytes)?;
        ks_is_trusted(&self.inner, &id).map_err(crypto_err)
    }

    /// Marks the peer identified by `peer_pubkey_bytes` as revoked in the local trust store.
    ///
    /// `peer_pubkey_bytes` must be the 32-byte Ed25519 compressed public key.
    ///
    /// # Errors
    ///
    /// Returns a `JsError` if `peer_pubkey_bytes` is not exactly 32 bytes or is invalid.
    #[wasm_bindgen]
    pub fn revoke_peer_by_key(&self, peer_pubkey_bytes: &[u8]) -> Result<(), JsError> {
        let id = identity_from_pubkey_bytes(peer_pubkey_bytes)?;
        ks_revoke_peer(&self.inner, &id).map_err(crypto_err)
    }
}

// ── R-SIG-AUTH: IdentityProof ────────────────────────────────────────────────

/// Signs a server-issued challenge, producing a 128-byte `IdentityProof` for R-SIG-AUTH.
///
/// The browser sends this in its signaling Hello message.  The server verifies it via
/// [`verify_identity_proof`] to prove the connecting peer owns the Ed25519 key behind the
/// fingerprint it claims.
///
/// # Parameters
///
/// - `keystore`: the local device identity (signing key stays in wasm).
/// - `session_id`: the 16-byte signaling session id.
/// - `challenge`: the 32-byte server-issued challenge nonce.
///
/// # Returns
///
/// 128 bytes: `DEVICE_PUBKEY[32] || CHALLENGE[32] || SIGNATURE[64]`.
///
/// # Errors
///
/// Returns a `JsError` if `session_id` is not exactly 16 bytes, `challenge` is not exactly
/// 32 bytes, or if the signing operation fails.
#[wasm_bindgen]
pub fn create_identity_proof(
    keystore: &WasmKeystore,
    session_id: &[u8],
    challenge: &[u8],
) -> Result<Vec<u8>, JsError> {
    let session_id_arr: [u8; 16] = session_id
        .try_into()
        .map_err(|_| JsError::new("session_id must be exactly 16 bytes"))?;
    let challenge_arr: [u8; 32] = challenge
        .try_into()
        .map_err(|_| JsError::new("challenge must be exactly 32 bytes"))?;

    let proof = pollster::block_on(sh_crypto::IdentityProof::create(
        &keystore.inner,
        &session_id_arr,
        &challenge_arr,
    ))
    .map_err(crypto_err)?;

    Ok(proof.encode().to_vec())
}

/// Verifies a received 128-byte `IdentityProof`.
///
/// Checks (in order): challenge binding, key validity (rejects weak/small-order keys),
/// fingerprint binding (constant-time), Ed25519 signature (`verify_strict`).
///
/// All checks return a uniform `JsError` — no oracle distinguishes which failed.
///
/// # Parameters
///
/// - `proof_bytes`: the 128-byte proof received from the peer.
/// - `expected_fp`: the 64-char lowercase hex fingerprint the peer claimed.
/// - `expected_session_id`: the 16-byte session id.
/// - `expected_challenge`: the 32-byte challenge nonce this server issued.
///
/// # Errors
///
/// Returns a `JsError` on any validation failure.
#[wasm_bindgen]
pub fn verify_identity_proof(
    proof_bytes: &[u8],
    expected_fp: &str,
    expected_session_id: &[u8],
    expected_challenge: &[u8],
) -> Result<(), JsError> {
    let session_id_arr: [u8; 16] = expected_session_id
        .try_into()
        .map_err(|_| JsError::new("expected_session_id must be exactly 16 bytes"))?;
    let challenge_arr: [u8; 32] = expected_challenge
        .try_into()
        .map_err(|_| JsError::new("expected_challenge must be exactly 32 bytes"))?;

    let proof = sh_crypto::IdentityProof::decode(proof_bytes).map_err(crypto_err)?;
    proof
        .verify(expected_fp, &session_id_arr, &challenge_arr)
        .map_err(crypto_err)
}

/// Extracts the 32-byte Ed25519 public key from a raw 128-byte `IdentityProof`.
///
/// Structural-only parse — does NOT verify the signature.  Call [`verify_identity_proof`] to
/// authenticate the proof.
///
/// # Errors
///
/// Returns a `JsError` if `proof_bytes` is not exactly 128 bytes.
#[wasm_bindgen]
pub fn decode_identity_proof_pubkey(proof_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    let proof = sh_crypto::IdentityProof::decode(proof_bytes).map_err(crypto_err)?;
    Ok(proof.device_pubkey().to_vec())
}

/// Derives a Streamhaul fingerprint (64-char hex) from a 32-byte Ed25519 public key.
///
/// # Errors
///
/// Returns a `JsError` if `pubkey_bytes` is not exactly 32 bytes or is an invalid / weak key.
#[wasm_bindgen]
pub fn fingerprint_from_pubkey(pubkey_bytes: &[u8]) -> Result<String, JsError> {
    let id = identity_from_pubkey_bytes(pubkey_bytes)?;
    Ok(id.fingerprint().as_str().to_owned())
}

// ── WasmNoiseHandshake ────────────────────────────────────────────────────────

/// An in-progress Noise XK or IK handshake.
///
/// # Message exchange (XK, 3 messages)
///
/// ```text
/// initiator: msg0 = write_message()
/// responder: read_message(msg0); msg1 = write_message()
/// initiator: read_message(msg1); msg2 = write_message()
/// responder: read_message(msg2)
/// both:      outcome = complete_trusted(ks)  OR  complete_for_first_pairing()
/// ```
///
/// # Message exchange (IK, 2 messages)
///
/// ```text
/// initiator: msg0 = write_message()
/// responder: read_message(msg0); msg1 = write_message()
/// initiator: read_message(msg1)
/// both:      outcome = complete_trusted(ks)  OR  complete_for_first_pairing()
/// ```
///
/// # Key security properties
///
/// The local X25519 static secret is generated inside this struct and NEVER exposed to JS.
/// The `BindCert` (carrying the committed DTLS fingerprint) is built and serialized inside
/// wasm; only the encrypted Noise handshake messages leave the wasm boundary.
///
/// `complete_trusted` enforces the trust check (step 6 of the BindCert protocol) and MUST
/// be used on all reconnect paths.
/// `complete_for_first_pairing` skips the trust check for TOFU — the caller MUST present
/// the peer fingerprint to the user and call [`WasmKeystore::trust_peer_by_key`] before
/// establishing a session.  **Do NOT call `complete_for_first_pairing` on reconnect.**
/// Doing so would silently accept any key, defeating TOFU pinning.
/// (Type-level enforcement — a distinct first-pairing outcome type that cannot be used to
/// open a session without going through `trust_peer_by_key` — is tracked under
/// R-BROWSER-CRYPTO-LIVE and lands with the live RTCPeerConnection wiring PR.)
#[wasm_bindgen]
pub struct WasmNoiseHandshake {
    inner: Option<sh_crypto::NoiseHandshake>,
}

#[wasm_bindgen]
impl WasmNoiseHandshake {
    /// Creates an XK initiator handshake that commits `local_dtls_fp` (WebRTC / P4-5).
    ///
    /// `peer_static_pub`: the 32-byte X25519 public key of the responder (from a prior
    /// handshake's `WasmHandshakeOutcome::peer_noise_static_pub`, or from TOFU storage).
    /// `local_dtls_fp`: the 32-byte SHA-256 of the local DTLS whole-certificate.
    /// `session_context`: 0–32 byte context (QUIC exporter output or empty for WebRTC).
    ///
    /// # Errors
    ///
    /// Returns a `JsError` if `peer_static_pub` or `local_dtls_fp` is not exactly 32 bytes.
    #[wasm_bindgen]
    pub fn initiator_xk_with_dtls(
        keystore: &WasmKeystore,
        peer_static_pub: &[u8],
        local_dtls_fp: &[u8],
        session_context: &[u8],
    ) -> Result<WasmNoiseHandshake, JsError> {
        let peer_pub: [u8; 32] = peer_static_pub
            .try_into()
            .map_err(|_| JsError::new("peer_static_pub must be exactly 32 bytes"))?;
        let dtls_fp: [u8; 32] = local_dtls_fp
            .try_into()
            .map_err(|_| JsError::new("local_dtls_fp must be exactly 32 bytes"))?;
        let commitment = sh_crypto::DtlsCommitment::sha256(dtls_fp);
        probe_entropy()?;
        let local_static = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let clock = WasmClock;
        let hs = pollster::block_on(sh_crypto::NoiseHandshake::initiator_xk_with_dtls(
            &keystore.inner,
            local_static,
            peer_pub,
            session_context,
            commitment,
            &clock,
        ))
        .map_err(crypto_err)?;
        Ok(WasmNoiseHandshake { inner: Some(hs) })
    }

    /// Creates an XK responder handshake that commits `local_dtls_fp` (WebRTC / P4-5).
    ///
    /// The local X25519 static key is generated internally and NEVER exposed to JS.
    ///
    /// # Errors
    ///
    /// Returns a `JsError` if `local_dtls_fp` is not exactly 32 bytes.
    #[wasm_bindgen]
    pub fn responder_xk_with_dtls(
        keystore: &WasmKeystore,
        local_dtls_fp: &[u8],
        session_context: &[u8],
    ) -> Result<WasmNoiseHandshake, JsError> {
        let dtls_fp: [u8; 32] = local_dtls_fp
            .try_into()
            .map_err(|_| JsError::new("local_dtls_fp must be exactly 32 bytes"))?;
        let commitment = sh_crypto::DtlsCommitment::sha256(dtls_fp);
        probe_entropy()?;
        let local_static = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let clock = WasmClock;
        let hs = pollster::block_on(sh_crypto::NoiseHandshake::responder_xk_with_dtls(
            &keystore.inner,
            local_static,
            session_context,
            commitment,
            &clock,
        ))
        .map_err(crypto_err)?;
        Ok(WasmNoiseHandshake { inner: Some(hs) })
    }

    /// Creates an IK initiator handshake that commits `local_dtls_fp` (post-pairing reconnect).
    ///
    /// # Errors
    ///
    /// Returns a `JsError` if `peer_static_pub` or `local_dtls_fp` is not exactly 32 bytes.
    #[wasm_bindgen]
    pub fn initiator_ik_with_dtls(
        keystore: &WasmKeystore,
        peer_static_pub: &[u8],
        local_dtls_fp: &[u8],
        session_context: &[u8],
    ) -> Result<WasmNoiseHandshake, JsError> {
        let peer_pub: [u8; 32] = peer_static_pub
            .try_into()
            .map_err(|_| JsError::new("peer_static_pub must be exactly 32 bytes"))?;
        let dtls_fp: [u8; 32] = local_dtls_fp
            .try_into()
            .map_err(|_| JsError::new("local_dtls_fp must be exactly 32 bytes"))?;
        let commitment = sh_crypto::DtlsCommitment::sha256(dtls_fp);
        probe_entropy()?;
        let local_static = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let clock = WasmClock;
        let hs = pollster::block_on(sh_crypto::NoiseHandshake::initiator_ik_with_dtls(
            &keystore.inner,
            local_static,
            peer_pub,
            session_context,
            commitment,
            &clock,
        ))
        .map_err(crypto_err)?;
        Ok(WasmNoiseHandshake { inner: Some(hs) })
    }

    /// Creates an IK responder handshake that commits `local_dtls_fp`.
    ///
    /// # Errors
    ///
    /// Returns a `JsError` if `local_dtls_fp` is not exactly 32 bytes.
    #[wasm_bindgen]
    pub fn responder_ik_with_dtls(
        keystore: &WasmKeystore,
        local_dtls_fp: &[u8],
        session_context: &[u8],
    ) -> Result<WasmNoiseHandshake, JsError> {
        let dtls_fp: [u8; 32] = local_dtls_fp
            .try_into()
            .map_err(|_| JsError::new("local_dtls_fp must be exactly 32 bytes"))?;
        let commitment = sh_crypto::DtlsCommitment::sha256(dtls_fp);
        probe_entropy()?;
        let local_static = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let clock = WasmClock;
        let hs = pollster::block_on(sh_crypto::NoiseHandshake::responder_ik_with_dtls(
            &keystore.inner,
            local_static,
            session_context,
            commitment,
            &clock,
        ))
        .map_err(crypto_err)?;
        Ok(WasmNoiseHandshake { inner: Some(hs) })
    }

    /// Writes the next handshake message, returning the bytes to send to the peer.
    ///
    /// At the appropriate message index, the local `BindCert` (with the committed DTLS
    /// fingerprint) is automatically injected into the Noise payload.
    ///
    /// # Errors
    ///
    /// Returns a `JsError` if the handshake is poisoned or already completed.
    #[wasm_bindgen]
    pub fn write_message(&mut self) -> Result<Vec<u8>, JsError> {
        let hs = self
            .inner
            .as_mut()
            .ok_or_else(|| JsError::new("handshake has already been completed or consumed"))?;
        hs.write_message().map_err(crypto_err)
    }

    /// Reads a handshake message from the peer.
    ///
    /// At the expected message index the peer's `BindCert` is extracted and verified
    /// (structural check + signature + freshness + Noise-static binding).
    ///
    /// # Errors
    ///
    /// Returns a `JsError` on any handshake or `BindCert` verification failure.
    #[wasm_bindgen]
    pub fn read_message(&mut self, msg: &[u8]) -> Result<(), JsError> {
        let hs = self
            .inner
            .as_mut()
            .ok_or_else(|| JsError::new("handshake has already been completed or consumed"))?;
        let clock = WasmClock;
        hs.read_message(msg, &clock).map_err(crypto_err)
    }

    /// Returns `true` if all handshake messages have been exchanged and `complete_*` is ready.
    #[wasm_bindgen]
    pub fn is_finished(&self) -> bool {
        self.inner.as_ref().is_some_and(|hs| hs.is_finished())
    }

    /// Completes the handshake for a **trusted** peer (post-pairing reconnect).
    ///
    /// Enforces the trust check: the peer must be in the local TOFU store.
    ///
    /// # Errors
    ///
    /// - `peer identity is not trusted` (`UntrustedPeer`) if the peer is not pinned.
    /// - Other `JsError` variants on structural / cryptographic failure.
    #[wasm_bindgen]
    pub fn complete_trusted(
        &mut self,
        keystore: &WasmKeystore,
    ) -> Result<WasmHandshakeOutcome, JsError> {
        let hs = self
            .inner
            .take()
            .ok_or_else(|| JsError::new("handshake has already been completed or consumed"))?;
        let outcome =
            pollster::block_on(hs.complete(&keystore.inner)).map_err(crypto_err)?;
        WasmHandshakeOutcome::from_native(outcome)
    }

    /// Completes the handshake for **TOFU first pairing**, skipping the trust check.
    ///
    /// **Use only on the first connection to a new device.** On reconnect always use
    /// `complete_trusted` so the trust store is enforced.  Using this method on reconnect
    /// silently accepts any peer key — defeating TOFU pinning.
    ///
    /// The caller MUST present `peer_fingerprint` from the resulting outcome to the user for
    /// TOFU confirmation and then call [`WasmKeystore::trust_peer_by_key`] before
    /// establishing a session.
    ///
    /// # Errors
    ///
    /// Returns a `JsError` if the handshake is not finished, the peer BindCert was never
    /// received / verified, or any structural check fails.
    #[wasm_bindgen]
    pub fn complete_for_first_pairing(&mut self) -> Result<WasmHandshakeOutcome, JsError> {
        // `TrustAllKeystore::new()` draws from `OsRng`; probe entropy first so an unavailable
        // WebCrypto surfaces as a catchable error rather than a wasm trap.
        probe_entropy()?;
        let hs = self
            .inner
            .take()
            .ok_or_else(|| JsError::new("handshake has already been completed or consumed"))?;
        // Drive `complete()` against a trust-all keystore so the trust check passes.
        // The trust-all keystore is an ephemeral `SoftwareKeystore` that overrides
        // `is_trusted` to return `true`.  It is dropped immediately after this call;
        // its signing key is zeroized on drop.
        let trust_all = TrustAllKeystore::new();
        let outcome =
            pollster::block_on(hs.complete(&trust_all)).map_err(crypto_err)?;
        WasmHandshakeOutcome::from_native(outcome)
    }
}

// ── TrustAllKeystore ──────────────────────────────────────────────────────────

/// A synthetic [`sh_crypto::Keystore`] that always returns `true` from `is_trusted`.
///
/// Used exclusively in [`WasmNoiseHandshake::complete_for_first_pairing`] to bypass the
/// trust check during TOFU first-pairing.  Ephemeral — created and dropped within that call.
///
/// `NoiseHandshake::complete` only calls `is_trusted` on this keystore (not `device_identity`
/// or `sign`).  The `device_identity` / `sign` / `trust_peer` / `revoke_peer` /
/// `was_peer_revoked` / `trust_peer_if_not_revoked` implementations delegate to an inner
/// `SoftwareKeystore` whose ephemeral signing key is zeroized on drop — these are present
/// only to satisfy the `Keystore` trait bound, not because `complete` calls them.
struct TrustAllKeystore {
    inner: sh_crypto::SoftwareKeystore,
}

impl TrustAllKeystore {
    fn new() -> Self {
        Self {
            inner: sh_crypto::SoftwareKeystore::generate(),
        }
    }
}

#[async_trait::async_trait]
impl sh_crypto::Keystore for TrustAllKeystore {
    async fn device_identity(
        &self,
    ) -> Result<sh_crypto::DeviceIdentity, sh_crypto::CryptoError> {
        self.inner.device_identity().await
    }

    async fn sign(
        &self,
        data: &[u8],
    ) -> Result<sh_crypto::Signature, sh_crypto::CryptoError> {
        self.inner.sign(data).await
    }

    async fn trust_peer(
        &self,
        id: &sh_crypto::DeviceIdentity,
    ) -> Result<(), sh_crypto::CryptoError> {
        self.inner.trust_peer(id).await
    }

    async fn is_trusted(
        &self,
        _id: &sh_crypto::DeviceIdentity,
    ) -> Result<bool, sh_crypto::CryptoError> {
        // Trust all peers — only used for TOFU first-pairing.
        Ok(true)
    }

    async fn revoke_peer(
        &self,
        id: &sh_crypto::DeviceIdentity,
    ) -> Result<(), sh_crypto::CryptoError> {
        self.inner.revoke_peer(id).await
    }

    async fn was_peer_revoked(
        &self,
        id: &sh_crypto::DeviceIdentity,
    ) -> Result<bool, sh_crypto::CryptoError> {
        self.inner.was_peer_revoked(id).await
    }

    async fn trust_peer_if_not_revoked(
        &self,
        id: &sh_crypto::DeviceIdentity,
    ) -> Result<sh_crypto::pairing::TrustOutcome, sh_crypto::CryptoError> {
        // Honour the revocation list even in TOFU mode.  Without this check,
        // `complete()` calling this method would silently re-pin a revoked peer,
        // bypassing the revocation gate — a latent security violation if `complete()`
        // ever routes through `trust_peer_if_not_revoked` on a future code path.
        if self.inner.was_peer_revoked(id).await? {
            return Ok(sh_crypto::pairing::TrustOutcome::WasRevoked);
        }
        self.inner.trust_peer(id).await?;
        Ok(sh_crypto::pairing::TrustOutcome::Pinned)
    }
}

// ── WasmHandshakeOutcome ──────────────────────────────────────────────────────

/// The result of a completed and fully-verified Noise handshake.
///
/// Contains the peer's verified fingerprint and public key, and the DTLS pin the browser
/// must enforce against the WebRTC SDP `a=fingerprint` field.
#[wasm_bindgen]
pub struct WasmHandshakeOutcome {
    /// The peer's verified fingerprint (64-char hex).
    peer_fingerprint: String,
    /// The peer's 32-byte Ed25519 public key (for trust-store operations).
    peer_pubkey: [u8; 32],
    /// The peer's committed DTLS SHA-256 fingerprint (32 bytes), or `None` if QUIC/ALG=NONE.
    dtls_pin: Option<[u8; 32]>,
}

impl WasmHandshakeOutcome {
    /// Build from a native [`sh_crypto::HandshakeOutcome`].
    fn from_native(outcome: sh_crypto::HandshakeOutcome) -> Result<Self, JsError> {
        let peer_fingerprint = outcome.peer_identity.fingerprint().as_str().to_owned();
        let peer_pubkey = *outcome.peer_identity.public_key_bytes();
        // dtls_pin: Some if the peer committed a non-zero SHA-256 fingerprint.
        let dtls_pin = outcome.peer_bind_cert.dtls_pin().map(|p| *p.commit());
        Ok(Self {
            peer_fingerprint,
            peer_pubkey,
            dtls_pin,
        })
    }
}

#[wasm_bindgen]
impl WasmHandshakeOutcome {
    /// Returns the peer's verified fingerprint (64-char lowercase hex).
    ///
    /// Authenticated: derived from the identity-signed `BindCert` delivered inside the
    /// verified Noise handshake.  Use for TOFU display and trust-store update.
    #[wasm_bindgen(getter)]
    pub fn peer_fingerprint(&self) -> String {
        self.peer_fingerprint.clone()
    }

    /// Returns the peer's 32-byte Ed25519 public key.
    ///
    /// Needed for [`WasmKeystore::trust_peer_by_key`] after TOFU confirmation.
    /// Public and safe to store.
    #[wasm_bindgen(getter)]
    pub fn peer_pubkey(&self) -> Vec<u8> {
        self.peer_pubkey.to_vec()
    }

    /// Returns the 32-byte DTLS pin the browser must enforce against the WebRTC SDP
    /// `a=fingerprint` field, or `undefined` if absent or all-zero (QUIC / ALG=NONE / downgrade).
    ///
    /// **Always returns `None`/`undefined` for all-zero commits** (where the peer sent
    /// `ALG=SHA256` but a zero commit — a malformed or downgrade attempt).  This prevents a
    /// JS caller from doing `if (outcome.dtls_pin !== undefined)` and bypassing the gate on
    /// a zero-commit outcome.  Use [`require_dtls_pin`](Self::require_dtls_pin) on the WebRTC
    /// path to enforce this as a hard error.
    #[wasm_bindgen(getter)]
    pub fn dtls_pin(&self) -> Option<Vec<u8>> {
        // Mirror `has_dtls_pin`: only expose a pin when it is non-zero.
        // A zero-commit Some([0;32]) is treated identically to None — both are downgrade.
        match self.dtls_pin {
            Some(pin) if pin != [0u8; 32] => Some(pin.to_vec()),
            _ => None,
        }
    }

    /// Returns the 32-byte DTLS pin, throwing a `JsError` if none is present (P4-5 anti-downgrade gate).
    ///
    /// Use this on the WebRTC session path where a missing or all-zero DTLS binding MUST be a
    /// hard abort.
    ///
    /// # Errors
    ///
    /// Returns `JsError` (DtlsBindingMissing) if the peer's `BindCert` carries `DTLS_FPR_ALG = NONE`
    /// or an all-zero commit.
    #[wasm_bindgen]
    pub fn require_dtls_pin(&self) -> Result<Vec<u8>, JsError> {
        match self.dtls_pin {
            Some(pin) if pin != [0u8; 32] => Ok(pin.to_vec()),
            _ => Err(crypto_err(sh_crypto::CryptoError::DtlsBindingMissing)),
        }
    }

    /// Returns `true` if this peer committed a non-zero SHA-256 DTLS fingerprint.
    #[wasm_bindgen]
    pub fn has_dtls_pin(&self) -> bool {
        self.dtls_pin.is_some_and(|p| p != [0u8; 32])
    }

    /// Returns `true` if `pinned_fp` matches the peer's verified fingerprint (constant-time).
    ///
    /// Use on post-pairing reconnect to confirm the peer is the same device as before.
    ///
    /// # Errors
    ///
    /// Returns a `JsError` if `pinned_fp` is not exactly 64 ASCII characters.
    /// Non-ASCII input (e.g. multi-byte UTF-8 that is 64 bytes but fewer than 64 chars) is
    /// rejected rather than silently returning `Ok(false)` (which would misclassify a valid
    /// trusted peer as untrusted on reconnect).
    #[wasm_bindgen]
    pub fn verify_peer_fingerprint(&self, pinned_fp: &str) -> Result<bool, JsError> {
        // `.len()` on `&str` counts *bytes*, not characters.  A 64-byte multi-byte-UTF-8
        // string has fewer than 64 characters and is not a valid hex fingerprint.
        // The `.is_ascii()` guard rejects that class and ensures each byte is a valid hex
        // digit candidate, preventing a `Ok(false)` mis-result on malformed input.
        if pinned_fp.len() != 64 || !pinned_fp.is_ascii() {
            return Err(JsError::new(
                "pinned_fp must be exactly 64 ASCII hex characters",
            ));
        }
        use subtle::ConstantTimeEq as _;
        let matches = self
            .peer_fingerprint
            .as_bytes()
            .ct_eq(pinned_fp.as_bytes())
            .unwrap_u8()
            == 1;
        Ok(matches)
    }
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Construct a [`sh_crypto::DeviceIdentity`] from a 32-byte public key slice.
///
/// Returns `JsError` if the slice is not exactly 32 bytes or is an invalid / small-order key.
fn identity_from_pubkey_bytes(bytes: &[u8]) -> Result<sh_crypto::DeviceIdentity, JsError> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| JsError::new("public key must be exactly 32 bytes"))?;
    sh_crypto::DeviceIdentity::from_public_key_bytes(&arr).map_err(crypto_err)
}

// ── Wire-parity + security tests (wasm-pack test --node) ─────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use wasm_bindgen_test::wasm_bindgen_test;

    // Configure the test runner to use Node.js (no browser required).
    // WebCrypto CSPRNG is available in Node via the built-in `crypto` module.
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_node_experimental);

    // ── Identity / CSPRNG entropy tests ──────────────────────────────────

    /// Two freshly generated identities must differ — proves WebCrypto CSPRNG produces
    /// real entropy (not a stub/constant).
    #[wasm_bindgen_test]
    fn two_generated_identities_differ() {
        let ks1 = crate::WasmKeystore::generate().unwrap();
        let ks2 = crate::WasmKeystore::generate().unwrap();
        let fp1 = ks1.fingerprint().unwrap();
        let fp2 = ks2.fingerprint().unwrap();
        assert_ne!(fp1, fp2, "two identities must differ (CSPRNG entropy check)");
    }

    /// Fingerprint is stable across repeated calls and has the correct format.
    #[wasm_bindgen_test]
    fn fingerprint_is_stable_and_correct_format() {
        let ks = crate::WasmKeystore::generate().unwrap();
        let fp1 = ks.fingerprint().unwrap();
        let fp2 = ks.fingerprint().unwrap();
        assert_eq!(fp1, fp2, "fingerprint must be stable");
        assert_eq!(fp1.len(), 64, "fingerprint must be 64 hex chars");
        assert!(
            fp1.chars().all(|c| c.is_ascii_hexdigit()),
            "fingerprint must be lowercase hex"
        );
    }

    /// `public_key_bytes()` → `fingerprint_from_pubkey()` round-trip.
    #[wasm_bindgen_test]
    fn pubkey_bytes_to_fingerprint_roundtrip() {
        let ks = crate::WasmKeystore::generate().unwrap();
        let fp_direct = ks.fingerprint().unwrap();
        let pk = ks.public_key_bytes().unwrap();
        assert_eq!(pk.len(), 32, "public key must be 32 bytes");
        let fp_derived = crate::fingerprint_from_pubkey(&pk).unwrap();
        assert_eq!(
            fp_direct, fp_derived,
            "fingerprint derived from pubkey must match direct"
        );
    }

    // ── R-SIG-AUTH: IdentityProof tests ──────────────────────────────────

    /// create_identity_proof → verify_identity_proof: valid round-trip.
    #[wasm_bindgen_test]
    fn identity_proof_valid_roundtrip() {
        let ks = crate::WasmKeystore::generate().unwrap();
        let session_id = [0x11u8; 16];
        let challenge = [0x22u8; 32];

        let proof_bytes = crate::create_identity_proof(&ks, &session_id, &challenge).unwrap();
        assert_eq!(proof_bytes.len(), 128, "proof must be 128 bytes");

        let fp = ks.fingerprint().unwrap();
        crate::verify_identity_proof(&proof_bytes, &fp, &session_id, &challenge).unwrap();
    }

    /// Cross-target parity: a proof created via the wasm bridge verifies natively via the
    /// native `sh_crypto::IdentityProof::verify` path — and vice versa.  This proves
    /// byte-identical wire format between the wasm bridge and the native stack.
    #[wasm_bindgen_test]
    fn identity_proof_cross_target_parity() {
        use sh_crypto::{IdentityProof, Keystore as _, SoftwareKeystore};

        let session_id = [0x55u8; 16];
        let challenge = [0x66u8; 32];

        // Build proof via native SoftwareKeystore, verify via wasm bridge.
        let native_ks = SoftwareKeystore::generate();
        let native_id = pollster::block_on(native_ks.device_identity()).unwrap();
        let native_proof =
            pollster::block_on(IdentityProof::create(&native_ks, &session_id, &challenge))
                .unwrap();
        let native_wire = native_proof.encode();
        // The wasm bridge must accept the native-produced proof.
        crate::verify_identity_proof(
            &native_wire,
            native_id.fingerprint().as_str(),
            &session_id,
            &challenge,
        )
        .unwrap();

        // Build proof via wasm bridge, verify natively.
        let wasm_ks = crate::WasmKeystore::generate().unwrap();
        let wasm_fp = wasm_ks.fingerprint().unwrap();
        let wasm_wire = crate::create_identity_proof(&wasm_ks, &session_id, &challenge).unwrap();
        // Decode and verify natively.
        let decoded = IdentityProof::decode(&wasm_wire).unwrap();
        decoded
            .verify(&wasm_fp, &session_id, &challenge)
            .unwrap();
    }

    /// Wrong challenge is rejected.
    #[wasm_bindgen_test]
    fn identity_proof_wrong_challenge_rejected() {
        let ks = crate::WasmKeystore::generate().unwrap();
        let session_id = [0x11u8; 16];
        let challenge = [0x22u8; 32];
        let wrong_challenge = [0x99u8; 32];

        let proof_bytes = crate::create_identity_proof(&ks, &session_id, &challenge).unwrap();
        let fp = ks.fingerprint().unwrap();
        let result =
            crate::verify_identity_proof(&proof_bytes, &fp, &session_id, &wrong_challenge);
        assert!(result.is_err(), "wrong challenge must return error");
    }

    /// Wrong fingerprint is rejected.
    #[wasm_bindgen_test]
    fn identity_proof_wrong_fingerprint_rejected() {
        let ks = crate::WasmKeystore::generate().unwrap();
        let other_ks = crate::WasmKeystore::generate().unwrap();
        let session_id = [0x11u8; 16];
        let challenge = [0x22u8; 32];

        let proof_bytes = crate::create_identity_proof(&ks, &session_id, &challenge).unwrap();
        let other_fp = other_ks.fingerprint().unwrap();
        let result =
            crate::verify_identity_proof(&proof_bytes, &other_fp, &session_id, &challenge);
        assert!(result.is_err(), "wrong fingerprint must return error");
    }

    /// Tampered signature is rejected.
    #[wasm_bindgen_test]
    fn identity_proof_tampered_signature_rejected() {
        let ks = crate::WasmKeystore::generate().unwrap();
        let session_id = [0x11u8; 16];
        let challenge = [0x22u8; 32];

        let mut proof_bytes = crate::create_identity_proof(&ks, &session_id, &challenge).unwrap();
        // Flip a byte in the signature region (bytes 64–127).
        proof_bytes[64] ^= 0xff;
        let fp = ks.fingerprint().unwrap();
        let result = crate::verify_identity_proof(&proof_bytes, &fp, &session_id, &challenge);
        assert!(result.is_err(), "tampered signature must return error");
    }

    // ── Hostile-input tests (no trap / no panic) ──────────────────────────

    /// Empty proof input → JsError, no wasm trap.
    #[wasm_bindgen_test]
    fn identity_proof_empty_input_is_js_error() {
        let session_id = [0u8; 16];
        let challenge = [0u8; 32];
        let result = crate::verify_identity_proof(&[], "a".repeat(64).as_str(), &session_id, &challenge);
        assert!(result.is_err(), "empty proof must return error");
    }

    /// 127-byte proof (one short) → JsError.
    #[wasm_bindgen_test]
    fn identity_proof_truncated_input_is_js_error() {
        let session_id = [0u8; 16];
        let challenge = [0u8; 32];
        let result =
            crate::verify_identity_proof(&[0u8; 127], "a".repeat(64).as_str(), &session_id, &challenge);
        assert!(result.is_err(), "127-byte proof must return error");
    }

    /// 256 bytes of 0xFF → JsError.
    #[wasm_bindgen_test]
    fn identity_proof_garbage_input_is_js_error() {
        let session_id = [0u8; 16];
        let challenge = [0u8; 32];
        let result = crate::verify_identity_proof(
            &[0xffu8; 256],
            "f".repeat(64).as_str(),
            &session_id,
            &challenge,
        );
        assert!(result.is_err(), "garbage proof must return error");
    }

    /// `decode_identity_proof_pubkey` on wrong-length input → JsError.
    #[wasm_bindgen_test]
    fn decode_proof_pubkey_wrong_length_is_js_error() {
        assert!(crate::decode_identity_proof_pubkey(&[]).is_err());
        assert!(crate::decode_identity_proof_pubkey(&[0u8; 127]).is_err());
        assert!(crate::decode_identity_proof_pubkey(&[0u8; 200]).is_err());
    }

    /// Garbage Noise message to a freshly created responder → JsError, no trap.
    #[wasm_bindgen_test]
    fn noise_read_garbage_is_js_error() {
        let ks = crate::WasmKeystore::generate().unwrap();
        let dtls_fp = [0x11u8; 32];
        let mut hs =
            crate::WasmNoiseHandshake::responder_xk_with_dtls(&ks, &dtls_fp, &[]).unwrap();
        assert!(
            hs.read_message(&[0xffu8; 256]).is_err(),
            "garbage Noise msg must return JsError"
        );
    }

    /// Empty Noise message → JsError, no trap.
    #[wasm_bindgen_test]
    fn noise_read_empty_is_js_error() {
        let ks = crate::WasmKeystore::generate().unwrap();
        let dtls_fp = [0x11u8; 32];
        let mut hs =
            crate::WasmNoiseHandshake::responder_xk_with_dtls(&ks, &dtls_fp, &[]).unwrap();
        assert!(
            hs.read_message(&[]).is_err(),
            "empty Noise msg must return JsError"
        );
    }

    // ── Full Noise XK handshake + DTLS binding ────────────────────────────

    /// Full XK handshake between two in-wasm parties (driven via native sh-crypto) with DTLS
    /// fingerprint binding.  Each side extracts the peer's DTLS pin and verifies it equals the
    /// other side's committed fingerprint.  Mirrors `xk_with_dtls_propagates_peer_pin` from the
    /// native test suite but driven entirely in wasm linear memory.
    #[wasm_bindgen_test]
    fn full_xk_handshake_with_dtls_binding() {
        use sh_crypto::{DtlsCommitment, Keystore as _, NoiseHandshake, SoftwareKeystore};

        let init_ks = SoftwareKeystore::generate();
        let resp_ks = SoftwareKeystore::generate();
        let clock = sh_types::FixedClock(1_000_000_000_i64);

        let resp_static = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let resp_pub = x25519_dalek::PublicKey::from(&resp_static);
        let init_static = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);

        let init_dtls = [0x11u8; 32];
        let resp_dtls = [0x22u8; 32];

        // Trust each other so complete() succeeds.
        let resp_id = pollster::block_on(resp_ks.device_identity()).unwrap();
        let init_id = pollster::block_on(init_ks.device_identity()).unwrap();
        pollster::block_on(init_ks.trust_peer(&resp_id)).unwrap();
        pollster::block_on(resp_ks.trust_peer(&init_id)).unwrap();

        let mut native_init = pollster::block_on(NoiseHandshake::initiator_xk_with_dtls(
            &init_ks,
            init_static,
            resp_pub.to_bytes(),
            &[],
            DtlsCommitment::sha256(init_dtls),
            &clock,
        ))
        .unwrap();

        let mut native_resp = pollster::block_on(NoiseHandshake::responder_xk_with_dtls(
            &resp_ks,
            resp_static,
            &[],
            DtlsCommitment::sha256(resp_dtls),
            &clock,
        ))
        .unwrap();

        // XK: 3 messages.
        let msg0 = native_init.write_message().unwrap();
        native_resp.read_message(&msg0, &clock).unwrap();
        let msg1 = native_resp.write_message().unwrap();
        native_init.read_message(&msg1, &clock).unwrap();
        let msg2 = native_init.write_message().unwrap();
        native_resp.read_message(&msg2, &clock).unwrap();

        assert!(native_init.is_finished());
        assert!(native_resp.is_finished());

        let init_outcome = pollster::block_on(native_init.complete(&init_ks)).unwrap();
        let resp_outcome = pollster::block_on(native_resp.complete(&resp_ks)).unwrap();

        // DTLS pin propagation: each side sees the other's committed fingerprint.
        assert_eq!(
            init_outcome.require_webrtc_dtls_pin().unwrap(),
            resp_dtls,
            "initiator must see responder's DTLS fingerprint"
        );
        assert_eq!(
            resp_outcome.require_webrtc_dtls_pin().unwrap(),
            init_dtls,
            "responder must see initiator's DTLS fingerprint"
        );

        // Wrap native outcomes in WasmHandshakeOutcome and verify the wasm bridge exposes the same pins.
        let wasm_init_outcome =
            crate::WasmHandshakeOutcome::from_native(init_outcome).unwrap();
        let wasm_resp_outcome =
            crate::WasmHandshakeOutcome::from_native(resp_outcome).unwrap();

        assert_eq!(
            wasm_init_outcome.require_dtls_pin().unwrap(),
            resp_dtls.to_vec(),
            "wasm initiator outcome must expose responder DTLS pin"
        );
        assert_eq!(
            wasm_resp_outcome.require_dtls_pin().unwrap(),
            init_dtls.to_vec(),
            "wasm responder outcome must expose initiator DTLS pin"
        );
        assert!(wasm_init_outcome.has_dtls_pin());
        assert!(wasm_resp_outcome.has_dtls_pin());

        // Fingerprints are correct.
        assert_eq!(
            wasm_init_outcome.peer_fingerprint(),
            resp_id.fingerprint().as_str()
        );
        assert_eq!(
            wasm_resp_outcome.peer_fingerprint(),
            init_id.fingerprint().as_str()
        );
    }

    /// Downgrade test: an outcome with `DTLS_FPR_ALG = NONE` (all-zero pin) causes
    /// `require_dtls_pin()` to return `JsError` — the P4-5 anti-downgrade gate.
    #[wasm_bindgen_test]
    fn dtls_binding_missing_is_js_error() {
        // All-zero pin = ALG=NONE / downgrade attempt.
        let outcome = crate::WasmHandshakeOutcome {
            peer_fingerprint: "a".repeat(64),
            peer_pubkey: [0u8; 32],
            dtls_pin: Some([0u8; 32]),
        };
        assert!(
            outcome.require_dtls_pin().is_err(),
            "all-zero DTLS pin must return JsError"
        );

        // None pin = QUIC path; also an error on WebRTC.
        let outcome_none = crate::WasmHandshakeOutcome {
            peer_fingerprint: "a".repeat(64),
            peer_pubkey: [0u8; 32],
            dtls_pin: None,
        };
        assert!(
            outcome_none.require_dtls_pin().is_err(),
            "None DTLS pin must return JsError for WebRTC path"
        );
    }

    /// `verify_peer_fingerprint` uses constant-time comparison.
    #[wasm_bindgen_test]
    fn verify_peer_fingerprint_constant_time() {
        let ks = crate::WasmKeystore::generate().unwrap();
        let fp = ks.fingerprint().unwrap();
        let outcome = crate::WasmHandshakeOutcome {
            peer_fingerprint: fp.clone(),
            peer_pubkey: [0u8; 32],
            dtls_pin: None,
        };
        assert!(outcome.verify_peer_fingerprint(&fp).unwrap());
        let other_ks = crate::WasmKeystore::generate().unwrap();
        let other_fp = other_ks.fingerprint().unwrap();
        assert!(!outcome.verify_peer_fingerprint(&other_fp).unwrap());
    }

    /// Trust-store round-trip: trust → is_trusted → revoke → not trusted.
    #[wasm_bindgen_test]
    fn trust_store_roundtrip() {
        let ks = crate::WasmKeystore::generate().unwrap();
        let peer_ks = crate::WasmKeystore::generate().unwrap();
        let peer_pk = peer_ks.public_key_bytes().unwrap();

        assert!(!ks.is_trusted_by_key(&peer_pk).unwrap(), "initially not trusted");
        ks.trust_peer_by_key(&peer_pk).unwrap();
        assert!(ks.is_trusted_by_key(&peer_pk).unwrap(), "should be trusted after pin");
        ks.revoke_peer_by_key(&peer_pk).unwrap();
        assert!(
            !ks.is_trusted_by_key(&peer_pk).unwrap(),
            "should not be trusted after revoke"
        );
    }

    /// `fingerprint_from_pubkey` with invalid keys returns `JsError`.
    #[wasm_bindgen_test]
    fn fingerprint_from_pubkey_invalid_is_js_error() {
        // Wrong length.
        assert!(crate::fingerprint_from_pubkey(&[0u8; 31]).is_err());
        // All-zero = identity element (small-order key) — rejected by `is_weak()`.
        assert!(crate::fingerprint_from_pubkey(&[0u8; 32]).is_err());
    }

    // ── FIX 1: Full XK handshake through the WasmNoiseHandshake API ──────────

    /// Full XK handshake driven through the `WasmNoiseHandshake` wasm API.
    ///
    /// The initiator side (browser client) uses the real wasm bridge:
    /// `WasmNoiseHandshake::initiator_xk_with_dtls`, `write_message`, `read_message`,
    /// `complete_for_first_pairing`.  The responder side uses the native API to supply the
    /// known static secret (required because `responder_xk_with_dtls` generates its own
    /// random static internally, which would not match the pub given to the initiator).
    ///
    /// This exercises the wasm code paths (`write_message`, `read_message`,
    /// `complete_for_first_pairing`, `TrustAllKeystore`) that were previously UNTESTED
    /// by the existing `full_xk_handshake_with_dtls_binding` test (which drove native
    /// `NoiseHandshake` types end-to-end).
    ///
    /// Non-vacuity proof:
    ///   - Dropping any of the 3 XK messages makes `is_finished()` false → `complete_for_first_pairing()` errors.
    ///   - `init_dtls != resp_dtls` so swapping pins produces assertion failures.
    ///   - `TrustAllKeystore` is actually exercised by `complete_for_first_pairing`.
    #[wasm_bindgen_test]
    fn wasm_api_full_xk_handshake_complete_for_first_pairing() {
        use sh_crypto::NoiseHandshake;

        let init_ks = crate::WasmKeystore::generate().unwrap();
        let resp_ks = crate::WasmKeystore::generate().unwrap();

        let init_dtls = [0xaau8; 32];
        let resp_dtls = [0xbbu8; 32];

        // Generate a known X25519 keypair for the responder so the initiator knows the pub.
        // In production, the responder's Noise static pub is delivered via the signaling server
        // (stored from a prior handshake or a TOFU pairing envelope).
        let resp_static = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let resp_noise_pub: [u8; 32] = x25519_dalek::PublicKey::from(&resp_static).to_bytes();

        // Initiator uses the wasm bridge (the actual path under test).
        let mut init_hs =
            crate::WasmNoiseHandshake::initiator_xk_with_dtls(&init_ks, &resp_noise_pub, &init_dtls, &[])
                .expect("initiator_xk_with_dtls must succeed");

        // Responder uses the native API with the *same* static secret so keys match.
        // The clock must be close to now (wasm side uses real Date.now()) so the BindCert
        // validity window is not expired when the wasm initiator calls read_message(msg1).
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let now_secs = (js_sys::Date::now() / 1000.0) as i64;
        let clock = sh_types::FixedClock(now_secs);
        let mut native_resp = pollster::block_on(NoiseHandshake::responder_xk_with_dtls(
            &resp_ks.inner,
            resp_static,
            &[],
            sh_crypto::DtlsCommitment::sha256(resp_dtls),
            &clock,
        ))
        .expect("native responder must succeed");

        // XK: 3 messages.  Initiator uses wasm write/read; responder uses native.
        let msg0 = init_hs.write_message().expect("wasm initiator write_message(0) must succeed");
        native_resp.read_message(&msg0, &clock).expect("responder read_message(0) must succeed");
        let msg1 = native_resp.write_message().expect("responder write_message(1) must succeed");
        init_hs.read_message(&msg1).expect("wasm initiator read_message(1) must succeed");
        let msg2 = init_hs.write_message().expect("wasm initiator write_message(2) must succeed");
        native_resp.read_message(&msg2, &clock).expect("responder read_message(2) must succeed");

        assert!(init_hs.is_finished(), "initiator must be finished after 3 messages");
        assert!(native_resp.is_finished(), "responder must be finished after 3 messages");

        // Complete the initiator via the wasm API — exercises TrustAllKeystore and
        // complete_for_first_pairing (the new paths under test).
        let init_outcome = init_hs.complete_for_first_pairing()
            .expect("complete_for_first_pairing must succeed");

        // For the responder's complete() the trust check enforces that init's identity is
        // in resp_ks's trust store.  We pin the initiator's pubkey before completing.
        // (In the real TOFU flow the responder would also use complete_for_first_pairing;
        // here we use the native path to verify the outcome struct is symmetric.)
        let init_pub = init_ks.public_key_bytes().expect("init pubkey");
        resp_ks.trust_peer_by_key(&init_pub).expect("resp trusts init");

        let native_resp_outcome = pollster::block_on(native_resp.complete(&resp_ks.inner))
            .expect("native responder complete must succeed");
        let resp_wasm_outcome = crate::WasmHandshakeOutcome::from_native(native_resp_outcome)
            .expect("from_native must succeed");

        // Initiator sees responder's DTLS commitment.
        assert_eq!(
            init_outcome.require_dtls_pin().expect("initiator must have DTLS pin"),
            resp_dtls.to_vec(),
            "initiator must see responder's DTLS pin (0xbb...)"
        );
        // Non-vacuity: pins are distinct — would fail if swapped.
        assert_ne!(
            init_outcome.require_dtls_pin().unwrap(),
            init_dtls.to_vec(),
            "initiator must NOT see its own pin (non-vacuity)"
        );

        // Responder sees initiator's DTLS commitment.
        assert_eq!(
            resp_wasm_outcome.require_dtls_pin().expect("responder must have DTLS pin"),
            init_dtls.to_vec(),
            "responder must see initiator's DTLS pin (0xaa...)"
        );
        assert_ne!(
            resp_wasm_outcome.require_dtls_pin().unwrap(),
            resp_dtls.to_vec(),
            "responder must NOT see its own pin (non-vacuity)"
        );

        // Fingerprints are correct.
        let resp_id = pollster::block_on(sh_crypto::Keystore::device_identity(&resp_ks.inner))
            .expect("resp_id must succeed");
        let init_id = pollster::block_on(sh_crypto::Keystore::device_identity(&init_ks.inner))
            .expect("init_id must succeed");
        assert_eq!(
            init_outcome.peer_fingerprint(),
            resp_id.fingerprint().as_str(),
            "initiator outcome must carry responder fingerprint"
        );
        assert_eq!(
            resp_wasm_outcome.peer_fingerprint(),
            init_id.fingerprint().as_str(),
            "responder outcome must carry initiator fingerprint"
        );
    }

    // ── FIX 1b: negative wasm path — ALG=NONE commit yields DtlsBindingMissing ──

    /// `require_dtls_pin()` on an outcome whose peer used the non-DTLS (QUIC / ALG=NONE) path
    /// returns `JsError(DtlsBindingMissing)` through the `from_native` conversion path.
    ///
    /// Complements `dtls_binding_missing_is_js_error` (which constructs `WasmHandshakeOutcome`
    /// directly) by driving a complete native handshake with no DTLS commitment and verifying
    /// that the `from_native` conversion + `require_dtls_pin()` both behave correctly.
    #[wasm_bindgen_test]
    fn wasm_api_alg_none_commit_yields_dtls_binding_missing() {
        use sh_crypto::{Keystore as _, NoiseHandshake, SoftwareKeystore};

        let init_ks = SoftwareKeystore::generate();
        let resp_ks = SoftwareKeystore::generate();
        let clock = sh_types::FixedClock(1_000_000_000_i64);

        let resp_static = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let resp_pub = x25519_dalek::PublicKey::from(&resp_static);
        let init_static = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);

        let resp_id = pollster::block_on(resp_ks.device_identity()).unwrap();
        let init_id = pollster::block_on(init_ks.device_identity()).unwrap();
        pollster::block_on(init_ks.trust_peer(&resp_id)).unwrap();
        pollster::block_on(resp_ks.trust_peer(&init_id)).unwrap();

        // Use initiator_xk (no _dtls suffix) to produce ALG=NONE in the BindCert.
        let mut native_init = pollster::block_on(NoiseHandshake::initiator_xk(
            &init_ks,
            init_static,
            resp_pub.to_bytes(),
            &[],
            &clock,
        ))
        .unwrap();

        let mut native_resp = pollster::block_on(NoiseHandshake::responder_xk(
            &resp_ks,
            resp_static,
            &[],
            &clock,
        ))
        .unwrap();

        let msg0 = native_init.write_message().unwrap();
        native_resp.read_message(&msg0, &clock).unwrap();
        let msg1 = native_resp.write_message().unwrap();
        native_init.read_message(&msg1, &clock).unwrap();
        let msg2 = native_init.write_message().unwrap();
        native_resp.read_message(&msg2, &clock).unwrap();

        let init_outcome = pollster::block_on(native_init.complete(&init_ks)).unwrap();

        // Wrap as WasmHandshakeOutcome via from_native.
        let wasm_outcome = crate::WasmHandshakeOutcome::from_native(init_outcome)
            .expect("from_native must succeed for ALG=NONE");

        // dtls_pin() getter returns None (ALG=NONE BindCert → no pin).
        assert!(
            wasm_outcome.dtls_pin().is_none(),
            "ALG=NONE outcome must return None from dtls_pin()"
        );
        // require_dtls_pin() returns JsError — anti-downgrade gate fires.
        assert!(
            wasm_outcome.require_dtls_pin().is_err(),
            "ALG=NONE outcome must return JsError from require_dtls_pin()"
        );
        assert!(
            !wasm_outcome.has_dtls_pin(),
            "ALG=NONE outcome must have has_dtls_pin() == false"
        );
    }

    // ── FIX 2: all-zero commit dtls_pin() getter returns None ────────────────

    /// An outcome where the peer sent ALG=SHA256 but an all-zero commit
    /// must NOT expose a pin via `dtls_pin()` (it would be a zero pin, usable as a
    /// bypass if the getter returned Some).  The fix: `dtls_pin()` returns `None` for
    /// all-zero commits, forcing callers through `require_dtls_pin()` which errors.
    #[wasm_bindgen_test]
    fn dtls_pin_getter_returns_none_for_zero_commit() {
        // All-zero commit stored as Some([0;32]) in the internal field (ALG=SHA256 + zero commit).
        let outcome = crate::WasmHandshakeOutcome {
            peer_fingerprint: "a".repeat(64),
            peer_pubkey: [0u8; 32],
            dtls_pin: Some([0u8; 32]),
        };

        // The getter must return None, not Some(vec![0;32]).
        assert!(
            outcome.dtls_pin().is_none(),
            "dtls_pin() must return None for all-zero commit (downgrade prevention)"
        );
        // require_dtls_pin() must also error.
        assert!(
            outcome.require_dtls_pin().is_err(),
            "require_dtls_pin() must error for all-zero commit"
        );
        // A legitimate non-zero pin is still exposed correctly.
        let legit_outcome = crate::WasmHandshakeOutcome {
            peer_fingerprint: "a".repeat(64),
            peer_pubkey: [0u8; 32],
            dtls_pin: Some([0x11u8; 32]),
        };
        assert!(
            legit_outcome.dtls_pin().is_some(),
            "dtls_pin() must return Some for a legitimate non-zero commit"
        );
        assert_eq!(
            legit_outcome.dtls_pin().unwrap(),
            vec![0x11u8; 32],
            "dtls_pin() must return the exact committed bytes"
        );
    }

    // ── FIX 3: verify_peer_fingerprint rejects non-ASCII input ───────────────

    /// `verify_peer_fingerprint` with a non-ASCII 64-byte input must return `Err`,
    /// not `Ok(false)`.  `Ok(false)` on malformed input would silently reject a valid
    /// trusted peer on reconnect — a correctness bug that appears as a connection failure.
    #[wasm_bindgen_test]
    fn verify_peer_fingerprint_non_ascii_is_error() {
        let ks = crate::WasmKeystore::generate().unwrap();
        let fp = ks.fingerprint().unwrap();
        let outcome = crate::WasmHandshakeOutcome {
            peer_fingerprint: fp.clone(),
            peer_pubkey: [0u8; 32],
            dtls_pin: None,
        };

        // A string that is 64 bytes but contains non-ASCII multi-byte chars (e.g. "é" = 2 bytes).
        // 32 × "é" = 64 bytes, 32 chars — len() == 64 but is_ascii() == false.
        let non_ascii_64_bytes = "é".repeat(32);
        assert_eq!(non_ascii_64_bytes.len(), 64, "test setup: must be 64 bytes");
        assert!(
            non_ascii_64_bytes.chars().count() < 64,
            "test setup: must be fewer than 64 chars"
        );

        let result = outcome.verify_peer_fingerprint(&non_ascii_64_bytes);
        assert!(
            result.is_err(),
            "non-ASCII 64-byte string must return Err, not Ok(false)"
        );
    }
}
