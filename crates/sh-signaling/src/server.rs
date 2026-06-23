//! Zero-knowledge WebSocket signaling server.
//!
//! [`SignalingServer`] binds a plain WebSocket listener (no in-process TLS). In production,
//! TLS is terminated by a reverse proxy (nginx, Caddy) in front of the server.
//!
//! ## Routing
//!
//! The server routes envelopes using only `(session_id, to_fp)`. It never inspects the
//! payload (zero-knowledge invariant, LLD §6.3).
//!
//! ## Spoof rejection
//!
//! Each connection is bound to a single `from_fp` on `Hello`. Any subsequent envelope with
//! a different `from_fp` causes the server to send an `Error` envelope back and close the
//! connection immediately.
//!
//! ## Session lifecycle
//!
//! - `Hello` → register `(session_id, from_fp)` in the session table.
//! - `Offer/Answer/Candidate/EndOfCandidates/Bye` → look up peer by `(session_id, to_fp)`
//!   and forward the envelope as-is.
//! - When a peer disconnects → remove from registry; if the other peer is still connected,
//!   send it a synthetic `Bye`.
//! - `MAX_SESSIONS` caps the number of concurrent sessions to prevent resource exhaustion.
//! - `MAX_CONNECTIONS` caps the number of concurrent WS connections (including pre-Hello).
//!
//! ## Peer authentication (R-SIG-AUTH)
//!
//! On connect, the server issues a fresh random 32-byte challenge (via an injected
//! [`ChallengeSource`]) in a `Challenge` envelope. The peer's `Hello` must carry a
//! possession-of-identity-key proof in its opaque payload; the server verifies it through the
//! injected [`PeerAuthenticator`] ([`IdentityProofAuthenticator`](crate::auth::IdentityProofAuthenticator)
//! in production). This binds `from_fp` to a key the peer demonstrably controls, over a fresh
//! challenge — defeating fingerprint spoofing, impersonation, and replay at the relay. The
//! challenge bytes never leave the connection task, and routing is still keyed only on
//! `(session_id, to_fp)` (zero-knowledge invariant intact).
//!
//! Server-side auth proves *ownership*, not *trust*: end-to-end peer trust remains the endpoints'
//! job via Noise/BindCert/TOFU (P3). See [`crate::auth`].
//!
//! ## Security limitations
//!
//! - Plain-WS signaling is vulnerable to MITM (candidate injection, session interference).
//!   End-to-end integrity depends on P4-5 BindCert/DTLS-fingerprint binding which the signaling
//!   layer does NOT provide.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock, Semaphore};
use tokio::time::{timeout, Duration};
use tokio_tungstenite::accept_async_with_config;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

use sh_crypto::peer_auth::PEER_AUTH_CHALLENGE_LEN;

use crate::auth::{AuthContext, PeerAuthenticator};
use crate::challenge::{ChallengeSource, OsChallengeSource};
use crate::envelope::{
    self, MessageKind, SessionId, SignalingEnvelope, ENVELOPE_HEADER_LEN, MAX_PAYLOAD_LEN,
};
use crate::error::SignalingError;

/// Maximum number of concurrent sessions the server will track.
///
/// Each session holds up to [`MAX_PEERS_PER_SESSION`] peers. When this limit is reached, new
/// `Hello` messages that would start a new session are rejected with
/// [`SignalingError::SessionTableFull`].
pub const MAX_SESSIONS: usize = 10_000;

/// Maximum number of peers per session (host + one guest = 2).
pub const MAX_PEERS_PER_SESSION: usize = 2;

/// Maximum number of concurrent WebSocket connections (including pre-Hello).
pub const MAX_CONNECTIONS: usize = 20_000;

/// Timeout for the WebSocket handshake (TLS/HTTP upgrade).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for receiving the first Hello after WS handshake completes.
const HELLO_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum WebSocket message/frame size accepted by the server.
///
/// Pre-computed to avoid arithmetic at runtime and to satisfy the `arithmetic_side_effects` lint.
/// Equals `ENVELOPE_HEADER_LEN + MAX_PAYLOAD_LEN` (149 + 65536 = 65685).
const MAX_WS_MESSAGE_SIZE: usize = ENVELOPE_HEADER_LEN + MAX_PAYLOAD_LEN as usize;

/// Sender half for routing envelopes to a connected peer.
type PeerTx = mpsc::Sender<SignalingEnvelope>;

/// Registry of active sessions and their connected peers.
///
/// `session_id → (fingerprint → sender)`
type SessionRegistry = HashMap<SessionId, HashMap<String, PeerTx>>;

/// A self-hostable WebSocket signaling server for Streamhaul session establishment.
///
/// The server routes [`SignalingEnvelope`] messages between peers using only `session_id`
/// and `to_fp`. It never inspects the payload (zero-knowledge relay, LLD §6.3).
///
/// # Security
///
/// See the [module-level documentation](self) for current security limitations. Until
/// R-SIG-AUTH and P4-5 are implemented, `from_fp` is not verified and plain-WS connections
/// are susceptible to MITM in the signaling layer.
///
/// # Examples
///
/// ```no_run
/// use sh_signaling::SignalingServer;
/// use std::sync::Arc;
/// # #[cfg(feature = "insecure-lan")]
/// use sh_signaling::auth::AcceptAll;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), sh_signaling::SignalingError> {
/// # #[cfg(feature = "insecure-lan")]
/// let server = SignalingServer::bind(
///     "127.0.0.1:0".parse().unwrap(),
///     Arc::new(AcceptAll),
/// ).await?;
/// # #[cfg(feature = "insecure-lan")]
/// println!("listening on {}", server.local_addr()?);
/// # Ok(())
/// # }
/// ```
pub struct SignalingServer {
    listener: TcpListener,
    auth: Arc<dyn PeerAuthenticator>,
    challenge: Arc<dyn ChallengeSource>,
}

impl SignalingServer {
    /// Binds the signaling server to the given address using the OS CSPRNG for challenges.
    ///
    /// This is the production entry point: it uses [`OsChallengeSource`] so every connection gets
    /// a cryptographically random challenge nonce. To inject a deterministic challenge source
    /// (tests), use [`bind_with_challenge_source`](Self::bind_with_challenge_source).
    ///
    /// # Errors
    ///
    /// Returns [`SignalingError::Io`] if the TCP bind fails.
    pub async fn bind(
        addr: SocketAddr,
        auth: Arc<dyn PeerAuthenticator>,
    ) -> Result<Self, SignalingError> {
        Self::bind_with_challenge_source(addr, auth, Arc::new(OsChallengeSource)).await
    }

    /// Binds the signaling server with an explicit [`ChallengeSource`] (for deterministic tests).
    ///
    /// # Errors
    ///
    /// Returns [`SignalingError::Io`] if the TCP bind fails.
    pub async fn bind_with_challenge_source(
        addr: SocketAddr,
        auth: Arc<dyn PeerAuthenticator>,
        challenge: Arc<dyn ChallengeSource>,
    ) -> Result<Self, SignalingError> {
        let listener = TcpListener::bind(addr).await?;
        info!(local_addr = %listener.local_addr()?, "signaling server bound");
        Ok(Self {
            listener,
            auth,
            challenge,
        })
    }

    /// Returns the local socket address the server is bound to.
    ///
    /// # Errors
    ///
    /// Returns [`SignalingError::Io`] if the OS cannot return the local address.
    pub fn local_addr(&self) -> Result<SocketAddr, SignalingError> {
        Ok(self.listener.local_addr()?)
    }

    /// Runs the signaling server, accepting connections indefinitely.
    ///
    /// This method consumes `self` and runs until the listener is closed or an unrecoverable
    /// I/O error occurs.
    ///
    /// # Errors
    ///
    /// Returns [`SignalingError::Io`] on a fatal accept error.
    pub async fn run(self) -> Result<(), SignalingError> {
        let registry: Arc<RwLock<SessionRegistry>> = Arc::new(RwLock::new(HashMap::new()));
        let auth = self.auth;
        let challenge_source = self.challenge;
        let conn_semaphore: Arc<Semaphore> = Arc::new(Semaphore::new(MAX_CONNECTIONS));

        loop {
            let (stream, peer_addr) = self.listener.accept().await?;
            debug!(peer = %peer_addr, "new TCP connection");

            let permit = match conn_semaphore.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    warn!("connection limit reached, dropping new connection");
                    continue;
                }
            };

            let registry = Arc::clone(&registry);
            let auth = Arc::clone(&auth);
            let challenge_source = Arc::clone(&challenge_source);

            tokio::spawn(async move {
                let _permit = permit; // released on drop
                if let Err(e) = handle_connection(stream, registry, auth, challenge_source).await {
                    warn!(error = %e, "connection handler error");
                }
            });
        }
    }
}

/// Drives a single WebSocket connection from acceptance through teardown.
async fn handle_connection(
    stream: TcpStream,
    registry: Arc<RwLock<SessionRegistry>>,
    auth: Arc<dyn PeerAuthenticator>,
    challenge_source: Arc<dyn ChallengeSource>,
) -> Result<(), SignalingError> {
    let ws_config = WebSocketConfig {
        max_message_size: Some(MAX_WS_MESSAGE_SIZE),
        max_frame_size: Some(MAX_WS_MESSAGE_SIZE),
        ..Default::default()
    };

    let ws = timeout(
        HANDSHAKE_TIMEOUT,
        accept_async_with_config(stream, Some(ws_config)),
    )
    .await
    .map_err(|_| {
        SignalingError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "WS handshake timeout",
        ))
    })??;

    let (mut ws_sink, mut ws_stream) = ws.split();

    // R-SIG-AUTH: issue a fresh per-connection challenge nonce. The peer must sign it in its
    // `Hello` identity proof; this is what defeats proof replay. The challenge stays local to this
    // connection task and is never persisted or routed.
    let mut challenge = [0u8; PEER_AUTH_CHALLENGE_LEN];
    challenge_source.fill_challenge(&mut challenge);
    let challenge_env = make_challenge_envelope(&challenge);
    match envelope::encode(&challenge_env) {
        Ok(encoded) => {
            if ws_sink
                .send(Message::Binary(encoded.to_vec()))
                .await
                .is_err()
            {
                debug!("failed to send challenge; dropping connection");
                return Ok(());
            }
        }
        Err(e) => {
            // Should never happen (placeholder fingerprints are valid 64-hex), but never panic.
            warn!(error = %e, "failed to encode challenge envelope");
            return Ok(());
        }
    }

    // Channel for inbound routed envelopes (other peers routing to this connection).
    let (tx, mut rx) = mpsc::channel::<SignalingEnvelope>(64);

    // State for this connection: set after a valid Hello.
    let mut registered_fp: Option<String> = None;
    let mut registered_session: Option<SessionId> = None;
    // Whether to exit the loop on the next iteration.
    let mut should_exit = false;

    // Hello idle timeout: close the connection if no Hello is received within the deadline.
    let hello_deadline = tokio::time::sleep(HELLO_TIMEOUT);
    tokio::pin!(hello_deadline);
    let mut hello_received = false;

    loop {
        if should_exit {
            break;
        }

        tokio::select! {
            // Inbound WS message from the remote peer.
            msg = ws_stream.next() => {
                match msg {
                    None => {
                        // WS stream closed cleanly.
                        should_exit = true;
                    }
                    Some(Err(e)) => {
                        debug!(error = %e, "WS read error");
                        should_exit = true;
                    }
                    Some(Ok(Message::Binary(bytes))) => {
                        let result = handle_message(
                            &bytes,
                            &mut registered_fp,
                            &mut registered_session,
                            &registry,
                            &auth,
                            &challenge,
                            &tx,
                        ).await;

                        // Update hello_received after a successful message dispatch.
                        if registered_fp.is_some() {
                            hello_received = true;
                        }

                        match result {
                            Ok(Some(reply)) => {
                                // Encode and send the reply.
                                match envelope::encode(&reply) {
                                    Ok(encoded) => {
                                        if let Err(e) = ws_sink.send(Message::Binary(encoded.to_vec())).await {
                                            debug!(error = %e, "WS send error");
                                            should_exit = true;
                                        }
                                    }
                                    Err(e) => {
                                        warn!(error = %e, "failed to encode reply envelope");
                                    }
                                }
                            }
                            Ok(None) => {} // normal, no reply needed
                            Err(e) => {
                                // Sanitise the error reason before sending to the client.
                                // FingerprintSpoofAttempt must never leak the registered fp on the wire.
                                let reason = match &e {
                                    SignalingError::FingerprintSpoofAttempt { .. } => {
                                        "fingerprint mismatch".to_owned()
                                    }
                                    _ => e.to_string(),
                                };
                                let err_env = make_error_envelope(
                                    registered_session,
                                    registered_fp.as_deref().unwrap_or(""),
                                    &reason,
                                );
                                if let Ok(encoded) = envelope::encode(&err_env) {
                                    let _ = ws_sink.send(Message::Binary(encoded.to_vec())).await;
                                }
                                if matches!(
                                    e,
                                    SignalingError::FingerprintSpoofAttempt { .. }
                                        | SignalingError::AuthenticationFailed
                                ) {
                                    should_exit = true;
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) => {
                        should_exit = true;
                    }
                    Some(Ok(Message::Ping(data))) => {
                        // Reply to pings to keep the connection alive.
                        if let Err(e) = ws_sink.send(Message::Pong(data)).await {
                            debug!(error = %e, "WS pong send error");
                            should_exit = true;
                        }
                    }
                    Some(Ok(_)) => {
                        // Text/Pong/Frame: ignore unexpected message types.
                        debug!("received unexpected WS message type, ignoring");
                    }
                }
            }

            // Outbound envelope routed to this peer by the server.
            routed = rx.recv() => {
                match routed {
                    None => {
                        // Sender dropped — server is shutting down.
                        should_exit = true;
                    }
                    Some(env) => {
                        match envelope::encode(&env) {
                            Ok(encoded) => {
                                if let Err(e) = ws_sink.send(Message::Binary(encoded.to_vec())).await {
                                    debug!(error = %e, "WS send error for routed envelope");
                                    should_exit = true;
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "failed to encode routed envelope");
                            }
                        }
                    }
                }
            }

            // Idle/Hello timeout: close if no Hello received within the deadline.
            _ = &mut hello_deadline, if !hello_received => {
                warn!("no Hello received within timeout, dropping connection");
                should_exit = true;
            }
        }
    }

    // Cleanup: remove this peer from the registry and notify the remaining peer (if any).
    if let (Some(session_id), Some(ref fp)) = (registered_session, &registered_fp) {
        let peer_sender = {
            let mut reg = registry.write().await;
            if let Some(session) = reg.get_mut(&session_id) {
                session.remove(fp);
                // Find any remaining peer in the session.
                let peer = session.values().next().cloned();
                if session.is_empty() {
                    reg.remove(&session_id);
                }
                peer
            } else {
                None
            }
        };

        // Notify the remaining peer with a synthetic Bye.
        if let Some(peer_tx) = peer_sender {
            let bye = SignalingEnvelope {
                kind: MessageKind::Bye,
                session_id,
                from_fp: fp.clone(),
                // to_fp is not meaningful for server-synthetic envelopes; use zeros.
                to_fp: "0".repeat(64),
                payload: Bytes::new(),
            };
            // Best-effort; ignore errors (the other peer may have gone away).
            let _ = peer_tx.try_send(bye);
        }
    }

    debug!("connection handler exiting");
    Ok(())
}

/// Processes a single binary WebSocket message and returns an optional reply envelope.
///
/// Returns `Ok(Some(env))` if a reply should be sent to the sender.
/// Returns `Ok(None)` if the message was forwarded or no reply is needed.
/// Returns `Err(…)` if the message should trigger an error response.
async fn handle_message(
    bytes: &[u8],
    registered_fp: &mut Option<String>,
    registered_session: &mut Option<SessionId>,
    registry: &Arc<RwLock<SessionRegistry>>,
    auth: &Arc<dyn PeerAuthenticator>,
    challenge: &[u8; PEER_AUTH_CHALLENGE_LEN],
    tx: &PeerTx,
) -> Result<Option<SignalingEnvelope>, SignalingError> {
    let env = envelope::decode(bytes)?;

    // Spoof detection: if this connection is already registered, the from_fp must match.
    if let Some(ref registered) = registered_fp {
        if env.from_fp != *registered {
            return Err(SignalingError::FingerprintSpoofAttempt {
                registered: registered.clone(),
                attempted: env.from_fp.clone(),
            });
        }
    }

    match env.kind {
        MessageKind::Hello => {
            handle_hello(
                env,
                registered_fp,
                registered_session,
                registry,
                auth,
                challenge,
                tx,
            )
            .await
        }
        MessageKind::Bye => {
            // Best-effort forward; peer may not be connected yet.
            let _ = forward_to_peer(&env, registry).await;
            Ok(None)
        }
        MessageKind::Offer
        | MessageKind::Answer
        | MessageKind::Candidate
        | MessageKind::EndOfCandidates => {
            forward_to_peer(&env, registry).await?;
            Ok(None)
        }
        MessageKind::Error | MessageKind::Challenge => {
            // Error and Challenge are server→client only; a client sending either is a protocol
            // violation.
            Err(SignalingError::UnexpectedMessageType)
        }
    }
}

/// Handles a `Hello` envelope: registers the peer and sends back a `Hello` ack.
async fn handle_hello(
    env: SignalingEnvelope,
    registered_fp: &mut Option<String>,
    registered_session: &mut Option<SessionId>,
    registry: &Arc<RwLock<SessionRegistry>>,
    auth: &Arc<dyn PeerAuthenticator>,
    challenge: &[u8; PEER_AUTH_CHALLENGE_LEN],
    tx: &PeerTx,
) -> Result<Option<SignalingEnvelope>, SignalingError> {
    // Reject a second Hello on an already-registered connection.
    if registered_fp.is_some() {
        return Err(SignalingError::AlreadyRegistered);
    }

    // Authenticate the peer (R-SIG-AUTH): verify the possession-of-identity-key proof carried in
    // the opaque `Hello` payload against the claimed fingerprint, the session, and the challenge
    // this connection issued. `env.payload` is hostile input; the authenticator parses it
    // panic-free. Any rejection collapses to the sanitized `AuthenticationFailed` (no oracle).
    let ctx = AuthContext {
        claimed_fp: &env.from_fp,
        session_id: env.session_id,
        challenge,
        proof: &env.payload,
    };
    if let Err(auth_err) = auth.authenticate(&ctx) {
        debug!(reason = %auth_err, "peer authentication rejected");
        return Err(SignalingError::from(auth_err));
    }

    {
        let mut reg = registry.write().await;

        // Enforce session table capacity.
        if !reg.contains_key(&env.session_id) && reg.len() >= MAX_SESSIONS {
            return Err(SignalingError::SessionTableFull { max: MAX_SESSIONS });
        }

        let session = reg.entry(env.session_id).or_insert_with(HashMap::new);

        // Enforce per-session peer cap.
        if session.len() >= MAX_PEERS_PER_SESSION && !session.contains_key(&env.from_fp) {
            return Err(SignalingError::SessionFull {
                max: MAX_PEERS_PER_SESSION,
            });
        }

        // Register (or replace) this peer's sender.
        session.insert(env.from_fp.clone(), tx.clone());
    }

    *registered_fp = Some(env.from_fp.clone());
    *registered_session = Some(env.session_id);

    debug!(
        fp = &env.from_fp[..8],
        session = ?env.session_id,
        "peer registered"
    );

    // Send back a Hello ack so the client knows it is registered.
    // The ack uses the client's own fp in both from/to fields as a simple echo.
    let ack = SignalingEnvelope {
        kind: MessageKind::Hello,
        session_id: env.session_id,
        from_fp: env.from_fp.clone(),
        to_fp: env.from_fp.clone(),
        payload: Bytes::new(),
    };
    Ok(Some(ack))
}

/// Looks up the recipient peer by `(session_id, to_fp)` and sends the envelope.
async fn forward_to_peer(
    env: &SignalingEnvelope,
    registry: &Arc<RwLock<SessionRegistry>>,
) -> Result<(), SignalingError> {
    let peer_tx = {
        let reg = registry.read().await;
        reg.get(&env.session_id)
            .ok_or(SignalingError::SessionNotFound {
                session_id: env.session_id,
            })?
            .get(&env.to_fp)
            .ok_or_else(|| SignalingError::PeerNotFound {
                fp: env.to_fp.clone(),
            })?
            .clone()
    };

    // Use try_send to avoid blocking the server task on a slow or unresponsive peer.
    peer_tx
        .try_send(env.clone())
        .map_err(|_| SignalingError::PeerNotFound {
            fp: env.to_fp.clone(),
        })?;

    Ok(())
}

/// Constructs the server-generated `Challenge` envelope carrying the 32-byte nonce.
///
/// The routing-header fingerprints are not meaningful for a server→client control message, so
/// they are all-zero hex placeholders (valid 64-char lowercase hex, accepted by `encode`). The
/// challenge nonce rides in the opaque payload — the routing header is unchanged.
fn make_challenge_envelope(challenge: &[u8; PEER_AUTH_CHALLENGE_LEN]) -> SignalingEnvelope {
    SignalingEnvelope {
        kind: MessageKind::Challenge,
        // SessionId is not yet known for this connection (Hello has not arrived); zeros.
        session_id: SessionId([0u8; 16]),
        from_fp: "0".repeat(64),
        to_fp: "0".repeat(64),
        payload: Bytes::copy_from_slice(challenge),
    }
}

/// Constructs a server-generated `Error` envelope.
fn make_error_envelope(
    session_id: Option<SessionId>,
    from_fp: &str,
    reason: &str,
) -> SignalingEnvelope {
    let session_id = session_id.unwrap_or(SessionId([0u8; 16]));
    // Clamp reason to MAX_PAYLOAD_LEN.
    let payload_bytes = reason.as_bytes();
    let payload_end = payload_bytes
        .len()
        .min(crate::envelope::MAX_PAYLOAD_LEN as usize);
    // Note: payload_end is computed with .min() so it is always <= payload_bytes.len().
    let payload_slice = if payload_end > 0 {
        payload_bytes.get(..payload_end).unwrap_or(b"error")
    } else {
        b""
    };
    let payload = Bytes::copy_from_slice(payload_slice);

    // Pad/truncate from_fp to exactly 64 chars for the server reply.
    let from_fp_padded: String = if from_fp.len() == 64 {
        from_fp.to_owned()
    } else {
        // Build a valid 64-char placeholder (all zeros hex).
        "0".repeat(64)
    };

    SignalingEnvelope {
        kind: MessageKind::Error,
        session_id,
        from_fp: from_fp_padded.clone(),
        to_fp: from_fp_padded,
        payload,
    }
}
