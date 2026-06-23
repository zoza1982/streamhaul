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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

use crate::auth::PeerAuthenticator;
use crate::envelope::{self, MessageKind, SessionId, SignalingEnvelope};
use crate::error::SignalingError;

/// Maximum number of concurrent sessions the server will track.
///
/// Each session holds up to two peers. When this limit is reached, new `Hello` messages
/// that would start a new session are rejected with [`SignalingError::SessionTableFull`].
pub const MAX_SESSIONS: usize = 10_000;

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
}

impl SignalingServer {
    /// Binds the signaling server to the given address.
    ///
    /// # Errors
    ///
    /// Returns [`SignalingError::Io`] if the TCP bind fails.
    pub async fn bind(
        addr: SocketAddr,
        auth: Arc<dyn PeerAuthenticator>,
    ) -> Result<Self, SignalingError> {
        let listener = TcpListener::bind(addr).await?;
        info!(local_addr = %listener.local_addr()?, "signaling server bound");
        Ok(Self { listener, auth })
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

        loop {
            let (stream, peer_addr) = self.listener.accept().await?;
            debug!(peer = %peer_addr, "new TCP connection");

            let registry = Arc::clone(&registry);
            let auth = Arc::clone(&auth);

            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, registry, auth).await {
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
) -> Result<(), SignalingError> {
    let ws = accept_async(stream).await?;
    let (mut ws_sink, mut ws_stream) = ws.split();

    // Channel for inbound routed envelopes (other peers routing to this connection).
    let (tx, mut rx) = mpsc::channel::<SignalingEnvelope>(64);

    // State for this connection: set after a valid Hello.
    let mut registered_fp: Option<String> = None;
    let mut registered_session: Option<SessionId> = None;
    // Whether to exit the loop on the next iteration.
    let mut should_exit = false;

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
                            &tx,
                        ).await;

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
                                // Send an error envelope back.
                                let err_env = make_error_envelope(
                                    registered_session,
                                    registered_fp.as_deref().unwrap_or(""),
                                    &e.to_string(),
                                );
                                if let Ok(encoded) = envelope::encode(&err_env) {
                                    let _ = ws_sink.send(Message::Binary(encoded.to_vec())).await;
                                }
                                if matches!(e, SignalingError::FingerprintSpoofAttempt { .. }) {
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
            handle_hello(env, registered_fp, registered_session, registry, auth, tx).await
        }
        MessageKind::Bye => {
            // Best-effort forward; peer may not be connected yet.
            let _ = forward_to_peer(&env, registry).await;
            Ok(None)
        }
        MessageKind::Offer
        | MessageKind::Answer
        | MessageKind::Candidate
        | MessageKind::EndOfCandidates
        | MessageKind::Error => {
            forward_to_peer(&env, registry).await?;
            Ok(None)
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
    tx: &PeerTx,
) -> Result<Option<SignalingEnvelope>, SignalingError> {
    // Authenticate the peer.
    if !auth.authenticate(&env.from_fp) {
        return Err(SignalingError::FingerprintSpoofAttempt {
            registered: String::new(),
            attempted: env.from_fp.clone(),
        });
    }

    {
        let mut reg = registry.write().await;

        // Enforce session table capacity.
        if !reg.contains_key(&env.session_id) && reg.len() >= MAX_SESSIONS {
            return Err(SignalingError::SessionTableFull { max: MAX_SESSIONS });
        }

        let session = reg.entry(env.session_id).or_insert_with(HashMap::new);
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

    // send() is async; a closed receiver means the peer disconnected.
    peer_tx
        .send(env.clone())
        .await
        .map_err(|_| SignalingError::PeerNotFound {
            fp: env.to_fp.clone(),
        })?;

    Ok(())
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
    // SAFETY: payload_end is computed with .min() so it is always <= payload_bytes.len().
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
