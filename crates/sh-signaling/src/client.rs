//! Signaling client with automatic reconnection.
//!
//! [`SignalingClient`] connects to a WebSocket signaling server, sends a `Hello` envelope
//! to register itself, and then provides [`send`](SignalingClient::send) /
//! [`recv`](SignalingClient::recv) primitives for exchanging [`SignalingEnvelope`] messages.
//!
//! ## Reconnection
//!
//! If the underlying WebSocket connection is lost, the client re-connects using the injected
//! [`BackoffStrategy`]. After each successful reconnect, the client re-sends `Hello` to
//! re-register in the session.
//!
//! ## Graceful shutdown
//!
//! Call [`close`](SignalingClient::close) to close the connection cleanly. The server's
//! disconnect handler will send a synthetic `Bye` to the remaining peer.
//! [`recv`](SignalingClient::recv) returns `Ok(None)` when a `Bye` is received from the peer
//! or when the connection is closed cleanly.

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::connect_async_with_config;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tracing::{debug, info, warn};

use crate::backoff::BackoffStrategy;
use crate::envelope::{
    self, MessageKind, SessionId, SignalingEnvelope, ENVELOPE_HEADER_LEN, MAX_PAYLOAD_LEN,
};
use crate::error::SignalingError;

/// Maximum WebSocket message/frame size used by the client.
///
/// Pre-computed to avoid arithmetic at runtime and to satisfy the `arithmetic_side_effects` lint.
/// Equals `ENVELOPE_HEADER_LEN + MAX_PAYLOAD_LEN` (149 + 65536 = 65685).
const MAX_WS_MESSAGE_SIZE: usize = ENVELOPE_HEADER_LEN + MAX_PAYLOAD_LEN as usize;

/// Type alias for the WS stream returned by `connect_async_with_config` over TCP.
type WsStream = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// A connected signaling client.
///
/// Construct with [`SignalingClient::connect`], then use [`send`](SignalingClient::send) and
/// [`recv`](SignalingClient::recv) to exchange envelopes with the remote peer.
///
/// # Examples
///
/// ```no_run
/// use sh_signaling::{SignalingClient, SessionId};
/// use sh_signaling::backoff::ExponentialBackoff;
///
/// # async fn run() -> Result<(), sh_signaling::SignalingError> {
/// let client = SignalingClient::connect(
///     "ws://127.0.0.1:8765",
///     SessionId([0u8; 16]),
///     "a".repeat(64),
///     ExponentialBackoff::default(),
/// ).await?;
/// # Ok(())
/// # }
/// ```
pub struct SignalingClient {
    ws: WsStream,
    url: String,
    session_id: SessionId,
    my_fp: String,
    backoff: Box<dyn BackoffStrategy>,
}

impl SignalingClient {
    /// Connects to the signaling server and sends an initial `Hello` envelope.
    ///
    /// # Arguments
    ///
    /// - `url` — WebSocket URL of the signaling server (e.g. `ws://127.0.0.1:8765`).
    /// - `session_id` — The session this client belongs to.
    /// - `my_fp` — This client's fingerprint (64-char lowercase hex); used as `from_fp` in `Hello`.
    /// - `backoff` — Reconnect delay strategy.
    ///
    /// # Errors
    ///
    /// - [`SignalingError::WebSocket`] if the initial connection or `Hello` send fails.
    /// - [`SignalingError::NotConnected`] if all reconnect attempts are exhausted on connect.
    pub async fn connect(
        url: impl Into<String>,
        session_id: SessionId,
        my_fp: impl Into<String>,
        backoff: impl BackoffStrategy + 'static,
    ) -> Result<Self, SignalingError> {
        let url = url.into();
        let my_fp = my_fp.into();
        let mut backoff: Box<dyn BackoffStrategy> = Box::new(backoff);

        let ws = connect_with_retry(&url, &session_id, &my_fp, &mut *backoff).await?;

        backoff.reset();
        info!(url = %url, "signaling client connected");

        Ok(Self {
            ws,
            url,
            session_id,
            my_fp,
            backoff,
        })
    }

    /// Sends an envelope to the server (which will route it to `env.to_fp`).
    ///
    /// # Errors
    ///
    /// - [`SignalingError::WebSocket`] if the send fails.
    /// - [`SignalingError::NotConnected`] if all reconnect attempts are exhausted.
    pub async fn send(&mut self, env: SignalingEnvelope) -> Result<(), SignalingError> {
        let encoded = envelope::encode(&env)?;
        self.ws.send(Message::Binary(encoded.to_vec())).await?;
        Ok(())
    }

    /// Receives the next envelope from the server.
    ///
    /// Returns `Ok(None)` when a `Bye` is received or the connection is closed cleanly.
    ///
    /// On connection loss, the client attempts to reconnect using the backoff strategy and
    /// re-sends `Hello` before retrying the read.
    ///
    /// # Errors
    ///
    /// - [`SignalingError::WebSocket`] on a protocol error that cannot be retried.
    /// - [`SignalingError::NotConnected`] if all reconnect attempts are exhausted.
    pub async fn recv(&mut self) -> Result<Option<SignalingEnvelope>, SignalingError> {
        loop {
            match self.ws.next().await {
                None => {
                    // Connection closed cleanly — attempt reconnect.
                    debug!("WS stream ended, attempting reconnect");
                    match connect_with_retry(
                        &self.url,
                        &self.session_id,
                        &self.my_fp,
                        &mut *self.backoff,
                    )
                    .await
                    {
                        Ok(ws) => {
                            self.ws = ws;
                            self.backoff.reset();
                            // Hello ack was consumed in try_connect; loop to read next message.
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                }
                Some(Err(e)) => {
                    debug!(error = %e, "WS recv error, attempting reconnect");
                    match connect_with_retry(
                        &self.url,
                        &self.session_id,
                        &self.my_fp,
                        &mut *self.backoff,
                    )
                    .await
                    {
                        Ok(ws) => {
                            self.ws = ws;
                            self.backoff.reset();
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                }
                Some(Ok(Message::Binary(bytes))) => {
                    let env = envelope::decode(&bytes)?;
                    if env.kind == MessageKind::Bye {
                        return Ok(None);
                    }
                    return Ok(Some(env));
                }
                Some(Ok(Message::Close(_))) => {
                    return Ok(None);
                }
                Some(Ok(Message::Ping(data))) => {
                    // Reply to pings; then loop to read the next message.
                    if let Err(e) = self.ws.send(Message::Pong(data)).await {
                        warn!(error = %e, "failed to send Pong");
                    }
                }
                Some(Ok(_)) => {
                    // Ignore text/pong/continuation frames.
                    debug!("ignoring non-binary WS message");
                }
            }
        }
    }

    /// Closes the WebSocket connection cleanly.
    ///
    /// Closing the socket triggers the server's disconnect handler, which sends a synthetic
    /// `Bye` to the remaining peer in the session. Callers do not need to send an explicit
    /// `Bye` envelope; the server handles peer notification automatically.
    ///
    /// # Errors
    ///
    /// Returns [`SignalingError::WebSocket`] if the close handshake fails. The connection is
    /// considered closed regardless of the error.
    pub async fn close(mut self) -> Result<(), SignalingError> {
        // Closing the socket triggers the server's disconnect-Bye to the remaining peer.
        self.ws.close(None).await?;
        Ok(())
    }
}

/// Establishes a WS connection and sends the initial `Hello` envelope.
///
/// Retries according to `backoff`. Returns the connected [`WsStream`] or
/// [`SignalingError::NotConnected`] if all attempts are exhausted.
async fn connect_with_retry(
    url: &str,
    session_id: &SessionId,
    my_fp: &str,
    backoff: &mut dyn BackoffStrategy,
) -> Result<WsStream, SignalingError> {
    loop {
        match try_connect(url, session_id, my_fp).await {
            Ok(ws) => return Ok(ws),
            Err(e) => {
                debug!(error = %e, "connection attempt failed");
                match backoff.next_delay() {
                    Some(delay) => {
                        if !delay.is_zero() {
                            tokio::time::sleep(delay).await;
                        }
                    }
                    None => {
                        return Err(SignalingError::NotConnected);
                    }
                }
            }
        }
    }
}

/// Single connection attempt: TCP + WS upgrade + `Hello` send + Hello ack consume.
///
/// Consuming the Hello ack here ensures that after reconnect, the first message returned
/// by [`SignalingClient::recv`] is a real application message, not a spurious Hello ack.
async fn try_connect(
    url: &str,
    session_id: &SessionId,
    my_fp: &str,
) -> Result<WsStream, SignalingError> {
    let ws_config = WebSocketConfig {
        max_message_size: Some(MAX_WS_MESSAGE_SIZE),
        max_frame_size: Some(MAX_WS_MESSAGE_SIZE),
        ..Default::default()
    };
    let (mut ws, _response) = connect_async_with_config(url, Some(ws_config), false).await?;

    // Send Hello to register this peer in the session.
    // `to_fp` is all-zeros for Hello; the server ignores it.
    let hello = SignalingEnvelope {
        kind: MessageKind::Hello,
        session_id: *session_id,
        from_fp: my_fp.to_owned(),
        to_fp: "0".repeat(64),
        payload: Bytes::new(),
    };
    let encoded = envelope::encode(&hello)?;
    ws.send(Message::Binary(encoded.to_vec())).await?;

    // Consume the server's Hello ack so post-reconnect recv() doesn't surface it.
    loop {
        match ws.next().await {
            Some(Ok(Message::Binary(bytes))) => {
                let env = envelope::decode(&bytes)?;
                if env.kind == MessageKind::Hello {
                    // Ack consumed; connection is registered and ready.
                    break;
                }
                // Any other message before the ack is unexpected.
                return Err(SignalingError::UnexpectedMessageType);
            }
            Some(Ok(Message::Ping(data))) => {
                ws.send(Message::Pong(data)).await?;
            }
            Some(Ok(_)) => {
                return Err(SignalingError::UnexpectedMessageType);
            }
            Some(Err(e)) => return Err(SignalingError::from(e)),
            None => return Err(SignalingError::NotConnected),
        }
    }

    debug!(url = %url, "Hello sent and acked");
    Ok(ws)
}
