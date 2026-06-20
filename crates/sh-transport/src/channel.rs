//! `Transport` and `Channel` trait abstractions for Streamhaul.
//!
//! This module defines the [`Transport`] and [`Channel`] traits that form the boundary between
//! the Streamhaul protocol stack and the underlying QUIC connection. The concrete implementation
//! is [`QuicTransport`], which wraps an established [`quinn::Connection`].
//!
//! # Design overview
//!
//! Each logical session channel maps to either:
//! - A **QUIC bidirectional stream** (`Reliability::Reliable`) — guaranteed delivery, ordered, with
//!   backpressure. Streams carry a 2-byte header on open so the accepting side can reconstruct the
//!   [`ChannelSpec`] without out-of-band signaling.
//! - **QUIC datagrams** (`Reliability::Unreliable`) — best-effort, unordered, low-latency. Both
//!   sides create the datagram channel independently (no per-channel handshake). Demuxing multiple
//!   datagram channels by SHP CHANNEL field is out of scope for P1-1 and noted as a follow-up.
//!
//! # Stream framing
//!
//! Reliable stream messages are length-delimited: a `u32` big-endian length prefix followed by the
//! payload bytes. Payloads larger than [`MAX_FRAME_LEN`] are rejected with
//! [`TransportError::MessageTooLarge`].
//!
//! # Priority mapping
//!
//! quinn uses `i32` stream priority where larger values are scheduled first. We invert the
//! `u8` `priority` field (`0 = highest urgency`) to quinn's space with the formula
//! `i32::from(u8::MAX - priority)`, giving priority 0 → `i32` 255 (highest), and
//! priority 255 → `i32` 0 (lowest).

use std::time::Duration;

use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use sh_types::ChannelId;

use crate::connection::Connection;
use crate::error::TransportError;

// ────────────────────────────────────────────────────────────────────────────
// Constants
// ────────────────────────────────────────────────────────────────────────────

/// Maximum payload length accepted in a single framed stream message (16 MiB).
///
/// Payloads with a declared length exceeding this are rejected with
/// [`TransportError::MessageTooLarge`] to prevent memory exhaustion on hostile input.
pub const MAX_FRAME_LEN: u32 = 16 * 1024 * 1024;

// 2-byte channel-open header written at the start of every reliable (stream) channel.
// Layout: [channel_discriminant: u8, priority: u8]
const HEADER_LEN: usize = 2;

// ────────────────────────────────────────────────────────────────────────────
// Public types
// ────────────────────────────────────────────────────────────────────────────

/// Delivery guarantee for a [`Channel`].
///
/// This maps directly to the underlying QUIC mechanism:
/// - [`Unreliable`](Reliability::Unreliable) uses QUIC datagrams (drop-allowed, unordered).
/// - [`Reliable`](Reliability::Reliable) uses a QUIC bidirectional stream (reliable, ordered).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reliability {
    /// Datagrams: best-effort, unordered delivery. Suitable for latency-sensitive media (video,
    /// audio) where a stale frame is worse than a dropped one.
    Unreliable,
    /// Stream: guaranteed, ordered delivery. Suitable for input events, control messages, and
    /// file/clipboard data.
    Reliable,
}

/// Specification for a logical session channel.
///
/// Passed to [`Transport::open_channel`] when opening, and returned by [`Channel::spec`] on
/// both the opening and accepting sides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelSpec {
    /// Which logical channel this is.
    pub channel: ChannelId,
    /// Delivery guarantee.
    pub reliability: Reliability,
    /// Scheduling priority. `0` is highest priority; `255` is lowest.
    ///
    /// For reliable channels this maps to quinn stream priority. For unreliable (datagram)
    /// channels it is advisory only (datagrams are not scheduled by quinn priority today).
    pub priority: u8,
}

impl ChannelSpec {
    /// Returns the quinn `i32` stream priority for this spec.
    ///
    /// quinn schedules streams with *higher* `i32` values first, so we invert the
    /// `u8` priority (0 = most urgent) by computing `255 - priority` via saturating
    /// subtraction to stay sound under the `arithmetic_side_effects` lint.
    ///
    /// Mapping: `priority 0` → `255` (highest quinn priority); `priority 255` → `0` (lowest).
    #[must_use]
    pub fn quinn_priority(&self) -> i32 {
        i32::from(u8::MAX.saturating_sub(self.priority))
    }

    /// Convenience constructor: input channel (reliable, highest priority).
    #[must_use]
    pub fn input() -> Self {
        Self {
            channel: ChannelId::Input,
            reliability: Reliability::Reliable,
            priority: 0,
        }
    }

    /// Convenience constructor: video channel (unreliable).
    #[must_use]
    pub fn video() -> Self {
        Self {
            channel: ChannelId::Video,
            reliability: Reliability::Unreliable,
            priority: 0,
        }
    }

    /// Convenience constructor: control channel (reliable, low priority).
    #[must_use]
    pub fn control() -> Self {
        Self {
            channel: ChannelId::Control,
            reliability: Reliability::Reliable,
            priority: 128,
        }
    }

    /// Encode this spec into the 2-byte channel-open header written at stream start.
    ///
    /// Layout: `[channel_discriminant: u8, priority: u8]`
    pub(crate) fn encode_header(&self) -> [u8; HEADER_LEN] {
        [channel_id_discriminant(self.channel), self.priority]
    }

    /// Decode the 2-byte channel-open header read from a newly accepted stream.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::InvalidChannelHeader`] if the channel discriminant byte
    /// does not correspond to a known [`ChannelId`].
    pub(crate) fn decode_header(bytes: [u8; HEADER_LEN]) -> Result<Self, TransportError> {
        let channel =
            channel_id_from_discriminant(bytes[0]).ok_or(TransportError::InvalidChannelHeader {
                reason: "unknown channel discriminant byte",
            })?;
        Ok(Self {
            channel,
            reliability: Reliability::Reliable,
            priority: bytes[1],
        })
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Channel discriminant helpers
// ────────────────────────────────────────────────────────────────────────────

/// Maps a [`ChannelId`] to its single-byte wire discriminant.
fn channel_id_discriminant(id: ChannelId) -> u8 {
    match id {
        ChannelId::Video => 0,
        ChannelId::Audio => 1,
        ChannelId::Input => 2,
        ChannelId::Clipboard => 3,
        ChannelId::File => 4,
        ChannelId::Control => 5,
    }
}

/// Maps a single-byte wire discriminant back to a [`ChannelId`], or `None` if unknown.
fn channel_id_from_discriminant(byte: u8) -> Option<ChannelId> {
    match byte {
        0 => Some(ChannelId::Video),
        1 => Some(ChannelId::Audio),
        2 => Some(ChannelId::Input),
        3 => Some(ChannelId::Clipboard),
        4 => Some(ChannelId::File),
        5 => Some(ChannelId::Control),
        _ => None,
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Channel trait
// ────────────────────────────────────────────────────────────────────────────

/// A bidirectional logical channel within a Streamhaul session.
///
/// Implementations are object-safe via `async-trait` so callers can hold a
/// `Box<dyn Channel>`.
#[async_trait]
pub trait Channel: Send {
    /// Send a message on this channel.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] on send failure (connection lost, stream reset, etc.).
    async fn send(&mut self, msg: Bytes) -> Result<(), TransportError>;

    /// Receive the next message from this channel.
    ///
    /// Returns `Ok(None)` when the remote peer has closed their send half cleanly (EOF).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] if the connection is lost or the stream is reset before
    /// a complete message arrives, or if a message header declares an absurd payload length.
    async fn recv(&mut self) -> Result<Option<Bytes>, TransportError>;

    /// Returns the [`ChannelSpec`] that governs this channel.
    fn spec(&self) -> &ChannelSpec;
}

// ────────────────────────────────────────────────────────────────────────────
// Transport trait
// ────────────────────────────────────────────────────────────────────────────

/// An established session transport capable of opening and accepting logical channels.
///
/// The `Transport` trait is object-safe (via `async-trait`) so callers may hold a
/// `Box<dyn Transport>` or `Arc<dyn Transport>`.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Open a new outgoing channel with the given [`ChannelSpec`].
    ///
    /// For reliable channels a QUIC bidirectional stream is opened and the spec is written
    /// as a 2-byte header so the peer's [`accept_channel`](Self::accept_channel) can
    /// reconstruct it. For unreliable channels a datagram-backed channel is returned
    /// immediately (no per-channel stream handshake).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] if the stream or datagram path cannot be established.
    async fn open_channel(&self, spec: ChannelSpec) -> Result<Box<dyn Channel>, TransportError>;

    /// Accept the next incoming reliable channel opened by the peer.
    ///
    /// Reads the 2-byte channel header from the newly accepted stream and reconstructs
    /// the [`ChannelSpec`]. Only reliable (stream) channels are accepted this way;
    /// unreliable (datagram) channels are opened on both sides independently.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] if the connection closes before a channel arrives, or
    /// if the channel header is malformed.
    async fn accept_channel(&self) -> Result<Box<dyn Channel>, TransportError>;

    /// The current QUIC-estimated round-trip time to the peer.
    fn rtt(&self) -> Duration;
}

// ────────────────────────────────────────────────────────────────────────────
// QUIC channel implementations (private)
// ────────────────────────────────────────────────────────────────────────────

/// A reliable (QUIC bidirectional stream) [`Channel`].
struct ReliableChannel {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    spec: ChannelSpec,
}

#[async_trait]
impl Channel for ReliableChannel {
    async fn send(&mut self, msg: Bytes) -> Result<(), TransportError> {
        // `try_from` is panic-free and handles the cast; the `>` check then validates the limit.
        let len_u32 = u32::try_from(msg.len())
            .map_err(|_| TransportError::MessageTooLarge { len: u32::MAX })?;
        // Reject before we write anything so the stream stays usable.
        if len_u32 > MAX_FRAME_LEN {
            return Err(TransportError::MessageTooLarge { len: len_u32 });
        }
        // Build: [u32 BE length (4 bytes)] [payload]
        // Use saturating_add to satisfy the arithmetic_side_effects lint; capacity is bounded by
        // MAX_FRAME_LEN (16 MiB) so this never actually saturates.
        let capacity = (4_usize).saturating_add(msg.len());
        let mut buf = BytesMut::with_capacity(capacity);
        buf.put_u32(len_u32);
        buf.put(msg);
        self.send
            .write_all(&buf.freeze())
            .await
            .map_err(TransportError::Io)
    }

    async fn recv(&mut self) -> Result<Option<Bytes>, TransportError> {
        // Read the 4-byte length prefix.
        let mut len_buf = [0u8; 4];
        match self.recv.read_exact(&mut len_buf).await {
            Ok(()) => {}
            Err(quinn::ReadExactError::FinishedEarly(_)) => return Ok(None),
            Err(e) => return Err(TransportError::StreamRead(e)),
        }
        let payload_len = u32::from_be_bytes(len_buf);
        if payload_len > MAX_FRAME_LEN {
            return Err(TransportError::MessageTooLarge { len: payload_len });
        }
        // Read the payload.
        let mut payload = vec![0u8; payload_len as usize];
        match self.recv.read_exact(&mut payload).await {
            Ok(()) => {}
            Err(quinn::ReadExactError::FinishedEarly(_)) => {
                return Err(TransportError::StreamClosed)
            }
            Err(e) => return Err(TransportError::StreamRead(e)),
        }
        Ok(Some(Bytes::from(payload)))
    }

    fn spec(&self) -> &ChannelSpec {
        &self.spec
    }
}

/// An unreliable (QUIC datagram) [`Channel`].
///
/// Both sides create this channel independently; no per-channel stream handshake is needed.
/// Demuxing multiple datagram channels by the SHP CHANNEL header field is a follow-up task (P1-5).
struct DatagramChannel {
    conn: quinn::Connection,
    spec: ChannelSpec,
}

#[async_trait]
impl Channel for DatagramChannel {
    async fn send(&mut self, msg: Bytes) -> Result<(), TransportError> {
        self.conn
            .send_datagram_wait(msg)
            .await
            .map_err(|e| match e {
                quinn::SendDatagramError::UnsupportedByPeer => {
                    TransportError::DatagramsNotSupported
                }
                other => TransportError::SendDatagram(other),
            })
    }

    async fn recv(&mut self) -> Result<Option<Bytes>, TransportError> {
        self.conn
            .read_datagram()
            .await
            .map(Some)
            .map_err(TransportError::Connection)
    }

    fn spec(&self) -> &ChannelSpec {
        &self.spec
    }
}

// ────────────────────────────────────────────────────────────────────────────
// QuicTransport
// ────────────────────────────────────────────────────────────────────────────

/// A [`Transport`] implementation backed by an established QUIC connection.
///
/// Construct with [`QuicTransport::new`], passing in a [`Connection`] obtained from
/// [`ServerEndpoint::accept`](crate::ServerEndpoint::accept) or
/// [`ClientEndpoint::connect`](crate::ClientEndpoint::connect).
///
/// `QuicTransport` is `Send + Sync` (behind `Arc` the inner `quinn::Connection` is cheaply
/// cloneable), enabling multiple tasks to open or accept channels concurrently.
pub struct QuicTransport {
    inner: quinn::Connection,
}

impl QuicTransport {
    /// Wrap an established [`Connection`] in a `QuicTransport`.
    #[must_use]
    pub fn new(conn: Connection) -> Self {
        Self {
            inner: conn.into_quinn(),
        }
    }
}

#[async_trait]
impl Transport for QuicTransport {
    async fn open_channel(&self, spec: ChannelSpec) -> Result<Box<dyn Channel>, TransportError> {
        match spec.reliability {
            Reliability::Reliable => {
                let (mut send, recv) = self
                    .inner
                    .open_bi()
                    .await
                    .map_err(TransportError::Connection)?;

                // Set quinn stream priority: larger i32 = scheduled first.
                // `set_priority` returns Err(ClosedStream) only if the stream is already
                // finished/reset, which cannot happen on a freshly opened stream. We surface it
                // as StreamAlreadyClosed rather than silently ignoring it.
                send.set_priority(spec.quinn_priority())
                    .map_err(|_| TransportError::StreamAlreadyClosed)?;

                // Write 2-byte channel header so accept_channel can reconstruct the spec.
                let header = spec.encode_header();
                send.write_all(&header).await.map_err(TransportError::Io)?;

                Ok(Box::new(ReliableChannel { send, recv, spec }))
            }
            Reliability::Unreliable => Ok(Box::new(DatagramChannel {
                conn: self.inner.clone(),
                spec,
            })),
        }
    }

    async fn accept_channel(&self) -> Result<Box<dyn Channel>, TransportError> {
        // Only reliable (stream) channels are accepted; datagram channels are opened
        // independently on both sides without a handshake.
        let (send, mut recv) = self
            .inner
            .accept_bi()
            .await
            .map_err(TransportError::Connection)?;

        // Read the 2-byte channel-open header.
        let mut header_buf = [0u8; HEADER_LEN];
        recv.read_exact(&mut header_buf)
            .await
            .map_err(TransportError::StreamRead)?;

        let spec = ChannelSpec::decode_header(header_buf)?;

        Ok(Box::new(ReliableChannel { send, recv, spec }))
    }

    fn rtt(&self) -> Duration {
        self.inner.rtt()
    }
}
