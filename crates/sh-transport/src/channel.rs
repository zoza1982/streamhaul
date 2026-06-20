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
//! `i32::from(u8::MAX.saturating_sub(priority))`, giving priority 0 → `i32` 255 (highest), and
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
///
/// Two related capabilities are **intentionally deferred** and so do not appear here yet:
/// per-channel `ordering`/`fec` profiles (P1-4) and a `Transport::stats()` accessor exposing
/// loss/cwnd/pacing alongside [`Transport::rtt`] (P1-5). They will be added when those tasks land.
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

    /// Convenience constructor: control channel (reliable, urgency 1).
    ///
    /// Maps to LLD §3.2 urgency 1 (RFC 9218). Priority 1 → quinn i32 254 (second-highest after
    /// input), ensuring RPC/control frames drain before clipboard and file traffic but never ahead
    /// of input events.
    #[must_use]
    pub fn control() -> Self {
        Self {
            channel: ChannelId::Control,
            reliability: Reliability::Reliable,
            priority: 1,
        }
    }

    /// Convenience constructor: clipboard channel (reliable, urgency 2).
    ///
    /// Maps to LLD §3.2 urgency 2 (RFC 9218). Priority 2 → quinn i32 253. Reliable and ordered
    /// so clipboard content is never truncated, but lower urgency than input and control.
    #[must_use]
    pub fn clipboard() -> Self {
        Self {
            channel: ChannelId::Clipboard,
            reliability: Reliability::Reliable,
            priority: 2,
        }
    }

    /// Convenience constructor: file-transfer channel (reliable, urgency 6 = lowest).
    ///
    /// Maps to LLD §3.2 urgency 6 (RFC 9218). Priority 6 → quinn i32 249. Each file transfer
    /// uses its own QUIC stream, giving it independent per-stream flow control so a bulk file
    /// copy cannot head-of-line-block input, video, or control streams — the congestion-isolation
    /// guarantee documented in LLD §4.7 is structural: separate streams, not a shared mutex.
    ///
    /// # Priority table (LLD §3.2)
    ///
    /// | Channel   | urgency | `priority` field | quinn i32 |
    /// |-----------|---------|-----------------|-----------|
    /// | input     | 0       | 0               | 255       |
    /// | control   | 1       | 1               | 254       |
    /// | clipboard | 2       | 2               | 253       |
    /// | file      | 6       | 6               | 249       |
    #[must_use]
    pub fn file() -> Self {
        Self {
            channel: ChannelId::File,
            reliability: Reliability::Reliable,
            priority: 6,
        }
    }

    /// Encode this spec into the 2-byte channel-open header written at stream start.
    ///
    /// Layout: `[channel_discriminant: u8, priority: u8]`. The discriminant comes from the single
    /// source of truth in `sh-types` ([`u8::from`]`(ChannelId)`), shared with the SHP common header.
    pub(crate) fn encode_header(&self) -> [u8; HEADER_LEN] {
        [u8::from(self.channel), self.priority]
    }

    /// Decode the 2-byte channel-open header read from a newly accepted stream.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::InvalidChannelHeader`] if the channel discriminant byte
    /// does not correspond to a known [`ChannelId`]. The mapping is the single source of truth in
    /// `sh-types` ([`ChannelId::try_from`]), shared with the SHP common header.
    pub(crate) fn decode_header(bytes: [u8; HEADER_LEN]) -> Result<Self, TransportError> {
        let channel =
            ChannelId::try_from(bytes[0]).map_err(|_| TransportError::InvalidChannelHeader {
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
// Framing decode (fuzz seam)
// ────────────────────────────────────────────────────────────────────────────

/// Pure, side-effect-free decode of the stream framing parsers, for fuzzing.
///
/// Exercises the two untrusted-byte parsers in this module without a live connection:
/// 1. the 2-byte channel-open header ([`ChannelSpec::decode_header`]), and
/// 2. the `u32` big-endian length-prefix bound check (`> MAX_FRAME_LEN` is rejected).
///
/// It performs no allocation and never reads the payload — only the framing decisions a hostile
/// peer can influence. Hidden from docs as it exists purely as a fuzz/test seam.
///
/// # Errors
///
/// Returns [`TransportError::InvalidChannelHeader`] for an unknown channel discriminant and
/// [`TransportError::MessageTooLarge`] for a declared length above [`MAX_FRAME_LEN`].
#[doc(hidden)]
pub fn fuzz_decode_framing(data: &[u8]) -> Result<(), TransportError> {
    // Header parse: take the first 2 bytes (or pad with zeros) and run the real decoder.
    let header = [
        data.first().copied().unwrap_or(0),
        data.get(1).copied().unwrap_or(0),
    ];
    let _ = ChannelSpec::decode_header(header)?;

    // Length-prefix parse: take the next 4 bytes (or pad) and apply the same bound check as recv.
    let len = u32::from_be_bytes([
        data.get(2).copied().unwrap_or(0),
        data.get(3).copied().unwrap_or(0),
        data.get(4).copied().unwrap_or(0),
        data.get(5).copied().unwrap_or(0),
    ]);
    if len > MAX_FRAME_LEN {
        return Err(TransportError::MessageTooLarge { len });
    }
    Ok(())
}

// ────────────────────────────────────────────────────────────────────────────
// Channel trait
// ────────────────────────────────────────────────────────────────────────────

/// A bidirectional logical channel within a Streamhaul session.
///
/// Implementations are object-safe via `async-trait` so callers can hold a
/// `Box<dyn Channel>`.
///
/// The bound is `Send + 'static` (per `LLD.md` §2). `Sync` is **intentionally omitted**: a channel
/// is single-owner (one task drives `send`/`recv` via `&mut self`), and the underlying
/// `quinn::SendStream`/`RecvStream` are not `Sync`. Add `Sync` only if a future design shares a
/// channel across tasks behind a lock.
#[async_trait]
pub trait Channel: Send + 'static {
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
/// `Box<dyn Transport>` or `Arc<dyn Transport>`. The bound is `Send + Sync + 'static` (per
/// `LLD.md` §2) so a transport can be shared across tasks behind an `Arc`.
#[async_trait]
pub trait Transport: Send + Sync + 'static {
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
    ///
    /// A richer `stats()` accessor (loss, cwnd, pacing) is intentionally deferred to P1-5; until
    /// then, `rtt` / [`rtt_us`](Self::rtt_us) are the only exposed link metrics.
    fn rtt(&self) -> Duration;

    /// The current RTT to the peer in whole microseconds, or `None` if it does not fit a [`u64`].
    ///
    /// Provided as a default that converts [`rtt`](Self::rtt), matching `LLD.md` §2, so impls do
    /// not have to repeat it.
    fn rtt_us(&self) -> Option<u64> {
        u64::try_from(self.rtt().as_micros()).ok()
    }
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
            // `FinishedEarly(0)` is a clean FIN exactly on a message boundary → EOF.
            Err(quinn::ReadExactError::FinishedEarly(0)) => return Ok(None),
            // `FinishedEarly(n > 0)` means the peer finished mid length-prefix: a truncated frame,
            // not a clean EOF. Treat it as a closed-mid-message error so callers don't mistake a
            // partial header for end-of-stream.
            Err(quinn::ReadExactError::FinishedEarly(_)) => {
                return Err(TransportError::StreamClosed)
            }
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
///
/// All datagram channels over one connection currently share a single receive queue: every
/// [`DatagramChannel::recv`] pulls from the same `quinn::Connection` datagram stream, so opening
/// several datagram channels does **not** give each its own demuxed feed. Demuxing by the SHP
/// CHANNEL header field is a follow-up task (P1-5).
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

    /// Receive the next datagram.
    ///
    /// Unlike a reliable channel, this **never returns `Ok(None)`**: datagrams have no stream FIN,
    /// so the only terminal outcome is `Err(`[`TransportError::Connection`]`)` when the connection
    /// closes. A successful read is always `Ok(Some(..))`.
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

    /// The maximum datagram payload size negotiated for this connection, or `None` if the peer
    /// does not support datagrams.
    ///
    /// Exposed so the P1-5 datagram-demux layer can size buffers without re-wrapping the
    /// consumed [`Connection`] (which `QuicTransport::new` takes by value).
    #[must_use]
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.inner.max_datagram_size()
    }

    /// Open a raw QUIC bidirectional stream with **no** channel-open header written.
    ///
    /// Test-only seam: lets negative tests inject malformed/hostile framing (bad headers, oversized
    /// length prefixes, truncated payloads) that `open_channel` would never produce. The peer
    /// accepts with [`Transport::accept_channel`].
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Connection`] if the stream cannot be opened.
    #[cfg(test)]
    pub(crate) async fn open_raw_bi(
        &self,
    ) -> Result<(quinn::SendStream, quinn::RecvStream), TransportError> {
        self.inner
            .open_bi()
            .await
            .map_err(TransportError::Connection)
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

        // Read the 2-byte channel-open header. A peer that opens a stream and finishes it before
        // (or partway through) the header is malformed input, not a transport read error: surface
        // it as InvalidChannelHeader so empty-stream floods can't masquerade as read failures.
        let mut header_buf = [0u8; HEADER_LEN];
        match recv.read_exact(&mut header_buf).await {
            Ok(()) => {}
            Err(quinn::ReadExactError::FinishedEarly(_)) => {
                return Err(TransportError::InvalidChannelHeader {
                    reason: "stream closed before header",
                });
            }
            Err(e) => return Err(TransportError::StreamRead(e)),
        }

        let spec = ChannelSpec::decode_header(header_buf)?;

        Ok(Box::new(ReliableChannel { send, recv, spec }))
    }

    fn rtt(&self) -> Duration {
        self.inner.rtt()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Unit tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
mod framing_tests {
    use super::*;

    #[test]
    fn fuzz_decode_framing_rejects_unknown_channel() {
        // Discriminant 0xFF is not a known channel.
        let err = fuzz_decode_framing(&[0xFF, 0]).unwrap_err();
        assert!(matches!(err, TransportError::InvalidChannelHeader { .. }));
    }

    #[test]
    fn fuzz_decode_framing_rejects_oversized_length() {
        // Valid channel byte (Input=2), priority 0, then a u32 length above MAX_FRAME_LEN.
        let oversized = MAX_FRAME_LEN.saturating_add(1).to_be_bytes();
        let data = [
            2u8,
            0,
            oversized[0],
            oversized[1],
            oversized[2],
            oversized[3],
        ];
        let err = fuzz_decode_framing(&data).unwrap_err();
        assert!(matches!(err, TransportError::MessageTooLarge { .. }));
    }

    #[test]
    fn fuzz_decode_framing_accepts_well_formed_short_input() {
        // Valid header + a small length is accepted; padding with zeros is fine.
        assert!(fuzz_decode_framing(&[0u8, 0, 0, 0, 0, 1]).is_ok());
        // Empty input pads to a zero header (channel 0 = Video) and zero length: still Ok.
        assert!(fuzz_decode_framing(&[]).is_ok());
    }

    #[test]
    fn decode_header_roundtrips_via_single_source_of_truth() {
        let spec = ChannelSpec::control();
        let header = spec.encode_header();
        let decoded = ChannelSpec::decode_header(header).unwrap();
        assert_eq!(decoded.channel, spec.channel);
        assert_eq!(decoded.priority, spec.priority);
    }
}

// Hostile-input / negative tests over a live loopback QUIC connection. These need the LAN-lab
// insecure TLS feature to stand up an endpoint pair, and the in-crate `open_raw_bi` seam to inject
// malformed framing that `open_channel` would never produce.
#[cfg(all(test, feature = "insecure-lan"))]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]
mod hostile_input_tests {
    use super::*;
    use std::net::SocketAddr;
    use std::time::Duration;

    use crate::{
        insecure_client_config, self_signed_server_config, ClientEndpoint, InsecureLanLab,
        ServerEndpoint,
    };

    fn ack() -> InsecureLanLab {
        InsecureLanLab::i_understand_this_skips_tls_verification()
    }

    fn loopback() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    async fn transport_pair() -> (QuicTransport, QuicTransport) {
        let server =
            ServerEndpoint::bind(loopback(), self_signed_server_config(ack()).unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let client = ClientEndpoint::bind(insecure_client_config(ack()).unwrap()).unwrap();

        let (server_conn, client_conn) =
            tokio::join!(server.accept(), client.connect(addr, "localhost"));

        (
            QuicTransport::new(server_conn.unwrap()),
            QuicTransport::new(client_conn.unwrap()),
        )
    }

    /// A peer declares a length far above `MAX_FRAME_LEN`; `recv` must reject it with
    /// `MessageTooLarge` and must NOT attempt to allocate the declared payload.
    #[tokio::test]
    async fn recv_rejects_oversized_declared_length() {
        let (server, client) = transport_pair().await;

        let (server_ch, raw) = tokio::join!(server.accept_channel(), async {
            let (mut send, recv) = client.open_raw_bi().await.unwrap();
            // Valid 2-byte header (Input, priority 0) so accept_channel succeeds.
            send.write_all(&ChannelSpec::input().encode_header())
                .await
                .unwrap();
            // Then an absurd u32 length prefix.
            let huge = u32::MAX.to_be_bytes();
            send.write_all(&huge).await.unwrap();
            (send, recv)
        });

        let mut server_ch = server_ch.unwrap();
        let _raw = raw; // keep the stream alive

        let err = tokio::time::timeout(Duration::from_secs(5), server_ch.recv())
            .await
            .expect("recv timed out")
            .unwrap_err();
        assert!(
            matches!(err, TransportError::MessageTooLarge { len } if len == u32::MAX),
            "expected MessageTooLarge, got {err:?}"
        );
    }

    /// `send` of a payload larger than `MAX_FRAME_LEN` is rejected before any bytes hit the wire.
    #[tokio::test]
    async fn send_rejects_oversized_message() {
        let (server, client) = transport_pair().await;

        let (server_ch, client_ch) = tokio::join!(
            server.accept_channel(),
            client.open_channel(ChannelSpec::input())
        );
        let _server_ch = server_ch.unwrap();
        let mut client_ch = client_ch.unwrap();

        // One byte over the limit is the cheapest construction that trips the check.
        let too_big = Bytes::from(vec![0u8; MAX_FRAME_LEN as usize + 1]);
        let err = client_ch.send(too_big).await.unwrap_err();
        assert!(
            matches!(err, TransportError::MessageTooLarge { .. }),
            "expected MessageTooLarge, got {err:?}"
        );
    }

    /// A peer opens a stream, writes a single byte, then finishes: `accept_channel` must return
    /// `InvalidChannelHeader` (stream closed before header), not hang or surface a read error.
    #[tokio::test]
    async fn accept_channel_rejects_partial_header() {
        let (server, client) = transport_pair().await;

        // Bound the accept so a regression that hangs fails fast instead of stalling the suite.
        let accept = tokio::time::timeout(Duration::from_secs(5), server.accept_channel());
        let (server_res, _client_side) = tokio::join!(accept, async {
            let (mut send, recv) = client.open_raw_bi().await.unwrap();
            send.write_all(&[2u8]).await.unwrap(); // only 1 of 2 header bytes
            send.finish().unwrap();
            recv
        });

        match server_res.expect("accept timed out") {
            Err(TransportError::InvalidChannelHeader {
                reason: "stream closed before header",
            }) => {}
            Err(other) => {
                panic!("expected InvalidChannelHeader(closed before header), got {other:?}")
            }
            Ok(_) => panic!("expected error, got an accepted channel"),
        }
    }

    /// A peer writes a full but unknown discriminant byte: `accept_channel` rejects it with
    /// `InvalidChannelHeader`.
    #[tokio::test]
    async fn accept_channel_rejects_unknown_discriminant() {
        let (server, client) = transport_pair().await;

        let (server_res, _raw) = tokio::join!(server.accept_channel(), async {
            let (mut send, recv) = client.open_raw_bi().await.unwrap();
            send.write_all(&[0xFFu8, 0]).await.unwrap(); // unknown channel, priority 0
            (send, recv)
        });

        match server_res {
            Err(TransportError::InvalidChannelHeader {
                reason: "unknown channel discriminant byte",
            }) => {}
            Err(other) => {
                panic!("expected InvalidChannelHeader(unknown discriminant), got {other:?}")
            }
            Ok(_) => panic!("expected error, got an accepted channel"),
        }
    }

    /// A peer writes a valid header and length prefix but finishes after fewer than N payload
    /// bytes: `recv` must return `StreamClosed` (truncated mid-payload), not `Ok(None)`.
    #[tokio::test]
    async fn recv_rejects_truncated_payload() {
        let (server, client) = transport_pair().await;

        let (server_ch, _raw) = tokio::join!(server.accept_channel(), async {
            let (mut send, recv) = client.open_raw_bi().await.unwrap();
            send.write_all(&ChannelSpec::input().encode_header())
                .await
                .unwrap();
            // Declare 16 bytes of payload but send only 4, then finish.
            send.write_all(&16u32.to_be_bytes()).await.unwrap();
            send.write_all(&[1u8, 2, 3, 4]).await.unwrap();
            send.finish().unwrap();
            recv
        });

        let mut server_ch = server_ch.unwrap();
        let err = tokio::time::timeout(Duration::from_secs(5), server_ch.recv())
            .await
            .expect("recv timed out")
            .unwrap_err();
        assert!(
            matches!(err, TransportError::StreamClosed),
            "expected StreamClosed, got {err:?}"
        );
    }

    /// A peer finishes the stream exactly on a message boundary (no partial prefix): `recv`
    /// returns `Ok(None)` (clean EOF).
    #[tokio::test]
    async fn recv_clean_eof_on_boundary_returns_none() {
        let (server, client) = transport_pair().await;

        let (server_ch, _raw) = tokio::join!(server.accept_channel(), async {
            let (mut send, recv) = client.open_raw_bi().await.unwrap();
            send.write_all(&ChannelSpec::input().encode_header())
                .await
                .unwrap();
            // No frame at all, finish cleanly on the boundary.
            send.finish().unwrap();
            recv
        });

        let mut server_ch = server_ch.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), server_ch.recv())
            .await
            .expect("recv timed out")
            .unwrap();
        assert_eq!(got, None, "expected clean EOF (Ok(None))");
    }

    /// When the connection closes, a datagram channel's `recv` returns `Err(Connection(..))` and
    /// never `Ok(None)`.
    #[tokio::test]
    async fn datagram_recv_errors_on_connection_close() {
        let (server, client) = transport_pair().await;

        let mut server_video = server.open_channel(ChannelSpec::video()).await.unwrap();

        // Tear down the client side so the server's connection closes.
        drop(client);

        let result = tokio::time::timeout(Duration::from_secs(5), server_video.recv()).await;
        match result {
            Ok(Err(TransportError::Connection(_))) => {}
            Ok(Ok(_)) => panic!("datagram recv must never return Ok on connection close"),
            Ok(Err(other)) => panic!("expected Connection error, got {other:?}"),
            Err(_elapsed) => panic!("datagram recv did not terminate after connection close"),
        }
    }
}
