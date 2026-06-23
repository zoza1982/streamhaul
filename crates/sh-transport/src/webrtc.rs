//! WebRTC transport backed by the [`str0m`] sans-IO WebRTC engine.
//!
//! This module provides [`WebRtcTransport`] and [`WebRtcChannel`], which implement the
//! [`Transport`] and [`Channel`] traits using WebRTC data channels. The underlying engine is
//! `str0m 0.20` — a sans-IO library that leaves network I/O, timers, and threading to the caller.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │  WebRtcTransport  (Arc<Mutex<WebRtcInner>>)     │
//! │                                                 │
//! │  drive(now)        ← call from timer task       │
//! │  handle_receive()  ← call on UDP socket recv    │
//! │                                                 │
//! │  open_channel()   → WebRtcChannel               │
//! │  accept_channel() → WebRtcChannel               │
//! └─────────────────────────────────────────────────┘
//!          │
//!          ▼
//!  std::sync::Mutex<WebRtcInner>
//!          │
//!          ▼
//!       str0m::Rtc   (sans-IO engine)
//! ```
//!
//! `str0m::Rtc` is not `Sync`, so we wrap it in a `std::sync::Mutex` (not a tokio `Mutex`) to
//! avoid holding a lock across `.await` points. The outer `Arc` allows the transport and its
//! channels to share the same engine.
//!
//! # Drive loop
//!
//! The str0m engine is driven by calling [`WebRtcTransport::drive`] periodically and after each
//! received packet. The caller is responsible for:
//! 1. Dispatching outbound [`str0m::net::Transmit`] datagrams to the network socket.
//! 2. Feeding inbound datagrams via [`WebRtcTransport::handle_receive`].
//! 3. Scheduling the next `drive` call at `Instant::now()` after each timeout output.
//!
//! In tests, this is done synchronously in the test body. In production, a tokio background task
//! will own the drive loop (deferred to P5 when the signaling path is wired up).

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use str0m::channel::ChannelId as Str0mChannelId;
use str0m::net::Receive;
use str0m::{Event, Input, Output, Rtc};

use crate::channel::{Channel, ChannelSpec, Reliability, Transport};
use crate::error::TransportError;

// ── Inner state ───────────────────────────────────────────────────────────────

/// All mutable state protected by the outer `Mutex`.
struct WebRtcInner {
    /// The str0m sans-IO WebRTC engine.
    rtc: Rtc,

    /// Per-channel receive queues. Data arriving from the remote peer is pushed here by
    /// [`WebRtcTransport::drive`] and consumed by [`WebRtcChannel::recv`].
    recv_queues: HashMap<Str0mChannelId, VecDeque<Bytes>>,

    /// Outbound datagrams waiting to be dispatched to the network socket.
    outbound: VecDeque<str0m::net::Transmit>,

    /// Channels that the remote peer has opened (via ChannelOpen events) and are pending acceptance.
    accept_queue: VecDeque<WebRtcChannelSpec>,

    /// Latest smoothed RTT observed from the engine.
    rtt: Duration,
}

/// Transient descriptor used to construct a [`WebRtcChannel`] on the accept path.
struct WebRtcChannelSpec {
    /// The str0m channel id.
    id: Str0mChannelId,
    /// The label assigned to the data channel (exposed to callers in future P5 accept API).
    #[allow(dead_code)]
    label: String,
}

impl WebRtcInner {
    fn new(rtc: Rtc) -> Self {
        Self {
            rtc,
            recv_queues: HashMap::new(),
            outbound: VecDeque::new(),
            accept_queue: VecDeque::new(),
            rtt: Duration::ZERO,
        }
    }

    /// Feed `Input::Timeout(now)` and drain all output into queues.
    fn drive(&mut self, now: Instant) -> Result<(), TransportError> {
        self.rtc
            .handle_input(Input::Timeout(now))
            .map_err(|e| TransportError::Webrtc(e.to_string()))?;
        self.drain_output()
    }

    /// Feed an inbound datagram.
    fn handle_receive(
        &mut self,
        from: SocketAddr,
        to: SocketAddr,
        data: &[u8],
        now: Instant,
    ) -> Result<(), TransportError> {
        let receive = Receive::new(str0m::net::Protocol::Udp, from, to, data)
            .map_err(|e| TransportError::Webrtc(e.to_string()))?;
        self.rtc
            .handle_input(Input::Receive(now, receive))
            .map_err(|e| TransportError::Webrtc(e.to_string()))?;
        self.drain_output()
    }

    /// Drain all pending output from the str0m engine into the internal queues.
    fn drain_output(&mut self) -> Result<(), TransportError> {
        loop {
            match self
                .rtc
                .poll_output()
                .map_err(|e| TransportError::Webrtc(e.to_string()))?
            {
                Output::Transmit(t) => {
                    self.outbound.push_back(t);
                }
                Output::Timeout(_) => {
                    // Timeout is a signal to the caller to schedule a future drive; no queuing.
                    break;
                }
                Output::Event(event) => {
                    self.handle_event(event);
                }
            }
        }
        Ok(())
    }

    /// Process a single str0m event.
    fn handle_event(&mut self, event: Event) {
        match event {
            Event::ChannelOpen(id, label) => {
                // Ensure a receive queue exists for this channel.
                self.recv_queues.entry(id).or_default();
                self.accept_queue.push_back(WebRtcChannelSpec { id, label });
            }
            // Binary frames only; text frames are not part of the SHP protocol.
            Event::ChannelData(cd) if cd.binary => {
                let queue = self.recv_queues.entry(cd.id).or_default();
                queue.push_back(Bytes::from(cd.data));
            }
            Event::ChannelData(_) => {
                // Text frame — discard silently.
            }
            Event::ChannelClose(id) => {
                self.recv_queues.remove(&id);
            }
            // All other events (Connected, IceConnectionStateChange, etc.) are informational.
            _ => {}
        }
    }

    /// Drain all queued outbound transmits and return them to the caller.
    fn take_outbound(&mut self) -> Vec<str0m::net::Transmit> {
        self.outbound.drain(..).collect()
    }
}

// ── WebRtcTransport ───────────────────────────────────────────────────────────

/// A [`Transport`] implementation backed by the str0m WebRTC sans-IO engine.
///
/// # Construction
///
/// ```rust,no_run
/// use std::time::Instant;
/// use str0m::Rtc;
/// use sh_transport::webrtc::WebRtcTransport;
/// use std::net::{Ipv4Addr, SocketAddr};
///
/// let now = Instant::now();
/// let rtc = Rtc::new(now);
/// let local_addr: SocketAddr = (Ipv4Addr::new(127, 0, 0, 1), 4000).into();
/// let remote_addr: SocketAddr = (Ipv4Addr::new(127, 0, 0, 1), 4001).into();
/// let transport = WebRtcTransport::new(rtc, local_addr, remote_addr);
/// ```
///
/// # Drive loop
///
/// The transport must be driven externally. Call [`drive`](Self::drive) periodically and after
/// every inbound datagram ([`handle_receive`](Self::handle_receive)). Collect the returned
/// transmits and send them on the network socket.
pub struct WebRtcTransport {
    inner: Arc<Mutex<WebRtcInner>>,
    /// Local socket address (used by the P5 drive task to bind the UDP socket).
    #[allow(dead_code)]
    local_addr: SocketAddr,
    /// Remote peer address (used by the P5 drive task to send datagrams).
    #[allow(dead_code)]
    remote_addr: SocketAddr,
}

impl WebRtcTransport {
    /// Wrap an already-configured [`str0m::Rtc`] in a `WebRtcTransport`.
    ///
    /// The `local_addr` / `remote_addr` must match the ICE candidates added to the `Rtc`
    /// before construction.
    #[must_use]
    pub fn new(rtc: Rtc, local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        Self {
            inner: Arc::new(Mutex::new(WebRtcInner::new(rtc))),
            local_addr,
            remote_addr,
        }
    }

    /// Feed a timeout tick into the engine and drain all output.
    ///
    /// Returns outbound datagrams to be sent on the network socket.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Webrtc`] if the str0m engine reports an error.
    pub fn drive(&self, now: Instant) -> Result<Vec<str0m::net::Transmit>, TransportError> {
        let mut inner = self.lock();
        inner.drive(now)?;
        Ok(inner.take_outbound())
    }

    /// Feed an inbound datagram received from `from`, addressed to `to`.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Webrtc`] if the datagram cannot be parsed or the engine errors.
    pub fn handle_receive(
        &self,
        from: SocketAddr,
        to: SocketAddr,
        data: &[u8],
    ) -> Result<(), TransportError> {
        let now = Instant::now();
        let mut inner = self.lock();
        inner.handle_receive(from, to, data, now)
    }

    /// The RTT observed from the ICE/DTLS layer (zero if not yet known).
    #[must_use]
    pub fn rtt(&self) -> Duration {
        self.lock().rtt
    }

    /// Loss fraction (0.0 if not yet known).
    ///
    /// Currently returns 0.0; per-packet loss tracking from TWCC is deferred to P5.
    #[must_use]
    pub fn packet_loss(&self) -> f64 {
        0.0
    }

    // ── Private ───────────────────────────────────────────────────────────────

    fn lock(&self) -> MutexGuard<'_, WebRtcInner> {
        // The mutex is never held across an await point (we use std::sync::Mutex, not tokio).
        // A poisoned mutex indicates an unrecoverable bug elsewhere; unwinding is correct.
        // SAFETY: lock() returns Err only if another thread panicked while holding the lock.
        //         We propagate via expect() because recovering from a poisoned engine is not
        //         meaningful — the internal str0m state would be corrupt.
        #[allow(clippy::expect_used)]
        self.inner.lock().expect("WebRtcInner mutex poisoned")
    }
}

#[async_trait]
impl Transport for WebRtcTransport {
    /// Open an outgoing data channel with the given [`ChannelSpec`].
    ///
    /// Maps [`Reliability::Reliable`] to an ordered SCTP stream and
    /// [`Reliability::Unreliable`] to an unordered SCTP stream.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Webrtc`] if the channel cannot be created.
    async fn open_channel(&self, spec: ChannelSpec) -> Result<Box<dyn Channel>, TransportError> {
        let id = {
            let mut inner = self.lock();
            let config = str0m::channel::ChannelConfig {
                label: format!("{:?}", spec.channel),
                ordered: matches!(spec.reliability, Reliability::Reliable),
                ..Default::default()
            };
            inner.rtc.direct_api().create_data_channel(config)
        };
        Ok(Box::new(WebRtcChannel {
            id,
            inner: Arc::clone(&self.inner),
            spec,
        }))
    }

    /// Accept the next incoming data channel opened by the remote peer.
    ///
    /// Polls the internal accept queue. The accept queue is populated by the drive loop when
    /// a `ChannelOpen` event arrives from the str0m engine.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::StreamClosed`] if no channel arrives within the polling budget.
    async fn accept_channel(&self) -> Result<Box<dyn Channel>, TransportError> {
        // We can't use a real async wait here without a condvar or tokio channel, because
        // WebRtcInner must be driven externally. Instead, yield a bounded number of times
        // and check the accept queue each time. This is sufficient for tests; in production
        // the drive task will fill the queue before accept_channel is called.
        for _ in 0..1_000usize {
            {
                let mut inner = self.lock();
                if let Some(spec) = inner.accept_queue.pop_front() {
                    let channel_spec = ChannelSpec {
                        channel: sh_types::ChannelId::Control, // best default for WebRTC
                        reliability: Reliability::Reliable,
                        priority: 0,
                    };
                    return Ok(Box::new(WebRtcChannel {
                        id: spec.id,
                        inner: Arc::clone(&self.inner),
                        spec: channel_spec,
                    }));
                }
            }
            tokio::task::yield_now().await;
        }
        Err(TransportError::StreamClosed)
    }

    /// The current RTT to the peer (zero if not yet known).
    fn rtt(&self) -> Duration {
        self.lock().rtt
    }
}

// ── WebRtcChannel ─────────────────────────────────────────────────────────────

/// A WebRTC data channel implementing the [`Channel`] trait.
///
/// Wraps a str0m [`ChannelId`](str0m::channel::ChannelId) and shares the engine via
/// `Arc<Mutex<WebRtcInner>>`.
pub struct WebRtcChannel {
    /// The str0m channel identifier.
    id: Str0mChannelId,

    /// Shared engine state.
    inner: Arc<Mutex<WebRtcInner>>,

    /// The spec this channel was opened with.
    spec: ChannelSpec,
}

#[async_trait]
impl Channel for WebRtcChannel {
    /// Send a binary message on this data channel.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Webrtc`] if the channel is not open or the write fails.
    /// Returns [`TransportError::StreamClosed`] if the channel no longer exists in the engine.
    async fn send(&mut self, msg: Bytes) -> Result<(), TransportError> {
        // Mutex poison indicates an unrecoverable bug; expect() is correct here.
        #[allow(clippy::expect_used)]
        let mut inner = self.inner.lock().expect("WebRtcInner mutex poisoned");

        // Write to the channel. `channel()` returns None if the channel is closed.
        {
            let mut chan = inner
                .rtc
                .channel(self.id)
                .ok_or(TransportError::StreamClosed)?;

            chan.write(true, &msg)
                .map_err(|e| TransportError::Webrtc(e.to_string()))?;
            // `chan` borrow ends here; inner.rtc is now fully accessible again.
        }

        // Drain str0m's output after mutating state (required by sans-IO contract).
        inner.drain_output()?;

        Ok(())
    }

    /// Receive the next binary message from this data channel.
    ///
    /// Yields if the receive queue is empty, then tries again. Returns `Ok(None)` if the
    /// channel has been closed (queue removed by a `ChannelClose` event).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::StreamClosed`] if the channel is closed and no data remains.
    async fn recv(&mut self) -> Result<Option<Bytes>, TransportError> {
        loop {
            {
                // Mutex poison indicates an unrecoverable bug; expect() is correct here.
                #[allow(clippy::expect_used)]
                let mut inner = self.inner.lock().expect("WebRtcInner mutex poisoned");

                // If the queue entry is gone, the channel was closed.
                match inner.recv_queues.get_mut(&self.id) {
                    None => return Err(TransportError::StreamClosed),
                    Some(queue) => {
                        if let Some(msg) = queue.pop_front() {
                            return Ok(Some(msg));
                        }
                    }
                }
            }
            // Queue was empty; yield to allow the drive loop to make progress.
            tokio::task::yield_now().await;
        }
    }

    fn spec(&self) -> &ChannelSpec {
        &self.spec
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::drain_collect
)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use str0m::channel::ChannelConfig;
    use str0m::{Candidate, Event, Input, Output, Rtc};

    // ── Synchronous drive helpers ─────────────────────────────────────────────

    /// Owned packet ready to be fed to the other peer.
    struct Packet {
        proto: str0m::net::Protocol,
        source: SocketAddr,
        destination: SocketAddr,
        contents: Vec<u8>,
    }

    /// Feed `Input::Timeout(now)` to `rtc`, drain all `Output::Transmit` packets into `pending`
    /// (addressed to the *other* peer), collect and return `Event::ChannelData` payloads.
    fn drive_step(rtc: &mut Rtc, now: Instant, pending: &mut Vec<Packet>) -> Vec<Vec<u8>> {
        rtc.handle_input(Input::Timeout(now)).unwrap();
        drain_output(rtc, pending)
    }

    /// Deliver pending packets from `packets` to `rtc` and drain that peer's output into
    /// `outgoing`. Returns collected ChannelData payloads.
    fn deliver_packets(
        rtc: &mut Rtc,
        now: Instant,
        packets: &mut Vec<Packet>,
        outgoing: &mut Vec<Packet>,
    ) -> Vec<Vec<u8>> {
        let mut received = Vec::new();
        // We drain via indices to avoid borrow issues.
        let batch: Vec<Packet> = packets.drain(..).collect();
        for pkt in batch {
            let receive = Receive {
                proto: pkt.proto,
                source: pkt.source,
                destination: pkt.destination,
                contents: str0m::net::DatagramRecv::try_from(&pkt.contents[..]).unwrap(),
            };
            rtc.handle_input(Input::Receive(now, receive)).unwrap();
            let mut payloads = drain_output(rtc, outgoing);
            received.append(&mut payloads);
        }
        received
    }

    /// Drain `poll_output` from `rtc` until Timeout, collecting Transmit into `pending` and
    /// returning any ChannelData payloads.
    fn drain_output(rtc: &mut Rtc, pending: &mut Vec<Packet>) -> Vec<Vec<u8>> {
        let mut payloads = Vec::new();
        loop {
            match rtc.poll_output().unwrap() {
                Output::Timeout(_) => break,
                Output::Transmit(t) => {
                    pending.push(Packet {
                        proto: t.proto,
                        source: t.source,
                        destination: t.destination,
                        contents: t.contents.to_vec(),
                    });
                }
                Output::Event(Event::ChannelData(cd)) => {
                    if cd.binary {
                        payloads.push(cd.data);
                    }
                }
                Output::Event(_) => {}
            }
        }
        payloads
    }

    /// Drive until the data channel `ch_id` is open on `a` (i.e., `a.channel(ch_id)` returns
    /// `Some`), or until `deadline` has elapsed. Panics on timeout.
    fn drive_until_channel_open(
        a: &mut Rtc,
        b: &mut Rtc,
        ch_id: Str0mChannelId,
        start: Instant,
        deadline: Duration,
    ) {
        let step = Duration::from_millis(5);
        let mut now = start;
        let mut a_to_b: Vec<Packet> = Vec::new();
        let mut b_to_a: Vec<Packet> = Vec::new();

        loop {
            now += step;
            drive_step(a, now, &mut a_to_b);
            drive_step(b, now, &mut b_to_a);

            deliver_packets(b, now, &mut a_to_b, &mut b_to_a);
            deliver_packets(a, now, &mut b_to_a, &mut a_to_b);

            // The channel is "open" when str0m allows writing (ChannelOpen event has fired).
            if a.channel(ch_id).is_some() {
                return;
            }
            if now.saturating_duration_since(start) > deadline {
                panic!("channel did not open within {deadline:?}");
            }
        }
    }

    /// Drive until data arrives on `b` or deadline is exceeded. Returns first received payload.
    fn drive_until_data(a: &mut Rtc, b: &mut Rtc, start: Instant, deadline: Duration) -> Vec<u8> {
        let step = Duration::from_millis(5);
        let mut now = start;
        let mut a_to_b: Vec<Packet> = Vec::new();
        let mut b_to_a: Vec<Packet> = Vec::new();

        loop {
            now += step;
            drive_step(a, now, &mut a_to_b);
            drive_step(b, now, &mut b_to_a);

            let mut received = deliver_packets(b, now, &mut a_to_b, &mut b_to_a);
            deliver_packets(a, now, &mut b_to_a, &mut a_to_b);

            if let Some(payload) = received.pop() {
                return payload;
            }
            if now.saturating_duration_since(start) > deadline {
                panic!("no data received within {deadline:?}");
            }
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /// Verify that two str0m peers can establish a data-channel connection and exchange data.
    ///
    /// This test exercises the complete handshake (ICE, DTLS, SCTP) and one round-trip of data
    /// using the pattern documented in `str0m/tests/data-channel-direct.rs`.
    #[test]
    fn webrtc_loopback_round_trip() {
        let a_addr: SocketAddr = (Ipv4Addr::new(1, 1, 1, 1), 1000).into();
        let b_addr: SocketAddr = (Ipv4Addr::new(2, 2, 2, 2), 2000).into();

        #[allow(clippy::disallowed_methods)]
        let now = Instant::now();

        let mut a = Rtc::new(now);
        let mut b = Rtc::new(now);

        // Add ICE candidates — each peer must know both its own and the peer's address.
        a.add_local_candidate(Candidate::host(a_addr, "udp").unwrap())
            .unwrap();
        a.add_remote_candidate(Candidate::host(b_addr, "udp").unwrap());
        b.add_local_candidate(Candidate::host(b_addr, "udp").unwrap())
            .unwrap();
        b.add_remote_candidate(Candidate::host(a_addr, "udp").unwrap());

        // Exchange DTLS fingerprints.
        let fp_a = a.direct_api().local_dtls_fingerprint().clone();
        let fp_b = b.direct_api().local_dtls_fingerprint().clone();
        a.direct_api().set_remote_fingerprint(fp_b);
        b.direct_api().set_remote_fingerprint(fp_a);

        // Exchange ICE credentials.
        let creds_a = a.direct_api().local_ice_credentials();
        let creds_b = b.direct_api().local_ice_credentials();
        a.direct_api().set_remote_ice_credentials(creds_b);
        b.direct_api().set_remote_ice_credentials(creds_a);

        // Set roles.
        a.direct_api().set_ice_controlling(true);
        b.direct_api().set_ice_controlling(false);
        a.direct_api().start_dtls(true).unwrap();
        b.direct_api().start_dtls(false).unwrap();
        a.direct_api().start_sctp(true);
        b.direct_api().start_sctp(false);

        // Create data channel out-of-band (both peers use the same negotiated stream id).
        let channel_config = ChannelConfig {
            negotiated: Some(1),
            label: "shp-control".into(),
            ..Default::default()
        };
        let ch_id = a.direct_api().create_data_channel(channel_config.clone());
        b.direct_api().create_data_channel(channel_config);

        // Drive until ICE/DTLS/SCTP are established AND the data channel is open.
        // `a.channel(ch_id)` returns Some only after the ChannelOpen event has been processed.
        drive_until_channel_open(&mut a, &mut b, ch_id, now, Duration::from_secs(10));

        // Write a message from a to b.
        let payload = b"hello streamhaul";
        {
            let mut chan = a.channel(ch_id).expect("channel must be open after drive");
            chan.write(true, payload).expect("write must succeed");
        }

        // Drive until b receives the data.
        let received = drive_until_data(
            &mut a,
            &mut b,
            now + Duration::from_millis(10),
            Duration::from_secs(5),
        );
        assert_eq!(
            received, payload,
            "received payload must match sent payload"
        );
    }

    /// Verify that `WebRtcTransport::new` constructs without panicking and returns sane defaults.
    #[test]
    fn webrtc_transport_constructs() {
        let local: SocketAddr = (Ipv4Addr::new(127, 0, 0, 1), 5000).into();
        let remote: SocketAddr = (Ipv4Addr::new(127, 0, 0, 1), 5001).into();

        #[allow(clippy::disallowed_methods)]
        let now = Instant::now();

        let rtc = Rtc::new(now);
        let transport = WebRtcTransport::new(rtc, local, remote);
        assert_eq!(transport.rtt(), Duration::ZERO, "initial RTT must be zero");
        assert_eq!(transport.packet_loss(), 0.0, "initial loss must be zero");
    }

    /// Verify that `drive()` does not panic on a freshly constructed transport.
    #[test]
    fn drive_does_not_panic() {
        let local: SocketAddr = (Ipv4Addr::new(1, 1, 1, 1), 1000).into();
        let remote: SocketAddr = (Ipv4Addr::new(2, 2, 2, 2), 2000).into();

        #[allow(clippy::disallowed_methods)]
        let now = Instant::now();

        let rtc = Rtc::new(now);
        let transport = WebRtcTransport::new(rtc, local, remote);
        let transmits = transport.drive(now).expect("drive must not error");
        // A fresh Rtc with no candidates may or may not produce transmits; either is fine.
        let _ = transmits;
    }
}
