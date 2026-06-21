//! Input round-trip latency (RTT) harness — Gate P1 "click-to-photon" proxy.
//!
//! Measures the **protocol/transport portion** of click-to-photon latency by running real
//! [`InputEvent`]s over the reliable, ordered, highest-priority Input channel end-to-end over
//! a loopback QUIC connection. The host side receives each event, injects it via a
//! [`RecordingInjector`], and echoes the raw 16-byte event back to the client. The client
//! matches each echo to its send timestamp, computing per-event RTT.
//!
//! Each event's RTT is measured as a serialized round-trip: the client sends event i, then
//! blocks waiting for its echo before sending event i+1. This yields the true per-event
//! transport RTT (the correct click-to-photon proxy for the network+transport contribution).
//!
//! True glass-to-photon additionally requires real input injection (deferred — R14) and real
//! capture/encode (deferred — P0-6/7/8). This harness bounds the *network + transport
//! contribution* and validates the input path end-to-end, leaving the OS injection overhead
//! as the only unquantified term.
//!
//! # Protocol
//!
//! The ack scheme is **echo**: the host echoes each received 16-byte `InputEvent` verbatim on
//! the same bidirectional Input channel. The client reconstructs the event from the echo and
//! uses `pointer_x` (which encodes the send index `i as u16`) to key the RTT map. This lets
//! the client detect reordering without a separate index field — the wire event itself carries
//! the index. Because the Input channel is reliable and ordered, reordering is not expected,
//! but the harness asserts `all_injected_in_order` by collecting each received event's
//! `pointer_x` into a `received_indices` vector (as events arrive) and comparing it against
//! `0..event_count`. (`RecordingInjector` is used only for the `inject()` side effect, not for
//! the order check.)
//!
//! # Harness Topology vs. Production
//!
//! In production the Input channel is **client → host only** (unidirectional in practice —
//! the host receives input events and injects them; it never needs to reply on the same
//! channel). This harness has the host **echo** every received event back to the client on
//! the same bidirectional Input stream solely for RTT measurement. Do not interpret the
//! host's echo behavior as validation of the real unidirectional host receive loop.
//!
//! # Connection lifetime
//!
//! The server `Connection` is moved into the host task; the client `Connection` is moved into
//! the client task. The reliable Input channel stream keeps data buffered by quinn until ACKed,
//! so all echoes are delivered to the client before either side drops its connection handle.
//! A oneshot coordinates teardown: the client signals "done" to the host, which then returns
//! and drops the server connection. This avoids `CONNECTION_CLOSE` racing with in-flight data.

use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::oneshot;

use sh_input::{InputInjector, RecordingInjector};
use sh_protocol::{EventType, InputEvent, Modifiers};
use sh_transport::{ChannelSpec, ClientEndpoint, QuicTransport, ServerEndpoint, Transport};

/// Parameters for the input RTT loopback harness.
#[derive(Debug, Clone)]
pub struct InputRttParams {
    /// Number of distinct [`InputEvent`]s to send and echo.
    ///
    /// Each event encodes its zero-based send index in `pointer_x` so injection order is
    /// verifiable without a separate sequence number.
    ///
    /// Maximum allowed value is 65 536 (`u16::MAX + 1`). Use [`InputRttError::TooManyEvents`]
    /// for counts that exceed this limit.
    pub event_count: usize,
}

/// Per-event RTT measurement produced by the input RTT harness.
#[derive(Debug, Clone)]
pub struct InputEventMeasurement {
    /// Zero-based index of this event (encoded as `pointer_x` on the wire).
    pub event_idx: usize,
    /// Instant at which the client sent this event.
    pub send_instant: Instant,
    /// Instant at which the client received the echo for this event.
    pub recv_instant: Instant,
    /// Round-trip time for this event in microseconds, measured from the instant the client
    /// sent this event to the instant it received the echo. RTT is serialized per-event
    /// (send then receive), not batch-pipelined.
    pub rtt_us: u64,
}

/// Aggregate report from the input RTT loopback harness.
#[derive(Debug, Clone)]
pub struct InputRttReport {
    /// Number of events the client sent.
    pub events_sent: usize,
    /// Number of echo acks the client received (reliable channel → should equal `events_sent`).
    pub events_echoed: usize,
    /// Minimum RTT across all measured events, in microseconds.
    pub rtt_min_us: u64,
    /// Median RTT, in microseconds.
    pub rtt_median_us: u64,
    /// 95th-percentile RTT, in microseconds.
    pub rtt_p95_us: u64,
    /// Maximum RTT, in microseconds.
    pub rtt_max_us: u64,
    /// `true` iff the host's [`RecordingInjector`] received events in exact send order
    /// (`pointer_x` values `0, 1, 2, …, event_count - 1`).
    pub all_injected_in_order: bool,
    /// Per-event RTT measurements.
    pub measurements: Vec<InputEventMeasurement>,
}

/// Errors that can occur during the input RTT harness.
#[derive(Debug, thiserror::Error)]
pub enum InputRttError {
    /// A transport-layer error occurred.
    #[error("transport: {0}")]
    Transport(#[from] sh_transport::TransportError),
    /// A tokio task join error occurred.
    #[error("task join: {0}")]
    Join(String),
    /// The harness deadline elapsed before all events were echoed.
    #[error("harness timed out")]
    Timeout,
    /// An event could not be decoded from the echo bytes.
    #[error("protocol decode: {0}")]
    Protocol(#[from] sh_protocol::ProtocolError),
    /// The injector returned an error during the host receive loop.
    #[error("injection: {0}")]
    Injection(#[from] sh_input::InputError),
    /// The stream ended before all events were exchanged.
    #[error("incomplete stream: received {received} of {expected} expected events")]
    IncompleteStream {
        /// Number of events actually received/echoed.
        received: usize,
        /// Number of events expected.
        expected: usize,
    },
    /// `event_count` exceeds the maximum encodable index (`u16::MAX + 1 = 65536`).
    ///
    /// The harness encodes the event index in `pointer_x` (a `u16` field). Requesting
    /// more than 65 536 events would cause index wrapping and corrupt the RTT map.
    #[error("too many events: {count} exceeds maximum of 65536")]
    TooManyEvents {
        /// The requested event count.
        count: usize,
    },
}

/// Construct the `index`-th synthetic [`InputEvent`] used by the harness.
///
/// Encodes `index` in `pointer_x` so the client can identify which send corresponds to each
/// echo without a separate sequence-number field. `pointer_y` is varied by a simple formula
/// to make each event distinct and increase content variety.
///
/// `index` is always ≤ `u16::MAX` (65535): the harness allows at most 65536 events (indices
/// `0..=65535`), enforced at entry via [`InputRttError::TooManyEvents`], so the `try_from` below
/// never falls back.
fn make_event(index: usize) -> InputEvent {
    // index ≤ u16::MAX by the TooManyEvents guard at harness entry; the unwrap_or is unreachable.
    let idx_u16 = u16::try_from(index).unwrap_or(u16::MAX);
    InputEvent {
        event_type: EventType::PointerMove,
        modifiers: Modifiers::empty(),
        pointer_x: idx_u16,
        pointer_y: idx_u16.wrapping_mul(3),
        button_mask: 0,
        key_code: 0,
        scroll_x: 0,
        scroll_y: 0,
        pressure: 0,
    }
}

/// Run the input RTT loopback harness.
///
/// Stands up a loopback QUIC server and client, opens the reliable, highest-priority Input
/// channel, sends `params.event_count` distinct events client→host, has the host inject each
/// via a [`RecordingInjector`] and echo the raw bytes back, then computes RTT statistics.
///
/// Each event's RTT is measured with a **serialized round-trip**: the client sends event i,
/// then blocks waiting for its echo before sending event i+1. This yields the true per-event
/// transport RTT (not batch-inflated queue-drain time).
///
/// `server_config` and `client_config` must be TLS-compatible with loopback — use
/// [`sh_transport::self_signed_server_config`] / [`sh_transport::insecure_client_config`] for
/// the LAN-lab insecure path. No datagrams are used; the Input channel is a reliable QUIC
/// bidirectional stream, so zero event loss is expected.
///
/// The overall deadline is derived from `event_count` plus a generous base to absorb CI
/// scheduling jitter, mirroring the approach in [`crate::harness::run_loopback_harness`].
///
/// # Errors
///
/// - [`InputRttError::TooManyEvents`] — `event_count` exceeds 65 536 (u16 index limit).
/// - [`InputRttError::Transport`] — binding, connecting, or channel open/accept failed.
/// - [`InputRttError::Join`] — a spawned task panicked.
/// - [`InputRttError::Timeout`] — the overall deadline elapsed.
/// - [`InputRttError::Protocol`] — an echo payload could not be decoded as an [`InputEvent`].
/// - [`InputRttError::Injection`] — the [`RecordingInjector`] returned an error.
/// - [`InputRttError::IncompleteStream`] — the stream ended before all events were exchanged.
#[allow(clippy::arithmetic_side_effects)]
pub async fn run_input_rtt_harness(
    server_config: quinn::ServerConfig,
    client_config: quinn::ClientConfig,
    params: InputRttParams,
) -> Result<InputRttReport, InputRttError> {
    let event_count = params.event_count;

    // Validate: pointer_x encodes the index as u16; reject counts that would overflow.
    if event_count > usize::from(u16::MAX) + 1 {
        return Err(InputRttError::TooManyEvents { count: event_count });
    }

    // Short-circuit for zero events: skip endpoint setup entirely and return a zero-stats
    // report. The loopback handshake is unnecessary when there is nothing to measure.
    if event_count == 0 {
        return Ok(InputRttReport {
            events_sent: 0,
            events_echoed: 0,
            rtt_min_us: 0,
            rtt_median_us: 0,
            rtt_p95_us: 0,
            rtt_max_us: 0,
            all_injected_in_order: true,
            measurements: Vec::new(),
        });
    }

    // ── Endpoint setup ─────────────────────────────────────────────────────────
    let server_ep = ServerEndpoint::bind(
        "127.0.0.1:0"
            .parse()
            .map_err(|_| InputRttError::Join("invalid bind address".to_owned()))?,
        server_config,
    )?;
    let server_addr = server_ep.local_addr()?;

    // Spawn the accept concurrently so the client connect does not deadlock.
    let server_accept = tokio::spawn(async move { server_ep.accept().await });

    let client_ep = ClientEndpoint::bind(client_config)?;
    let client_conn = client_ep.connect(server_addr, "localhost").await?;

    let server_conn = server_accept
        .await
        .map_err(|e| InputRttError::Join(e.to_string()))?
        .map_err(InputRttError::Transport)?;

    // ── Deadline ──────────────────────────────────────────────────────────────
    // Budget: 20 s base + 1 s per 10 events (reliable, no loss expected; budget absorbs CI
    // scheduling jitter). The overall deadline is 10 s longer than the per-message timeout.
    let event_count_u64 = u64::try_from(event_count).unwrap_or(u64::MAX);
    let budget_secs = event_count_u64.saturating_div(10).saturating_add(20);
    let msg_timeout = Duration::from_secs(budget_secs);
    let overall_deadline =
        tokio::time::Instant::now() + Duration::from_secs(budget_secs.saturating_add(10));

    // ── Coordination ──────────────────────────────────────────────────────────
    // Oneshot: client signals "done receiving all echoes" to the host. The host waits before
    // dropping its Connection, preventing CONNECTION_CLOSE from racing with in-flight data.
    let (client_done_tx, client_done_rx) = oneshot::channel::<()>();

    // ── Host task ─────────────────────────────────────────────────────────────
    // Accepts the Input channel (reliable stream, no datagram config needed), decodes and
    // injects each event, echoes the raw bytes back. Returns the `pointer_x` values in
    // receive order for injection-order verification.
    let host_handle: tokio::task::JoinHandle<Result<Vec<u16>, InputRttError>> =
        tokio::spawn(async move {
            let transport = QuicTransport::new(server_conn);
            let mut ch = transport.accept_channel().await?;

            let mut injector = RecordingInjector::new();
            let mut received_indices: Vec<u16> = Vec::with_capacity(event_count);

            for _ in 0..event_count {
                let msg = tokio::time::timeout(msg_timeout, ch.recv())
                    .await
                    .map_err(|_| InputRttError::Timeout)?
                    .map_err(InputRttError::Transport)?;

                let bytes = match msg {
                    Some(b) => b,
                    // Clean EOF before all events: error immediately rather than awaiting the
                    // client (which would deadlock — client is blocked waiting for echoes).
                    None => {
                        return Err(InputRttError::IncompleteStream {
                            received: received_indices.len(),
                            expected: event_count,
                        })
                    }
                };

                let event = InputEvent::decode(&bytes)?;
                injector.inject(&event)?;
                received_indices.push(event.pointer_x);

                // Echo: return the raw 16 bytes unchanged.
                ch.send(bytes).await.map_err(InputRttError::Transport)?;
            }

            // Wait for the client to drain all echoes before letting the Connection drop.
            let _ = client_done_rx.await;
            Ok(received_indices)
        });

    // ── Client task ───────────────────────────────────────────────────────────
    // Opens the Input channel, interleaves send+recv per event: for each event i, records the
    // send instant, sends the event, then immediately waits for its echo before proceeding to
    // event i+1. This serialized per-event RTT is the true transport contribution — not
    // batch-pipelined queue-drain time.
    let client_handle: tokio::task::JoinHandle<Result<Vec<InputEventMeasurement>, InputRttError>> =
        tokio::spawn(async move {
            let transport = QuicTransport::new(client_conn);
            let mut ch = transport.open_channel(ChannelSpec::input()).await?;

            let mut measurements: Vec<InputEventMeasurement> = Vec::with_capacity(event_count);

            for i in 0..event_count {
                let event = make_event(i);
                let wire = Bytes::from(event.encode().to_vec());
                let send_instant = Instant::now();
                ch.send(wire).await.map_err(InputRttError::Transport)?;

                let msg = tokio::time::timeout(msg_timeout, ch.recv())
                    .await
                    .map_err(|_| InputRttError::Timeout)?
                    .map_err(InputRttError::Transport)?;

                let recv_instant = Instant::now();
                let bytes = match msg {
                    Some(b) => b,
                    None => {
                        return Err(InputRttError::IncompleteStream {
                            received: i,
                            expected: event_count,
                        })
                    }
                };

                let echo_event = InputEvent::decode(&bytes)?;
                let idx = usize::from(echo_event.pointer_x);
                let elapsed = recv_instant.duration_since(send_instant).as_micros();
                // Monotonic-clock anomaly guard: with serialized per-event RTT, elapsed is
                // always finite; u64::MAX sentinel is unreachable in practice.
                let rtt_us = u64::try_from(elapsed).unwrap_or(u64::MAX);
                measurements.push(InputEventMeasurement {
                    event_idx: idx,
                    send_instant,
                    recv_instant,
                    rtt_us,
                });
            }

            // Signal the host that we have consumed all echoes.
            let _ = client_done_tx.send(());
            Ok(measurements)
        });

    // ── Await both tasks with overall deadline ─────────────────────────────────
    let (host_result, client_result) = tokio::time::timeout_at(overall_deadline, async {
        tokio::join!(host_handle, client_handle)
    })
    .await
    .map_err(|_| InputRttError::Timeout)?;

    let received_indices = host_result.map_err(|e| InputRttError::Join(e.to_string()))??;

    let measurements = client_result.map_err(|e| InputRttError::Join(e.to_string()))??;

    // ── Order verification ─────────────────────────────────────────────────────
    // The reliable + ordered Input channel guarantees events arrive at the host in send order.
    // Count-complete: also verify that we received exactly the right number of events.
    let all_injected_in_order = received_indices.len() == event_count
        && received_indices
            .iter()
            .enumerate()
            .all(|(expected, &got)| usize::from(got) == expected);

    // ── RTT statistics ─────────────────────────────────────────────────────────
    let mut rtts: Vec<u64> = measurements.iter().map(|m| m.rtt_us).collect();
    rtts.sort_unstable();
    let (rtt_min_us, rtt_median_us, rtt_p95_us, rtt_max_us) = crate::stats::percentiles(&rtts);

    Ok(InputRttReport {
        events_sent: event_count,
        events_echoed: measurements.len(),
        rtt_min_us,
        rtt_median_us,
        rtt_p95_us,
        rtt_max_us,
        all_injected_in_order,
        measurements,
    })
}
