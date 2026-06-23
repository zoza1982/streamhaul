//! Tests for the async WebRTC drive loop and `AsyncUdpSocket` seam.
//!
//! Test groups:
//! A. Deterministic sim-socket unit tests (`sim_socket_*`, `driver_shutdown_clean`).
//! B. Deterministic handshake test using `tokio::time::pause()` + `SimNetwork`
//!    (`webrtc_driver_sim_handshake_deterministic`).
//! C. Real UDP loopback test (`webrtc_driver_real_udp_loopback`) — `#[ignore]` by default.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use sh_transport::{
    spawn_webrtc_driver, AsyncUdpSocket, ChannelSpec, PinnedWebRtcTransport, SimNetwork,
    TokioUdpSocket, Transport, WebRtcTransportBuilder,
};
use str0m::{Candidate, Rtc};

// ── Shared test helpers ────────────────────────────────────────────────────────

/// A process-wide deterministic monotonic base `Instant` (mirrors dtls_identity_binding.rs).
fn sim_base() -> Instant {
    static BASE: OnceLock<Instant> = OnceLock::new();
    #[allow(clippy::disallowed_methods)]
    *BASE.get_or_init(Instant::now)
}

/// Build an `Rtc` with ICE candidates and roles/DTLS/SCTP configured but DTLS fingerprint
/// NOT yet pinned (mirrors the pattern in dtls_identity_binding.rs).
fn make_configured_rtc(
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    controlling: bool,
    now: Instant,
) -> Rtc {
    let mut rtc = Rtc::new(now);
    rtc.add_local_candidate(Candidate::host(local_addr, "udp").expect("local candidate"))
        .expect("add local candidate");
    rtc.add_remote_candidate(Candidate::host(peer_addr, "udp").expect("remote candidate"));
    rtc.direct_api().set_ice_controlling(controlling);
    rtc.direct_api()
        .start_dtls(controlling)
        .expect("start_dtls");
    rtc.direct_api().start_sctp(controlling);
    rtc
}

/// Exchange ICE credentials between two raw `Rtc`s.
fn exchange_ice_credentials(a: &mut Rtc, b: &mut Rtc) {
    let creds_a = a.direct_api().local_ice_credentials();
    let creds_b = b.direct_api().local_ice_credentials();
    a.direct_api().set_remote_ice_credentials(creds_b);
    b.direct_api().set_remote_ice_credentials(creds_a);
}

/// Build a pair of [`PinnedWebRtcTransport`]s with mutually pinned DTLS fingerprints,
/// driving directly from Rtc fingerprints (no Noise handshake needed for driver tests).
fn make_transport_pair(
    a_addr: SocketAddr,
    b_addr: SocketAddr,
    start: Instant,
) -> (Arc<PinnedWebRtcTransport>, Arc<PinnedWebRtcTransport>) {
    let mut rtc_a = make_configured_rtc(a_addr, b_addr, true, start);
    let mut rtc_b = make_configured_rtc(b_addr, a_addr, false, start);
    exchange_ice_credentials(&mut rtc_a, &mut rtc_b);

    let fp_a = rtc_a.direct_api().local_dtls_fingerprint().clone();
    let fp_b = rtc_b.direct_api().local_dtls_fingerprint().clone();

    let ta = Arc::new(WebRtcTransportBuilder::new(rtc_a, a_addr, b_addr).pin_remote_dtls(fp_b));
    let tb = Arc::new(WebRtcTransportBuilder::new(rtc_b, b_addr, a_addr).pin_remote_dtls(fp_a));
    (ta, tb)
}

// ── A. SimUdpSocket unit tests ─────────────────────────────────────────────────

/// Two `SimUdpSocket`s in a `SimNetwork` can exchange a datagram.
#[tokio::test]
async fn sim_socket_send_recv() {
    let a_addr: SocketAddr = (Ipv4Addr::new(10, 0, 0, 1), 5000).into();
    let b_addr: SocketAddr = (Ipv4Addr::new(10, 0, 0, 2), 5001).into();

    let mut net = SimNetwork::new();
    let sock_a = net.add_socket(a_addr);
    let sock_b = net.add_socket(b_addr);

    let payload = b"hello sim";
    sock_a.send_to(payload, b_addr).await.expect("send_to");

    let mut buf = vec![0u8; 1500];
    let (n, from) = sock_b.recv_from(&mut buf).await.expect("recv_from");

    assert_eq!(&buf[..n], payload);
    assert_eq!(from, a_addr);
}

/// `send_to` an unregistered address returns an error and does not panic.
#[tokio::test]
async fn sim_socket_unknown_dest() {
    let a_addr: SocketAddr = (Ipv4Addr::new(10, 0, 0, 1), 5100).into();
    let unknown: SocketAddr = (Ipv4Addr::new(10, 0, 0, 99), 9999).into();

    let mut net = SimNetwork::new();
    let sock_a = net.add_socket(a_addr);

    let result = sock_a.send_to(b"nobody home", unknown).await;
    assert!(result.is_err(), "send to unknown address must return Err");
}

/// `local_addr()` returns the address the socket was bound to.
#[test]
fn sim_socket_local_addr() {
    let addr: SocketAddr = (Ipv4Addr::new(10, 0, 0, 1), 5200).into();
    let mut net = SimNetwork::new();
    let sock = net.add_socket(addr);
    assert_eq!(sock.local_addr(), addr);
}

/// A driver with no traffic can be shut down cleanly within a short timeout.
#[tokio::test]
async fn driver_shutdown_clean() {
    let a_addr: SocketAddr = (Ipv4Addr::new(10, 0, 1, 1), 6000).into();
    let b_addr: SocketAddr = (Ipv4Addr::new(10, 0, 1, 2), 6001).into();
    let start = sim_base();

    let (ta, _tb) = make_transport_pair(a_addr, b_addr, start);

    let mut net = SimNetwork::new();
    let sock_a = Arc::new(net.add_socket(a_addr));
    // Note: we never add b's socket so it has no peer — the driver just idles.

    let handle = spawn_webrtc_driver(Arc::clone(&ta), sock_a as Arc<dyn AsyncUdpSocket>, start);

    // The driver must shut down cleanly within 1 second even with no traffic.
    tokio::time::timeout(Duration::from_secs(1), handle.shutdown())
        .await
        .expect("driver shutdown must complete within 1 s");
}

// ── B. Deterministic sim handshake with paused time ───────────────────────────

/// Deterministic CI gate: two `PinnedWebRtcTransport`s driven by `WebRtcDriver` over a
/// `SimNetwork`, with `tokio::time::pause()` for fully deterministic timing.
///
/// The test:
/// 1. Builds two transports with mutually pinned DTLS fingerprints.
/// 2. Wires them to two `SimUdpSocket`s in a `SimNetwork`.
/// 3. Spawns a driver for each.
/// 4. Runs a continuous time-advance pump (aborted once the round-trip completes) so the test
///    never hangs if the handshake needs more virtual time and is not margin-fragile.
/// 5. Opens a channel on A, accepts on B, round-trips a byte-exact payload.
/// 6. Asserts byte-exact delivery — non-vacuous (fails if transmits are not pumped).
/// 7. Shuts down both drivers.
#[tokio::test]
async fn webrtc_driver_sim_handshake_deterministic() {
    tokio::time::pause();

    let a_addr: SocketAddr = (Ipv4Addr::new(10, 0, 2, 1), 7000).into();
    let b_addr: SocketAddr = (Ipv4Addr::new(10, 0, 2, 2), 7001).into();
    let start = sim_base();

    let (ta, tb) = make_transport_pair(a_addr, b_addr, start);

    let mut net = SimNetwork::new();
    let sock_a: Arc<dyn AsyncUdpSocket> = Arc::new(net.add_socket(a_addr));
    let sock_b: Arc<dyn AsyncUdpSocket> = Arc::new(net.add_socket(b_addr));

    let handle_a = spawn_webrtc_driver(Arc::clone(&ta), Arc::clone(&sock_a), start);
    let handle_b = spawn_webrtc_driver(Arc::clone(&tb), Arc::clone(&sock_b), start);

    // Give the initial drives a chance to run before we start advancing time.
    tokio::task::yield_now().await;

    // Continuous time-advance pump: runs until aborted after the round-trip completes.
    // Using an infinite loop (rather than a fixed step count) means the test never hangs if
    // the handshake needs more virtual time — and is not fragile to margin changes.
    // `abort()` is called once the round-trip outcome is decided (see below).
    let advance_task = tokio::spawn(async {
        loop {
            tokio::time::advance(Duration::from_millis(5)).await;
            // Yield so driver tasks can process timer wakeups between advances.
            tokio::task::yield_now().await;
        }
    });

    // Open a channel on A (returns immediately — channel creation is local).
    let open_fut = ta.open_channel(ChannelSpec::input());

    // Accept on B with a generous timeout. Under paused time the 10 s timeout advances only
    // when the advance_task calls `tokio::time::advance()`.
    let accept_fut = tokio::time::timeout(Duration::from_secs(10), tb.accept_channel());

    // Run open and accept concurrently; let the advance_task pump both drivers.
    let (open_res, accept_res) = tokio::join!(open_fut, accept_fut);

    let mut chan_a = open_res.expect("open_channel must succeed");
    let mut chan_b = accept_res
        .expect("accept_channel must not time out")
        .expect("accept_channel must succeed");

    // Send a payload from A to B and verify byte-exact delivery.
    let payload = bytes::Bytes::from_static(b"webrtc-driver-sim-gate");
    chan_a
        .send(payload.clone())
        .await
        .expect("send must succeed");

    let got = tokio::time::timeout(Duration::from_secs(5), chan_b.recv())
        .await
        .expect("recv must not time out")
        .expect("recv must succeed")
        .expect("recv must return Some (channel not closed)");

    assert_eq!(got, payload, "received payload must match sent payload");

    // Round-trip is done — abort the advance pump and clean up.
    advance_task.abort();
    let _ = advance_task.await; // JoinError::Cancelled is expected; ignore it.
    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

// ── C. Real UDP loopback test (ignored by default) ────────────────────────────

/// Real UDP loopback: two `PinnedWebRtcTransport`s driven by `WebRtcDriver` over real
/// `tokio::net::UdpSocket`s bound to `127.0.0.1:0`.
///
/// This test exercises the production code path end-to-end. It is excluded from the default
/// CI suite (`cargo test`) because it uses real sockets and wall-clock timing. Run with:
///
/// ```bash
/// cargo test -p sh-transport -- --include-ignored webrtc_driver_real_udp_loopback
/// ```
#[tokio::test]
#[ignore = "real UDP loopback — uses real sockets and wall-clock timing; reliable on loopback \
            but excluded from default CI; run with --include-ignored; \
            tracked: R-WEBRTC-LIVE (promote to default CI once real-socket paths are wired in sh-core)"]
async fn webrtc_driver_real_udp_loopback() {
    let loopback = Ipv4Addr::new(127, 0, 0, 1);
    let any: SocketAddr = (loopback, 0).into();

    let sock_a = TokioUdpSocket::bind(any).await.expect("bind socket A");
    let sock_b = TokioUdpSocket::bind(any).await.expect("bind socket B");

    let a_addr = sock_a.local_addr();
    let b_addr = sock_b.local_addr();

    #[allow(clippy::disallowed_methods)]
    let start = Instant::now();

    let (ta, tb) = make_transport_pair(a_addr, b_addr, start);

    let sock_a: Arc<dyn AsyncUdpSocket> = Arc::new(sock_a);
    let sock_b: Arc<dyn AsyncUdpSocket> = Arc::new(sock_b);

    let handle_a = spawn_webrtc_driver(Arc::clone(&ta), Arc::clone(&sock_a), start);
    let handle_b = spawn_webrtc_driver(Arc::clone(&tb), Arc::clone(&sock_b), start);

    // Open on A, accept on B.
    let open_fut = ta.open_channel(ChannelSpec::input());
    let accept_fut = tokio::time::timeout(Duration::from_secs(10), tb.accept_channel());

    let (open_res, accept_res) = tokio::join!(open_fut, accept_fut);
    let mut chan_a = open_res.expect("open_channel must succeed");
    let mut chan_b = accept_res
        .expect("accept_channel must not time out")
        .expect("accept_channel must succeed");

    let payload = bytes::Bytes::from_static(b"webrtc-driver-real-udp");
    chan_a
        .send(payload.clone())
        .await
        .expect("send must succeed");

    let got = tokio::time::timeout(Duration::from_secs(5), chan_b.recv())
        .await
        .expect("recv must not time out")
        .expect("recv must succeed")
        .expect("recv must return Some");

    assert_eq!(got, payload);

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}
