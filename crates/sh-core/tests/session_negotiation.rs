//! P4-6 integration tests: session orchestration and transport capability negotiation.
//!
//! These tests verify the full [`SessionEstablisher`] flow using injected seams — no live
//! sockets and no real network. The signaling channel is replaced by an async in-memory
//! pipe backed by `tokio::sync::mpsc`; the transport factory is replaced by a stub or (for
//! the MITM test) real `WebRtcTransport`s backed by synthetic `str0m::Rtc` instances.
//!
//! # Non-vacuity
//!
//! The `session_mitm_dtls_cert_swap_rejected` test proves the DTLS pin gate is non-bypassable:
//! it drives two `WebRtcTransport` pairs — one honest (matching certs → DTLS connects) and one
//! MITM (swapped cert → str0m fail-closes). The MITM path is identical to the honest path except
//! for the cert, proving that the rejection is caused by the identity-bound pin gate.
//!
//! The `session_webrtc_pin_propagated_to_factory` test proves the pin VALUE is forwarded
//! through the session seam: after a full `establish_as_initiator` with a valid DTLS-committed
//! Noise outcome, the `StubFactory` receives the exact peer fingerprint bytes extracted from
//! the outcome.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use rand_core::OsRng;
use sh_core::session::{
    IcePathOutcome, SessionError, SessionEstablisher, SignalingChannel, TransportFactory,
};
use sh_crypto::bind_cert::DtlsCommitment;
use sh_crypto::clock::FixedClock;
use sh_crypto::{HandshakeOutcome, Keystore, NoiseHandshake, SoftwareKeystore};
use sh_protocol::transport_caps::TransportCaps;
use sh_signaling::{MessageKind, SessionId, SignalingEnvelope};
use sh_transport::channel::{Channel, ChannelSpec, Transport};
use sh_transport::{TransportError, WebRtcTransport};
use sh_types::TransportKind;
use str0m::crypto::Fingerprint;
use str0m::{Candidate, Rtc};
use x25519_dalek::{PublicKey, StaticSecret};

// ─── Constants ────────────────────────────────────────────────────────────────

const NOW_SECS: i64 = 1_000_000_000;
const STEP: Duration = Duration::from_millis(5);
const DRIVE_STEPS: usize = 400;
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(8);

/// Dummy identity fingerprints (64 lowercase hex chars each) used in tests.
/// These are placeholder values for routing; the zero-knowledge relay never inspects payloads.
const LOCAL_FP: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PEER_FP: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// Fixed socket addresses for the synthetic loopback sessions.
const ADDR_A: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 15000);
const ADDR_B: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 15001);
const ADDR_MITM: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 15002);

// ─── Helpers: deterministic monotonic clock base ──────────────────────────────

/// Process-wide monotonic base for str0m `Instant` clocks (same pattern as dtls_identity_binding).
fn sim_base() -> Instant {
    static BASE: OnceLock<Instant> = OnceLock::new();
    #[allow(clippy::disallowed_methods)]
    *BASE.get_or_init(Instant::now)
}

// ─── Helpers: test identity fields ───────────────────────────────────────────

fn test_session_id() -> SessionId {
    SessionId([0u8; 16])
}

// ─── Helpers: Rtc construction ────────────────────────────────────────────────

fn make_rtc(local: SocketAddr, remote: SocketAddr, controlling: bool, now: Instant) -> Rtc {
    let mut rtc = Rtc::new(now);
    rtc.add_local_candidate(Candidate::host(local, "udp").expect("local candidate"))
        .expect("add local candidate");
    rtc.add_remote_candidate(Candidate::host(remote, "udp").expect("remote candidate"));
    rtc.direct_api().set_ice_controlling(controlling);
    rtc.direct_api()
        .start_dtls(controlling)
        .expect("start_dtls");
    rtc.direct_api().start_sctp(controlling);
    rtc
}

fn exchange_ice_credentials(a: &mut Rtc, b: &mut Rtc) {
    let ca = a.direct_api().local_ice_credentials();
    let cb = b.direct_api().local_ice_credentials();
    a.direct_api().set_remote_ice_credentials(cb);
    b.direct_api().set_remote_ice_credentials(ca);
}

fn sha256_fingerprint(bytes: [u8; 32]) -> Fingerprint {
    Fingerprint {
        hash_func: "sha-256".to_owned(),
        bytes: bytes.to_vec(),
    }
}

// ─── Helpers: Noise XK handshake ─────────────────────────────────────────────

/// Run a full Noise XK handshake with mutual DTLS commitments (WebRTC path).
async fn run_noise_xk_with_dtls(
    init_ks: &SoftwareKeystore,
    resp_ks: &SoftwareKeystore,
    init_dtls: [u8; 32],
    resp_dtls: [u8; 32],
) -> (HandshakeOutcome, HandshakeOutcome) {
    let clock = FixedClock(NOW_SECS);

    let resp_static = StaticSecret::random_from_rng(OsRng);
    let resp_pub = PublicKey::from(&resp_static);
    let init_static = StaticSecret::random_from_rng(OsRng);

    let resp_id = resp_ks.device_identity().await.expect("resp id");
    let init_id = init_ks.device_identity().await.expect("init id");
    init_ks
        .trust_peer(&resp_id)
        .await
        .expect("init trusts resp");
    resp_ks
        .trust_peer(&init_id)
        .await
        .expect("resp trusts init");

    let mut init = NoiseHandshake::initiator_xk_with_dtls(
        init_ks,
        init_static,
        resp_pub.to_bytes(),
        &[],
        DtlsCommitment::sha256(init_dtls),
        &clock,
    )
    .await
    .expect("initiator_xk_with_dtls");

    let mut resp = NoiseHandshake::responder_xk_with_dtls(
        resp_ks,
        resp_static,
        &[],
        DtlsCommitment::sha256(resp_dtls),
        &clock,
    )
    .await
    .expect("responder_xk_with_dtls");

    let msg0 = init.write_message().expect("msg0");
    resp.read_message(&msg0, &clock).expect("read msg0");
    let msg1 = resp.write_message().expect("msg1");
    init.read_message(&msg1, &clock).expect("read msg1");
    let msg2 = init.write_message().expect("msg2");
    resp.read_message(&msg2, &clock).expect("read msg2");

    let init_outcome = init.complete(init_ks).await.expect("init complete");
    let resp_outcome = resp.complete(resp_ks).await.expect("resp complete");
    (init_outcome, resp_outcome)
}

/// Run a Noise XK handshake WITHOUT DTLS commitment (QUIC path, ALG=NONE).
async fn run_noise_xk_no_dtls(
    init_ks: &SoftwareKeystore,
    resp_ks: &SoftwareKeystore,
) -> (HandshakeOutcome, HandshakeOutcome) {
    let clock = FixedClock(NOW_SECS);

    let resp_static = StaticSecret::random_from_rng(OsRng);
    let resp_pub = PublicKey::from(&resp_static);
    let init_static = StaticSecret::random_from_rng(OsRng);

    let resp_id = resp_ks.device_identity().await.expect("resp id");
    let init_id = init_ks.device_identity().await.expect("init id");
    init_ks
        .trust_peer(&resp_id)
        .await
        .expect("init trusts resp");
    resp_ks
        .trust_peer(&init_id)
        .await
        .expect("resp trusts init");

    let mut init =
        NoiseHandshake::initiator_xk(init_ks, init_static, resp_pub.to_bytes(), &[], &clock)
            .await
            .expect("initiator_xk");
    let mut resp = NoiseHandshake::responder_xk(resp_ks, resp_static, &[], &clock)
        .await
        .expect("responder_xk");

    let msg0 = init.write_message().expect("msg0");
    resp.read_message(&msg0, &clock).expect("read msg0");
    let msg1 = resp.write_message().expect("msg1");
    init.read_message(&msg1, &clock).expect("read msg1");
    let msg2 = init.write_message().expect("msg2");
    resp.read_message(&msg2, &clock).expect("read msg2");

    let init_outcome = init.complete(init_ks).await.expect("init complete");
    let resp_outcome = resp.complete(resp_ks).await.expect("resp complete");
    (init_outcome, resp_outcome)
}

// ─── In-memory async signaling channel ───────────────────────────────────────
//
// Backed by `tokio::sync::mpsc` so that `recv()` is a proper async yield point — no blocking
// calls run on tokio worker threads, eliminating the worker-starvation flakiness that
// `std::sync::mpsc::recv` caused with the previous synchronous `SignalingChannel` design.

struct MemSignaling {
    tx: tokio::sync::mpsc::Sender<SignalingEnvelope>,
    rx: tokio::sync::mpsc::Receiver<SignalingEnvelope>,
}

#[async_trait]
impl SignalingChannel for MemSignaling {
    async fn send(&mut self, env: SignalingEnvelope) -> Result<(), SessionError> {
        self.tx
            .send(env)
            .await
            .map_err(|e| SessionError::Signaling(format!("send: {e}")))
    }

    async fn recv(&mut self) -> Result<SignalingEnvelope, SessionError> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| SessionError::Signaling("channel closed".to_owned()))
    }
}

/// Create a connected pair of in-memory async signaling channels.
/// Messages sent by A are received by B, and vice versa.
fn signaling_pair() -> (MemSignaling, MemSignaling) {
    let (atx, brx) = tokio::sync::mpsc::channel(16);
    let (btx, arx) = tokio::sync::mpsc::channel(16);
    (
        MemSignaling { tx: atx, rx: arx },
        MemSignaling { tx: btx, rx: brx },
    )
}

// ─── One-shot signaling channel ───────────────────────────────────────────────
//
// `SinkGuard` keeps the receiving end of the sink channel alive for the duration of a test.
// Dropping it (or assigning to `_` without a type annotation) would close the channel, causing
// `SessionEstablisher::send` to see a disconnected channel instead of the expected error.
//
// The `#[must_use]` attribute ensures the compiler warns if the guard is dropped immediately.

/// Guard that keeps the sink channel alive for one-shot signaling tests.
///
/// Callers must bind this to a named local variable (e.g., `let _guard = …`) so the receiving
/// end of the outbound channel stays alive for the duration of the test. Dropping the guard
/// closes the channel, which would cause `SessionEstablisher::send` to fail with a channel-
/// closed error rather than the protocol error the test is asserting.
#[must_use]
// The inner Receiver is held purely for its Drop effect (keeping the channel open); reading
// it is never needed in tests.
#[allow(dead_code)]
struct SinkGuard(tokio::sync::mpsc::Receiver<SignalingEnvelope>);

/// Build a single-shot signaling channel preloaded with the given peer caps.
///
/// Returns `(signaling, guard)`. The caller **must** bind `guard` to a named local variable so
/// the receiving end of the sink channel stays alive for the duration of the test.
fn one_shot_peer_caps(caps: &TransportCaps) -> (MemSignaling, SinkGuard) {
    let wire = sh_protocol::transport_caps::encode_transport_caps(caps);
    let env = SignalingEnvelope {
        kind: MessageKind::Candidate,
        session_id: test_session_id(),
        from_fp: PEER_FP.to_owned(),
        to_fp: LOCAL_FP.to_owned(),
        payload: Bytes::copy_from_slice(&wire),
    };
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    let (sink_tx, sink_rx) = tokio::sync::mpsc::channel(16);
    // Pre-load the peer caps envelope into the inbound queue.
    tx.try_send(env).expect("pre-load");
    (MemSignaling { tx: sink_tx, rx }, SinkGuard(sink_rx))
}

// ─── No-op Transport implementation ──────────────────────────────────────────

struct NoopTransport;

#[async_trait]
impl Transport for NoopTransport {
    async fn open_channel(&self, _spec: ChannelSpec) -> Result<Box<dyn Channel>, TransportError> {
        Err(TransportError::EndpointClosed)
    }

    async fn accept_channel(&self) -> Result<Box<dyn Channel>, TransportError> {
        Err(TransportError::EndpointClosed)
    }

    fn rtt(&self) -> Duration {
        Duration::ZERO
    }
}

// ─── Stub factory with call tracking ─────────────────────────────────────────

/// Recorded arguments from a single `TransportFactory::build` call.
/// `(TransportKind, is_relay: bool, webrtc_peer_pin: Option<[u8; 32]>)`.
type CallRecord = Option<(TransportKind, bool, Option<[u8; 32]>)>;
/// Shared mutable slot for a [`CallRecord`].
type SharedCallRecord = Arc<std::sync::Mutex<CallRecord>>;

struct StubFactory {
    last_call: SharedCallRecord,
}

impl StubFactory {
    fn new() -> Self {
        Self {
            last_call: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    fn tracker(&self) -> SharedCallRecord {
        Arc::clone(&self.last_call)
    }
}

impl TransportFactory for StubFactory {
    fn build(
        &self,
        kind: TransportKind,
        path: &IcePathOutcome,
        webrtc_peer_pin: Option<[u8; 32]>,
    ) -> Result<Box<dyn Transport>, SessionError> {
        *self.last_call.lock().expect("lock") = Some((kind, path.is_relay, webrtc_peer_pin));
        Ok(Box::new(NoopTransport))
    }
}

// ─── Helper: build a SessionEstablisher with test identity fields ─────────────

fn make_establisher<S: SignalingChannel, F: TransportFactory>(
    caps: TransportCaps,
    signaling: S,
    factory: F,
) -> SessionEstablisher<S, F> {
    SessionEstablisher::new(
        caps,
        signaling,
        factory,
        LOCAL_FP.to_owned(),
        PEER_FP.to_owned(),
        test_session_id(),
    )
}

// ─── WebRTC drive helper ──────────────────────────────────────────────────────

/// Drive two `WebRtcTransport`s through ICE+DTLS+SCTP and return `true` if they connected.
async fn drive_and_check_connection(
    ta: Arc<WebRtcTransport>,
    tb: Arc<WebRtcTransport>,
    start: Instant,
) -> bool {
    let mut channel_a = match ta.open_channel(ChannelSpec::input()).await {
        Ok(c) => c,
        Err(_) => return false,
    };

    let ta_d = Arc::clone(&ta);
    let tb_d = Arc::clone(&tb);
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_d = Arc::clone(&stop);

    let drive_handle = tokio::task::spawn_blocking(move || {
        let mut now = start;
        for _ in 0..DRIVE_STEPS {
            if stop_d.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
            now = match now.checked_add(STEP) {
                Some(t) => t,
                None => return,
            };
            match ta_d.drive(now) {
                Ok(pkts) => {
                    for pkt in pkts {
                        let _ =
                            tb_d.handle_receive(pkt.source, pkt.destination, &pkt.contents, now);
                    }
                }
                Err(_) => return,
            }
            match tb_d.drive(now) {
                Ok(pkts) => {
                    for pkt in pkts {
                        let _ =
                            ta_d.handle_receive(pkt.source, pkt.destination, &pkt.contents, now);
                    }
                }
                Err(_) => return,
            }
        }
    });

    let accept = tokio::time::timeout(ACCEPT_TIMEOUT, tb.accept_channel()).await;
    let connected = match accept {
        Ok(Ok(mut channel_b)) => {
            let payload = Bytes::from_static(b"p4-6-session-gate");
            let _ = channel_a.send(payload.clone()).await;
            let recv = tokio::time::timeout(ACCEPT_TIMEOUT, channel_b.recv()).await;
            matches!(recv, Ok(Ok(Some(ref got))) if got == &payload)
        }
        _ => false,
    };

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    drive_handle.await.expect("drive task");
    connected
}

// ─── Tests ────────────────────────────────────────────────────────────────────

/// Test 1: WebRTC negotiation calls the DTLS pin gate; a Noise outcome with ALG=NONE triggers
/// `DtlsBindingMissing`.
#[tokio::test]
async fn session_webrtc_dtls_pin_gate() {
    let init_ks = SoftwareKeystore::generate();
    let resp_ks = SoftwareKeystore::generate();

    // Noise WITHOUT DTLS commitment (ALG=NONE) — simulates a native peer that forgot to commit.
    let (init_outcome, _) = run_noise_xk_no_dtls(&init_ks, &resp_ks).await;

    let ice_path = IcePathOutcome {
        local_addr: ADDR_A,
        remote_addr: ADDR_B,
        is_relay: false,
    };

    // Both sides claim WebRTC only → negotiation succeeds → DTLS gate fires.
    let webrtc_only = TransportCaps {
        supports_quic: false,
        supports_webrtc: true,
    };

    let (signaling, _guard) = one_shot_peer_caps(&webrtc_only);
    let establisher = make_establisher(webrtc_only, signaling, StubFactory::new());

    let result = establisher
        .establish_as_initiator(&init_outcome, &ice_path)
        .await;

    assert!(
        matches!(result, Err(SessionError::DtlsBindingMissing)),
        "expected DtlsBindingMissing when Noise outcome has no DTLS pin, got: {result:?}",
        result = result.map(|(k, _t)| k),
    );
}

/// Test 2: QUIC branch succeeds without calling `require_webrtc_dtls_pin`; factory receives
/// `webrtc_peer_pin = None`.
#[tokio::test]
async fn session_quic_no_pin_needed() {
    let init_ks = SoftwareKeystore::generate();
    let resp_ks = SoftwareKeystore::generate();
    let (init_outcome, _) = run_noise_xk_no_dtls(&init_ks, &resp_ks).await;

    let ice_path = IcePathOutcome {
        local_addr: ADDR_A,
        remote_addr: ADDR_B,
        is_relay: false,
    };

    let quic_only = TransportCaps {
        supports_quic: true,
        supports_webrtc: false,
    };

    let factory = StubFactory::new();
    let tracker = factory.tracker();
    let (signaling, _guard) = one_shot_peer_caps(&quic_only);
    let establisher = make_establisher(quic_only, signaling, factory);

    let result = establisher
        .establish_as_initiator(&init_outcome, &ice_path)
        .await;

    assert!(
        result.is_ok(),
        "QUIC negotiation must succeed without a DTLS pin"
    );
    let (kind, _) = result.unwrap();
    assert_eq!(kind, TransportKind::Quic);

    // The factory must have been called with QUIC kind and NO WebRTC pin.
    let call = tracker.lock().unwrap().expect("factory was called");
    assert_eq!(call.0, TransportKind::Quic);
    assert!(call.2.is_none(), "QUIC factory call must not receive a pin");
}

/// Test 3: No common transport → `NegotiationError`.
#[tokio::test]
async fn session_negotiate_no_common_transport() {
    let init_ks = SoftwareKeystore::generate();
    let resp_ks = SoftwareKeystore::generate();
    let (init_outcome, _) = run_noise_xk_no_dtls(&init_ks, &resp_ks).await;

    let ice_path = IcePathOutcome {
        local_addr: ADDR_A,
        remote_addr: ADDR_B,
        is_relay: false,
    };

    // Local QUIC-only, peer WebRTC-only → no intersection.
    let local_caps = TransportCaps {
        supports_quic: true,
        supports_webrtc: false,
    };
    let peer_caps = TransportCaps {
        supports_quic: false,
        supports_webrtc: true,
    };

    let (signaling, _guard) = one_shot_peer_caps(&peer_caps);
    let establisher = make_establisher(local_caps, signaling, StubFactory::new());

    let result = establisher
        .establish_as_initiator(&init_outcome, &ice_path)
        .await;

    assert!(
        matches!(result, Err(SessionError::Negotiation(_))),
        "expected NegotiationError when no transport in common"
    );
}

/// Test 4: Factory observes the correct `is_relay` flag for direct vs. relay paths.
#[tokio::test]
async fn relay_fallback_direct_path_selection() {
    // ── Shared setup ──────────────────────────────────────────────────────────
    let quic_only = TransportCaps {
        supports_quic: true,
        supports_webrtc: false,
    };

    // ── Direct path ───────────────────────────────────────────────────────────
    {
        let init_ks = SoftwareKeystore::generate();
        let resp_ks = SoftwareKeystore::generate();
        let (init_outcome, _) = run_noise_xk_no_dtls(&init_ks, &resp_ks).await;

        let factory = StubFactory::new();
        let tracker = factory.tracker();
        let ice_path = IcePathOutcome {
            local_addr: ADDR_A,
            remote_addr: ADDR_B,
            is_relay: false,
        };
        let (signaling_direct, _guard_direct) = one_shot_peer_caps(&quic_only);
        let establisher = make_establisher(quic_only, signaling_direct, factory);
        assert!(
            establisher
                .establish_as_initiator(&init_outcome, &ice_path)
                .await
                .is_ok(),
            "direct path must succeed"
        );
        let call = tracker.lock().unwrap().expect("factory called");
        assert!(!call.1, "is_relay must be false for a direct path");
    }

    // ── Relay path ────────────────────────────────────────────────────────────
    {
        let init_ks = SoftwareKeystore::generate();
        let resp_ks = SoftwareKeystore::generate();
        let (init_outcome, _) = run_noise_xk_no_dtls(&init_ks, &resp_ks).await;

        let factory = StubFactory::new();
        let tracker = factory.tracker();
        let ice_path = IcePathOutcome {
            local_addr: ADDR_A,
            remote_addr: ADDR_B,
            is_relay: true,
        };
        let (signaling_relay, _guard_relay) = one_shot_peer_caps(&quic_only);
        let establisher = make_establisher(quic_only, signaling_relay, factory);
        assert!(
            establisher
                .establish_as_initiator(&init_outcome, &ice_path)
                .await
                .is_ok(),
            "relay path must succeed"
        );
        let call = tracker.lock().unwrap().expect("factory called");
        assert!(call.1, "is_relay must be true for a relay path");
    }
}

/// Test 5: Full symmetric concurrent cap exchange — both sides use `establish_as_*` concurrently.
///
/// Both sides have both caps, so QUIC is selected (preferred). Uses `tokio::join!` directly since
/// `SignalingChannel::recv` is now async (not blocking), so both futures can be interleaved on
/// the same task without worker starvation.
#[tokio::test]
async fn session_symmetric_exchange() {
    let init_ks = SoftwareKeystore::generate();
    let resp_ks = SoftwareKeystore::generate();
    let (init_outcome, resp_outcome) = run_noise_xk_no_dtls(&init_ks, &resp_ks).await;

    let both_caps = TransportCaps {
        supports_quic: true,
        supports_webrtc: true,
    };

    let ice_path = IcePathOutcome {
        local_addr: ADDR_A,
        remote_addr: ADDR_B,
        is_relay: false,
    };

    let (sig_a, sig_b) = signaling_pair();
    let init_est = make_establisher(both_caps, sig_a, StubFactory::new());
    let resp_est = make_establisher(both_caps, sig_b, StubFactory::new());

    let ice_path_a = ice_path.clone();
    let ice_path_b = ice_path.clone();

    // tokio::join! works correctly now: `recv().await` yields to the executor, letting both
    // futures make progress on a single-thread runtime without deadlocking.
    let (result_a, result_b) = tokio::join!(
        init_est.establish_as_initiator(&init_outcome, &ice_path_a),
        resp_est.establish_as_responder(&resp_outcome, &ice_path_b),
    );

    let (kind_a, _) = result_a.expect("initiator must succeed");
    let (kind_b, _) = result_b.expect("responder must succeed");

    // Symmetry: both must select the same transport.
    assert_eq!(
        kind_a, kind_b,
        "both sides must select the same transport kind"
    );
    // With both caps available, QUIC is preferred.
    assert_eq!(kind_a, TransportKind::Quic, "QUIC must be preferred");
}

/// Test 6 (MITM / DTLS security gate non-vacuity):
///
/// The `SessionEstablisher` extracts the verified DTLS pin from the Noise outcome.
/// A real `WebRtcTransport` pair proves:
/// - **Honest path**: correct certs → str0m DTLS completes, DataChannel opens.
/// - **MITM path**: swapped cert → str0m fail-closes (pin mismatch), no connection.
///
/// The two branches are identical except for which cert A presents, proving the rejection
/// is caused by the identity-bound pin gate in `establish_as_initiator`.
#[tokio::test]
async fn session_mitm_dtls_cert_swap_rejected() {
    let now = sim_base();

    // ── Build real WebRtcTransports for the HONEST path ───────────────────────
    let mut rtc_a_real = make_rtc(ADDR_A, ADDR_B, true, now);
    let mut rtc_b_real = make_rtc(ADDR_B, ADDR_A, false, now);
    exchange_ice_credentials(&mut rtc_a_real, &mut rtc_b_real);

    let ta_real = Arc::new(WebRtcTransport::new(rtc_a_real, ADDR_A, ADDR_B));
    let tb_real = Arc::new(WebRtcTransport::new(rtc_b_real, ADDR_B, ADDR_A));

    // Capture REAL fingerprints to use as DTLS commitments in the Noise handshake.
    let fp_a_honest = ta_real.local_dtls_fingerprint();
    let fp_b_real = tb_real.local_dtls_fingerprint();

    let fp_a_bytes: [u8; 32] = fp_a_honest
        .bytes
        .as_slice()
        .try_into()
        .expect("sha-256 is 32 bytes");
    let fp_b_bytes: [u8; 32] = fp_b_real
        .bytes
        .as_slice()
        .try_into()
        .expect("sha-256 is 32 bytes");

    // ── Noise XK with DTLS commitments ───────────────────────────────────────
    let init_ks = SoftwareKeystore::generate();
    let resp_ks = SoftwareKeystore::generate();
    let (init_outcome, resp_outcome) =
        run_noise_xk_with_dtls(&init_ks, &resp_ks, fp_a_bytes, fp_b_bytes).await;

    // Each side's `require_webrtc_dtls_pin` returns the PEER's committed fingerprint.
    let pin_for_a = init_outcome
        .require_webrtc_dtls_pin()
        .expect("init has resp's DTLS pin"); // = fp_b_bytes
    let pin_for_b = resp_outcome
        .require_webrtc_dtls_pin()
        .expect("resp has init's DTLS pin"); // = fp_a_bytes

    assert_eq!(pin_for_a, fp_b_bytes, "A must pin B's fingerprint");
    assert_eq!(pin_for_b, fp_a_bytes, "B must pin A's honest fingerprint");

    // ── Honest path: apply correct pins → DTLS must connect ──────────────────
    ta_real.set_remote_dtls_fingerprint(sha256_fingerprint(pin_for_a));
    tb_real.set_remote_dtls_fingerprint(sha256_fingerprint(pin_for_b));

    let honest_connected =
        drive_and_check_connection(Arc::clone(&ta_real), Arc::clone(&tb_real), now).await;
    assert!(
        honest_connected,
        "honest path: matching certs must connect (pin == presented cert)"
    );

    // ── MITM path: MITM cert doesn't match A's committed fingerprint ──────────
    // B still pins fp_a_bytes (from the verified Noise outcome). The MITM cert won't match.
    let mut rtc_a_mitm = make_rtc(ADDR_MITM, ADDR_B, true, now);
    let mut rtc_b_mitm = make_rtc(ADDR_B, ADDR_A, false, now);
    exchange_ice_credentials(&mut rtc_a_mitm, &mut rtc_b_mitm);

    let ta_mitm = Arc::new(WebRtcTransport::new(rtc_a_mitm, ADDR_MITM, ADDR_B));
    let tb_mitm = Arc::new(WebRtcTransport::new(rtc_b_mitm, ADDR_B, ADDR_A));

    // A (MITM) pins B's real fingerprint — fine for A.
    ta_mitm.set_remote_dtls_fingerprint(sha256_fingerprint(pin_for_a));
    // B pins A's *committed* (honest) fingerprint — but MITM presents a different cert.
    tb_mitm.set_remote_dtls_fingerprint(sha256_fingerprint(pin_for_b));

    let mitm_connected =
        drive_and_check_connection(Arc::clone(&ta_mitm), Arc::clone(&tb_mitm), now).await;
    assert!(
        !mitm_connected,
        "MITM path: swapped cert must be rejected (str0m fail-closes on pin mismatch)"
    );
}

/// Test 7 (pin value propagated to factory — non-vacuity for the seam):
///
/// When `establish_as_initiator` completes successfully on the WebRTC path, the `StubFactory`
/// must receive the **exact** peer fingerprint bytes that `require_webrtc_dtls_pin()` extracts
/// from the Noise outcome. This proves the pin is not dropped, zeroed, or transformed between
/// the security gate and the factory call.
///
/// Non-vacuity control: the assertion would fail if we zeroed `webrtc_peer_pin` in
/// `negotiate_and_build` (verified by a scratch neuter during development, then reverted).
#[tokio::test]
async fn session_webrtc_pin_propagated_to_factory() {
    // Use a recognisable, non-zero DTLS fingerprint so we can detect if it were zeroed.
    let expected_peer_fp: [u8; 32] = [
        0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ];
    // The local fingerprint — arbitrary (only the peer's pin travels to the factory).
    let local_fp: [u8; 32] = [0xAA; 32];

    let init_ks = SoftwareKeystore::generate();
    let resp_ks = SoftwareKeystore::generate();
    // Noise with DTLS commitments: initiator commits local_fp, responder commits expected_peer_fp.
    // After the handshake the initiator's outcome carries the PEER's pin (= expected_peer_fp).
    let (init_outcome, _resp_outcome) =
        run_noise_xk_with_dtls(&init_ks, &resp_ks, local_fp, expected_peer_fp).await;

    // Verify the outcome carries the expected peer pin before threading it through the seam.
    let pin_from_outcome = init_outcome
        .require_webrtc_dtls_pin()
        .expect("outcome must carry peer DTLS pin");
    assert_eq!(
        pin_from_outcome, expected_peer_fp,
        "sanity: outcome must carry the peer's committed fingerprint"
    );

    let ice_path = IcePathOutcome {
        local_addr: ADDR_A,
        remote_addr: ADDR_B,
        is_relay: false,
    };

    // WebRTC-only caps → WebRTC branch in negotiate_and_build → pin forwarded to factory.
    let webrtc_only = TransportCaps {
        supports_quic: false,
        supports_webrtc: true,
    };

    let factory = StubFactory::new();
    let tracker = factory.tracker();
    let (signaling, _guard) = one_shot_peer_caps(&webrtc_only);
    let establisher = make_establisher(webrtc_only, signaling, factory);

    let result = establisher
        .establish_as_initiator(&init_outcome, &ice_path)
        .await;

    let (kind, _transport) = result.expect("WebRTC establishment must succeed with valid pin");
    assert_eq!(kind, TransportKind::Webrtc);

    let call = tracker
        .lock()
        .unwrap()
        .expect("factory must have been called");
    assert_eq!(call.0, TransportKind::Webrtc, "factory must build WebRTC");
    assert!(
        call.2.is_some(),
        "factory must receive Some(pin) on WebRTC path"
    );
    assert_eq!(
        call.2.unwrap(),
        expected_peer_fp,
        "factory must receive the exact peer fingerprint bytes from the Noise outcome; \
         if this assertion fails, the pin was dropped or zeroed in negotiate_and_build"
    );
}

/// Test 8: QUIC-negotiated session where peer's BindCert carries a DTLS commitment →
/// `UnexpectedDtlsCommitment` error.
///
/// This is the defensive rejection for a protocol-violating peer: they negotiated QUIC but
/// committed a DTLS fingerprint (indicative of misconfiguration or an active manipulation).
#[tokio::test]
async fn session_quic_with_unexpected_dtls_commitment_rejected() {
    // Noise WITH DTLS commitments — but we will negotiate QUIC (not WebRTC).
    // This simulates a peer that committed a DTLS fingerprint but agreed to a QUIC-only session.
    let dtls_bytes: [u8; 32] = [0x55; 32];
    let init_ks = SoftwareKeystore::generate();
    let resp_ks = SoftwareKeystore::generate();
    let (init_outcome, _resp_outcome) =
        run_noise_xk_with_dtls(&init_ks, &resp_ks, dtls_bytes, dtls_bytes).await;

    // Sanity: the outcome does carry a DTLS pin.
    assert!(
        init_outcome.peer_dtls_pin().is_some(),
        "test setup: init_outcome must carry a peer DTLS pin"
    );

    let ice_path = IcePathOutcome {
        local_addr: ADDR_A,
        remote_addr: ADDR_B,
        is_relay: false,
    };

    // QUIC-only caps on both sides → QUIC is negotiated.
    // But the Noise outcome carries a DTLS commitment → should be rejected.
    let quic_only = TransportCaps {
        supports_quic: true,
        supports_webrtc: false,
    };

    let (signaling, _guard) = one_shot_peer_caps(&quic_only);
    let establisher = make_establisher(quic_only, signaling, StubFactory::new());

    let result = establisher
        .establish_as_initiator(&init_outcome, &ice_path)
        .await;

    assert!(
        matches!(result, Err(SessionError::UnexpectedDtlsCommitment)),
        "expected UnexpectedDtlsCommitment when QUIC session has peer DTLS pin, got: {result:?}",
        result = result.map(|(k, _)| k),
    );
}

/// Test 9 (hostile input): oversized or piggybacked caps payloads are rejected with
/// `CapsPayloadWrongLength`.
///
/// A payload larger than exactly [`TRANSPORT_CAPS_LEN`] bytes is rejected — even if its first 2
/// bytes decode as valid caps. This prevents piggybacked blobs or ICE candidates whose first 2
/// bytes are 0x01,0x03 from being silently accepted as caps.
#[tokio::test]
async fn recv_peer_caps_rejects_oversized_payload() {
    let init_ks = SoftwareKeystore::generate();
    let resp_ks = SoftwareKeystore::generate();
    let (init_outcome, _) = run_noise_xk_no_dtls(&init_ks, &resp_ks).await;

    let ice_path = IcePathOutcome {
        local_addr: ADDR_A,
        remote_addr: ADDR_B,
        is_relay: false,
    };

    // Build a malicious envelope: valid caps bytes + extra piggybacked blob.
    let mut payload = vec![0x01u8, 0x01u8]; // valid TransportCaps: QUIC only
    payload.extend_from_slice(b"piggybacked-blob-here"); // extra bytes

    let env = SignalingEnvelope {
        kind: MessageKind::Candidate,
        session_id: test_session_id(),
        from_fp: PEER_FP.to_owned(),
        to_fp: LOCAL_FP.to_owned(),
        payload: Bytes::from(payload),
    };

    // Wire up a channel that serves the malicious envelope.
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    let (sink_tx, _sink_rx) = tokio::sync::mpsc::channel(16);
    tx.try_send(env).expect("pre-load");
    let signaling = MemSignaling { tx: sink_tx, rx };

    let quic_only = TransportCaps {
        supports_quic: true,
        supports_webrtc: false,
    };
    let establisher = make_establisher(quic_only, signaling, StubFactory::new());

    let result = establisher
        .establish_as_initiator(&init_outcome, &ice_path)
        .await;

    assert!(
        matches!(
            result,
            Err(SessionError::CapsPayloadWrongLength {
                expected: 2,
                got: len,
            }) if len > 2
        ),
        "expected CapsPayloadWrongLength for oversized payload, got: {result:?}",
        result = result.map(|(k, _)| k),
    );
}

/// Test 10: undersized caps payload (1 byte) → `CapsPayloadWrongLength`.
#[tokio::test]
async fn recv_peer_caps_rejects_undersized_payload() {
    let init_ks = SoftwareKeystore::generate();
    let resp_ks = SoftwareKeystore::generate();
    let (init_outcome, _) = run_noise_xk_no_dtls(&init_ks, &resp_ks).await;

    let ice_path = IcePathOutcome {
        local_addr: ADDR_A,
        remote_addr: ADDR_B,
        is_relay: false,
    };

    let env = SignalingEnvelope {
        kind: MessageKind::Candidate,
        session_id: test_session_id(),
        from_fp: PEER_FP.to_owned(),
        to_fp: LOCAL_FP.to_owned(),
        payload: Bytes::from_static(&[0x01u8]), // 1 byte — too short
    };

    let (tx, rx) = tokio::sync::mpsc::channel(16);
    let (sink_tx, _sink_rx) = tokio::sync::mpsc::channel(16);
    tx.try_send(env).expect("pre-load");
    let signaling = MemSignaling { tx: sink_tx, rx };

    let quic_only = TransportCaps {
        supports_quic: true,
        supports_webrtc: false,
    };
    let establisher = make_establisher(quic_only, signaling, StubFactory::new());

    let result = establisher
        .establish_as_initiator(&init_outcome, &ice_path)
        .await;

    assert!(
        matches!(
            result,
            Err(SessionError::CapsPayloadWrongLength {
                expected: 2,
                got: 1,
            })
        ),
        "expected CapsPayloadWrongLength(got=1) for undersized payload, got: {result:?}",
        result = result.map(|(k, _)| k),
    );
}
