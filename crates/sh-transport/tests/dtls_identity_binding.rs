//! P4-5 integration test: bind the DTLS fingerprint to device identity.
//!
//! This is the authoritative proof that a signaling/SDP MITM which swaps the DTLS fingerprint is
//! rejected. It is a *dev-only* cross-crate test: `sh-crypto` is a dev-dependency of `sh-transport`
//! solely for this file. There is no production `sh-transport → sh-crypto` coupling — the binding
//! primitives live in their owning crates and the only glue (read the verified pin from the Noise
//! handshake, then pin it on the transport before DTLS) lives here, standing in for the `sh-core`
//! session-orchestration layer that lands with P4-6.
//!
//! ## What it proves
//!
//! 1. Two devices run a real Noise XK handshake over an in-memory channel, exchanging
//!    identity-signed `BindCert`s. Each `BindCert` commits the device's REAL
//!    [`WebRtcTransport::local_dtls_fingerprint()`].
//! 2. Each side extracts the peer's committed fingerprint from the *verified* handshake outcome
//!    ([`HandshakeOutcome::require_webrtc_dtls_pin`]) and pins it via
//!    [`WebRtcTransport::set_remote_dtls_fingerprint`] BEFORE the DTLS handshake runs.
//! 3. **Matching path:** the cert each transport presents matches its committed fingerprint →
//!    str0m completes DTLS → a DataChannel opens and a frame round-trips. The pinned value equals
//!    what str0m reports via [`WebRtcTransport::remote_dtls_fingerprint`].
//! 4. **MITM path:** an attacker substitutes one side's DTLS certificate (a different `Rtc` with a
//!    different fingerprint) while the *committed* fingerprint stays the legitimate one. str0m
//!    fail-closes: DTLS never completes and no data flows. The swap is rejected.
//!
//! ## Non-vacuity
//!
//! The single [`run_dtls_session`] driver is parameterised by which certificate the "A" side
//! actually presents. The matching case and the MITM case differ ONLY in that cert. The MITM case
//! asserts the session does NOT connect; if the pin were not applied (or applied to the cert the
//! attacker presents instead of the committed one), the MITM case WOULD connect and the test would
//! fail. The dedicated `mitm_without_pinning_would_connect_control` test makes this explicit: with
//! the pin deliberately set to the attacker's cert, the same MITM cert DOES connect — proving the
//! rejection in `dtls_fingerprint_swap_is_rejected` is caused by the pin, not by an unrelated setup
//! failure.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use sh_crypto::bind_cert::DtlsCommitment;
use sh_crypto::clock::FixedClock;
use sh_crypto::{HandshakeOutcome, Keystore, NoiseHandshake, SoftwareKeystore};
use sh_transport::{ChannelSpec, Transport, WebRtcTransport};
use str0m::crypto::Fingerprint;
use str0m::{Candidate, Rtc};
use x25519_dalek::{PublicKey, StaticSecret};

const NOW: i64 = 1_000_000_000;

/// Per-step virtual-time advance fed to the str0m `Rtc` clock.
const STEP: Duration = Duration::from_millis(5);

/// Drive-loop iteration budget. str0m's ICE + DTLS + SCTP convergence over a synthetic
/// loopback completes in well under ~400 steps (≈ 2 virtual seconds at [`STEP`]); 400 leaves a
/// comfortable margin while keeping the *real* wall-clock cost of the blocking drive loop far
/// below the 8 s `accept_channel`/`recv` timeouts on a loaded CI runner (the previous 2 000-step
/// budget could spin long enough to race that async timeout → spurious honest-path failure).
const DRIVE_STEPS: usize = 400;

/// Async timeout for `accept_channel` / `recv`. Generous relative to the bounded drive loop above
/// so that, on the honest path, the channel always opens before this fires; on the MITM path the
/// loop stops driving (str0m fail-closes) and this is the deadline that reports "not connected".
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(8);

/// A process-wide, deterministic monotonic base `Instant` for the str0m clock.
///
/// str0m requires a monotonically-advancing `Instant`; `Instant` cannot be built from an absolute
/// value, so we capture one opaque base per test process and advance it by fixed [`STEP`] deltas.
/// Every session in the test uses the *same* base + the *same* step schedule, so the str0m clock
/// timeline is identical run-to-run (mirroring the `FixedClock(NOW)` discipline used for the Noise
/// clock): timing is decoupled from per-call wall-clock readings (`Instant::now()` is read exactly
/// once for the whole process, not per session/step). The honest and MITM branches therefore see
/// byte-for-byte the same drive schedule and differ only in the presented cert.
fn sim_base() -> Instant {
    static BASE: OnceLock<Instant> = OnceLock::new();
    #[allow(clippy::disallowed_methods)]
    *BASE.get_or_init(Instant::now)
}

/// Build an `Rtc` configured for a direct (no-trickle) host-to-host session against `peer_addr`,
/// with ICE credentials/roles/DTLS/SCTP started. The DTLS *fingerprint* is intentionally NOT set
/// here — it is pinned later from the verified BindCert.
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

/// Exchange ICE credentials between two raw `Rtc`s (must happen before they are wrapped).
fn exchange_ice_credentials(a: &mut Rtc, b: &mut Rtc) {
    let creds_a = a.direct_api().local_ice_credentials();
    let creds_b = b.direct_api().local_ice_credentials();
    a.direct_api().set_remote_ice_credentials(creds_b);
    b.direct_api().set_remote_ice_credentials(creds_a);
}

/// Reconstruct the str0m `Fingerprint` str0m enforces from a 32-byte whole-cert SHA-256 commit.
fn sha256_fingerprint(commit: [u8; 32]) -> Fingerprint {
    Fingerprint {
        hash_func: "sha-256".to_owned(),
        bytes: commit.to_vec(),
    }
}

/// Run a full Noise XK handshake in memory with mutual trust, each side committing its own
/// `local_dtls`. Returns `(initiator_outcome, responder_outcome)`.
async fn run_noise_with_dtls(
    init_ks: &SoftwareKeystore,
    resp_ks: &SoftwareKeystore,
    init_dtls: [u8; 32],
    resp_dtls: [u8; 32],
) -> (HandshakeOutcome, HandshakeOutcome) {
    let clock = FixedClock(NOW);

    let resp_static = StaticSecret::random_from_rng(rand_core::OsRng);
    let resp_pub = PublicKey::from(&resp_static);
    let init_static = StaticSecret::random_from_rng(rand_core::OsRng);

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

    // XK: 3-message exchange. BindCerts ride in messages 2 and 3.
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

/// Drive two already-pinned `WebRtcTransport`s through ICE + DTLS + SCTP and attempt a single
/// DataChannel round-trip. Returns `true` if a frame was delivered (DTLS connected), `false` if it
/// never connected within the deadline (str0m fail-closed on a fingerprint mismatch).
///
/// On a successful connection, asserts that each side's `remote_dtls_fingerprint()` (the value
/// str0m actually verified against the peer cert) equals the fingerprint that was pinned — i.e.
/// str0m enforced exactly the identity-bound commitment.
async fn try_round_trip(
    ta: Arc<WebRtcTransport>,
    tb: Arc<WebRtcTransport>,
    expect_a_pins: Fingerprint,
    expect_b_pins: Fingerprint,
    start: Instant,
) -> bool {
    // Open a channel on A.
    let mut channel_a = ta
        .open_channel(ChannelSpec::input())
        .await
        .expect("open_channel");

    // Background synchronous drive loop driven by a deterministic simulated `Instant` (CR-10):
    // it advances `now` by fixed `STEP` deltas from the shared `start` base — no per-step
    // wall-clock reads. On a fingerprint mismatch str0m returns an error from
    // drive()/handle_receive(); we stop driving (the connection is dead) so the accept/recv below
    // time out and report "not connected". `stop` lets the foreground abort the loop early once
    // the round-trip outcome is known (CR-7), so neither path wastes the full budget spinning.
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
                        // A dead/rejecting peer may error here; ignore — the deadline handles it.
                        let _ =
                            tb_d.handle_receive(pkt.source, pkt.destination, &pkt.contents, now);
                    }
                }
                Err(_) => return, // str0m fail-closed (e.g. DTLS fingerprint mismatch).
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

    // Accept on B with a bounded timeout. If DTLS never completes, no ChannelOpen ever fires.
    let accept = tokio::time::timeout(ACCEPT_TIMEOUT, tb.accept_channel()).await;
    let connected = match accept {
        Ok(Ok(mut channel_b)) => {
            // DTLS connected and the channel opened — push one frame through to confirm.
            let payload = bytes::Bytes::from_static(b"p4-5 dtls bound");
            let _ = channel_a.send(payload.clone()).await;
            let recv = tokio::time::timeout(ACCEPT_TIMEOUT, channel_b.recv()).await;
            matches!(recv, Ok(Ok(Some(ref got))) if got == &payload)
        }
        // Timed out or errored → never connected.
        _ => false,
    };

    // The round-trip outcome is now decided; signal the drive loop to stop wasting steps (CR-7).
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    drive_handle.await.expect("drive task panicked");

    if connected {
        // str0m only exposes the *verified* remote fingerprint after DTLS completes. Assert it
        // equals what we pinned — proof that str0m enforced the identity-bound commitment.
        assert_eq!(
            ta.remote_dtls_fingerprint()
                .expect("A verified remote fingerprint after connect"),
            expect_a_pins,
            "A must have verified exactly the pinned fingerprint"
        );
        assert_eq!(
            tb.remote_dtls_fingerprint()
                .expect("B verified remote fingerprint after connect"),
            expect_b_pins,
            "B must have verified exactly the pinned fingerprint"
        );
    }

    connected
}

/// The headline test: a fingerprint swap by a signaling MITM is rejected, while the honest path
/// connects. Both branches share `run_dtls_session`; they differ ONLY in the cert "A" presents and
/// the assertion — proving the rejection is caused by the identity-bound pin.
#[tokio::test]
async fn dtls_fingerprint_swap_is_rejected() {
    // ── Honest path: matching certs connect ───────────────────────────────────────────────────
    assert!(
        run_dtls_session(Mitm::None).await,
        "honest path: matching DTLS certs must connect (pin == presented cert)"
    );

    // ── MITM path: A presents an attacker cert that does NOT match its committed fingerprint ────
    assert!(
        !run_dtls_session(Mitm::SubstituteACert).await,
        "MITM path: a swapped DTLS cert must be rejected (str0m fail-closes on pin mismatch)"
    );
}

/// Non-vacuity control: with the pin deliberately set to the ATTACKER's cert (i.e. pinning is
/// effectively bypassed), the very same MITM substitution DOES connect. This proves the rejection
/// in `dtls_fingerprint_swap_is_rejected` is caused by the pin, not by an unrelated setup failure.
#[tokio::test]
async fn mitm_without_pinning_would_connect_control() {
    assert!(
        run_dtls_session(Mitm::SubstituteACertButPinIt).await,
        "control: if the pin tracks the attacker cert, the MITM substitution connects — so the \
         rejection in the headline test is genuinely caused by the identity-bound pin"
    );
}

#[derive(Clone, Copy)]
enum Mitm {
    /// No tampering: A presents the cert whose fingerprint it committed.
    None,
    /// A presents a different (attacker) cert; B still pins the committed (legitimate) one.
    SubstituteACert,
    /// A presents a different (attacker) cert AND B pins that attacker cert (pin bypass control).
    SubstituteACertButPinIt,
}

/// Set up two devices, run the Noise handshake to derive identity-bound DTLS pins, pin them on the
/// transports per `mitm`, then attempt a DataChannel round-trip. Returns whether it connected.
async fn run_dtls_session(mitm: Mitm) -> bool {
    let a_addr: SocketAddr = (Ipv4Addr::new(10, 0, 0, 1), 4000).into();
    let b_addr: SocketAddr = (Ipv4Addr::new(10, 0, 0, 2), 4001).into();

    // Deterministic simulated clock base for the str0m `Rtc`s (CR-10): a single process-wide
    // monotonic base advanced by fixed `STEP` deltas in the drive loop — not a fresh per-session
    // `Instant::now()`. This decouples str0m timing from wall-clock and makes the schedule
    // reproducible across runs (mirroring `FixedClock(NOW)` for the Noise clock).
    let start = sim_base();

    // The legitimate A-side Rtc (whose fingerprint A will commit in its BindCert).
    let mut rtc_a_legit = make_configured_rtc(a_addr, b_addr, true, start);
    let mut rtc_b = make_configured_rtc(b_addr, a_addr, false, start);

    // The fingerprint A *commits* is the legitimate one (read before A may be substituted).
    let fp_a_committed = rtc_a_legit.direct_api().local_dtls_fingerprint().clone();

    // Decide which Rtc A actually presents on the wire.
    let mut rtc_a_present = match mitm {
        Mitm::None => rtc_a_legit,
        Mitm::SubstituteACert | Mitm::SubstituteACertButPinIt => {
            // Attacker substitutes a fresh cert (different fingerprint) while the committed
            // fingerprint stays `fp_a_committed`. Drop the legitimate Rtc; A presents the attacker.
            drop(rtc_a_legit);
            make_configured_rtc(a_addr, b_addr, true, start)
        }
    };
    // The substituted cert must actually differ from the committed one, else the test is vacuous.
    if matches!(mitm, Mitm::SubstituteACert | Mitm::SubstituteACertButPinIt) {
        assert_ne!(
            rtc_a_present.direct_api().local_dtls_fingerprint().bytes,
            fp_a_committed.bytes,
            "attacker cert must differ from committed cert for the MITM test to be meaningful"
        );
    }

    let fp_b = rtc_b.direct_api().local_dtls_fingerprint().clone();

    // ICE credentials are exchanged between the certs that will actually run DTLS.
    exchange_ice_credentials(&mut rtc_a_present, &mut rtc_b);

    let ta = Arc::new(WebRtcTransport::new(rtc_a_present, a_addr, b_addr));
    let tb = Arc::new(WebRtcTransport::new(rtc_b, b_addr, a_addr));

    // Sanity: the committed A-fingerprint and B-fingerprint are the values fed into the BindCerts.
    let init_dtls: [u8; 32] = fp_a_committed
        .bytes
        .clone()
        .try_into()
        .expect("A committed fingerprint must be 32 bytes (SHA-256)");
    let resp_dtls: [u8; 32] = fp_b
        .bytes
        .clone()
        .try_into()
        .expect("B fingerprint must be 32 bytes (SHA-256)");

    // Run the identity handshake: A commits its (legitimate) fingerprint; B commits its own.
    let init_ks = SoftwareKeystore::generate();
    let resp_ks = SoftwareKeystore::generate();
    let (a_outcome, b_outcome) =
        run_noise_with_dtls(&init_ks, &resp_ks, init_dtls, resp_dtls).await;

    // Each side extracts the peer's identity-bound DTLS pin from the VERIFIED handshake.
    let a_pins_b = a_outcome
        .require_webrtc_dtls_pin()
        .expect("A must obtain B's committed pin");
    let b_pins_a = b_outcome
        .require_webrtc_dtls_pin()
        .expect("B must obtain A's committed pin");

    // A pins B's committed fingerprint (always honest in this test).
    ta.set_remote_dtls_fingerprint(sha256_fingerprint(a_pins_b));

    // B pins A. In the honest/MITM cases B pins the COMMITTED (legitimate) A fingerprint. In the
    // control case B pins the ATTACKER's actual cert (bypassing the binding) to show the
    // substitution would otherwise succeed.
    let b_pin_for_a = match mitm {
        Mitm::None | Mitm::SubstituteACert => b_pins_a, // == fp_a_committed (legitimate)
        Mitm::SubstituteACertButPinIt => {
            // Pin the attacker cert that A actually presents.
            ta.local_dtls_fingerprint()
                .bytes
                .try_into()
                .expect("A presented fingerprint 32 bytes")
        }
    };
    tb.set_remote_dtls_fingerprint(sha256_fingerprint(b_pin_for_a));

    // Before DTLS completes, str0m does not yet expose a *verified* remote fingerprint on either
    // side (the getter reads the peer-cert-derived value, populated only post-handshake).
    assert!(
        tb.remote_dtls_fingerprint().is_none(),
        "tb: remote_dtls_fingerprint() is None until DTLS verifies the peer cert"
    );
    assert!(
        ta.remote_dtls_fingerprint().is_none(),
        "ta: remote_dtls_fingerprint() is None until DTLS verifies the peer cert"
    );

    try_round_trip(
        ta,
        tb,
        sha256_fingerprint(a_pins_b),
        sha256_fingerprint(b_pin_for_a),
        start,
    )
    .await
}
