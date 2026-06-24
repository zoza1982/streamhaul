//! Browser end-to-end tests for `sh-web-client` (headless Firefox).
//!
//! These run in a real browser (`wasm-pack test --headless --firefox`) because
//! `RTCPeerConnection` does not exist in Node.  They prove:
//!
//! 1. SDP `a=fingerprint` parsing is byte-exact (`test_parse_sdp_fingerprint`).
//! 2. A mismatched pin is rejected (`test_verify_sdp_fingerprint_pin_mismatch`).
//! 3. A full two-`RTCPeerConnection` loopback connects, runs the real Noise XK handshake with each
//!    side committing its REAL local DTLS fingerprint in an identity-signed `BindCert`, each side
//!    verifies the OTHER's SDP fingerprint against the committed pin, the DataChannel opens, and an
//!    SHP-encoded frame round-trips (`test_browser_loopback_happy_path`).
//! 4. A signaling/SDP fingerprint swap is rejected, with a NON-VACUITY control proving the
//!    rejection is caused by the mismatch and not by setup failure
//!    (`test_mitm_rejection_non_vacuous`).
//! 5. Completing the WebRTC connection with a tampered SDP fails before any remote description is
//!    applied (`test_mitm_rejection_in_connection`, offerer path; `test_mitm_rejection_answerer_path`,
//!    answerer path), each with a non-vacuity control proving the honest SDP passes the same gate.
//! 6. The MITM gate is **fail-closed**: `connect_as_*` refuses to apply any remote description when
//!    no DTLS pin has been set (`test_connect_without_pin_is_rejected`).
//!
//! The signaling seam is simplified to direct in-page calls between the two sides.  The crypto
//! (`sh-crypto` Noise XK + `BindCert`) and the SHP codec (`sh-wasm`) are the REAL primitives — the
//! DTLS pin each side enforces is the genuine identity-bound commitment from the handshake.
//!
//! ## On the handshake driver
//!
//! XK requires the initiator to know the responder's X25519 static up front (its security model).
//! The `sh-crypto-wasm` bridge generates that static internally and does not expose it, so a
//! pure-bridge XK in a single page is not expressible.  We therefore drive the handshake via
//! `sh-crypto` directly (a dev-dependency, no production coupling — mirroring the native
//! `sh-transport/tests/dtls_identity_binding.rs` pattern and the `sh-crypto-wasm` suite's own
//! `full_xk_handshake_with_dtls_binding` test).  The pins it yields are the real
//! `HandshakeOutcome::require_webrtc_dtls_pin()` values.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::*;
use web_sys::{
    RtcDataChannel, RtcDataChannelEvent, RtcPeerConnection, RtcPeerConnectionIceEvent, RtcSdpType,
    RtcSessionDescriptionInit,
};

use sh_crypto::bind_cert::DtlsCommitment;
use sh_crypto::clock::FixedClock;
use sh_crypto::{Keystore, NoiseHandshake, SoftwareKeystore};
use sh_web_client::{parse_sdp_fingerprint, verify_sdp_fingerprint_pin};
use x25519_dalek::{PublicKey, StaticSecret};

wasm_bindgen_test_configure!(run_in_browser);

// ── A known-good SDP fingerprint line ─────────────────────────────────────────

const SAMPLE_SDP: &str = "v=0\r\n\
o=- 0 0 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:\
AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\r\n\
a=setup:actpass\r\n";

const SAMPLE_PIN: [u8; 32] = [
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];

const NOW: i64 = 1_000_000_000;

// ── Test 1: parse a known fingerprint ─────────────────────────────────────────

#[wasm_bindgen_test]
fn test_parse_sdp_fingerprint() {
    let fp = parse_sdp_fingerprint(SAMPLE_SDP).expect("parse must succeed");
    assert_eq!(fp.len(), 32, "fingerprint must be 32 bytes");
    assert_eq!(
        fp,
        SAMPLE_PIN.to_vec(),
        "fingerprint bytes must match exactly"
    );
}

// ── Test 2: mismatched pin is rejected ────────────────────────────────────────

#[wasm_bindgen_test]
fn test_verify_sdp_fingerprint_pin_mismatch() {
    // Correct pin verifies (non-vacuity control for this small test).
    verify_sdp_fingerprint_pin(SAMPLE_SDP, &SAMPLE_PIN).expect("matching pin must verify");

    // Flip one byte → must reject.
    let mut wrong = SAMPLE_PIN;
    wrong[0] ^= 0xFF;
    assert!(
        verify_sdp_fingerprint_pin(SAMPLE_SDP, &wrong).is_err(),
        "mismatched pin must be rejected"
    );

    // Wrong-length pin → must reject.
    assert!(
        verify_sdp_fingerprint_pin(SAMPLE_SDP, &[0u8; 16]).is_err(),
        "wrong-length pin must be rejected"
    );
}

// ── Noise XK handshake driver (real sh-crypto, dev-only) ──────────────────────

/// Run a full Noise XK handshake with mutual trust (TOFU), each side committing its own DTLS
/// fingerprint.  Returns `(offerer_pins_answerer, answerer_pins_offerer)` — the 32-byte DTLS pin
/// each side must enforce against the OTHER's SDP `a=fingerprint`.
///
/// The offerer plays the XK initiator and the answerer the XK responder.
fn drive_xk(offerer_dtls: &[u8], answerer_dtls: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let init_dtls: [u8; 32] = offerer_dtls.try_into().expect("offerer dtls is 32 bytes");
    let resp_dtls: [u8; 32] = answerer_dtls.try_into().expect("answerer dtls is 32 bytes");

    let clock = FixedClock(NOW);
    let init_ks = SoftwareKeystore::generate();
    let resp_ks = SoftwareKeystore::generate();

    // Responder static is known to the initiator up front (XK precondition).
    let resp_static = StaticSecret::random_from_rng(rand_core::OsRng);
    let resp_pub = PublicKey::from(&resp_static);
    let init_static = StaticSecret::random_from_rng(rand_core::OsRng);

    // Mutual TOFU trust so `complete` succeeds.
    // SAFETY on wasm32: sh-crypto's Keystore and NoiseHandshake futures are immediately-ready
    // (no waker needed). pollster::block_on busy-spins on wasm32 if the future yields —
    // safe here, but must be revisited if sh-crypto ever introduces real async work.
    let resp_id = pollster::block_on(resp_ks.device_identity()).expect("resp id");
    // SAFETY on wasm32: immediately-ready future (see note above) — no yield, no waker.
    let init_id = pollster::block_on(init_ks.device_identity()).expect("init id");
    // SAFETY on wasm32: immediately-ready future (see note above) — no yield, no waker.
    pollster::block_on(init_ks.trust_peer(&resp_id)).expect("init trusts resp");
    // SAFETY on wasm32: immediately-ready future (see note above) — no yield, no waker.
    pollster::block_on(resp_ks.trust_peer(&init_id)).expect("resp trusts init");

    // SAFETY on wasm32: immediately-ready future (see note above) — no yield, no waker.
    let mut init = pollster::block_on(NoiseHandshake::initiator_xk_with_dtls(
        &init_ks,
        init_static,
        resp_pub.to_bytes(),
        &[],
        DtlsCommitment::sha256(init_dtls),
        &clock,
    ))
    .expect("initiator_xk_with_dtls");
    // SAFETY on wasm32: immediately-ready future (see note above) — no yield, no waker.
    let mut resp = pollster::block_on(NoiseHandshake::responder_xk_with_dtls(
        &resp_ks,
        resp_static,
        &[],
        DtlsCommitment::sha256(resp_dtls),
        &clock,
    ))
    .expect("responder_xk_with_dtls");

    // XK: 3 messages; BindCerts ride in messages 2 and 3.
    let msg0 = init.write_message().expect("msg0");
    resp.read_message(&msg0, &clock).expect("read msg0");
    let msg1 = resp.write_message().expect("msg1");
    init.read_message(&msg1, &clock).expect("read msg1");
    let msg2 = init.write_message().expect("msg2");
    resp.read_message(&msg2, &clock).expect("read msg2");

    // SAFETY on wasm32: immediately-ready future (see note above) — no yield, no waker.
    let init_outcome = pollster::block_on(init.complete(&init_ks)).expect("init complete");
    // SAFETY on wasm32: immediately-ready future (see note above) — no yield, no waker.
    let resp_outcome = pollster::block_on(resp.complete(&resp_ks)).expect("resp complete");

    // Each side extracts the peer's identity-bound DTLS pin from the VERIFIED handshake.
    let offerer_pins_answerer = init_outcome
        .require_webrtc_dtls_pin()
        .expect("offerer obtains answerer's committed pin");
    let answerer_pins_offerer = resp_outcome
        .require_webrtc_dtls_pin()
        .expect("answerer obtains offerer's committed pin");
    (
        offerer_pins_answerer.to_vec(),
        answerer_pins_offerer.to_vec(),
    )
}

// ── WebRTC plumbing helpers ───────────────────────────────────────────────────

fn new_pc() -> RtcPeerConnection {
    RtcPeerConnection::new().expect("RtcPeerConnection::new")
}

/// Wire each PC's locally-gathered ICE candidates to the other PC (loopback, no STUN/TURN).
fn wire_ice(a: &RtcPeerConnection, b: &RtcPeerConnection) {
    let b_clone = b.clone();
    let on_a_ice = Closure::<dyn FnMut(RtcPeerConnectionIceEvent)>::new(
        move |evt: RtcPeerConnectionIceEvent| {
            if let Some(c) = evt.candidate() {
                let _ = b_clone.add_ice_candidate_with_opt_rtc_ice_candidate(Some(&c));
            }
        },
    );
    a.set_onicecandidate(Some(on_a_ice.as_ref().unchecked_ref()));
    on_a_ice.forget();

    let a_clone = a.clone();
    let on_b_ice = Closure::<dyn FnMut(RtcPeerConnectionIceEvent)>::new(
        move |evt: RtcPeerConnectionIceEvent| {
            if let Some(c) = evt.candidate() {
                let _ = a_clone.add_ice_candidate_with_opt_rtc_ice_candidate(Some(&c));
            }
        },
    );
    b.set_onicecandidate(Some(on_b_ice.as_ref().unchecked_ref()));
    on_b_ice.forget();
}

fn sdp_init(kind: RtcSdpType, sdp: &str) -> RtcSessionDescriptionInit {
    let init = RtcSessionDescriptionInit::new(kind);
    init.set_sdp(sdp);
    init
}

fn local_sdp(pc: &RtcPeerConnection) -> String {
    pc.local_description().expect("local desc").sdp()
}

/// Resolve once `dc` reaches the `open` state, or reject after a generous (10 s) timeout.
///
/// Fails fast if there is no `window` (so the 10 s safety timeout cannot be armed) rather than
/// silently waiting forever with no timeout backstop.
async fn await_channel_open(dc: &RtcDataChannel) -> Result<(), JsValue> {
    if dc.ready_state() == web_sys::RtcDataChannelState::Open {
        return Ok(());
    }
    // Arm the safety timeout up front; if there is no window we cannot, so abort now.
    let win = web_sys::window()
        .ok_or_else(|| JsValue::from_str("no window available to arm datachannel-open timeout"))?;
    let dc2 = dc.clone();
    let promise = js_sys::Promise::new(&mut |resolve, reject| {
        let reject2 = reject.clone();
        let timeout_cb = Closure::<dyn FnMut()>::new(move || {
            let _ = reject2.call1(
                &JsValue::NULL,
                &JsValue::from_str("datachannel open timeout"),
            );
        });
        let _ = win.set_timeout_with_callback_and_timeout_and_arguments_0(
            timeout_cb.as_ref().unchecked_ref(),
            10_000,
        );
        timeout_cb.forget();

        let on_open = Closure::<dyn FnMut()>::new(move || {
            let _ = resolve.call0(&JsValue::NULL);
        });
        dc2.set_onopen(Some(on_open.as_ref().unchecked_ref()));
        on_open.forget();
    });
    JsFuture::from(promise).await.map(|_| ())
}

/// Run a full two-PC offer/answer exchange, returning `(offer_dc, offer_sdp, answer_sdp)` with
/// local descriptions set on both sides (so both have real DTLS fingerprints).  The remote
/// description is NOT yet applied on the offerer — that happens only after the pin check.
async fn negotiate(
    offerer: &RtcPeerConnection,
    answerer: &RtcPeerConnection,
) -> (RtcDataChannel, String, String) {
    let dc = offerer.create_data_channel("shp");

    let offer = JsFuture::from(offerer.create_offer())
        .await
        .expect("create_offer");
    let offer: RtcSessionDescriptionInit = offer.unchecked_into();
    JsFuture::from(offerer.set_local_description(&offer))
        .await
        .expect("offerer setLocalDescription");
    let offer_sdp = local_sdp(offerer);

    JsFuture::from(answerer.set_remote_description(&sdp_init(RtcSdpType::Offer, &offer_sdp)))
        .await
        .expect("answerer setRemoteDescription(offer)");
    let answer = JsFuture::from(answerer.create_answer())
        .await
        .expect("create_answer");
    let answer: RtcSessionDescriptionInit = answer.unchecked_into();
    JsFuture::from(answerer.set_local_description(&answer))
        .await
        .expect("answerer setLocalDescription");
    let answer_sdp = local_sdp(answerer);

    (dc, offer_sdp, answer_sdp)
}

// ── Test 3: full loopback happy path ──────────────────────────────────────────

#[wasm_bindgen_test]
async fn test_browser_loopback_happy_path() {
    sh_web_client::set_panic_hook();

    let offerer = new_pc();
    let answerer = new_pc();
    wire_ice(&offerer, &answerer);

    // Register the answerer's inbound-DataChannel + message receiver BEFORE negotiation, because
    // `ondatachannel` fires during `setRemoteDescription(offer)` inside `negotiate`.  The received
    // frame is captured into `got` and `recv_promise` resolves on first binary message.
    let got: js_sys::Array = js_sys::Array::new();
    let got_clone = got.clone();
    let answerer_for_dc = answerer.clone();
    let recv_promise = js_sys::Promise::new(&mut |resolve, _reject| {
        let got_inner = got_clone.clone();
        let resolve = resolve.clone();
        let on_dc =
            Closure::<dyn FnMut(RtcDataChannelEvent)>::new(move |evt: RtcDataChannelEvent| {
                let ch = evt.channel();
                ch.set_binary_type(web_sys::RtcDataChannelType::Arraybuffer);
                let got2 = got_inner.clone();
                let resolve2 = resolve.clone();
                let on_msg = Closure::<dyn FnMut(web_sys::MessageEvent)>::new(
                    move |msg: web_sys::MessageEvent| {
                        if let Ok(buf) = msg.data().dyn_into::<js_sys::ArrayBuffer>() {
                            let arr = js_sys::Uint8Array::new(&buf);
                            got2.push(&arr);
                            let _ = resolve2.call0(&JsValue::NULL);
                        }
                    },
                );
                ch.set_onmessage(Some(on_msg.as_ref().unchecked_ref()));
                on_msg.forget();
            });
        answerer_for_dc.set_ondatachannel(Some(on_dc.as_ref().unchecked_ref()));
        on_dc.forget();
    });

    let (offer_dc, offer_sdp, answer_sdp) = negotiate(&offerer, &answerer).await;

    // Each side's REAL local DTLS fingerprint from its local SDP.
    let offerer_fp = parse_sdp_fingerprint(&offer_sdp).expect("offerer local fp");
    let answerer_fp = parse_sdp_fingerprint(&answer_sdp).expect("answerer local fp");

    // Real Noise XK handshake; each side commits its real fingerprint and obtains the OTHER's pin.
    let (offerer_pins_answerer, answerer_pins_offerer) = drive_xk(&offerer_fp, &answerer_fp);

    // MITM gate: verify the OTHER's SDP fingerprint against the committed pin BEFORE applying it.
    verify_sdp_fingerprint_pin(&answer_sdp, &offerer_pins_answerer)
        .expect("offerer must accept answerer's honest SDP fingerprint");
    verify_sdp_fingerprint_pin(&offer_sdp, &answerer_pins_offerer)
        .expect("answerer must accept offerer's honest SDP fingerprint");

    // Apply the remote answer only after the pin check passed.
    JsFuture::from(offerer.set_remote_description(&sdp_init(RtcSdpType::Answer, &answer_sdp)))
        .await
        .expect("offerer setRemoteDescription(answer)");

    await_channel_open(&offer_dc)
        .await
        .expect("offerer datachannel must open");

    // Round-trip a real SHP-encoded frame.
    let frame = sh_wasm::encode_input_event(3, 0, 0x1234, 0x5678, 0, 0x0004, 0, 0, 0)
        .expect("encode SHP frame");

    offer_dc.set_binary_type(web_sys::RtcDataChannelType::Arraybuffer);
    offer_dc.send_with_u8_array(&frame).expect("send frame");

    JsFuture::from(recv_promise)
        .await
        .expect("answerer must receive the frame");

    let received: js_sys::Uint8Array = got.get(0).unchecked_into();
    assert_eq!(
        received.to_vec(),
        frame,
        "round-tripped SHP frame must be byte-identical"
    );
}

// ── Test 4: MITM rejection (non-vacuous) ──────────────────────────────────────

#[wasm_bindgen_test]
async fn test_mitm_rejection_non_vacuous() {
    let offerer = new_pc();
    let answerer = new_pc();

    let (_dc, offer_sdp, answer_sdp) = negotiate(&offerer, &answerer).await;
    let offerer_fp = parse_sdp_fingerprint(&offer_sdp).expect("offerer fp");
    let answerer_fp = parse_sdp_fingerprint(&answer_sdp).expect("answerer fp");

    // The offerer commits its real fingerprint; the answerer's pin for the offerer is that real fp.
    let (_offerer_pins_answerer, answerer_pins_offerer) = drive_xk(&offerer_fp, &answerer_fp);

    // ── NON-VACUITY CONTROL: the ORIGINAL, untampered offer SDP MUST verify Ok ────────────────
    // Proves the rejection below is caused by the tamper, not by a broken setup.
    verify_sdp_fingerprint_pin(&offer_sdp, &answerer_pins_offerer)
        .expect("CONTROL: the honest offer SDP must verify against the committed pin");

    // ── TAMPER: a signaling MITM rewrites the offer's a=fingerprint to a DIFFERENT value ──────
    let tampered = tamper_sdp_fingerprint(&offer_sdp);
    assert_ne!(tampered, offer_sdp, "tamper must actually change the SDP");
    let tampered_fp = parse_sdp_fingerprint(&tampered).expect("tampered fp still parses");
    assert_ne!(
        tampered_fp, answerer_pins_offerer,
        "tampered fingerprint must differ from the committed pin"
    );

    // The pin check on the tampered SDP MUST fail.
    assert!(
        verify_sdp_fingerprint_pin(&tampered, &answerer_pins_offerer).is_err(),
        "MITM: tampered SDP fingerprint must be rejected against the committed pin"
    );
}

// ── Test 5: MITM rejection inside the connection flow ─────────────────────────

#[wasm_bindgen_test]
async fn test_mitm_rejection_in_connection() {
    use sh_web_client::{SignalingChannel, WebClient};

    // Drive the whole offer/answer through the WebClient so its internal PC is a real offerer and
    // `connect_as_offerer(answer)` is a valid WebRTC step (setRemoteDescription on an offered PC).
    let noop = js_sys::Function::new_no_args("return null;");
    let mut client = WebClient::new(SignalingChannel::new(noop)).expect("WebClient::new");

    // A separate answerer PC produces the honest answer to the client's offer.
    let answerer = new_pc();

    let offer_sdp = client.create_offer().await.expect("client create_offer");
    JsFuture::from(answerer.set_remote_description(&sdp_init(RtcSdpType::Offer, &offer_sdp)))
        .await
        .expect("answerer setRemoteDescription(offer)");
    let answer = JsFuture::from(answerer.create_answer())
        .await
        .expect("create_answer");
    let answer: RtcSessionDescriptionInit = answer.unchecked_into();
    JsFuture::from(answerer.set_local_description(&answer))
        .await
        .expect("answerer setLocalDescription");
    let answer_sdp = local_sdp(&answerer);

    // Real handshake: offerer (client) and answerer commit their real fingerprints.
    let offerer_fp = parse_sdp_fingerprint(&offer_sdp).expect("offerer fp");
    let answerer_fp = parse_sdp_fingerprint(&answer_sdp).expect("answerer fp");
    let (offerer_pins_answerer, _answerer_pins_offerer) = drive_xk(&offerer_fp, &answerer_fp);

    client
        .set_dtls_pin(&offerer_pins_answerer)
        .expect("set pin");

    // A MITM swaps the answer's fingerprint.  connect_as_offerer MUST reject before applying the
    // remote description — so no DataChannel can ever open over the attacker's DTLS cert.
    let tampered_answer = tamper_sdp_fingerprint(&answer_sdp);
    assert_ne!(tampered_answer, answer_sdp, "tamper must change the SDP");

    let result = client.connect_as_offerer(tampered_answer).await;
    assert!(
        result.is_err(),
        "connect_as_offerer must abort on a tampered DTLS fingerprint (no setRemoteDescription)"
    );

    // NON-VACUITY CONTROL: the SAME call with the HONEST answer SDP passes the pin gate AND the
    // subsequent setRemoteDescription succeeds — proving the rejection above is caused by the pin
    // mismatch, not by an unrelated WebRTC setup failure.
    let honest = client.connect_as_offerer(answer_sdp).await;
    assert!(
        honest.is_ok(),
        "CONTROL: the honest answer SDP must pass the pin gate and apply (proves rejection is the pin)"
    );
}

// ── Test 6: MITM rejection on the ANSWERER path ───────────────────────────────

#[wasm_bindgen_test]
async fn test_mitm_rejection_answerer_path() {
    use sh_web_client::{SignalingChannel, WebClient};

    // The offerer is a plain PC that produces an honest offer.
    let offerer = new_pc();
    let _offer_dc = offerer.create_data_channel("shp");
    let offer = JsFuture::from(offerer.create_offer())
        .await
        .expect("create_offer");
    let offer: RtcSessionDescriptionInit = offer.unchecked_into();
    JsFuture::from(offerer.set_local_description(&offer))
        .await
        .expect("offerer setLocalDescription");
    let offer_sdp = local_sdp(&offerer);

    // The answerer is driven through the WebClient so connect_as_answerer is the real path.
    let noop = js_sys::Function::new_no_args("return null;");
    let mut answerer_client = WebClient::new(SignalingChannel::new(noop)).expect("WebClient::new");

    // The answerer needs a local DTLS fingerprint of its own for the handshake; create a throwaway
    // answer against the honest offer to obtain the answerer PC's fingerprint, then run the real XK.
    let probe_answerer = new_pc();
    JsFuture::from(probe_answerer.set_remote_description(&sdp_init(RtcSdpType::Offer, &offer_sdp)))
        .await
        .expect("probe answerer setRemoteDescription(offer)");
    let probe_answer = JsFuture::from(probe_answerer.create_answer())
        .await
        .expect("probe create_answer");
    let probe_answer: RtcSessionDescriptionInit = probe_answer.unchecked_into();
    JsFuture::from(probe_answerer.set_local_description(&probe_answer))
        .await
        .expect("probe answerer setLocalDescription");
    let answerer_fp = parse_sdp_fingerprint(&local_sdp(&probe_answerer)).expect("answerer fp");

    let offerer_fp = parse_sdp_fingerprint(&offer_sdp).expect("offerer fp");

    // Real handshake: the answerer pins the offerer's committed fingerprint.
    let (_offerer_pins_answerer, answerer_pins_offerer) = drive_xk(&offerer_fp, &answerer_fp);
    answerer_client
        .set_dtls_pin(&answerer_pins_offerer)
        .expect("set pin");

    // A MITM swaps the OFFER's fingerprint.  connect_as_answerer MUST reject before applying the
    // remote description (and before producing any answer).
    let tampered_offer = tamper_sdp_fingerprint(&offer_sdp);
    assert_ne!(tampered_offer, offer_sdp, "tamper must change the SDP");

    let result = answerer_client.connect_as_answerer(tampered_offer).await;
    assert!(
        result.is_err(),
        "connect_as_answerer must abort on a tampered offer DTLS fingerprint (no setRemoteDescription, no answer)"
    );

    // NON-VACUITY CONTROL: the SAME call with the HONEST offer SDP passes the pin gate and produces
    // an answer — proving the rejection above is the pin mismatch, not a setup failure.
    let honest = answerer_client.connect_as_answerer(offer_sdp).await;
    assert!(
        honest.is_ok(),
        "CONTROL: the honest offer SDP must pass the pin gate and produce an answer"
    );
}

// ── Test 7: guard_remote_sdp is fail-closed when no pin is set ─────────────────

#[wasm_bindgen_test]
async fn test_connect_without_pin_is_rejected() {
    use sh_web_client::{SignalingChannel, WebClient};

    // Build a real offerer client but NEVER call set_dtls_pin.
    let noop = js_sys::Function::new_no_args("return null;");
    let mut client = WebClient::new(SignalingChannel::new(noop)).expect("WebClient::new");

    // Produce a real, well-formed answer SDP from a separate answerer so the only reason to reject
    // is the missing pin (not malformed SDP).
    let offer_sdp = client.create_offer().await.expect("client create_offer");
    let answerer = new_pc();
    JsFuture::from(answerer.set_remote_description(&sdp_init(RtcSdpType::Offer, &offer_sdp)))
        .await
        .expect("answerer setRemoteDescription(offer)");
    let answer = JsFuture::from(answerer.create_answer())
        .await
        .expect("create_answer");
    let answer: RtcSessionDescriptionInit = answer.unchecked_into();
    JsFuture::from(answerer.set_local_description(&answer))
        .await
        .expect("answerer setLocalDescription");
    let answer_sdp = local_sdp(&answerer);

    // Without a pin, connect_as_offerer must FAIL CLOSED — never apply the remote description.
    let result = client.connect_as_offerer(answer_sdp).await;
    assert!(
        result.is_err(),
        "connect_as_offerer must fail closed when no DTLS pin has been set (forgotten handshake)"
    );
}

// ── SDP tamper helper ─────────────────────────────────────────────────────────

/// Replace the SDP's `a=fingerprint:sha-256 …` value with a different (well-formed) one,
/// simulating a signaling MITM.  Flips the first hex group so the result still parses to 32 bytes
/// but differs from the original.  Preserves each line's original ending (`\r\n` vs bare `\n`) so
/// the tampered SDP is byte-faithful to the input apart from the one flipped hex group.
fn tamper_sdp_fingerprint(sdp: &str) -> String {
    let mut out = String::with_capacity(sdp.len());
    for raw_line in sdp.split_inclusive('\n') {
        // Split the line body from its terminator so we can re-emit the exact ending.
        let (body, ending) = if let Some(stripped) = raw_line.strip_suffix("\r\n") {
            (stripped, "\r\n")
        } else if let Some(stripped) = raw_line.strip_suffix('\n') {
            (stripped, "\n")
        } else {
            // Final line with no trailing newline.
            (raw_line, "")
        };

        if let Some(rest) = body.strip_prefix("a=fingerprint:") {
            if let Some((alg, value)) = rest.split_once(' ') {
                let mut groups: Vec<String> =
                    value.trim().split(':').map(|s| s.to_owned()).collect();
                if let Some(first) = groups.first_mut() {
                    *first = if first.eq_ignore_ascii_case("AA") {
                        "BB".to_owned()
                    } else {
                        "AA".to_owned()
                    };
                }
                out.push_str("a=fingerprint:");
                out.push_str(alg);
                out.push(' ');
                out.push_str(&groups.join(":"));
                out.push_str(ending);
                continue;
            }
        }
        out.push_str(body);
        out.push_str(ending);
    }
    out
}
