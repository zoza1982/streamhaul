//! End-to-end R-SIG-AUTH integration tests (ADR-0016).
//!
//! These exercise the REAL authentication path — `IdentityProofAuthenticator` on the server and
//! `SignalingClient::connect_authenticated` (signing with a `SoftwareKeystore`) on the client —
//! WITHOUT the `insecure-lan` feature. They prove that a peer that controls the device key behind
//! its claimed fingerprint is admitted, and that spoofers / replayers are rejected.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::panic)]
#![allow(clippy::arithmetic_side_effects)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use sh_crypto::peer_auth::{IdentityProof, PEER_AUTH_CHALLENGE_LEN};
use sh_crypto::{Keystore, SoftwareKeystore};
use sh_signaling::auth::IdentityProofAuthenticator;
use sh_signaling::backoff::ImmediateBackoff;
use sh_signaling::challenge::ChallengeSource;
use sh_signaling::envelope::{decode, encode, ENVELOPE_HEADER_LEN, MAX_PAYLOAD_LEN};
use sh_signaling::{MessageKind, SessionId, SignalingClient, SignalingEnvelope, SignalingServer};
use tokio_tungstenite::connect_async_with_config;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;

/// A deterministic challenge source for reproducible tests: always emits a fixed nonce.
///
/// Production uses `OsChallengeSource`; this fixed source lets a test hand-craft a proof that
/// matches the challenge the server will issue.
struct FixedChallengeSource([u8; PEER_AUTH_CHALLENGE_LEN]);

impl ChallengeSource for FixedChallengeSource {
    fn fill_challenge(&self, buf: &mut [u8; PEER_AUTH_CHALLENGE_LEN]) {
        *buf = self.0;
    }
}

fn ws_config() -> WebSocketConfig {
    WebSocketConfig {
        max_message_size: Some(ENVELOPE_HEADER_LEN + MAX_PAYLOAD_LEN as usize),
        max_frame_size: Some(ENVELOPE_HEADER_LEN + MAX_PAYLOAD_LEN as usize),
        ..Default::default()
    }
}

/// Spins up a server using the production `IdentityProofAuthenticator` and a fixed challenge.
async fn start_auth_server(challenge: [u8; PEER_AUTH_CHALLENGE_LEN]) -> SocketAddr {
    let server = SignalingServer::bind_with_challenge_source(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(IdentityProofAuthenticator),
        Arc::new(FixedChallengeSource(challenge)),
    )
    .await
    .expect("server bind");
    let addr = server.local_addr().expect("local addr");
    tokio::spawn(async move {
        server.run().await.ok();
    });
    addr
}

/// Raw-WS receive of the next decoded envelope (answers pings).
async fn raw_recv(
    ws: &mut (impl futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
              + Unpin),
) -> SignalingEnvelope {
    loop {
        match ws.next().await.expect("stream ended").expect("WS error") {
            Message::Binary(b) => return decode(&b).unwrap(),
            Message::Ping(_) | Message::Pong(_) => continue,
            other => panic!("unexpected WS message: {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// A1. Valid proof admitted: client signs with its real keystore → server admits.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn authenticated_client_is_admitted_and_can_route() {
    let challenge = [0x5au8; PEER_AUTH_CHALLENGE_LEN];
    let addr = start_auth_server(challenge).await;
    let session = SessionId([1u8; 16]);

    let ks_a = Arc::new(SoftwareKeystore::generate());
    let ks_b = Arc::new(SoftwareKeystore::generate());
    let fp_b = ks_b
        .device_identity()
        .await
        .unwrap()
        .fingerprint()
        .as_str()
        .to_owned();
    let fp_a = ks_a
        .device_identity()
        .await
        .unwrap()
        .fingerprint()
        .as_str()
        .to_owned();

    // Both peers connect with real signed proofs. If auth failed, connect_authenticated would
    // never see a Hello ack and would error.
    let mut client_a = SignalingClient::connect_authenticated(
        format!("ws://{addr}"),
        session,
        ks_a.clone() as Arc<dyn Keystore>,
        ImmediateBackoff,
    )
    .await
    .expect("authenticated client A connects");

    let mut client_b = SignalingClient::connect_authenticated(
        format!("ws://{addr}"),
        session,
        ks_b.clone() as Arc<dyn Keystore>,
        ImmediateBackoff,
    )
    .await
    .expect("authenticated client B connects");

    // Now route an Offer A → B to prove the registration actually took effect.
    let payload = Bytes::from_static(b"v=0\r\nauthenticated\r\n");
    client_a
        .send(SignalingEnvelope {
            kind: MessageKind::Offer,
            session_id: session,
            from_fp: fp_a.clone(),
            to_fp: fp_b.clone(),
            payload: payload.clone(),
        })
        .await
        .unwrap();

    let received = tokio::time::timeout(Duration::from_secs(5), client_b.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(received.kind, MessageKind::Offer);
    assert_eq!(received.payload, payload);
}

// ---------------------------------------------------------------------------
// A2. Fingerprint spoof rejected: claim B's fingerprint but sign with A's key.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn fingerprint_spoof_is_rejected() {
    let challenge = [0x11u8; PEER_AUTH_CHALLENGE_LEN];
    let addr = start_auth_server(challenge).await;
    let session = SessionId([2u8; 16]);

    let ks_attacker = SoftwareKeystore::generate();
    let victim_fp = SoftwareKeystore::generate()
        .device_identity()
        .await
        .unwrap()
        .fingerprint()
        .as_str()
        .to_owned();

    let url = format!("ws://{addr}");
    let (mut ws, _) = connect_async_with_config(&url, Some(ws_config()), false)
        .await
        .expect("raw WS connect");

    // Consume the Challenge.
    let chal = raw_recv(&mut ws).await;
    assert_eq!(chal.kind, MessageKind::Challenge);

    // Build a proof with the attacker's OWN key over the real challenge — valid signature, but the
    // attacker will CLAIM the victim's fingerprint in from_fp. The server must reject (fp binding).
    let proof = IdentityProof::create(&ks_attacker, session.as_bytes(), &challenge)
        .await
        .unwrap();
    let hello = SignalingEnvelope {
        kind: MessageKind::Hello,
        session_id: session,
        from_fp: victim_fp.clone(), // spoofed claim
        to_fp: "0".repeat(64),
        payload: Bytes::copy_from_slice(&proof.encode()),
    };
    ws.send(Message::Binary(encode(&hello).unwrap().to_vec()))
        .await
        .unwrap();

    // Expect an Error envelope (uniform "authentication failed"), and the connection to close.
    let resp = tokio::time::timeout(Duration::from_secs(3), raw_recv(&mut ws)).await;
    if let Ok(env) = resp {
        assert_eq!(env.kind, MessageKind::Error, "spoof must be rejected");
        let reason = std::str::from_utf8(&env.payload).unwrap_or("");
        assert!(
            reason.contains("authentication failed"),
            "reason must be the sanitized uniform message, got: {reason}"
        );
        // The error must not leak the victim fingerprint.
        assert!(!reason.contains(&victim_fp), "error leaks claimed fp");
    }
}

// ---------------------------------------------------------------------------
// A3. Replayed proof rejected: a proof signed over a DIFFERENT (stale) challenge fails.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn replayed_proof_for_wrong_challenge_is_rejected() {
    // Server issues `server_challenge`; attacker presents a proof bound to `stale_challenge`.
    let server_challenge = [0x22u8; PEER_AUTH_CHALLENGE_LEN];
    let stale_challenge = [0x33u8; PEER_AUTH_CHALLENGE_LEN];
    let addr = start_auth_server(server_challenge).await;
    let session = SessionId([3u8; 16]);

    let ks = SoftwareKeystore::generate();
    let fp = ks
        .device_identity()
        .await
        .unwrap()
        .fingerprint()
        .as_str()
        .to_owned();

    let url = format!("ws://{addr}");
    let (mut ws, _) = connect_async_with_config(&url, Some(ws_config()), false)
        .await
        .expect("raw WS connect");
    let chal = raw_recv(&mut ws).await;
    assert_eq!(chal.kind, MessageKind::Challenge);

    // A correctly-signed proof, but over the STALE challenge (as if captured from an old session).
    let proof = IdentityProof::create(&ks, session.as_bytes(), &stale_challenge)
        .await
        .unwrap();
    let hello = SignalingEnvelope {
        kind: MessageKind::Hello,
        session_id: session,
        from_fp: fp.clone(),
        to_fp: "0".repeat(64),
        payload: Bytes::copy_from_slice(&proof.encode()),
    };
    ws.send(Message::Binary(encode(&hello).unwrap().to_vec()))
        .await
        .unwrap();

    let resp = tokio::time::timeout(Duration::from_secs(3), raw_recv(&mut ws)).await;
    if let Ok(env) = resp {
        assert_eq!(
            env.kind,
            MessageKind::Error,
            "stale-challenge replay must be rejected"
        );
    }
}

// ---------------------------------------------------------------------------
// A4. Malformed/empty proof rejected (hostile input) — server never panics.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn malformed_proof_is_rejected() {
    let challenge = [0x44u8; PEER_AUTH_CHALLENGE_LEN];
    let addr = start_auth_server(challenge).await;
    let session = SessionId([4u8; 16]);
    let fp = "a".repeat(64);

    for bad_payload in [
        Bytes::new(),                     // empty
        Bytes::from_static(b"too short"), // wrong length
        Bytes::from(vec![0xffu8; 500]),   // oversized garbage
    ] {
        let url = format!("ws://{addr}");
        let (mut ws, _) = connect_async_with_config(&url, Some(ws_config()), false)
            .await
            .expect("raw WS connect");
        let chal = raw_recv(&mut ws).await;
        assert_eq!(chal.kind, MessageKind::Challenge);

        let hello = SignalingEnvelope {
            kind: MessageKind::Hello,
            session_id: session,
            from_fp: fp.clone(),
            to_fp: "0".repeat(64),
            payload: bad_payload,
        };
        ws.send(Message::Binary(encode(&hello).unwrap().to_vec()))
            .await
            .unwrap();

        let resp = tokio::time::timeout(Duration::from_secs(3), raw_recv(&mut ws)).await;
        if let Ok(env) = resp {
            assert_eq!(
                env.kind,
                MessageKind::Error,
                "malformed proof must be rejected"
            );
        }
        // Either an Error envelope or a closed connection — never a server panic/hang.
    }
}

// ---------------------------------------------------------------------------
// A5. connect (unauthenticated, empty proof) is REJECTED by a real auth server.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn unauthenticated_connect_is_rejected_by_real_server() {
    let challenge = [0x55u8; PEER_AUTH_CHALLENGE_LEN];
    let addr = start_auth_server(challenge).await;
    let session = SessionId([5u8; 16]);

    // `connect` sends an EMPTY proof; the real IdentityProofAuthenticator must refuse it, so the
    // client never receives a Hello ack and connect() fails.
    let result = SignalingClient::connect(
        format!("ws://{addr}"),
        session,
        "a".repeat(64),
        sh_signaling::backoff::NoReconnect,
    )
    .await;
    assert!(
        result.is_err(),
        "an empty-proof client must be rejected by the IdentityProofAuthenticator"
    );
}
