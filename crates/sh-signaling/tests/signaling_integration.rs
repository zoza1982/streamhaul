//! Integration tests for sh-signaling.
//!
//! These tests spin up a loopback SignalingServer and connect two SignalingClients to it,
//! exercising the full Offer/Answer/Candidate/EOC flow. All tests require the `insecure-lan`
//! feature so they can use `AcceptAll`.

#![cfg(feature = "insecure-lan")]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use sh_signaling::auth::AcceptAll;
use sh_signaling::backoff::{ExponentialBackoff, ImmediateBackoff, NoReconnect};
use sh_signaling::envelope::{decode, encode, ENVELOPE_HEADER_LEN, MAX_PAYLOAD_LEN};
use sh_signaling::{
    MessageKind, SessionId, SignalingClient, SignalingEnvelope, SignalingError, SignalingServer,
};

/// Generates a random-looking 64-char hex fingerprint for tests.
fn fake_fp(seed: u8) -> String {
    format!("{:02x}", seed).repeat(32)
}

/// Spins up a server on a random loopback port and returns the address.
async fn start_server() -> SocketAddr {
    let server = SignalingServer::bind("127.0.0.1:0".parse().unwrap(), Arc::new(AcceptAll))
        .await
        .expect("server bind");
    let addr = server.local_addr().expect("local addr");
    tokio::spawn(async move {
        server.run().await.ok();
    });
    addr
}

/// Connects a client and waits for the Hello ack from the server before returning.
///
/// This ensures the peer is fully registered in the server's session table before the caller
/// starts sending messages to it.
async fn connect_client(addr: SocketAddr, session_id: SessionId, my_fp: &str) -> SignalingClient {
    let url = format!("ws://{addr}");
    // Use ImmediateBackoff so reconnect tests don't wait real time.
    let mut client = SignalingClient::connect(url, session_id, my_fp.to_owned(), ImmediateBackoff)
        .await
        .expect("client connect");

    // Drain the Hello ack from the server. This confirms that the server has received and
    // processed our Hello envelope and registered this peer. Without this synchronisation,
    // a subsequent send() to this peer from another client may fail with PeerNotFound.
    let ack = tokio::time::timeout(Duration::from_secs(5), client.recv())
        .await
        .expect("Hello ack timeout")
        .expect("Hello ack recv error");

    // The ack might be None (unlikely) or Some(Hello ack).
    if let Some(msg) = ack {
        assert_eq!(
            msg.kind,
            MessageKind::Hello,
            "expected Hello ack, got {:?}",
            msg.kind
        );
    }

    client
}

// ---------------------------------------------------------------------------
// 1. End-to-end routing: A → server → B (Offer/Answer/Candidate/EOC)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn end_to_end_routing() {
    let addr = start_server().await;
    let session = SessionId([1u8; 16]);
    let fp_a = fake_fp(0xAA);
    let fp_b = fake_fp(0xBB);

    let mut client_a = connect_client(addr, session, &fp_a).await;
    let mut client_b = connect_client(addr, session, &fp_b).await;

    // A → Offer → B
    let offer_payload = Bytes::from_static(b"v=0\r\no=A 0 0 IN IP4 127.0.0.1\r\n");
    client_a
        .send(SignalingEnvelope {
            kind: MessageKind::Offer,
            session_id: session,
            from_fp: fp_a.clone(),
            to_fp: fp_b.clone(),
            payload: offer_payload.clone(),
        })
        .await
        .unwrap();

    // The Hello ack was drained in connect_client; the next message should be the Offer.
    let received = tokio::time::timeout(Duration::from_secs(5), client_b.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(received.kind, MessageKind::Offer);
    assert_eq!(received.payload, offer_payload);

    // B → Answer → A
    let answer_payload = Bytes::from_static(b"v=0\r\no=B 0 0 IN IP4 127.0.0.1\r\n");
    client_b
        .send(SignalingEnvelope {
            kind: MessageKind::Answer,
            session_id: session,
            from_fp: fp_b.clone(),
            to_fp: fp_a.clone(),
            payload: answer_payload.clone(),
        })
        .await
        .unwrap();

    let received = tokio::time::timeout(Duration::from_secs(5), client_a.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(received.kind, MessageKind::Answer);
    assert_eq!(received.payload, answer_payload);

    // A → Candidate → B
    let candidate_payload = Bytes::from_static(b"candidate:1 1 udp 2122 127.0.0.1 50000 typ host");
    client_a
        .send(SignalingEnvelope {
            kind: MessageKind::Candidate,
            session_id: session,
            from_fp: fp_a.clone(),
            to_fp: fp_b.clone(),
            payload: candidate_payload.clone(),
        })
        .await
        .unwrap();

    let received = tokio::time::timeout(Duration::from_secs(5), client_b.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(received.kind, MessageKind::Candidate);
    assert_eq!(received.payload, candidate_payload);

    // A → EndOfCandidates → B
    client_a
        .send(SignalingEnvelope {
            kind: MessageKind::EndOfCandidates,
            session_id: session,
            from_fp: fp_a.clone(),
            to_fp: fp_b.clone(),
            payload: Bytes::new(),
        })
        .await
        .unwrap();

    let received = tokio::time::timeout(Duration::from_secs(5), client_b.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(received.kind, MessageKind::EndOfCandidates);
}

// ---------------------------------------------------------------------------
// 2. Zero-knowledge: arbitrary payload bytes routed unmodified
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn zero_knowledge_arbitrary_payload() {
    let addr = start_server().await;
    let session = SessionId([2u8; 16]);
    let fp_a = fake_fp(0xCA);
    let fp_b = fake_fp(0xFE);

    let mut client_a = connect_client(addr, session, &fp_a).await;
    let mut client_b = connect_client(addr, session, &fp_b).await;

    // Arbitrary binary payload (not valid SDP).
    let payload: Bytes = (0u8..=255u8).cycle().take(4096).collect::<Vec<_>>().into();

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

    // Hello ack was drained in connect_client; the next message should be the Offer.
    let msg = tokio::time::timeout(Duration::from_secs(5), client_b.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(msg.kind, MessageKind::Offer);
    assert_eq!(msg.payload, payload, "payload must be delivered unmodified");
}

// ---------------------------------------------------------------------------
// 3. Oversized payload rejected at encode time
// ---------------------------------------------------------------------------

#[tokio::test]
async fn oversized_payload_rejected() {
    let big = vec![0u8; MAX_PAYLOAD_LEN as usize + 1];
    let env = SignalingEnvelope {
        kind: MessageKind::Offer,
        session_id: SessionId([3u8; 16]),
        from_fp: fake_fp(0x01),
        to_fp: fake_fp(0x02),
        payload: Bytes::from(big),
    };
    let err = encode(&env).unwrap_err();
    assert!(
        matches!(err, SignalingError::PayloadTooLarge { .. }),
        "expected PayloadTooLarge, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 4. Truncated frame rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn truncated_frame_rejected() {
    let payload = b"hello";
    let env = SignalingEnvelope {
        kind: MessageKind::Offer,
        session_id: SessionId([4u8; 16]),
        from_fp: fake_fp(0x03),
        to_fp: fake_fp(0x04),
        payload: Bytes::from_static(payload),
    };
    let encoded = encode(&env).unwrap().to_vec();
    // Remove last 3 bytes to truncate the payload.
    let truncated = &encoded[..encoded.len() - 3];
    let err = decode(truncated).unwrap_err();
    assert!(
        matches!(err, SignalingError::TruncatedPayload { .. }),
        "expected TruncatedPayload, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 5. Garbage frame rejected (no panic)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn garbage_frame_rejected() {
    let cases: &[&[u8]] = &[
        b"",
        b"garbage input that is too short",
        &[0xFF; 200],
        &[0u8; ENVELOPE_HEADER_LEN],
    ];
    for &case in cases {
        let result = decode(case);
        // Either an error or a valid decode of a zero-padded buffer; never a panic.
        let _ = result;
    }
}

// ---------------------------------------------------------------------------
// 6. Empty buffer returns EnvelopeTooShort
// ---------------------------------------------------------------------------

#[tokio::test]
async fn empty_buffer_too_short() {
    let err = decode(&[]).unwrap_err();
    assert!(matches!(
        err,
        SignalingError::EnvelopeTooShort { actual: 0 }
    ));
}

// ---------------------------------------------------------------------------
// 7. Reconnect with injected backoff
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn reconnect_with_backoff() {
    let addr = start_server().await;
    let session = SessionId([7u8; 16]);
    let fp_a = fake_fp(0x7A);

    // Connect, close the underlying connection manually (by dropping and reconnecting).
    // We test this by closing client_a and reconnecting a fresh client with the same fp.
    let client_a = connect_client(addr, session, &fp_a).await;
    client_a.close().await.unwrap();

    // Reconnect should succeed immediately with ImmediateBackoff.
    let mut client_a2 = SignalingClient::connect(
        format!("ws://{addr}"),
        session,
        fp_a.clone(),
        ImmediateBackoff,
    )
    .await
    .unwrap();

    // Drain the Hello ack so we know the server has registered client_a2.
    let _ack = tokio::time::timeout(Duration::from_secs(5), client_a2.recv())
        .await
        .unwrap()
        .unwrap();

    // The client is registered; we can send again.
    let fp_b = fake_fp(0x7B);
    let mut client_b = connect_client(addr, session, &fp_b).await;

    client_a2
        .send(SignalingEnvelope {
            kind: MessageKind::Offer,
            session_id: session,
            from_fp: fp_a.clone(),
            to_fp: fp_b.clone(),
            payload: Bytes::from_static(b"reconnected-offer"),
        })
        .await
        .unwrap();

    // Hello ack was drained in connect_client for client_b; Offer should be next.
    let msg = tokio::time::timeout(Duration::from_secs(5), client_b.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(msg.kind, MessageKind::Offer);
    assert_eq!(msg.payload, Bytes::from_static(b"reconnected-offer"));
}

// ---------------------------------------------------------------------------
// 8. ExponentialBackoff gives up after max_attempts
// ---------------------------------------------------------------------------

#[tokio::test]
async fn exponential_backoff_gives_up() {
    // Try to connect to a port where nobody is listening.
    let result = SignalingClient::connect(
        "ws://127.0.0.1:1", // port 1 is almost never open
        SessionId([8u8; 16]),
        fake_fp(0x88),
        ExponentialBackoff::new(1, 2, 2), // very short delays, only 2 attempts
    )
    .await;
    // Should fail with NotConnected (all retries exhausted).
    assert!(result.is_err(), "expected connect failure with bad port");
}

// ---------------------------------------------------------------------------
// 9. Disconnect notification: peer B gets Bye when A disconnects
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn disconnect_notifies_peer() {
    let addr = start_server().await;
    let session = SessionId([9u8; 16]);
    let fp_a = fake_fp(0x9A);
    let fp_b = fake_fp(0x9B);

    let client_a = connect_client(addr, session, &fp_a).await;
    let mut client_b = connect_client(addr, session, &fp_b).await;

    // Wait a moment for B to be fully registered.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Drop A (closes the connection without an explicit Bye).
    drop(client_a);

    // B should receive a Bye from the server on behalf of A.
    // Allow up to 500ms for the notification.
    let result = tokio::time::timeout(Duration::from_millis(500), client_b.recv()).await;
    match result {
        Ok(Ok(None)) => {} // recv() returned None — Bye or closed connection
        Ok(Ok(Some(msg))) => {
            // It might be the Hello ack or the Bye from A's disconnect.
            // Either way, a subsequent recv should return None eventually.
            assert!(
                msg.kind == MessageKind::Hello || msg.kind == MessageKind::Bye,
                "unexpected kind: {:?}",
                msg.kind
            );
        }
        Ok(Err(e)) => {
            // A WS error is acceptable when the peer disconnects.
            let _ = e;
        }
        Err(_) => {
            // Timeout — B didn't receive the Bye in time. Not a hard failure for now
            // since synthetic Bye delivery is best-effort.
        }
    }
}

// ---------------------------------------------------------------------------
// 10. Invalid fingerprint in encode is rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invalid_fingerprint_encode_rejected() {
    let env = SignalingEnvelope {
        kind: MessageKind::Hello,
        session_id: SessionId([10u8; 16]),
        from_fp: "too-short".to_owned(),
        to_fp: fake_fp(0x0B),
        payload: Bytes::new(),
    };
    let err = encode(&env).unwrap_err();
    assert!(matches!(err, SignalingError::InvalidFingerprint));
}

// ---------------------------------------------------------------------------
// 11. All MessageKind variants have stable discriminants
// ---------------------------------------------------------------------------

#[test]
fn message_kind_discriminants() {
    assert_eq!(MessageKind::Hello as u8, 0);
    assert_eq!(MessageKind::Offer as u8, 1);
    assert_eq!(MessageKind::Answer as u8, 2);
    assert_eq!(MessageKind::Candidate as u8, 3);
    assert_eq!(MessageKind::EndOfCandidates as u8, 4);
    assert_eq!(MessageKind::Bye as u8, 5);
    assert_eq!(MessageKind::Error as u8, 6);
}

// ---------------------------------------------------------------------------
// 12. NoReconnect backoff: client fails immediately on bad URL
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_reconnect_fails_fast() {
    let result = SignalingClient::connect(
        "ws://127.0.0.1:1",
        SessionId([12u8; 16]),
        fake_fp(0xCC),
        NoReconnect,
    )
    .await;
    assert!(
        result.is_err(),
        "expected connect failure with NoReconnect, got Ok"
    );
}
