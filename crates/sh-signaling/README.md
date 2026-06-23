# sh-signaling

WebSocket signaling server and client for Streamhaul session establishment (Phase 4, P4-1).

## What this crate does

`sh-signaling` implements the signaling layer that enables two Streamhaul peers to exchange
SDP offers/answers and trickle-ICE candidates before a peer-to-peer QUIC or WebRTC session
is established.

### Architecture

```
Peer A (initiator)                  SignalingServer                  Peer B (responder)
        │                                  │                                  │
        │──Hello(session_id, fp_A)────────►│                                  │
        │◄──Hello ack──────────────────────│                                  │
        │                                  │◄─Hello(session_id, fp_B)─────────│
        │                                  │──Hello ack──────────────────────►│
        │──Offer(to=fp_B, payload=SDP)────►│──Offer(payload=SDP)─────────────►│
        │◄─Answer(to=fp_A, payload=SDP)────│◄─Answer(payload=SDP)─────────────│
        │──Candidate(to=fp_B, payload=…)──►│──Candidate(payload=…)───────────►│
        │◄─Candidate(to=fp_A, payload=…)───│◄─Candidate(payload=…)────────────│
        │──EndOfCandidates─────────────────►│──EndOfCandidates────────────────►│
        │◄─EndOfCandidates──────────────────│◄─EndOfCandidates─────────────────│
        │   [signaling exits the path]      │   [connection established P2P]   │
```

### Zero-knowledge relay invariant

The server routes envelopes using **only** `session_id` and `to_fp`. It **never** inspects
the `payload` field (LLD §6.3). SDP blobs, ICE candidates, and BindCert material live inside
`payload` as opaque bytes.

### Wire format

Each message is a `SignalingEnvelope` encoded as a hand-rolled binary frame (ADR-0011):

```
Offset  Len   Field
0       1     kind: u8   (Hello=0, Offer=1, Answer=2, Candidate=3, EndOfCandidates=4, Bye=5, Error=6)
1       16    session_id: [u8; 16]
17      64    from_fp:   [u8; 64]  (ASCII hex fingerprint)
81      64    to_fp:     [u8; 64]  (ASCII hex fingerprint)
145     4     payload_len: u32 BE
149     N     opaque_payload (N ≤ 64 KiB)
```

The decoder is bounds-checked and never panics. A `cargo-fuzz` target covers the decode path.

### TLS / WSS

The server binds plain WebSocket (no in-process TLS). Production deployments terminate TLS
with a reverse proxy (nginx, Caddy) in front of the signaling server. Tests use plain `ws://`
on loopback.

### Authentication seam

`SignalingServer::bind` takes an `Arc<dyn PeerAuthenticator>`. The default `AcceptAll`
implementation (available with the `insecure-lan` feature) admits every peer — suitable for
loopback tests only. Production code must supply a real authenticator that validates peer
fingerprints against a signed token (planned for the signed-token auth work after P4-5).

## Usage

### Server

`AcceptAll` is **test-only** and is exported only under the `insecure-lan` feature (which
fails to compile in release builds — see Security notes). A production server must supply a
real `PeerAuthenticator` that validates each peer's `from_fp` against a signed token.

```rust,no_run
# #[cfg(feature = "insecure-lan")]
# {
use std::sync::Arc;
use sh_signaling::{SignalingServer, auth::AcceptAll};

#[tokio::main]
async fn main() -> Result<(), sh_signaling::SignalingError> {
    // PRODUCTION: replace `AcceptAll` with a real PeerAuthenticator (R-SIG-AUTH).
    let server = SignalingServer::bind(
        "0.0.0.0:8765".parse().unwrap(),
        Arc::new(AcceptAll),
    ).await?;
    server.run().await
}
# }
```

### Client

```rust,no_run
use sh_signaling::{SignalingClient, SessionId, SignalingEnvelope, MessageKind};
use sh_signaling::backoff::ExponentialBackoff;
use bytes::Bytes;

#[tokio::main]
async fn main() -> Result<(), sh_signaling::SignalingError> {
    let my_fp = "a".repeat(64); // replace with real DeviceIdentity::fingerprint().as_str()
    let peer_fp = "b".repeat(64);
    let session_id = SessionId([42u8; 16]);

    let mut client = SignalingClient::connect(
        "ws://127.0.0.1:8765",
        session_id,
        my_fp.clone(),
        ExponentialBackoff::default(),
    ).await?;

    client.send(SignalingEnvelope {
        kind: MessageKind::Offer,
        session_id,
        from_fp: my_fp,
        to_fp: peer_fp,
        payload: Bytes::from_static(b"v=0\r\n..."),
    }).await?;

    while let Some(env) = client.recv().await? {
        println!("received {:?}", env.kind);
    }
    Ok(())
}
```

## Features

| Feature | Description |
|---------|-------------|
| `insecure-lan` | Enables `InsecureLanLab` witness and `AcceptAll` authenticator. For tests only. |

## Security notes

- The `insecure-lan` feature must not be enabled in production builds. A `compile_error!` guard
  **is implemented** (`auth.rs`): `cargo build --release --features insecure-lan` fails to compile.
- The `payload` field is opaque to the server — this is the structural enforcement of the
  zero-knowledge relay invariant (the server routes on `(session_id, to_fp)` only and never
  parses, logs, or branches on the payload).
- The server performs spoof rejection: each connection is bound to a single `from_fp` on `Hello`;
  a subsequent message with a different `from_fp` is rejected and the connection closed. DoS
  bounds are enforced (max connections, per-session peer cap, WS message-size cap, handshake +
  idle timeouts).
- **Residual risks (NOT yet mitigated by P4-1 — do not over-rely on signaling security):**
  - **`from_fp` is not bound to a verified identity until R-SIG-AUTH lands.** With the test-only
    `AcceptAll` authenticator, any peer can register (and thus impersonate) any fingerprint within
    a session. The production `PeerAuthenticator` must cryptographically bind `from_fp`.
  - **Plain-WS signaling is MITM-exposed.** TLS is terminated at a reverse proxy; even so, a
    signaling-path MITM cannot read content (the payload is E2E-encrypted) but **can drop,
    reorder, or inject ICE candidates** to force a worse path, downgrade, or block connection
    setup. This is defeated only by the **P4-5 BindCert/DTLS-fingerprint binding**, which P4-1
    does not provide.

## Related crates

- `sh-crypto` — `DeviceIdentity` / `Fingerprint` (used as routing keys)
- `sh-ice` (P4-2) — ICE/STUN candidate gathering; feeds `Candidate` envelopes through this crate
- `sh-transport` — QUIC/WebRTC session transport established after signaling completes
