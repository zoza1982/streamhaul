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
0       1     kind: u8   (Hello=0, Offer=1, Answer=2, Candidate=3, EndOfCandidates=4, Bye=5, Error=6, Challenge=7)
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

### Authentication seam (R-SIG-AUTH, ADR-0016)

`SignalingServer::bind` takes an `Arc<dyn PeerAuthenticator>`. **Production uses
`IdentityProofAuthenticator`**, which verifies a possession-of-identity-key proof: on connect the
server issues a fresh random 32-byte `Challenge` (kind = 7); the peer's `Hello` carries an
`sh_crypto::peer_auth::IdentityProof` in its opaque payload (`device_pubkey || challenge ||
signature`, 128 bytes). The server verifies, in order: the echoed challenge (anti-replay,
constant-time), the key is valid/non-weak, `Fingerprint::from(pubkey) == from_fp` (constant-time),
and the Ed25519 signature (`verify_strict`) over a canonical domain-separated message binding
`session_id`, the key, and the challenge. This binds `from_fp` to a key the peer demonstrably
controls and defeats spoofing/impersonation/DoS/replay at the relay — even a malicious relay.

The `AuthContext` → `Result<(), AuthError>` seam stays a trait so an allow-list / rate-limiter /
issuer policy can wrap the possession check. Every rejection is collapsed to a single sanitized
`Error` reason on the wire (no enumeration oracle). The test-only `AcceptAll` (available with the
`insecure-lan` feature) admits every peer for loopback tests.

**Server-side auth proves ownership, not peer-to-peer trust** — end-to-end trust is established
separately by the endpoints via Noise/BindCert/TOFU pairing (P3).

## Usage

### Server

Production servers use `IdentityProofAuthenticator` (R-SIG-AUTH). `AcceptAll` is **test-only** and
is exported only under the `insecure-lan` feature (which fails to compile in release builds — see
Security notes).

```rust,no_run
use std::sync::Arc;
use sh_signaling::{SignalingServer, auth::IdentityProofAuthenticator};

#[tokio::main]
async fn main() -> Result<(), sh_signaling::SignalingError> {
    // Production: verify a possession-of-identity-key proof per peer. The OS CSPRNG supplies the
    // per-connection challenge (use `bind_with_challenge_source` to inject a deterministic source
    // in tests).
    let server = SignalingServer::bind(
        "0.0.0.0:8765".parse().unwrap(),
        Arc::new(IdentityProofAuthenticator),
    ).await?;
    server.run().await
}
```

### Client

Production clients use `SignalingClient::connect_authenticated`, which signs the server challenge
with the device `Keystore`:

```rust,no_run
use std::sync::Arc;
use sh_crypto::{Keystore, SoftwareKeystore};
use sh_signaling::{SignalingClient, SessionId};
use sh_signaling::backoff::ExponentialBackoff;

#[tokio::main]
async fn main() -> Result<(), sh_signaling::SignalingError> {
    let keystore: Arc<dyn Keystore> = Arc::new(SoftwareKeystore::generate());
    let session_id = SessionId([42u8; 16]);
    let _client = SignalingClient::connect_authenticated(
        "ws://127.0.0.1:8765",
        session_id,
        keystore,
        ExponentialBackoff::default(),
    ).await?;
    Ok(())
}
```

The lower-level `connect` (empty proof) remains for `insecure-lan` loopback tests only.

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
- **`from_fp` is cryptographically bound to a verified identity (R-SIG-AUTH, ADR-0016).** The
  production `IdentityProofAuthenticator` admits a peer only if it presents a valid Ed25519
  possession proof over a fresh server challenge whose key hashes to the claimed `from_fp`. A peer
  can no longer register a fingerprint it does not control; replay (incl. by a malicious relay) is
  defeated by the per-connection challenge. **This proves ownership at the relay, not end-to-end
  trust** — trust is established by the endpoints via Noise/BindCert/TOFU (P3).
- **Residual risks (NOT mitigated by the signaling layer — do not over-rely on signaling security):**
  - **Plain-WS signaling is MITM-exposed.** TLS is terminated at a reverse proxy (R-SIG-TLS); even so, a
    signaling-path MITM cannot read content (the payload is E2E-encrypted) but **can drop,
    reorder, or inject ICE candidates** to force a worse path, downgrade, or block connection
    setup. This is defeated only by the **P4-5 BindCert/DTLS-fingerprint binding**, which P4-1
    does not provide.

## Related crates

- `sh-crypto` — `DeviceIdentity` / `Fingerprint` (used as routing keys) and
  `peer_auth::IdentityProof` (the R-SIG-AUTH possession proof verified by the server)
- `sh-ice` (P4-2) — ICE/STUN candidate gathering; feeds `Candidate` envelopes through this crate
- `sh-transport` — QUIC/WebRTC session transport established after signaling completes
