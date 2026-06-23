# sh-transport

Minimal QUIC datagram transport for Streamhaul (Phase-0 LAN lab), built on
[`quinn`](https://crates.io/crates/quinn) 0.11 + tokio with the **ring** crypto backend.

It provides the concrete endpoints/connection used by the Phase-0 "hello pixels" slice. The
codec-agnostic `Transport`/`Channel` trait abstraction (LLD §2) is **not** here yet — that is task
**P1-1**. ICE/NAT traversal (P4) and the Streamhaul end-to-end crypto layer (P3/P4) also land later.

## API

- `ServerEndpoint::bind(addr, quinn::ServerConfig)` → `accept().await` → `Connection`
- `ClientEndpoint::bind(quinn::ClientConfig)` → `connect(addr, server_name).await` → `Connection`
- `Connection`: `send_datagram(Bytes)`, `read_datagram().await`, `max_datagram_size()`, `remote_address()`
- `TransportError` — typed errors wrapping quinn's connect/connection/datagram/io failures
- `WebRtcTransportBuilder` + `PinnedWebRtcTransport` (str0m backend, P4-5/P4-6):
  - `WebRtcTransportBuilder::new(rtc, local, remote).pin_remote_dtls(fp)` → `PinnedWebRtcTransport`
    — the **only** public path to a `Transport`-implementing WebRTC type. The builder applies
    `set_remote_fingerprint` **before** constructing the inner engine, making it structurally
    impossible to forget the DTLS pin (closes the P4-6 API footgun identified in code review).
  - `PinnedWebRtcTransport`: `drive(now)`, `handle_receive(...)`, `next_drive_at()`,
    `local_dtls_fingerprint()`, `remote_dtls_fingerprint()`, `rtt()`, `packet_loss()`.
  - The bare `WebRtcTransport` is `pub(crate)` — external callers cannot name or construct it.
  - See ADR-0014 (DTLS identity binding), ADR-0017 (structural pin enforcement), ADR-0018
    (async drive loop), and the `tests/dtls_identity_binding.rs` integration test (dev-only
    `sh-crypto` dep; no production coupling).
- **Async drive loop** (`sh_transport::driver`, ADR-0018):
  - `AsyncUdpSocket` — injectable async socket seam (`Send + Sync + 'static`).
  - `TokioUdpSocket::bind(addr)` — production wrapper around `tokio::net::UdpSocket`.
  - `SimNetwork` / `SimUdpSocket` — deterministic in-memory socket pair for tests; compatible
    with `tokio::time::pause()` because delivery uses mpsc channels, not the timer.
  - `spawn_webrtc_driver(transport, socket, std_base)` → `DriverHandle` — spawns the tokio
    task that runs the `drive()`/`handle_receive()` loop with `next_drive_at()` scheduling.
    Shutdown via `handle.shutdown().await`.

## ⚠️ `insecure-lan` feature (LAN lab only)

QUIC mandates TLS even on a LAN. The optional, **non-default** `insecure-lan` feature provides
`self_signed_server_config(..)` and `insecure_client_config(..)` that **skip certificate
verification** — strictly for loopback/LAN testing. They require an `InsecureLanLab` witness so every
call site is explicit, and a release build with this feature enabled is a **hard compile error**
(`#[cfg(all(feature = "insecure-lan", not(debug_assertions)))] compile_error!`). This whole path is
removed when real crypto lands (P3/P4).

```rust
# #[cfg(feature = "insecure-lan")]
# fn demo() -> Result<(), sh_transport::TransportError> {
use sh_transport::{InsecureLanLab, ServerEndpoint, ClientEndpoint};
let ack = InsecureLanLab::i_understand_this_skips_tls_verification();
let server = ServerEndpoint::bind("127.0.0.1:0".parse().unwrap(),
    sh_transport::self_signed_server_config(ack)?)?;
let client = ClientEndpoint::bind(sh_transport::insecure_client_config(ack)?)?;
# Ok(()) }
```

## Tests

Integration tests live in `tests/loopback.rs` and require the feature:

```bash
cargo test -p sh-transport --features insecure-lan
```

The async drive-loop tests live in `tests/webrtc_driver.rs` and run without any extra feature flag:

```bash
# Deterministic suite (sim sockets + tokio::time::pause, no real network):
cargo test -p sh-transport --test webrtc_driver

# Real UDP loopback proof (requires real OS sockets; excluded from default CI):
cargo test -p sh-transport --test webrtc_driver -- --include-ignored webrtc_driver_real_udp_loopback
```

The `webrtc_driver_sim_handshake_deterministic` test drives a full ICE+DTLS+SCTP+DataChannel
handshake between two in-memory `SimUdpSocket`s under `tokio::time::pause()`. It is the CI gate
for the async driver and is non-vacuous: the assertion fails if transmits are not actually pumped
between the two transports.
