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
- `WebRtcTransport` (str0m backend): `local_dtls_fingerprint()`, `set_remote_dtls_fingerprint(fp)`,
  and `remote_dtls_fingerprint()` — the P4-5 DTLS-fingerprint pinning seam. The remote fingerprint
  is pinned from the identity-signed `BindCert` (via `sh-crypto`) **before** the DTLS handshake;
  str0m fail-closes any peer cert that does not match. See ADR-0014 and the
  `tests/dtls_identity_binding.rs` integration test (dev-only `sh-crypto` dep; no production
  coupling).

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
