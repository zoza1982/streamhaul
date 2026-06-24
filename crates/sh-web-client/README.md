# `sh-web-client`

Browser WebRTC client for Streamhaul Phase 5.  Orchestrates an `RTCPeerConnection` session and
enforces **DTLS-fingerprint identity pinning** — the same MITM defense the native transport
enforces (P4-5 / ADR-0014).  A signaling/SDP fingerprint swap is rejected *before* any DTLS
traffic flows.

**Target:** `wasm32-unknown-unknown` exclusively (it depends on `web-sys` `RTCPeerConnection`).
Excluded from the root workspace (`Cargo.toml` `exclude` list) with its own `[workspace]` isolation
table.  `cargo build --workspace` and the native CI three-OS matrix are unaffected.

## Security model

- **DTLS identity pin (the MITM defense).**  The peer's DTLS certificate fingerprint is committed
  inside the identity-authenticated Noise `BindCert` (delivered over the *encrypted* handshake, not
  the untrusted signaling channel).  Before applying a remote description, the client parses the
  remote SDP's `a=fingerprint:sha-256 …` and compares it byte-for-byte (constant-time) against the
  committed pin.  On a mismatch it aborts and never calls `setRemoteDescription` — so no DataChannel
  can ever open over an attacker's DTLS certificate.

- **SDP is hostile input.**  `parse_sdp_fingerprint` strictly decodes the colon-hex fingerprint to
  exactly 32 bytes and returns a `JsError` on any malformed input.  It never panics, never traps,
  never indexes out of bounds.

- **Panic-free boundary.**  Every fallible entry point returns `Result<_, JsValue>` (a catchable JS
  exception).  A wasm panic traps the linear-memory process and crashes the browser tab; this crate
  prevents that.  `unwrap`/`expect`/`panic` are denied in production paths by the clippy lint table.

- **Private keys stay in wasm.**  Key material is owned by `sh-crypto-wasm`; this crate never
  touches raw private bytes.  SHP frame payloads are opaque — never inspected here.

## Exposed API

| Export | Description |
|--------|-------------|
| `parse_sdp_fingerprint(sdp)` | Parse the SDP `a=fingerprint:sha-256` value to 32 bytes (hostile-input safe) |
| `verify_sdp_fingerprint_pin(sdp, pin)` | Constant-time check of the SDP fingerprint against a 32-byte pin (the MITM gate) |
| `set_panic_hook()` | Install `console_error_panic_hook` (development aid) |
| `SignalingChannel::new(send_fn)` | Wrap a JS callback used to transmit SDP/ICE to the peer |
| `WebClient::new(signaling)` | Create the client (builds the `RTCPeerConnection`) |
| `WebClient::set_dtls_pin(pin)` | Pin the peer's committed DTLS fingerprint from the verified handshake |
| `WebClient::local_dtls_fingerprint()` | Extract the local SDP fingerprint to commit in the `BindCert` |
| `WebClient::create_offer()` | `createOffer` + `setLocalDescription`; returns the offer SDP |
| `WebClient::connect_as_offerer(answer)` | Pin-check the answer, then `setRemoteDescription` |
| `WebClient::connect_as_answerer(offer)` | Pin-check the offer, then produce a pinned answer (the only answerer entry point) |
| `WebClient::add_ice_candidate(c)` | Add a remote ICE candidate received via signaling |
| `WebClient::send_frame(frame)` | Send an opaque SHP frame over the DataChannel |
| `WebClient::on_frame(cb)` | Register a callback for received SHP frames |
| `WebClient::on_data_channel(cb)` | (Answerer) capture the offerer's inbound DataChannel |
| `WebClient::on_ice_candidate(cb)` | Register a callback for locally-gathered ICE candidates |

## The DTLS-pin flow

```text
1. createOffer/createAnswer → setLocalDescription → gather ICE
2. local fp  = parse_sdp_fingerprint(localDescription.sdp)   // commit in BindCert
3. run Noise XK handshake (sh-crypto-wasm), committing local fp
4. pin = outcome.require_dtls_pin()                          // peer's committed fp
5. verify_sdp_fingerprint_pin(remoteSdp, pin)  --MISMATCH--> ABORT (no setRemoteDescription)
6.                                             --MATCH-----> setRemoteDescription → ICE → DataChannel
```

## Building & testing

```sh
# Prerequisites (once)
rustup target add wasm32-unknown-unknown
cargo install wasm-pack            # 0.13.1 pinned in CI
# headless Firefox + geckodriver on $PATH

# Run the suite (11 SDP-parser unit tests + 7 WebRTC e2e tests) in headless Firefox.
wasm-pack test --headless --firefox crates/sh-web-client

# Build the wasm binary for bundler integration.
wasm-pack build --target web crates/sh-web-client     # → crates/sh-web-client/pkg/

# Lint (panic-ban, wasm target).
cargo clippy --target wasm32-unknown-unknown --manifest-path crates/sh-web-client/Cargo.toml -- -D warnings
```

`tests/browser_e2e.rs` (headless Firefox):

```
test tests::* (11 SDP-parser unit tests)             ... ok   (parse/decode + length cap + valueless-line skip)
test test_parse_sdp_fingerprint                       ... ok
test test_verify_sdp_fingerprint_pin_mismatch         ... ok
test test_browser_loopback_happy_path                 ... ok   (2 PCs, real XK + DTLS pin, SHP frame round-trip)
test test_mitm_rejection_non_vacuous                  ... ok   (control verifies, tamper rejected)
test test_mitm_rejection_in_connection                ... ok   (offerer: connect aborts on tamper, honest passes)
test test_mitm_rejection_answerer_path                ... ok   (answerer: connect aborts on tamper, honest passes)
test test_connect_without_pin_is_rejected             ... ok   (fail-closed: no pin → no setRemoteDescription)

test result: ok. 18 passed; 0 failed
```

`webdriver.json` enables `media.peerconnection.ice.loopback` so two in-page `RTCPeerConnection`s
connect over loopback host candidates without STUN/TURN.

## Architecture decision

See [ADR-0021](../../docs/adr/0021-browser-webrtc-client.md) for the rationale (Rust/wasm
orchestration, the browser DTLS-pin mechanism, headless-Firefox e2e) and deferred items
(browser↔native interop R-BROWSER-INTEROP, TS viewer UI P5-2, Chrome/Safari matrix
R-BROWSER-MATRIX).
