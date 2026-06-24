# sh-wasm — SHP wire-parity bridge

WebAssembly bindings for the Streamhaul Protocol (SHP) codec.

## Purpose

`sh-wasm` compiles `sh-protocol` to `wasm32-unknown-unknown` and exposes the SHP wire
codec to browser JavaScript via `wasm-bindgen`.  A browser client built against this
crate speaks the **exact same wire format** as the native Rust host — there is no
secondary protocol or translation layer.

## What is exposed

| JS function / class | Direction | Description |
|---|---|---|
| `decode_common_header(bytes)` | host→browser | Decode the 9-byte SHP common header |
| `decode_video_header(bytes)` | host→browser | Decode the 12-byte video payload header |
| `encode_input_event(...)` | browser→host | Encode a 16-byte input event |
| `decode_input_event(bytes)` | — | Decode (for testing) |
| `encode_nack_feedback(...)` | browser→host | Encode a 25-byte NACK feedback message |
| `decode_nack_feedback(bytes)` | — | Decode (for testing) |
| `encode_caps(...)` | browser→host | Encode a 4-byte codec-capability payload |
| `decode_caps(bytes)` | host→browser | Decode a codec-capability payload |
| `encode_transport_caps(...)` | browser→host | Encode a 2-byte transport-capability payload |
| `decode_transport_caps(bytes)` | host→browser | Decode a transport-capability payload |
| `negotiate_transport(...)` | — | Run the symmetric QUIC>WebRTC negotiation |
| `encode_file_offer(...)` / `decode_file_offer(bytes)` | sender↔receiver | File-transfer offer framing (P7-2) |
| `encode_file_chunk_header(...)` / `decode_file_chunk_header(bytes)` | sender→receiver | 21-byte file chunk header (payload follows) |
| `encode_file_accept(...)` / `decode_file_accept(bytes)` | receiver→sender | Accept + resume-offset framing |
| `encode_file_complete(...)` / `decode_file_complete(bytes)` | receiver→sender | Integrity-result framing |

## Building

```bash
# Build a web-target package (produces pkg/ directory)
wasm-pack build --target web crates/sh-wasm

# Run wire-parity tests in Node (no browser required)
wasm-pack test --node crates/sh-wasm
```

## Wire parity

The `wasm-pack test --node` suite decodes the same byte vectors used by `sh-protocol`'s
native golden tests and asserts field-by-field equality.  It also runs
`native_encode` → `wasm_decode` round-trips to prove byte-for-byte parity.

## Deferred

The live browser client — `web-sys` `RTCPeerConnection`/`DataChannel` wiring, H.264 render,
input-capture to host, and the Chrome/FF/Safari compatibility matrix — is deferred to
P5-1 second half / P5-2 (requires a browser-equipped CI session).  See ADR-0019 and
Risk Register entries `R-BROWSER-INTEROP` and `R-BROWSER-MATRIX`.
