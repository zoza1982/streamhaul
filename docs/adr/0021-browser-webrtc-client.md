# ADR-0021: Browser WebRTC Client (`sh-web-client`, P5-1c)

- **Status:** Accepted
- **Date:** 2026-06-23
- **Deciders:** security-engineer, network-engineer, rust-staff-engineer (P5 browser-client slice)
- **Builds on:** ADR-0014 (DTLS↔device-identity binding), ADR-0017 (pinned WebRTC transport
  builder), ADR-0019 (`sh-wasm` wire-parity bridge), ADR-0020 (`sh-crypto-wasm` crypto bridge).

## Context

Phase 5 needs a **browser** WebRTC client with the *same* DTLS-fingerprint MITM defense the native
transport enforces (P4-5 / ADR-0014).  On native, str0m fail-closes any DTLS certificate whose
RFC-8122 fingerprint does not equal the identity-signed commitment delivered inside the Noise
`BindCert`.  The browser cannot pin a fingerprint on the DTLS stack directly — `RTCPeerConnection`
owns DTLS and exposes the peer's fingerprint only through the SDP `a=fingerprint` attribute, which
arrives over the **untrusted signaling channel**.  A signaling/SDP fingerprint swap is therefore
the single most important MITM vector on the browser WebRTC transport, exactly as on native.

The crypto (`sh-crypto-wasm`, ADR-0020) and the SHP codec (`sh-wasm`, ADR-0019) already compile to
wasm and run the full identity-bound Noise XK/IK handshake in the browser.  What was missing is the
orchestration layer that (a) drives `RTCPeerConnection`, (b) extracts the local DTLS fingerprint
from the local SDP to commit it in the `BindCert`, and (c) **checks the remote SDP fingerprint
against the committed pin before `setRemoteDescription`**.

The environment now has headless Firefox 152 + geckodriver 0.37 + `wasm-pack` 0.13.1, unblocking
the live `RTCPeerConnection` e2e that was deferred from P5-1 (R-BROWSER-INTEROP).

## Decision

### 1. Rust/wasm orchestration (minimize the TS attack surface)

`sh-web-client` is a new `crate-type = ["cdylib", "rlib"]` crate, workspace-excluded (own
`[workspace]` table + root `exclude` list), depending on the parent wasm bridges (`sh-wasm`,
`sh-crypto-wasm`) plus `web-sys` / `wasm-bindgen-futures` / `js-sys`.  The security-critical glue —
SDP fingerprint extraction, constant-time pin comparison, handshake sequencing — lives in audited,
panic-free Rust, **not** in untyped TypeScript.  The TS viewer/control UI (P5-2) sits *above* this
crate and never re-implements the pin check.

### 2. The browser DTLS-pin mechanism (the MITM defense)

The flow, with the pin enforced **before** the remote description is ever applied:

1. Create `RTCPeerConnection`, `createOffer`/`createAnswer`, `setLocalDescription`, gather ICE.
2. Parse the **local** SDP `a=fingerprint:sha-256 …` → 32 bytes (`parse_sdp_fingerprint`).  This is
   the RFC-8122 whole-certificate SHA-256 — byte-identical to what the Noise `BindCert` commits and
   what `WasmHandshakeOutcome::require_dtls_pin` returns (ADR-0014 §2).
3. Run the identity-bound Noise XK handshake (`sh-crypto-wasm`), committing the local DTLS
   fingerprint in the `BindCert`.
4. Complete the handshake (TOFU first-pairing) → peer identity + `require_dtls_pin()` (the peer's
   committed 32-byte DTLS fingerprint).  A missing/`ALG=NONE` binding is a hard abort
   (anti-downgrade gate, inherited from ADR-0020 §7).
5. **Before `setRemoteDescription`**, parse the remote SDP's `a=fingerprint` and compare it
   byte-for-byte, constant-time, against the pin (`verify_sdp_fingerprint_pin`).  On a mismatch,
   **abort** — `WebClient::connect_as_offerer` / `connect_as_answerer` return a `JsError` and never
   call `setRemoteDescription`, so no DTLS traffic ever flows over the attacker's cert.
6. On a match, apply the remote description, finish ICE, open the DataChannel; SHP frames are
   opaque bytes over the channel.

The relayed SDP fingerprint is advisory; the **identity-signed commitment** is authoritative —
identical to the native posture.

### 3. SDP parsing treats the wire as hostile

`parse_sdp_fingerprint` scans for the first `a=fingerprint:sha-256` line (case-insensitive on the
algorithm token), splits algorithm from value, and strictly decodes the colon-separated hex into
exactly 32 bytes.  Malformed input (missing line, wrong algorithm, wrong group length, non-hex
digit, wrong byte count) returns a `JsError` — it never panics, never traps, never indexes out of
bounds.  `verify_sdp_fingerprint_pin` returns one opaque error for parse-failure *and* mismatch so a
caller cannot distinguish them, and the byte comparison is constant-time.

### 4. Panic-free boundary, no `unwrap/expect/panic` in production

A wasm panic traps the linear-memory process and crashes the browser tab.  Every fallible entry
point returns `Result<_, JsValue>`.  `#![deny(missing_docs)]` plus the workspace clippy panic-ban
(`unwrap_used`/`expect_used`/`panic` denied) are mirrored in this crate's `Cargo.toml`.  Private
keys never leave wasm (owned by `sh-crypto-wasm`); SHP payloads are never inspected.

### 5. Headless Firefox, not Node, for the e2e

Node has no `RTCPeerConnection`, so the integration suite (`tests/browser_e2e.rs`) runs under
`wasm-pack test --headless --firefox`.  A `webdriver.json` enables `media.peerconnection.ice.loopback`
so two in-page `RTCPeerConnection`s connect over loopback host candidates with no STUN/TURN.  The
inline SDP-parser unit tests are also configured `run_in_browser` so a single Firefox invocation
covers both suites.

CI pins **geckodriver `v0.37.0`** (the version proven on the local Firefox 152 toolchain) in the
`browser-webrtc-client` job (`.github/workflows/ci.yml`); `wasm-pack` is pinned to `0.13.1`.

The XK handshake in the e2e is driven via `sh-crypto` directly (a **dev-dependency only**, no
production coupling — the same pattern as the native `sh-transport/tests/dtls_identity_binding.rs`).
XK requires the initiator to know the responder's X25519 static up front; the `sh-crypto-wasm`
bridge generates that static internally and does not expose it, so a pure-bridge XK in a single page
is not expressible.  The pins the driver yields are the genuine
`HandshakeOutcome::require_webrtc_dtls_pin()` values — real identity-bound commitments.

### 6. Non-vacuous MITM test

`test_mitm_rejection_non_vacuous` is the headline security test.  It commits the offerer's real
fingerprint in the `BindCert`, then:
- **Control:** the original, untampered SDP verifies `Ok` against the committed pin (proves the
  setup is sound).
- **Attack:** a tampered SDP (first fingerprint hex group flipped, still well-formed and 32 bytes
  but different) is **rejected**.

Because the only difference between the two assertions is the tampered byte, the rejection is
provably caused by the mismatch, not by an unrelated setup failure — mirroring the native test's
`mitm_without_pinning_would_connect_control` discipline.  `test_mitm_rejection_in_connection`
extends this to the full `WebClient::connect_as_offerer` path: a tampered answer aborts before
`setRemoteDescription`, while the honest answer passes the gate and applies.

## Consequences

- **Positive:**
  - The browser enforces the same identity-bound DTLS MITM defense as native: a signaling/SDP
    fingerprint swap is rejected before any DTLS traffic flows.  Proven by a non-vacuous e2e in a
    real browser.
  - Security-critical logic stays in audited, panic-free Rust; the TS layer (P5-2) cannot bypass
    the pin check.
  - Zero production cross-crate coupling to `sh-crypto` (dev-dependency only for the e2e driver).
  - Live `RTCPeerConnection` ↔ DataChannel loopback now runs in CI (closes the P5-1 `R-BROWSER-INTEROP`
    gap for the *intra-browser* case).
- **Negative / trade-offs:**
  - The e2e drives the XK handshake via `sh-crypto` directly because the `sh-crypto-wasm` bridge
    does not surface the responder's X25519 static.  Exposing a `peer_noise_static_pub` accessor on
    `WasmHandshakeOutcome` (referenced aspirationally in the bridge docs) would let the e2e use the
    bridge end-to-end; tracked under R-BROWSER-CRYPTO-LIVE.
  - Headless Firefox loopback needs `media.peerconnection.ice.loopback`; the `webdriver.json` is
    Firefox-specific (Chrome/Safari prefs differ — R-BROWSER-MATRIX).
- **Follow-ups:**
  - **R-BROWSER-INTEROP (browser↔native):** the e2e here is browser↔browser in one page.  A live
    browser `RTCPeerConnection` ↔ *native* str0m DataChannel over `sh-signaling` is still deferred.
  - **P5-2:** TS viewer/control UI, H.264 decode + `<video>` render, input capture → `encode_input_event`.
  - **R-BROWSER-MATRIX:** Chrome / Firefox / Safari (+ WKWebView) matrix.

## Alternatives considered

- **Implement the pin check in TypeScript.** Rejected: it is the security-critical control; keeping
  it in untyped JS widens the attack surface and risks divergence from the native rule.  Rust/wasm
  keeps it inside the audited, constant-time, panic-free surface.
- **Trust the SDP fingerprint directly (no signed commitment).** Rejected — identical to ADR-0014's
  rejection: the SDP traverses the untrusted signaling server; a swap there is undetectable without
  the identity-signed commitment.
- **Set the DTLS fingerprint on the DTLS stack like native str0m.** Not possible: the browser
  `RTCPeerConnection` owns DTLS and exposes no fingerprint-pinning API.  Checking the SDP
  `a=fingerprint` against the committed pin before `setRemoteDescription` is the browser-equivalent
  fail-closed gate.
- **Run the e2e in Node.** Rejected: Node has no `RTCPeerConnection`.  Headless Firefox is required
  for any live WebRTC test.
