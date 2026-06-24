# ADR-0023: Browser↔Native WebRTC Interop (P5-3)

**Status:** Accepted  
**Date:** 2026-06-24  
**Deciders:** Engineering team  
**Relates to:** P5-3, ADR-0013 (WebRTC backend), ADR-0014 (DTLS binding), ADR-0017 (PinnedWebRtcTransport), ADR-0021 (browser WebRTC client), R-BROWSER-INTEROP

---

## Context

Phase 4 delivered the `str0m`-backed `PinnedWebRtcTransport` (ADR-0013/0017) on the native side
and the `sh-web-client` wasm crate (ADR-0021) on the browser side. P5-3 closes the remaining gap:
proving that a real Firefox `RTCPeerConnection` can negotiate a DTLS DataChannel with the native
str0m engine, exchange frames, and receive an echo — all routed through the zero-knowledge
`sh-signaling` relay.

The key open item was the absence of an SDP offer/answer bridge. The existing
`WebRtcTransportBuilder` API requires a remote DTLS fingerprint (`pin_remote_dtls`) and addresses
(`local`, `remote`), but there was no public pathway to accept a browser-generated SDP offer and
produce an SDP answer — the native side had no equivalent of `RTCPeerConnection.setRemoteDescription`.

---

## Decision

### 1. `SdpBridgeBuilder` in `sh-transport`

A new type `SdpBridgeBuilder` (backed by a `str0m::Rtc`) provides:

- `accept_browser_offer(offer_sdp, local_addr, remote_addr) -> Result<SdpBridgeResult, SdpBridgeError>`

  which:
  1. Bounds the SDP at 64 KiB before any parsing (hostile-input guard).
  2. Parses the `a=fingerprint:sha-256` line with bounded line scanning (≤10 000 lines, ≤200
     chars/line) and group-level hex validation (exactly 2 chars per group, exactly 32 bytes total).
  3. Calls `str0m::change::SdpOffer::from_sdp_string` + `rtc.sdp_api().accept_offer()`.
  4. Pins the remote fingerprint via `WebRtcTransportBuilder::pin_remote_dtls()` before returning
     the transport — preserving the structural DTLS-pin invariant from ADR-0017.

- `add_remote_candidate(&mut self, candidate_sdp)` — trickle ICE before offer acceptance.

`SdpBridgeResult` bundles `answer_sdp`, `local_dtls_fingerprint`, and the fully-pinned
`PinnedWebRtcTransport`. The type is publicly exported from `sh-transport`.

`PinnedWebRtcTransport::add_remote_candidate(candidate_sdp)` is added for post-offer trickle ICE.

### 2. `streamhaul-signaling` binary

A thin wrapper around `SignalingServer::bind(addr, Arc::new(AcceptAll))` for local/integration
use (gated behind `insecure-lan`). Prints `SIGNALING_READY addr=…` on stdout so process
spawners can wait for readiness.

### 3. `streamhaul-webrtc-host` binary

A single-session native answerer that:
1. Creates `Rtc`, extracts the local DTLS fingerprint, prints `HOST_DTLS_FP=<hex>`.
2. Connects to `streamhaul-signaling` via `SignalingClient::connect` (insecure-lan path).
3. Waits for a `MessageKind::Offer` envelope from the browser peer.
4. Calls `SdpBridgeBuilder::new(rtc).accept_browser_offer(…)` to get the `SdpBridgeResult`.
5. Sends the `MessageKind::Answer` envelope back.
6. Spawns the tokio drive loop via `spawn_webrtc_driver` + `TokioUdpSocket`.
7. Pumps trickle ICE `Candidate` envelopes to `transport.add_remote_candidate`.
8. Accepts the first DataChannel, echoes the received frame, sends an SHP echo frame.

### 4. TypeScript signaling envelope module

`clients/web/src/signaling/envelope.ts` provides `encodeEnvelope` / `decodeEnvelope` matching
the `sh-signaling` wire format exactly (big-endian, 149-byte header). This is the browser side's
equivalent of `sh_signaling::envelope::encode/decode`.

### 5. Playwright e2e test + HTML page

`clients/web/e2e/browser-native.{ts,html,spec.ts}` drive an in-browser RTCPeerConnection through
the full signaling + DTLS DataChannel flow with the native host. The spec is guarded by
`BROWSER_NATIVE_E2E=1` so it only runs in the dedicated CI job.

### 6. CI job `browser-native-e2e`

Builds the native binaries, installs Firefox + geckodriver (pinned ADR-0021/0022 versions), and
runs `browser-native.spec.ts` with `BROWSER_NATIVE_E2E=1`. Linux-only for now; Windows/macOS
browser↔native CI is deferred (R-BROWSER-MATRIX).

---

## Security analysis

### DTLS fingerprint pin invariant (ADR-0017) is preserved

`SdpBridgeBuilder::accept_browser_offer` always calls `pin_remote_dtls(parsed_fp)` before
returning the transport. The parsed `fp` is extracted from the SDP before `accept_offer` is
called, so the pin set by `accept_offer` internally and the explicit `set_remote_fingerprint`
call from `pin_remote_dtls` set the same value. str0m fail-closes any mismatch.

### SDP parsing is hostile-input bounded

- 64 KiB size cap checked before any character-level scanning.
- Line count capped at 10 000; individual line length capped at 200 bytes.
- Per-hex-group length enforced to exactly 2 characters.
- Byte count of decoded fingerprint enforced to exactly 32 (SHA-256).
- Any parse error surfaces as a typed `SdpBridgeError` variant; no panic or silent fallback.

### `insecure-lan` fence retained

Both new binaries use `features = ["insecure-lan"]` and will trigger the existing
`compile_error!` if compiled `--release` — matching the existing fence in `sh-signaling`.

### Zero-knowledge relay invariant is not weakened

`streamhaul-signaling` uses the same `SignalingServer` codebase and routes only on
`(session_id, to_fp)`. The SDP and ICE payloads are opaque to the relay.

---

## Alternatives considered

### A. Browser creates the offer; native uses `setRemoteDescription`-equivalent only

Chosen (implemented). Cleanest flow: browser is always the offerer in a browser↔native session
(matching the `sh-web-client` architecture from ADR-0021). The native side is always the answerer.

### B. Native creates the offer; browser answers

Would require `rtc.sdp_api().create_offer()` on the native side, adding complexity.
Deferred — not needed for the initial DataChannel interop proof.

### C. Skip SDP; connect via ICE restart / raw DTLS

Not compatible with `RTCPeerConnection` semantics (browsers require SDP). Rejected.

---

## Interop quirks discovered during live testing

The following quirks were discovered when connecting a real Firefox to a real native str0m host
and are recorded here so future implementors are not surprised.

### 1. Firefox mDNS candidate obfuscation

By default, Firefox obfuscates local IP addresses in ICE candidates by replacing them with
`.local` mDNS hostnames (e.g. `candidate:… 127.0.0.1 →  abc12345.local`). str0m has no mDNS
resolver and cannot pair `.local` candidates. Fix: set
`media.peerconnection.ice.obfuscate_host_addresses: false` in Firefox prefs (done in
`playwright.config.ts`). This is the primary bug that prevented ICE connectivity pre-fix.

### 2. `addIceCandidate` requires `sdpMid` in Firefox

Firefox throws `"Cannot add a candidate without specifying either sdpMid or sdpMLineIndex"` if
`addIceCandidate` is called without `sdpMid` or `sdpMLineIndex`. Chrome is lenient and accepts
bare candidate strings. The fix: always pass `{ candidate: str, sdpMid: "0", sdpMLineIndex: 0 }`
for the single `m=application` DataChannel section (index 0 / mid "0").

### 3. DataChannel `binaryType` defaults to `"blob"` in Firefox

Firefox defaults `RTCDataChannel.binaryType = "blob"`. Receiving an ArrayBuffer from str0m would
then trigger `dc.onmessage` with a `Blob`, not an `ArrayBuffer`, and the handler's `instanceof
ArrayBuffer` check would fail. Fix: set `dc.binaryType = "arraybuffer"` immediately after
`createDataChannel` (or `ondatachannel`).

### 4. Local ICE candidate must be trickled (not in answer SDP)

`add_local_host_candidate` is called AFTER `accept_browser_offer`, so the local UDP address is
not present in the SDP answer. The browser must learn it via a trickle `Candidate` signaling
message. `add_local_host_candidate` now returns the candidate SDP string so the host can trickle
it. Without trickling, the browser has no path to reach the native host and ICE stalls.

### 5. Firefox may send an empty-string end-of-candidates trickle

Firefox occasionally emits a trickle ICE candidate with an empty string (`""`) to signal
end-of-candidates (in addition to the `onicecandidate({ candidate: null })` path). The native host's
`pump_candidates` receives this as a `Candidate` envelope with an empty payload, which
`Candidate::from_sdp_string("")` rejects with `missing 'candidate:' prefix`. This is harmless and
logged at `WARN` level; the proper EOC is handled via `EndOfCandidates` envelope anyway.

### 6. Host must delay exit to allow driver to flush outbound queue

After `channel.send()` returns `Ok`, the echo bytes are written to str0m's SCTP buffer and queued
in `inner.outbound` by `drain_output()`. They are NOT yet transmitted over UDP. The `WebRtcDriver`
task dispatches outbound datagrams on its own timer cycle (next poll, typically within 50 ms). If
the host exits immediately after `run_data_channel` completes, the tokio runtime shuts down the
driver task before it can transmit the queued echo, and the browser never receives it.

Fix: add a 500 ms `tokio::time::sleep` after `accept_task.await` in `main` to give the driver
time to drain the outbound queue. This is a test-binary workaround; a production server would
never exit after one exchange and this would be naturally handled.

---

## Consequences

- `SdpBridgeBuilder`, `SdpBridgeError`, `SdpBridgeResult` are added to `sh-transport`'s public API.
- `PinnedWebRtcTransport::add_remote_candidate` is added for trickle ICE.
- Two new workspace members: `bins/streamhaul-signaling`, `bins/streamhaul-webrtc-host`.
- `clients/web/src/signaling/envelope.ts` is added to the web client.
- `anyhow = "1"` is added to workspace dependencies (used only by binary crates).
- CI gains a `browser-native-e2e` job (Linux, Firefox + geckodriver pinned).
- R-BROWSER-INTEROP partially closed (DataChannel-only path, browser as offerer, Linux CI).
  Full closure (media tracks, Chrome/Safari, H.264 decode) remains deferred per R-BROWSER-MATRIX.

---

## Addendum — Stage 2: identity-bound DTLS pin (the headline MITM defense)

**Status:** Accepted · **Date:** 2026-06-24 · **Relates to:** P5-3 Stage 2, ADR-0014 (DTLS↔identity
binding), ADR-0017 (PinnedWebRtcTransport), ADR-0020/0021 (browser crypto + WebRTC client), ADR-0016
(R-SIG-AUTH).

### Context

Stage 1 (above) pinned the host's DTLS fingerprint **from the SDP `a=fingerprint`** — transport
interop only, NOT identity-bound. A signaling/SDP man-in-the-middle could swap the fingerprint
and the browser would happily pin (and DTLS-verify against) the attacker's certificate. Stage 2
makes the live browser↔native session **MITM-protected** by sourcing the DTLS pin from the
**identity-signed Noise `BindCert`** (the P4-5 defense), exactly as the native↔native transport does.

### Decision

#### 1. Noise XK over signaling — message ordering

A new opaque envelope kind `MessageKind::Noise = 8` carries the peer-to-peer Noise transcript. The
relay routes it on `(session_id, to_fp)` **only** — it never inspects the payload (zero-knowledge
invariant preserved, identical treatment to `Offer`/`Answer`). The payload is `[sub_type: u8] ||
body`:

| sub_type | name | direction | body |
|----------|------|-----------|------|
| `0x00` | `HELLO` | browser → host | empty — lets the host learn the browser's `from_fp` |
| `0x01` | `HOST_STATIC_PUB` | host → browser | host's 32-byte X25519 static **public** key |
| `0x02` | `MSG` | either | one opaque Noise XK handshake message (carries the BindCert) |

```text
B → H : Noise(HELLO, [])            # host learns the browser's from_fp (the reply address)
H → B : Noise(HOST_STATIC_PUB, X)   # host advertises its X25519 static pub
B → H : Noise(MSG, msg0)            # XK message 1 (commits browser DTLS fp in BindCert)
H → B : Noise(MSG, msg1)            # XK message 2 (commits host DTLS fp in BindCert)
B → H : Noise(MSG, msg2)            # XK message 3
both  : complete → extract the OTHER's committed DTLS fingerprint
```

The browser is the **XK initiator** (matching the `WebClient` offerer role; the
`sh-crypto-wasm` bridge generates the browser's X25519 static internally). XK requires the
initiator to know the responder's static up front, so the host (responder) publishes its static
pub first — this is *why* `HOST_STATIC_PUB` precedes the handshake messages.

#### 2. Each peer commits its own DTLS fingerprint; pins the peer's committed value (NOT the SDP)

- **Browser** commits its local DTLS `a=fingerprint` (`WebClient.local_dtls_fingerprint()`) in its
  BindCert. After completion it extracts the **host's** committed fingerprint
  (`WasmHandshakeOutcome.require_dtls_pin()`) → `WebClient.set_dtls_pin(pin)` →
  `connect_as_offerer(answerSdp)` runs the **fail-closed** `guard_remote_sdp` /
  `verify_sdp_fingerprint_pin` against the host **answer** SDP **before** `setRemoteDescription`. A
  swapped answer fingerprint aborts the connection — no DTLS over the attacker cert.
- **Native host** commits its own DTLS fingerprint and extracts the **browser's** committed
  fingerprint (`HandshakeOutcome::require_webrtc_dtls_pin()`), then pins it via the new
  `SdpBridgeBuilder::accept_browser_offer_with_pin(offer_sdp, bindcert_fp, local, remote)`. This
  variant **ignores the offer's SDP `a=fingerprint`** and pins the identity-bound value via
  `WebRtcTransportBuilder::pin_remote_dtls` (ADR-0017 invariant preserved). str0m fail-closes the
  DTLS handshake unless the browser's genuine certificate hashes to the BindCert-committed value, so
  a relay that rewrote the offer fingerprint is defeated (it cannot present the genuine cert).

#### 3. TOFU first pairing

Stage 2 first pairing uses `complete_for_first_pairing` (browser) and a native `TrustAllKeystore`
in `streamhaul-webrtc-host` (mirroring the wasm one — `NoiseHandshake::complete` only calls
`is_trusted` on the supplied keystore). This proves the DTLS↔identity binding; **persistent TOFU
pinning across reconnects is deferred**.

#### 4. ICE quirk: `WebClient.add_ice_candidate` now sets `sdpMid`/`sdpMLineIndex`

Firefox rejects a bare remote candidate (ADR-0023 quirk #2). `WebClient.add_ice_candidate` now sets
`sdpMid = "0"` / `sdpMLineIndex = 0` (the single `m=application` section) and treats an empty
candidate string as an end-of-candidates marker (ignored). The browser also sends its offer
**before** trickling candidates, because the host's `receive_offer` loop drops non-`Offer`
envelopes — candidates sent earlier would be lost, leaving the native peer with no remote candidate
(ICE failure).

### Security analysis

- **Identity binding ≠ signaling auth.** The DTLS↔identity binding is the Noise/BindCert layer and
  holds regardless of the signaling authenticator. The e2e stays `insecure-lan` / `AcceptAll`
  (empty proof) — this is honest: it proves the headline MITM defense without conflating it with
  R-SIG-AUTH. Wiring the production `IdentityProofAuthenticator` into the live browser↔native path
  is deferred (R-SIG-AUTH-LIVE).
- **Non-vacuous MITM proof.** The e2e MITM arm swaps the host's answer SDP fingerprint to a
  different but well-formed value *after* the BindCert committed the real one; the fail-closed pin
  gate rejects it. The happy-path arm is the honest control (the same setup connects when
  untampered, and asserts `pinUsedHex === host_fp` — the pin equals the BindCert commit, not just
  any SDP value). This is the browser↔native equivalent of the native `dtls_identity_binding` test.
- **Zero-knowledge preserved.** `MessageKind::Noise` is routed only by `(session_id, to_fp)`; the
  relay never parses the Noise/BindCert payload.

### Deferrals (honest)

- **R-SIG-AUTH on the live signaling path** (R-SIG-AUTH-LIVE) — separable from the identity binding.
- **Persistent TOFU pinning across reconnects** — Stage 2 uses first-pairing trust-all.
- **Chrome/Safari** (R-BROWSER-MATRIX — Safari impossible on Linux), **coturn** (R-COTURN-DEPLOY),
  **media / H.264-over-wire from a real native capture** (live-native media/UI path).
