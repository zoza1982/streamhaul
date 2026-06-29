# ADR 0032: Live WebRTC host — real X11 capture + OpenH264 over the browser DataChannel

- **Status:** Accepted
- **Date:** 2026-06-29
- **Deciders:** rust-staff-engineer, realtime-systems-engineer (consulted), security-engineer (consulted)
- **Builds on:** ADR-0028/0029 (OpenH264 codec + workspace isolation), ADR-0030 (EvenDimCapturer + preview host), ADR-0031 (baked-clip WebRTC host + SHP framing)

## Context

ADR-0031 proved the browser↔host video *transport* end to end (baked H.264 clip → DataChannel → WebCodecs decode in CI). The content was a fixed fixture; the host had no real screen capture or live encoder. This ADR adds an excluded binary that streams the *live* X11 screen as OpenH264 H.264 over the same DataChannel path.

Two constraints from prior ADRs govern the design:

1. **Workspace isolation (ADR-0028/0029):** anything linking OpenH264 must be workspace-EXCLUDED. `cargo build/clippy/test --workspace --all-features` must never compile the vendored C, and the default OSS build must link no H.264 encoder.
2. **SHP 64 KB cap (ADR-0031):** `CommonHeader.payload_len` is a `u16`; a single SHP frame cannot exceed 65 535 bytes. Full-screen keyframes easily exceed this. SHP fragmentation (the correct fix) is a deferred follow-up; this ADR uses a downscale adapter as a practical workaround.

## Decision

### 1. `streamhaul-webrtc-host` becomes lib + bin

The existing connection logic (Noise XK responder, SDP offer/answer, ICE, DataChannel accept) is extracted from `src/main.rs` into `src/lib.rs`. A new `VideoFrameSource` trait parameterises the video loop:

```rust
pub trait VideoFrameSource: Send {
    fn next_frame(&mut self) -> anyhow::Result<(FrameType, Vec<u8>)>;
}
```

The streaming loop in the lib calls `source.next_frame()` each tick instead of indexing the baked array directly. `BakedFrameSource` (in the lib) wraps the fixture and is used by the workspace binary (behavior unchanged). `HostConfig` + `StreamMode` + `run_webrtc_host(config, mode, on_fingerprint)` are the public entry point. The third parameter is a `FnOnce(&str)` callback invoked with the host's 64-hex DTLS fingerprint the moment it is derived (before any network I/O): the caller publishes it (the bins `println!("HOST_DTLS_FP=…")` + flush), keeping the **library itself I/O-free** rather than hard-coding a stdout print into the reusable connection path.

The trait also has a defaulted `request_keyframe()` (no-op): the streamer calls it when it must DROP a frame so a source whose keyframe was lost can re-arm an IDR (see §4); `BakedFrameSource` keeps the no-op since its frames are always in-cap.

The workspace binary (`main.rs`) becomes thin: parse args → build `BakedFrameSource` → call `run_webrtc_host`. The existing five unit tests and all baked-fixture behavior are preserved; the `browser-native` Playwright e2e is unaffected.

### 2. `bins/streamhaul-webrtc-preview` (workspace-EXCLUDED)

A new excluded crate with a lib and binary:

- **`DownscaleCapturer<C>`** (`ScreenCapturer` adapter): integer nearest-neighbor BGRA downscale, factor = `ceil(width / max_width)` (default `--max-width 960`). Keeps encoded keyframes under the 64 KB cap. The capture chain is: `X11ScreenCapturer → DownscaleCapturer → EvenDimCapturer → LiveFrameSource`.
- **`LiveFrameSource<C: ScreenCapturer>`** (implements `VideoFrameSource`): each `next_frame` call captures a frame, encodes it with `OpenH264Encoder::with_config`, and returns `(FrameType, Annex-B)`. The first frame is forced IDR (so the browser decoder initialises). If the encoder skips (`Ok(None)`), the next frame is captured and retried.
- **Binary `streamhaul-webrtc-preview`**: parses `--signaling-url --session-id --bind --max-width --bitrate-kbps --fps --frames`; on Linux builds the capture chain and calls `streamhaul_webrtc_host::run_webrtc_host(config, StreamMode::Video{...})`; on non-Linux errors cleanly. Prints `HOST_DTLS_FP=` via the lib path (unchanged).

### 3. CI

A new `webrtc-preview` CI job (Linux): installs nasm, `cargo audit`, fmt-check, clippy `-D warnings`, and `cargo test` — all via `--manifest-path bins/streamhaul-webrtc-preview/Cargo.toml`. The deterministic test uses `SyntheticCapturer` (no display required), so it runs anywhere.

### 4. 64 KB constraint and downscale approach

A full-screen IDR (e.g. 1920×1080 at even mild quality) encodes to several hundred KB — well over the 16-bit `payload_len` cap. Downscaling to ≤ 960 px wide (factor 2 for 1080p) reduces the IDR to ~20–60 KB in practice. The trade-off is lower resolution in the preview; once SHP fragmentation lands the downscaler can be removed or made opt-in.

`DownscaleCapturer` does integer nearest-neighbor sampling (no interpolation): fast, simple, and correct for the preview use case. The factor is computed as `ceil(width / max_width)` so the output is always ≤ `max_width` wide.

The factor bounds **width** only, so it is a heuristic, not a guarantee, that an encoded frame fits 64 KB (a high-entropy or portrait IDR can still overflow). The streamer's safety net is therefore **drop + re-arm**: an oversize frame is dropped with a `warn!`, and `source.request_keyframe()` is called so the *next* frame is forced back to an IDR. Without the re-arm, dropping the IDR (whose keyframe flag the encoder has already cleared) would leave the stream with only P-frames the receiver can't decode; with it, the stream self-heals once a frame fits. (SHP fragmentation is the permanent fix.)

## Consequences

- **Positive:** a locally-runnable `streamhaul-webrtc-preview` binary streams the *live* X11 screen as real H.264 to the browser tab — the ADR-0031 fixture path is now complemented by a live path. CI verifies the encode+SHP-frame pipeline deterministically (no display required). Both ADR-0028 isolation invariants are preserved (workspace build: no OpenH264; root Cargo.lock: no openh264 entry).
- **Security (bonus, from the extraction):** the per-message `recv_bounded` signaling timeout was replaced by a single `tokio::time::timeout` wrapping each handshake-receive *filter loop*, so the hello/offer phase has a fixed total budget — a hostile peer can no longer reset the deadline by injecting junk just before each expiry. The identity-bound Noise/BindCert/DTLS-pin path itself was extracted byte-faithfully (security-engineer verified line-by-line); the new `pub` API cannot reach the channel or stream without completing the pinned handshake.
- **Negative / trade-offs:** the downscale loses resolution (deferred: SHP fragmentation); `ScreenCapturer::next_frame` blocks in the async loop (acceptable for a dev tool; production would use `spawn_blocking`); no periodic keyframe or loss-recovery (deferred: same as ADR-0030/0031 follow-ups). Only Linux/X11 is supported (the same `sh-platform-linux` constraint as ADR-0030).
- **Follow-ups:** SHP fragmentation (remove the downscale workaround); periodic IDR; full browser↔live-host Playwright e2e with `streamhaul-webrtc-preview`; input back-channel; macOS/Windows capture adapters.
