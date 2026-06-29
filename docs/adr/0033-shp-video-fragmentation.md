# ADR 0033: SHP video fragmentation — full-resolution frames over the DataChannel

- **Status:** Accepted
- **Date:** 2026-06-29
- **Deciders:** realtime-systems-engineer, network-engineer (consulted), rust-staff-engineer
- **Builds on:** ADR-0031 (SHP framing + browser decode), ADR-0032 (live host + downscale workaround)

## Context

SHP's `CommonHeader.payload_len` is a `u16`, so a single SHP video frame's payload cannot exceed
65 535 bytes. A full-resolution H.264 keyframe easily exceeds that, so ADR-0031 sent only single
(≤ 64 KiB) frames and ADR-0032 worked around the cap by **downscaling** the captured screen before
encoding. That caps the live browser path at a reduced resolution and adds a CPU pass.

The `VideoHeader` already carries the fields needed to fragment: `frag_index` (u8), `total_frags`
(u8), and `marker` (last-fragment flag) — they were defined for exactly this and were simply always
`0 / 1 / true` before. The WebRTC DataChannel is **reliable + ordered** (SCTP), so fragments arrive
in order with no loss — reassembly is a simple in-order concatenation.

## Decision

Fragment encoded access units at the SHP layer; reassemble in the browser.

### Host (`streamhaul-webrtc-host` lib)

`build_shp_video_fragments(seq_start, frame_id, ts_us, frame_type, payload, max_fragment_bytes)`
splits the Annex-B payload into chunks of ≤ `max_fragment_bytes` (clamped to the 64 KiB wire cap),
emitting one SHP message per chunk: all share `frame_id` + `frame_type`; `frag_index` runs
from 0 to `total_frags - 1` inclusive; the `fragment` flag is set on every fragment of a multi-fragment frame and
`last_fragment`/`marker` on the final one; `sequence` increments per fragment. **A frame that fits in
one chunk produces exactly one fragment whose bytes are identical to the previous non-fragmented
layout** (`total_frags == 1`, flags clear, marker set) — so the existing browser-native e2e is
unchanged. The streaming loop sends every fragment in order; the old ">64 KiB → drop" branch is gone
(only a frame needing > 255 fragments — ~16 MiB — is dropped, with a keyframe re-arm). A
`--max-fragment-bytes` flag (default 65535) lets the e2e force fragmentation of small frames.

### Browser (`clients/web`)

A `VideoFragmentReassembler` (`src/protocol/reassembler.ts`) buffers fragments by `frame_id` and
concatenates them in `frag_index` order, emitting the complete Annex-B access unit on the `marker`
fragment; `total_frags == 1` is a no-buffer fast path. It is defensive against out-of-order /
wrong-`frame_id` / oversize input (drop + resync, never throw, bounded memory) even though ordered
delivery makes those rare. It is inserted between `parseVideoFrame` and `decoder.pushAnnexB` in both
the production app and the e2e harness.

### Downscale becomes optional

With fragmentation, `DownscaleCapturer` is no longer needed for *correctness* — it is now a
bandwidth/CPU knob. The preview binary's default `--max-width` is raised to 3840 (4K), so typical
displays stream at **full resolution**; users can still downscale for bandwidth.

### Verification

- Host unit tests: single-fragment output is byte-identical to `build_shp_video_frame`; a 200 KB
  payload splits into 4 fragments that reassemble to the exact original; a tiny `max_fragment_bytes`
  forces many fragments; > 255 fragments errors.
- Browser Vitest: the reassembler returns the payload immediately for single fragments, concatenates
  a multi-fragment frame only on the marker, and resyncs on malformed/out-of-order input.
- The `browser-native` video e2e spawns the host with `--max-fragment-bytes 4096` (forcing 2–3
  fragments per baked frame), so it now proves the browser **reassembles fragmented frames** end to
  end (decode still gated on `h264DecodeSupported`).

## Consequences

- **Positive:** the browser live path is no longer capped at 64 KiB/frame — full-resolution video
  works; the downscale workaround is demoted to an optional knob. The change is wire-compatible
  (single-fragment bytes unchanged) and reassembly is exercised in CI.
- **Negative / trade-offs:** a lost fragment would lose the whole frame — fine today (reliable ordered
  DataChannel), but a future unreliable/partial-reliability mode would need FEC/NACK + a reassembly
  timeout. `total_frags` is u8 (≤ 255 fragments ≈ 16 MiB/frame — beyond any real frame). Per-frame
  fragment fan-out adds a few small SCTP messages; negligible at these sizes.
- **Follow-ups:** reassembly timeout/eviction for an eventual unreliable mode; periodic keyframes;
  input back-channel.
