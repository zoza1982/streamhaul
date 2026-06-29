# ADR 0035: Periodic keyframes (GOP) for the OpenH264 stream

- **Status:** Accepted
- **Date:** 2026-06-29
- **Deciders:** realtime-systems-engineer, rust-staff-engineer
- **Builds on:** ADR-0029 (OpenH264 `with_config`), ADR-0031/0032 (browser video path)

## Context

`OpenH264Encoder::with_config` left the encoder's GOP at OpenH264's default (`uiIntraPeriod = 0`),
so the **only** IDR in a live stream was the one forced at startup; every later frame was a
P-frame. (OpenH264's `0` = `auto()`; with `ScreenContentRealTime` usage + CBR rate control, screen
content's low scene-change variance means `auto` produces effectively **no** periodic IDRs in
practice.) A receiver that joins mid-stream, or that loses the leading keyframe, then has **no
keyframe to decode from** and renders nothing until the next on-demand `request_keyframe()`. For a
streaming remote desktop this is a real robustness gap (the bug-bot/realtime reviews on ADR-0030/0033
both flagged "no periodic keyframes" as a deferred follow-up).

## Decision

Set a periodic IDR (GOP) in `with_config` when a frame rate is known:
`intra_frame_period = IntraFramePeriod::from_num_frames(target_fps × KEYFRAME_INTERVAL_SECS)`, with
`KEYFRAME_INTERVAL_SECS = 2`. So at 30 fps the encoder emits an IDR every ~60 frames (~2 s).
`request_keyframe()` still forces an extra IDR on demand between these (e.g. on a NACK / explicit
recovery request). The frame-type mapping and keyframe-durability logic are unchanged.

**2 seconds** is the standard screen-share GOP: short enough that a joining/recovering client waits
at most ~2 s for a decodable frame, long enough that the periodic-IDR bandwidth cost (keyframes are
much larger than P-frames) stays modest. It is encoder-level (the proper place), so it applies to
the live `LiveFrameSource` path automatically. The baked-fixture path already cycles a leading IDR
every 16 frames, so it is unaffected (16 < the 60-frame GOP).

## Consequences

- **Positive:** the live browser stream self-heals — a tab that joins late or drops the IDR recovers
  within ~2 s instead of staying black. No API change; on-demand `request_keyframe()` still works.
- **Negative / trade-offs:** periodic IDRs add bandwidth (a keyframe every 2 s vs. only one ever),
  though for screen content an IDR is only ~3–8× a P-frame (not the ~50× of camera video), so the
  cost is modest. Under **extreme bitrate starvation** OpenH264 may `Skip` the scheduled IDR (mapped
  to `Ok(None)`) and emit it on the **next** encode call — a ≤1-frame delay, not a missed GOP; the
  encoder retries internally and the existing skip/frame-type handling copes. Tunable via the
  constant. The interval is fixed (not yet adaptive to loss feedback) — a NACK/PLI-driven keyframe
  (P2 loss recovery) is the future refinement.
- **Why encoder-level (not a host timer):** `intra_frame_period` counts *encoded* frames, so it stays
  correct when `skip_frames(true)` drops frames under congestion (a wall-clock timer in the host loop
  would drift) and has no async-timer jitter. The host loop owns only *demand* IDRs (NACK/reconnect).
- **Follow-ups:** NACK/PLI-driven keyframes from real receiver feedback; making the interval
  configurable from the `EncoderConfig` / allocator.
