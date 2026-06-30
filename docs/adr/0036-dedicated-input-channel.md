# ADR 0036: Dedicated low-latency Input DataChannel

- **Status:** Accepted (host side; browser side staged as a follow-up)
- **Date:** 2026-06-29
- **Deciders:** network-engineer (design), realtime-systems-engineer (consulted), security-engineer (consulted)
- **Builds on:** ADR-0034 (input back-channel), ADR-0031/0032/0033 (browser↔host video), P1-1 (multi-channel `Transport`/`Channel`)

## Context

The browser↔host input back-channel (ADR-0034) carries 16-byte `InputEvent`s on the **same**
"shp" DataChannel the host streams video on. Two costs follow from sharing one channel:

1. **Latency.** `send`/`recv` both take `&mut self` on one `Channel` object, so a dedicated
   continuous receive task can't run alongside the video send loop. Input is therefore drained
   *between video frames* (`timeout(ZERO, recv())`), adding up to one frame interval (~33 ms at
   30 fps) to every event — directly against Gate P1's click-to-photon target.
2. **Head-of-line blocking.** Input and video share one reliable+ordered SCTP stream, so a large
   video fragment queued ahead of an input event delays its delivery.

## Decision

Carry input on its **own** reliable+ordered SCTP DataChannel, separate from video.

- **Labels** (`{channel_u8}:{priority}:{ordered_u8}`, parsed by `parse_channel_label`): video
  `"0:128:1"` (`ChannelId::Video`), input `"2:255:1"` (`ChannelId::Input`). The `priority` field is
  advisory today (not yet wired to str0m's `ChannelConfig.priority`; that is a follow-up — when wired,
  input gets the highest SCTP priority).
- **Browser (offerer)** creates **both** channels before `createOffer` (so both appear in the single
  `m=application` section), sends input on the input channel, and receives video on the video channel.
- **Host (answerer)** accepts both channels and **routes by parsed `spec().channel`** (NOT open
  order — SCTP stream numbering need not match `createDataChannel` order). The video loop owns the
  video channel; a **dedicated input task** owns the input channel and loops `recv()` →
  the existing bounded injection mpsc → `spawn_blocking` injection thread. The two channel objects
  have distinct ids and never alias, so the `&mut self` borrow conflict is gone and input is no
  longer gated by frame pacing.
- **Reliability:** input stays **reliable + ordered** — a dropped or reordered `Button`/`Key` release
  would stick (the ADR-0034 hazard); a reliable+ordered SCTP stream is lossless and in-sequence.

### Teardown (the safety-critical invariant)

`release_all()` MUST fire on session end so no button/key is left stuck. With two concurrent tasks
either of which can end first, the injection thread is fed by a bounded mpsc held by **two sender
clones** (video loop + input task). The host `tokio::select!`s the two task handles; whichever ends
first aborts the other; both handles are awaited (dropping their sender clones); the outer clone is
then dropped, so the injection thread sees all senders gone, exits its `blocking_recv` loop, and runs
`release_all()`. This holds on every exit path: normal completion, peer-close on either channel,
stream error, or a task panic.

### Staging

- **PR 1 (host-only, this ADR's accepted scope):** the host accepts up to two channels (the second
  with a **bounded** wait so a single-channel peer doesn't block on the 30 s accept timeout), routes
  by spec, and runs the dedicated input task when an Input channel is present. A single-channel peer
  (today's browser, whose `"shp"` label parses to `ChannelId::Control`) falls back to the **legacy**
  between-frames drain — so the existing `browser-native` e2e stays green with no browser change.
- **PR 2 (browser + e2e):** `sh-web-client` opens both channels and sends input on the input channel;
  the `browser-native` e2e sends input on the input channel and asserts the dedicated-task path.

## Security

Both DataChannels are SCTP streams inside the **same** DTLS session, so the DTLS-fingerprint pin
(ADR-0023/P4-5) covers them uniformly — no new trust boundary. str0m processes SCTP only after DTLS
completes and the pin is verified, so `ChannelOpen` (hence `accept_channel`) cannot resolve before
the MITM check passes. The input channel label is hostile-parseable but `parse_channel_label` is
already bounded + fallback-safe. The dedicated input task removes the `MAX_INPUT_PER_FRAME` drain cap,
so the rate limiter (`MAX_THROTTLED_INPUT_PER_SEC` / burst) becomes the first DoS line before the
bounded mpsc — its adequacy as a standalone guard is confirmed in review.

## Consequences

- **Positive:** input latency drops from ≤1 frame interval to ~1 SCTP RTT; input is no longer
  head-of-line-blocked by video; the `&mut self` borrow conflict that forced between-frames draining
  is gone; the legacy single-channel path remains as a fallback.
- **Negative / follow-ups:** SCTP send-side priority is not yet wired (input/video both default
  priority); the browser side + live e2e land in PR 2. **Tracked (from the PR-1 gate):** an
  unbounded transport `accept_queue`/`recv_queues` under a hostile peer opening many channels
  (pre-existing, transport-layer — bound the accept queue / cap concurrent channels); a coarse
  always-on injected-events/s backstop for the discrete `Button`/`Key` flood the rate limiter can't
  cap (security-assessed low — the peer already has full control; bounded today by the mpsc depth +
  serial injection); and a defense-in-depth guard so `release_all()` runs *immediately* even if the
  inline video loop itself panicked (today it would run when the peer next closes the input channel
  — the video paths are panic-free by construction, so this is unreachable).
