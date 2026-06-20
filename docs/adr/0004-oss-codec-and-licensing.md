# ADR 0004: OSS codec default and licensing posture

- **Status:** Accepted (refines ADR-0002)
- **Date:** 2026-06-19
- **Deciders:** realtime-systems-engineer, software-architect (LLD phase)
- **Resolves:** PRD §9 open question Q2

## Context

The PRD named **H.265/HEVC** the primary codec for compression and near-universal hardware support.
HEVC is encumbered by overlapping patent pools (MPEG-LA, Access Advance, Velos). Shipping a compiled HEVC
encoder in an **Apache-2.0** binary makes the distributor a licensee — the same reason `x265` is GPL and no
major Apache/permissive media toolkit bundles a software HEVC encoder. We are open-core and must keep the
OSS build legally clean while staying performant.

## Decision

- **OSS (Apache-2.0) build default:** **AV1** (royalty-free under the AOM pledge), with **H.264 via OS
  system codec APIs only** (`VideoToolbox` / `Media Foundation` / `VA-API`) — **never** bundling `x264`,
  `openh264`, or any software H.264/HEVC encoder. The defensible boundary (used by OBS, browsers, WebRTC):
  we *call* a system-provided codec; we are not a codec implementor/licensee.
- **Commercial/enterprise build:** adds **HEVC** (same OS-API pattern, plus a commercial HEVC license /
  enterprise device-license representation). Neither build bundles `x265`.
- **Apple exception:** VideoToolbox has no AV1 *encode*; macOS OSS hosts fall back to H.264.
- **Negotiation:** OSS Game Mode `AV1 HW → H.264 HW(OS) → H.264 SW(last resort, rate-limited)`;
  commercial `HEVC HW → AV1 HW → H.264 HW(OS)`. Browsers always offer H.264 decode.

## Consequences

- Positive: OSS build is licensing-clean; AV1 gives strong compression where HW exists; commercial tier keeps
  the HEVC quality/coverage story.
- Negative: AV1 HW encode isn't universal (older GPUs, all Apple encode) → H.264 fallback paths must be solid;
  two codec-priority ladders to maintain.
- Follow-ups: track AV1 HW install base; revisit if Apple ships AV1 encode.

## Alternatives considered

- **Bundle x265 in OSS** — rejected: patent-pool licensee exposure incompatible with Apache-2.0 distribution.
- **H.264-only OSS** — simpler but cedes meaningful bandwidth/quality vs AV1/HEVC.
- **VP9** — no viable host HW encode path; rejected (consistent with ADR-0002).
