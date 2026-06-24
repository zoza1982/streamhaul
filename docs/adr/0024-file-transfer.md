# ADR 0024: Congestion-isolated file transfer (Phase 7)

- **Status:** Accepted
- **Date:** 2026-06-24
- **Deciders:** network-engineer, rust-staff-engineer, security-engineer (consulted); systems-design-engineer (isolation model)

## Context

Phase 7 adds bidirectional file transfer (PRD §file transfer; LLD §3.2, §4.7). The product
invariant is that a bulk file copy **consumes only spare bandwidth and can never degrade the
interactive video/input experience**, and that transfers are **resumable** and **integrity-verified**.

Most of the plumbing already exists and must not be re-invented:

- `ChannelId::File` is a first-class wire channel (`sh-types`), self-identifying in the SHP
  `CommonHeader` 4-bit channel field.
- `ChannelSpec::file()` (`sh-transport`) is reliable, urgency 6, and — critically — **each transfer
  opens its own QUIC stream / WebRTC DataChannel**, giving independent per-stream flow control. This
  is the *structural* congestion-isolation guarantee (LLD §4.7): separate streams, not a shared lock.
- The P2-2 `RateAllocator` (`sh-adaptive`) already assigns the File channel **pure leftover** after
  input/control/clipboard reserves, the audio floor, and video (capped at `video_max`). File can
  never starve video below `video_max`.
- Per-channel ChaCha20-Poly1305 already derives a File subkey (`sh-crypto`), so chunks are AEAD-sealed.
- `Capabilities::FILE` (`sh-core::authz`) already gates the privilege.

What is **net-new**: (1) the file-transfer **application wire format** (offer/accept/abort/complete
control messages + a per-chunk data header carrying a transfer id + byte offset), (2) a **token-bucket
pacer** that makes the sender respect `allocate().file()` so file traffic is budget-isolated as well
as stream-isolated, (3) the **`FileSender`/`FileReceiver` orchestrator** in `sh-core` implementing resume (byte
offset) and integrity (SHA-256 over the whole file), gated on `Capabilities::FILE`, and (4) a client
surface in `clients/web`.

## Decision

### Wire format — `sh-protocol::file` (new module, big-endian, hostile-input-safe)

**Control plane** — carried as `ControlFrame` payloads on the existing reliable Control channel,
mirroring `capability.rs` (new `KIND_FILE_*` bytes, typed payload structs with `encode`/`decode`):

| Kind | Message | Wire layout |
|------|---------|-------------|
| `0x30` `KIND_FILE_OFFER` | `FileOffer` | `transfer_id u64 | total_size u64 | chunk_size u32 | sha256 [u8;32] | name_len u8 | name[name_len]` |
| `0x31` `KIND_FILE_ACCEPT` | `FileAccept` | `transfer_id u64 | resume_offset u64` |
| `0x32` `KIND_FILE_ABORT` | `FileAbort` | `transfer_id u64 | code u8` |
| `0x33` `KIND_FILE_COMPLETE` | `FileComplete` | `transfer_id u64 | ok u8(0/1)` |

(The `0x30` block avoids collision with `capability` `0x10`–`0x11` and `transport_caps` `0x20`–`0x21`
on the shared Control channel; a compile-time uniqueness assertion in `sh-protocol::lib` enforces it.)

**Data plane** — carried as `Bytes` payloads on a dedicated `ChannelSpec::file()` stream (one per
transfer): a fixed **21-byte** `FileChunkHeader { transfer_id u64, offset u64, len u32, flags u8 }`
followed by `len` payload bytes. `flags` bit 0 = `LAST_CHUNK`.

**Bounds (DoS-hardening, all enforced on decode, never panic):**
- `MAX_FILE_NAME = 255` (1-byte length prefix; the name is opaque bytes here — the orchestrator
  rejects path separators / non-UTF-8 / `..`).
- `MAX_FILE_CHUNK = 1 MiB` — `chunk_size` in an offer and `len` in a chunk header must be
  `1..=MAX_FILE_CHUNK`; larger is rejected (`ProtocolError::FileChunkTooLarge`).
- `resume_offset ≤ total_size` and `code`/`ok` range-validated by the orchestrator/decoder.

### Budget isolation — `sh-adaptive::TokenBucket` + file pacing

A small deterministic `TokenBucket` (injected clock, bytes/sec fill) wraps `allocate(total).file()`.
The sender awaits sufficient tokens before each chunk, so file throughput tracks the leftover budget.
This composes with the structural per-stream isolation: file is isolated **twice** — its own flow-
control window *and* a leftover-only send budget.

### Orchestration — `sh-core::file` (`FileSender` + `FileReceiver`)

Implemented as **two side-agnostic state machines** (`FileSender`, `FileReceiver`) rather than one
combined `FileTransfer` type, so the security-critical logic is unit-testable with no transport or
async runtime. They drive offer → accept(resume_offset) → chunk stream → complete over the Control +
File channels. **Resume:** the receiver advertises how many contiguous bytes it already holds as
`resume_offset`; the sender resumes from there (and seeds its hash with the retained prefix so
integrity still covers the whole file). **Integrity:** SHA-256 (the already-vetted `sha2` crate — no
new dependency) over the *entire* reconstructed file is compared to the offer digest; a mismatch is a
`FileComplete{ok:0}` + discard. `FileReceiver::accept_offer` checks `Capabilities::FILE`.

### P7-2 orchestrator requirements (security carry-forward — MUST enforce)

The `sh-protocol::file` layer is **pure framing**: it bounds per-field/per-chunk values (chunk ≤ 1
MiB, name ≤ 255 B, reserved-bit + discriminant rejection, never panics) but cannot enforce
cross-message or stateful invariants. The P7-2 `FileReceiver` orchestrator **must** enforce all of
the following (each is a confirmed gate-review finding, tracked here so none is dropped):

1. **`Capabilities::FILE`** checked at *every* entry point that acts on an offer/accept/chunk before
   any allocation or disk write.
2. `resume_offset ≤ total_size` (the `InvalidFileField` doc no longer claims the wire layer does this).
3. `offset + len ≤ total_size`, and chunk `offset`s are monotonic / non-overlapping (a peer must not
   steer writes outside the declared file or inflate the reassembly buffer past `total_size`).
4. A cap on **aggregate** buffered bytes before the SHA-256 check (the per-chunk cap bounds one
   chunk; nothing bounds total buffering — that is the receiver's job).
5. **Name sanitization**: reject path separators, `..`, NUL, and non-UTF-8 (`name` is opaque bytes
   by design at the wire layer).
6. **`transfer_id` is untrusted**: reject chunks/control for unknown or already-completed ids; a peer
   must not hijack or collide another active transfer by reusing its id.
7. **SHA-256 verification** over the entire reassembled file before delivery; mismatch → discard +
   `FileComplete{ok:false}` / `FileAbort{IntegrityFailed}`.

### Client surface — `clients/web`

A strict-TypeScript `file/` module encodes/decodes the same framing **through the wasm bridge**
(no TS reimplementation of the wire), with Vitest **byte-parity** tests against the Rust codec
(the P5-2 pattern) and a minimal drag-and-drop UI. The **live browser↔native file e2e is deferred**
(→ R-BROWSER-FILE) consistent with the existing "clipboard/file/audio deferred" posture of
R-BROWSER-INTEROP — it needs the same browser-matrix / live-media environment that is already gated.

### Crate placement note

P7-1's nominal crates are `sh-protocol` + `sh-transport`; the `TokenBucket` pacer lands in
`sh-adaptive` (beside the allocator it consumes) and the `FileStreamer`/`FileReassembler` in
`sh-transport`. This deviation is intentional — rate control belongs with the rate allocator.

## Consequences

- **Positive:** file transfer is congestion-isolated by two independent mechanisms (per-stream flow
  control + leftover budget); resumable and integrity-verified; the wire parsers are bounded and
  fuzzed; no new crypto and no new third-party dependency (SHA-256 via existing `sha2`).
- **Negative / trade-offs:** SHA-256 is computed over the whole file (no Merkle/partial-verify), so
  a corrupt resume re-verifies the full content — acceptable for v1. The token-bucket pacer is a
  coarse budget shaper, not a full congestion controller (it rides on top of SCReAM/GCC, which owns
  the aggregate target).
- **Follow-ups:** R-BROWSER-FILE (live browser↔native file e2e); persistent on-disk resume state
  across reconnects; per-chunk/Merkle integrity for partial re-verification; multi-file/dir transfer.

## Alternatives considered

- **BLAKE3 for integrity** — faster + Merkle-friendly, but adds a dependency; `sha2` is already in
  the tree and vetted. Deferred unless partial-verify is needed.
- **Single shared file stream for all transfers** — rejected: breaks per-transfer flow-control
  isolation and complicates resume; the LLD mandates a stream per transfer.
- **Carrying offer/accept on the File data stream itself** — rejected: control belongs on the
  reliable Control channel (urgency 1) so signaling is not stuck behind paced bulk data.
- **A new `ChannelId`/transport enum for file** — unnecessary; `ChannelId::File` + multiple
  `open_channel(ChannelSpec::file())` calls already model "a stream per transfer".
