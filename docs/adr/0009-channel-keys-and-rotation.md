# ADR 0009: Channel key hierarchy, AEAD nonce discipline, rekey, and ratchet

- **Status:** Accepted
- **Date:** 2026-06-22
- **Deciders:** security-engineer, rust-staff-engineer, network-engineer, code-reviewer
- **Builds on:** ADR-0005 (SHA-256), ADR-0006 (Ed25519 trust root), ADR-0007 (Noise handshake,
  `NoiseSession::export_keying_material`, `HandshakeOutcome`).
- **Phase / task:** P3-4 (`IMPLEMENTATION_PLAN.md`). Consumed by P3-5 (kill-switch RAM-key
  zeroize) and P1-style transport channels (`sh-transport`).
- **Scope:** **Design only.** The implementer (`rust-staff-engineer`) builds to the companion
  spec (§ "Implementation spec") in `crates/sh-crypto` plus a thin `sh-transport` seam, then this
  ADR's author (`security-engineer`) gates the diff per CLAUDE.md §2/§3.

## Context

Streamhaul grants **full remote control of a machine** over a hostile network through a
**zero-knowledge relay**. After ADR-0007 establishes a mutually-authenticated, identity-bound Noise
tunnel, every byte of screen, audio, input, clipboard, and file data still has to cross that relay.
LLD §6.3 pins the shape of the post-handshake key hierarchy but leaves the concrete primitives open:

> `Per-connection ephemerals (PFS)` → `native-path session transport keys (Noise AEAD:
> ChaCha20-Poly1305 or AES-256-GCM, rekey ≤2²⁰ msgs or 15min)` → `per-channel subkeys (HKDF,
> ratchet every N frames)`. **Relay/signaling sees only opaque ciphertext, public `device_id`
> fingerprints, routing metadata** — the enforced zero-knowledge boundary.

The forces:

1. **Six logical channels** (`ChannelId`: Video/Audio/Input/Clipboard/File/Control) multiplex over
   one Noise session. Each must use a **separate key** so a compromise or nonce-management bug on
   one channel cannot decrypt or forge another, and so a frame can never be replayed cross-channel.
2. **Nonce reuse under a fixed key is catastrophic** for both ChaCha20-Poly1305 and AES-GCM
   (Poly1305/GHASH one-time-key recovery → full authentication-key forgery, plus plaintext XOR
   leakage). The nonce discipline is therefore the single most security-critical decision here.
3. **Out-of-order and lost frames** are normal: Video/Audio ride QUIC **datagrams** (unordered,
   drop-allowed; `sh-transport` `Reliability::Unreliable`). A strict monotonic-counter AEAD that
   refuses any out-of-order sequence would break media. We need a **bounded replay window**, not a
   strict counter.
4. **Forward secrecy beyond the handshake ephemerals**: LLD §6.3 demands a **rekey** and a
   **per-channel ratchet** so that compromise of a current key does not expose previously-sent
   frames. The ephemerals already give PFS for the session root; we must extend that property
   across rekeys and ratchet steps.
5. **Deterministic, testable, panic-free**: the 15-minute rekey bound must use the injected
   `Clock` (ADR-0007 already threads `&dyn Clock`), and the frame-header decoder parses
   attacker-controlled bytes → must be bounds-checked and fuzzed (CLAUDE.md §5/§7).
6. **P3-5 kill-switch** must be able to zeroize the entire in-RAM key set instantly so post-kill
   ciphertext fails AEAD. This ADR defines exactly which key material exists in RAM.

This ADR decides the concrete derivation labels, the AEAD and nonce construction, the rekey and
ratchet policy + the peer-sync mechanism, the frame header, and the threat analysis.

## Decision

### 1. Key hierarchy — concrete derivation from the Noise root

The root is the `NoiseSession` from ADR-0007. `NoiseSession::export_keying_material(label, context,
out)` performs `HKDF-SHA256-Expand(PRK = Extract(h), info = lp(label) || lp(context))` where `h` is
the handshake hash (the construction is already implemented and length-prefixes both inputs, so two
distinct `(label, context)` pairs can never collide). **We do not use the raw `snow` transport
cipher for channel traffic** (see §2 for why); we use `export_keying_material` purely as the KDF and
layer our own AEAD above it.

#### 1.1 Domain-separated labels (the authoritative list)

All channel material is derived with a fixed protocol label, a version, the **channel discriminant**
(the wire-stable `u8::from(ChannelId)` — the single source of truth in `sh-types`), and an explicit
**direction** byte. The HKDF `context` carries the **epoch** so that each rekey produces an
independent key space.

```
label   = b"shp chan v1"                       // 11-byte protocol/version domain tag
context = channel_id_u8(1) || direction_u8(1) || epoch_u64_be(8)   // 10 bytes, fixed width
out     = 32 bytes  (one ChaCha20-Poly1305 key)

direction_u8:  0x00 = initiator→responder ("i2r")
               0x01 = responder→initiator ("r2i")

channel_id_u8 (from sh-types, wire-stable):
    Video=0  Audio=1  Input=2  Clipboard=3  File=4  Control=5
```

The base key for `(channel, direction, epoch)` is:

```
k_base(channel, dir, epoch) = export_keying_material(
        b"shp chan v1",
        channel_id_u8 || dir || epoch_be8,
        out=32)
```

- **Send vs receive separation is by absolute direction, not by local role.** Each side derives the
  same two keys for a channel (`i2r` and `r2i`); the **initiator** *sends* with `i2r` and *receives*
  with `r2i`; the **responder** does the reverse. This guarantees the two directions occupy disjoint
  key spaces and disjoint nonce spaces, so a frame can never be reflected back and accepted, and the
  two peers never both encrypt under the same (key, nonce). The local mapping uses
  `HandshakeOutcome::role` (already exposed by ADR-0007).
- **Epoch in `context`, not just in the ratchet:** baking the epoch into the HKDF context means a
  rekey is a *fresh independent derivation from the root*, and the per-frame `epoch` in the header
  (§4) selects which base key to use. `epoch` starts at 0.
- **Why direction is a distinct field rather than folding role into the label:** it keeps the label
  a constant byte string (one domain tag for the whole product) and makes the i2r/r2i split explicit
  and symmetric for both peers.

#### 1.2 Per-channel ratchet chain

Within an epoch, each `(channel, direction)` advances an **HKDF ratchet** every `RATCHET_INTERVAL`
frames (§3.2). The ratchet root is `k_base`; ratchet generation `g` (a `u32`) yields the AEAD key:

```
k_ratchet(g=0)   = k_base                                   // generation 0 is the base key
k_ratchet(g+1)   = HKDF-SHA256-Expand(
                       PRK = Extract(salt=∅, IKM = k_ratchet(g)),
                       info = b"shp ratchet v1",
                       L = 32)
```

This is a one-way chain (`k_{g+1} = KDF(k_g)`): given `k_{g+1}` an attacker cannot recover `k_g`
(HKDF/HMAC-SHA256 preimage resistance) → **forward secrecy within an epoch**. The sender deletes
`k_g` (zeroizes) the moment it advances to `g+1` and will not re-send under `g`. The receiver tracks
the highest generation seen and keeps a **small bounded set of live generations** to tolerate
reorder/loss (§3.3).

The complete identifier of the key that protects any single frame is therefore the triple
**(epoch, generation, direction)** plus the channel — all of which the receiver can reconstruct from
the frame header (§4) and its own derived `k_base`.

### 2. AEAD and nonce discipline (CRITICAL)

#### 2.1 AEAD choice: standalone RustCrypto `chacha20poly1305`, **not** the snow transport cipher

We use **`chacha20poly1305::ChaCha20Poly1305`** (RustCrypto, IETF construction: 256-bit key, 96-bit
nonce, 128-bit tag) as the per-channel AEAD, with **caller-controlled explicit nonces**. We do
**not** reuse `snow::TransportState` for channel data.

Rationale (this is a deliberate departure from "reuse the Noise cipher"):

- **Out-of-order is mandatory and snow forbids it.** `snow`'s `TransportState` derives the nonce
  from an **internal monotonic counter** it owns; it offers no API to set a per-message nonce and
  (in the default resolver) rejects/decrypts strictly in counter order. Media frames arrive out of
  order over datagrams. A caller-controlled nonce is required to decrypt frame `n+1` before `n`.
- **Per-channel keys.** snow has one send/recv cipher pair for the whole tunnel; we need six
  channels × two directions with independent keys and **independent nonce spaces**. Driving six
  logical streams through one snow counter is impossible without nonce collisions.
- **We still never roll crypto** (CLAUDE.md §7): `chacha20poly1305` is a vetted RustCrypto crate,
  the same primitive family snow uses internally. ChaCha20-Poly1305 is **constant-time in software**
  on every target (ARM thin clients, LLD §1) — the same reason ADR-0007 picked it over AES-GCM. The
  AES-256-GCM variant in LLD §6.3 remains a **HW-gated future option** (not in P3-4), exactly
  mirroring ADR-0007 §1.3.
- The Noise tunnel's own transport cipher (`NoiseSession::encrypt/decrypt`) remains available for
  the **control/handshake-adjacent** in-order messages that ADR-0007 already encrypts; channel media
  uses the layer defined here. The two do not share key or nonce material.

#### 2.2 Nonce construction (MUST never repeat under a given key)

The AEAD key is uniquely determined by `(channel, direction, epoch, generation)` (§1). Under one
such key, the nonce is a **96-bit (12-byte) counter built from the in-epoch frame sequence number**:

```
nonce[12] = generation_u32_be (4 bytes) || seq_u64_be (8 bytes)
```

- `seq` is a **per-(channel, direction, epoch)** monotonically increasing `u64`, assigned by the
  sender, starting at 0 for each new epoch. It is carried in the clear in the frame header (§4) so
  the receiver can reconstruct the nonce.
- Including `generation` in the high 4 bytes means even if the same `seq` value were ever paired with
  two different generations under the *same base key derivation*, the nonces differ — defence in
  depth. But the *primary* uniqueness guarantee is that **the key already changes per generation and
  per epoch**, and `seq` is unique within `(channel, direction, epoch)`.
- **Uniqueness argument:** for a fixed key `k(channel,dir,epoch,gen)`, the nonce varies only with
  `seq`. The sender never reuses a `seq` within an `(channel, dir, epoch)` (it is a strictly
  increasing counter it owns). Therefore `(key, nonce)` is never repeated. The two directions use
  different keys; the two peers never encrypt under the same direction's key (§1.1). **No
  random-nonce path exists** — nonces are purely deterministic counters, removing birthday-bound
  risk entirely.

#### 2.3 Counter exhaustion → forced rekey BEFORE wrap

`seq` is a `u64`; `generation` is a `u32`. Wrapping either would repeat a nonce. We force rotation
**well before** any wrap:

- The **rekey trigger** (§3.1) fires at `2²⁰` messages per session (LLD §6.3) — vastly below the
  `u64` `seq` ceiling, so `seq` cannot wrap in practice. The implementation MUST additionally treat
  `seq == SEQ_HARD_LIMIT` (a constant `< u64::MAX`, e.g. `2⁶³`) and `generation == GEN_HARD_LIMIT`
  (`< u32::MAX`) as a **hard stop**: `seal()` returns `CryptoError` rather than emitting a frame
  that could ever approach wrap. A correct deployment rekeys at `2²⁰` long before this; the hard
  stop is a belt-and-suspenders guard against a stuck/maliciously-suppressed rekey signal.
- A ratchet advance resets `seq`'s role only insofar as the key changes; we keep `seq` strictly
  increasing across generations within an epoch (it is the epoch-wide frame counter), and a rekey
  (new epoch) resets `seq` to 0 under a fresh base key.

#### 2.4 AAD — bind channel, epoch, generation, seq

The Additional Authenticated Data committed by the AEAD is the **full frame header** (§4):

```
AAD = b"shp aead v1" || channel_id_u8 || direction_u8 || epoch_u64_be || generation_u32_be || seq_u64_be
```

Binding `channel_id` + `direction` + `epoch` + `generation` + `seq` into the AAD means:

- A frame sealed for Video cannot be **replayed on Audio** (different `channel_id` in AAD → tag
  mismatch even before the key differs).
- A frame from epoch N cannot be **replayed in epoch N+1** (different `epoch` → tag mismatch; and the
  key differs anyway).
- An attacker cannot **rewrite the header** (e.g. lie about `seq` to dodge the replay window) without
  invalidating the tag.

Because the key is *already* domain-separated by `(channel, direction, epoch, generation)`, the AAD
is defence-in-depth on top of key separation, **and** it authenticates the cleartext `seq` the
receiver uses for windowing. Both properties are required.

### 3. Rotation / rekey + ratchet policy

#### 3.1 Session rekey: ≤ 2²⁰ messages OR 15 minutes (LLD §6.3 pinned)

A **rekey** advances the epoch for the whole session (all channels, both directions) and derives a
fresh `k_base` per channel/direction from the root via §1.1 with `epoch+1`.

- **Which counter:** a single **session-wide message counter** = the sum of frames sealed across all
  channels in the current epoch by *this* peer's send side, plus a wall-clock check via the injected
  `Clock`. `needs_rekey()` returns `true` when **either**:
  - `messages_this_epoch >= REKEY_MSG_LIMIT` where `REKEY_MSG_LIMIT = 2²⁰ = 1_048_576`, **or**
  - `clock.now_unix_secs() - epoch_started_at >= REKEY_TIME_LIMIT_SECS` where
    `REKEY_TIME_LIMIT_SECS = 900` (15 min).
- **Peer sync — signaled, not purely deterministic.** Deterministic message-count triggers desync
  under loss (datagrams drop, so two peers disagree on counts), and clocks drift. Therefore rekey is
  **explicitly signaled in-band on the reliable Control channel**: when a peer's `needs_rekey()`
  fires, it sends a `RekeyRequest{ proposed_epoch = current+1 }` control message and **begins
  sealing new traffic under `epoch+1`** while continuing to *open* late-arriving `epoch` frames for
  a bounded grace period (§3.4). The receiver, seeing either the `RekeyRequest` **or** the first
  frame header carrying `epoch+1`, derives the new base keys lazily and switches its receive side.
  The `epoch` in every frame header (§4) is the **authoritative, authenticated** signal; the Control
  message is an early heads-up. **Both peers therefore converge on the new epoch from the
  authenticated frame headers — there is no unauthenticated trigger.** A peer never accepts an epoch
  more than `+1` ahead of its current (bounds a malicious far-future epoch; §5).
- **Forward secrecy across rekey:** the new epoch key is derived from the **same root PRK** but the
  per-epoch base keys are *independent* HKDF outputs; additionally, on advancing the epoch the sender
  **zeroizes all `epoch N` base keys and ratchet keys** once the grace period closes (§3.4). Because
  the per-epoch key is `Expand(PRK, info=...||epoch_be)`, knowledge of epoch N keys does not yield
  epoch N−1 or N+1 keys (HKDF outputs are independent given distinct `info`). To obtain a one-way
  *ratchet across epochs as well* (so a root-PRK compromise at time T cannot derive *past* epoch keys
  without also storing the PRK), the PRK itself is **not** kept beyond what export requires; see §4
  "PFS & lifecycle". The dominant FS mechanism is the per-epoch independence + prompt zeroization;
  the within-epoch generation ratchet (§3.2) gives finer-grained FS between rekeys.

#### 3.2 Per-channel ratchet: every N frames

- `RATCHET_INTERVAL = 16_384` frames per `(channel, direction)` within an epoch. (Chosen so a busy
  60 fps video channel ratchets roughly every ~4–5 min of continuous send, bounding the plaintext
  exposed by any single generation-key compromise to one interval, while keeping ratchet KDF
  overhead negligible — one HKDF-Expand per 16 384 frames. It is a tunable constant, documented in
  one place.)
- When the sender's per-(channel,direction) frame count crosses a multiple of `RATCHET_INTERVAL`, it
  advances the chain (`k_{g+1} = KDF(k_g)`), **zeroizes `k_g`**, increments the header `generation`,
  and continues sealing. `seq` keeps increasing monotonically across the boundary (epoch-wide).
- The receiver derives generation keys **on demand** from its `k_base` by walking the chain forward
  to the `generation` in the frame header, caching a bounded window of live generations (§3.3),
  zeroizing generations that fall out of the window.

#### 3.3 Out-of-order / lost frames within a bounded window (no ratchet break)

The ratchet must not break under reorder/loss. The receiver maintains, per `(channel, direction,
epoch)`:

- `max_gen_seen` and a **live-generation cache** of at most `GEN_WINDOW = 2` generations
  (`max_gen_seen` and `max_gen_seen − 1`). A frame whose `generation` is within the window is opened
  with the cached key; a frame one generation ahead triggers one forward ratchet step (deriving the
  next key, evicting+zeroizing the oldest). A frame whose `generation < max_gen_seen − GEN_WINDOW`
  (too old) or `> max_gen_seen + GEN_AHEAD_LIMIT` (`GEN_AHEAD_LIMIT = 2`, too far ahead) is
  **dropped** — never an error that tears down the session, because a single hostile/late datagram
  must not be a DoS.
- A **per-(channel, direction, epoch) sliding replay window** over `seq`: a 64-bit (or 1024-bit
  bitmap) window anchored at the highest accepted `seq`. A frame with `seq` already marked, or below
  the window floor, is **dropped as a replay**; a frame above the window slides it forward. This is
  the standard IPsec/DTLS anti-replay window and tolerates the bounded reorder of QUIC datagrams
  without accepting duplicates. Window width `REPLAY_WINDOW = 1024`.
- **Crucially, AEAD success is required before a frame updates any window** — the tag is verified
  first; only an authentic, in-window, non-replayed frame advances `max_gen_seen`/replay state. A
  forged header cannot poison the window.

#### 3.4 Rekey grace period

After signaling/observing a rekey to `epoch+1`, a receiver keeps the `epoch N` receive keys live for
`REKEY_GRACE` = `min(REKEY_TIME_LIMIT_SECS/3, 5 s)` **or** until a small number of `epoch+1` frames
have been accepted on each channel, whichever first, to drain in-flight `epoch N` datagrams. When the
grace closes it **zeroizes all `epoch N` key material** (base + all cached generations, both
directions). The sender stops emitting `epoch N` frames immediately on rekey. This bounds how long
two epochs coexist and keeps the in-RAM key set small.

### 4. Frame header, PFS, and key lifecycle

#### 4.1 Frame header (the bytes added per channel frame)

```
SHP channel frame =
    MAGIC          u8       = 0x53 ('S')         // 1  cheap structural sanity / version anchor
    HDR_VERSION    u8       = 0x01               // 1
    CHANNEL_ID     u8                            // 1  must map to a known ChannelId (0..=5)
    DIRECTION      u8                            // 1  0x00 i2r | 0x01 r2i
    EPOCH          u64 BE                        // 8
    GENERATION     u32 BE                        // 4
    SEQ            u64 BE                        // 8
    ──────────────────────────────────────────  // 24-byte fixed header, all big-endian (SHP §3.1)
    CIPHERTEXT     [..]                          // AEAD output = plaintext_len + 16 (Poly1305 tag)
```

- The 24-byte header is exactly the AAD input (§2.4, minus the constant `b"shp aead v1"` domain
  prefix which is prepended at AEAD time, not transmitted). Fixed-width, big-endian, no optional
  fields → one canonical encoding, bounds-checkable in constant steps.
- `DIRECTION` on the wire lets the receiver pick the right key without ambiguity and lets the AAD
  bind it; a receiver MUST reject a frame whose `DIRECTION` equals its own send direction (a frame
  can't be reflected).

#### 4.2 PFS and the in-RAM key set (defines what P3-5 zeroizes)

PFS layers, strongest to weakest granularity:

1. **Per-connection ephemerals** (Noise handshake, ADR-0007) — already PFS; the root PRK is derived
   from `h`. A future session uses fresh ephemerals; recorded ciphertext of a past session is not
   decryptable from a later static-key compromise.
2. **Per-epoch base keys** — independent HKDF outputs per epoch; old epochs zeroized after the grace
   period (§3.4). Compromise of epoch N does not yield epoch N−1.
3. **Per-generation ratchet keys** — one-way chain; `k_g` zeroized on advance to `k_{g+1}` →
   FS within an epoch at `RATCHET_INTERVAL` granularity.

The **in-RAM key set** that P3-5's kill-switch zeroizes, owned by the `ChannelCrypto`/`SessionKeys`
type, is exactly:

- the root **PRK** (`Zeroizing<[u8;32]>`, inside `NoiseSession`),
- for each `(channel, direction)`: the current-epoch **base key** and the **live generation keys**
  in the window (each `Zeroizing<[u8;32]>` / wrapped in a key type that zeroizes on drop),
- any **grace-period prior-epoch** keys not yet zeroized.

All are `Zeroizing` (or hold `Zeroizing` buffers) so dropping the `SessionKeys` zeroizes everything;
P3-5 calls an explicit `zeroize_all()` that overwrites in place **and** drops, so post-kill
`open()`/`seal()` cannot succeed (keys are gone → AEAD fails / calls error). No key material appears
in `Debug` or `tracing` output.

### 5. Threat model

| Threat | Defence |
|--------|---------|
| **Nonce reuse (catastrophic)** | Deterministic counter nonce = `generation_be \|\| seq_be`; key is unique per `(channel,dir,epoch,gen)`; `seq` strictly increasing per `(channel,dir,epoch)`; two directions/peers never share a key. No random-nonce path. Hard-stop before `seq`/`gen` wrap; rekey at `2²⁰` ≪ wrap. **(channel,dir,epoch,gen,seq)** is therefore unique ⇒ `(key,nonce)` never repeats. |
| **Cross-channel replay** | `channel_id` in the per-channel key derivation **and** in the AAD: a Video frame opened against the Audio key/AAD fails the tag. |
| **Cross-epoch replay** | `epoch` in key derivation and AAD; old-epoch keys zeroized after grace. A replayed epoch-N frame in epoch N+1 has no live key and fails the AAD bind. |
| **In-epoch replay / duplication** | Per-(channel,dir,epoch) sliding `seq` replay window (`REPLAY_WINDOW=1024`); duplicate or below-floor `seq` dropped *after* AEAD success. |
| **Key compromise / forward secrecy** | One-way HKDF ratchet (`k_{g+1}=KDF(k_g)`, `k_g` zeroized) ⇒ a leaked current generation key cannot decrypt earlier generations; independent per-epoch derivation + prompt zeroization ⇒ leaked epoch-N keys don't yield epoch N±1. |
| **Out-of-order abuse / DoS** | Bounded generation window (`GEN_WINDOW=2`, `GEN_AHEAD_LIMIT=2`) and replay window; out-of-window or far-future-epoch (`> current+1`) frames are **dropped, not fatal** — a hostile datagram cannot tear down the session or force unbounded key derivation. |
| **Downgrade** | Suite/version are bound in the Noise prologue (ADR-0007 §1.4) and the handshake `h` feeds the PRK; channel `HDR_VERSION`/`label` are versioned. A peer can't negotiate a weaker channel cipher — there is exactly one (`shp aead v1`). |
| **Forged / tampered header** | Entire 24-byte header is AEAD AAD; any bit-flip → tag failure → drop. Windows update only on AEAD success, so a forged header can't poison replay/ratchet state. |
| **Zero-knowledge relay boundary** | Relay sees only `{header (channel/dir/epoch/gen/seq metadata), ciphertext+tag}`. No plaintext, no keys. Metadata is routing/ordering only (already implied by separate QUIC streams/datagrams) and is explicitly the LLD §6.3 permitted set. |
| **Kill-switch race (P3-5)** | `zeroize_all()` overwrites the entire in-RAM key set in place; subsequent `seal`/`open` error or fail AEAD ⇒ no input actuates post-kill, no network needed (LLD §6.4). |

## Consequences

- **Positive:**
  - Concrete, testable channel-key hierarchy keyed by the wire-stable `ChannelId` with explicit
    direction separation; one set of HKDF labels documented in one place.
  - Deterministic counter-nonce discipline eliminates nonce-reuse risk by construction; AAD binds
    channel/epoch/gen/seq so cross-channel and cross-epoch replay are impossible.
  - Rekey (`2²⁰`/15 min) and ratchet (`16 384` frames) pin LLD §6.3 with an **authenticated**
    epoch-in-header sync that survives datagram loss and clock drift.
  - Forward secrecy at epoch and generation granularity; a single key compromise has bounded blast
    radius; all keys `Zeroizing`, giving P3-5 a clean `zeroize_all()` seam.
  - Out-of-order/loss tolerated via standard sliding replay + bounded generation window; hostile
    frames are dropped, never fatal.
- **Negative / trade-offs:**
  - Per-channel AEAD layered above the Noise tunnel adds a 16-byte tag + 24-byte header per frame
    and one ChaCha20-Poly1305 pass. Accepted: media frames are large relative to 40 bytes, and the
    cipher is fast/constant-time.
  - Not reusing snow's transport cipher means a second AEAD dependency (`chacha20poly1305`). Accepted
    and justified (§2.1): snow can't do out-of-order or per-channel keys.
  - Two epochs briefly coexist during the grace period (more live keys). Bounded by `REKEY_GRACE`
    and small windows.
  - AES-256-GCM HW-gated variant is deferred (not P3-4), matching ADR-0007.
- **Follow-ups:**
  - **P3-5** consumes `SessionKeys::zeroize_all()` for the kill-switch.
  - WebRTC media path uses **SRTP AES-128-GCM from the DTLS export** (LLD §6.3), *not* this
    hierarchy — out of scope here; defined in P4.
  - Add channel-key **conformance vectors** (fixed `h` → fixed per-channel keys, nonces, ciphertext)
    to the test corpus so any KDF/label change is caught.
  - Consider an **epoch-chaining ratchet** (root advances one-way per epoch) pre-GA if a stronger
    cross-epoch FS guarantee is required than per-epoch HKDF independence + zeroization provides.

## Alternatives considered

- **Reuse `snow::TransportState` for channel data** — Rejected (§2.1): no per-message nonce control,
  no out-of-order decrypt, single key for the whole tunnel. Cannot serve six channels or media
  datagrams.
- **AES-256-GCM as the P3-4 default** — Rejected for now: software AES is variable-time on ARM thin
  clients (LLD §1). ChaCha20-Poly1305 is constant-time everywhere. AES-256-GCM stays HW-gated
  (matches ADR-0007 §1.3).
- **Random 96-bit nonces per frame** — Rejected: birthday bound (~2³² frames before non-negligible
  collision probability) is *far* below our per-key frame volume and a single collision is
  catastrophic for ChaCha20-Poly1305. Deterministic counter nonces have zero collision risk by
  construction.
- **Strict monotonic counter (no replay window)** — Rejected: breaks media on QUIC datagrams
  (unordered, drop-allowed). A bounded sliding window is required.
- **Purely deterministic rekey (no in-band signal)** — Rejected: datagram loss desyncs message
  counts and clocks drift, so two peers would disagree on the epoch boundary. We make the
  **authenticated epoch field in the frame header** the ground truth and use a Control-channel
  `RekeyRequest` as an early heads-up.
- **Per-frame DH ratchet (Signal Double Ratchet)** — Rejected for P3-4: a DH step per frame is far
  too costly for 60 fps media and unnecessary given the session is already mutually authenticated
  with PFS ephemerals. A symmetric HKDF ratchet + periodic rekey gives the needed FS at media rates.
- **One key per channel, shared across both directions** — Rejected: shared key + two senders ⇒
  nonce-space collision risk and reflection attacks. Separate i2r/r2i keys are mandatory.
