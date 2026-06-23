# ADR 0010: Authorization (sealed capability mask), UGC, epoch-floor revocation, and kill-switch

- **Status:** Proposed
- **Date:** 2026-06-22
- **Deciders:** security-engineer, rust-staff-engineer, software-architect, code-reviewer
- **Resolves:** LLD §6.4 (authorization / kill-switch / revocation), §6.1 (UGC custody),
  §6.5 (threat-model deltas: stolen-UGC replay, mid-session escalation, offline revocation).
- **Builds on:** ADR-0006 (`DeviceIdentity` / `Keystore::sign` / `verify_strict`), ADR-0007
  (Noise — `HandshakeOutcome.peer_identity` is the authenticated grantee identity; canonical
  length-prefixed domain-separated signed-blob discipline = the BindCert pattern this ADR mirrors),
  ADR-0009 (`SessionKeys::zeroize_all()` — the kill-switch seam: wipes channel keys + the session PRK
  so post-kill ciphertext fails AEAD).
- **Phase / task:** P3-5 (`IMPLEMENTATION_PLAN.md`). **Design only** — the implementer
  (`rust-staff-engineer`) builds to the companion spec below in `sh-core`, using `sh-crypto`.

## Context

Streamhaul grants **full remote control of a machine** over a hostile network through a
**zero-knowledge relay**. P3-1..P3-4 established a confidential, authenticated, key-rotating channel:
the peer that completes the Noise handshake is a *cryptographically authenticated device identity*
(`HandshakeOutcome.peer_identity`, ADR-0007), and all six channels (Video/Audio/Input/Clipboard/File/
Control, `sh-types::ChannelId`) are E2E-encrypted (ADR-0009). What is still missing is the layer that
decides **what an authenticated peer is allowed to do** — and the ability to **stop it instantly**.

The forces (LLD §6.4, §6.5):

1. **Authentication ≠ authorization.** A verified `peer_identity` proves *who* is connected, not *what*
   they may do. A controller paired for view-only must not be able to inject keystrokes. The grant is
   the **intersection** of four independent sources — `{device ACL, UGC.caps, attended selection,
   account policy}` — and the product invariant is **most-restrictive wins**: any source can only
   *remove* capability, never add it.

2. **Non-escalatability is a hard requirement.** The single worst failure for a remote-control product
   is mid-session privilege escalation: a peer that negotiates VIEW and then talks its way up to INPUT.
   The mask must be **host-authoritative**, **sealed immutable at session start**, and the peer must
   have **no in-band API to widen it**. `ELEVATION` (admin/UAC-class actions) additionally requires
   *fresh* presence/MFA — it can never be satisfied by a cached grant.

3. **Unattended access must be hardware-bound and offline-revocable.** Unattended grants are carried by
   a host-signed **Unattended Grant Certificate (UGC)** (LLD §6.1): `{grantee device_id, caps, epoch,
   not_after}`, signed by the *host* identity. A UGC is **inert without the grantee's hardware key** —
   it only authorizes the device whose identity equals the **live, authenticated Noise
   `peer_identity`**, so a stolen UGC file is useless to a thief who lacks the grantee's
   non-exportable key. Revocation must work **with zero network** (a compromised host may be offline or
   the relay may be down) and must **survive restart**: a host-local **monotonic `min_epoch`** floor;
   bumping it instantly invalidates every sub-epoch UGC.

4. **The kill-switch must be instant, local, and irreversible-for-the-session.** "Stop now" cannot
   depend on the network, on the relay, or on the peer cooperating. ADR-0009 gave us the seam:
   `SessionKeys::zeroize_all()` wipes the channel keys *and* the session PRK in RAM, so any subsequent
   ciphertext fails AEAD — no input frame can be opened, therefore **no input actuates**, with no
   packet sent. The kill-switch also bumps `min_epoch` so a re-handshake replaying the same UGC is
   rejected too.

5. **Zero-knowledge boundary is preserved.** The authorizer runs **host-side**. The relay/signaling
   sees only opaque ciphertext and public fingerprints (LLD §6.3); it never sees the capability mask,
   the UGC contents (UGC rides inside the encrypted handshake/control channel like the BindCert,
   ADR-0007 §2.5), or the kill decision.

This ADR fixes the capability set, the intersection/seal rules, the exact UGC byte layout and its five
verification checks, the epoch-floor semantics, and the kill-switch wiring. It is **design only**.

## Decision

### 1. Capability model

#### 1.1 The capability set — a `bitflags` `Capabilities`

```rust
bitflags! {
    pub struct Capabilities: u32 {
        const VIEW      = 1 << 0;  // observe the screen (Video channel) — the baseline grant
        const CONTROL   = 1 << 1;  // pointer + keyboard injection (Input channel)
        const CLIPBOARD = 1 << 2;  // read/write the host clipboard (Clipboard channel)
        const FILE      = 1 << 3;  // start/receive file transfers (File channel)
        const AUDIO     = 1 << 4;  // receive host audio (Audio channel)
        const ELEVATION = 1 << 5;  // perform admin/UAC-class actions — requires FRESH presence/MFA
    }
}
```

Decisions baked into the set:

- **`VIEW` is the floor for a useful session** but is *not* implied by any other cap — each cap is an
  independent bit. A grant of `CONTROL` without `VIEW` is *valid and representable* (e.g. blind input
  for automation); the model does not silently add `VIEW`. (Product UX may default to granting `VIEW`,
  but that is a policy choice expressed by the *sources*, not a hard-coded implication in the bitflags.)
- **`CONTROL` is the merged pointer/key cap** (the task spec lists `CONTROL` and `INPUT` separately;
  we collapse them — both gate the single `ChannelId::Input` channel, and splitting "pointer" from
  "key" buys no security and doubles the matrix; if a future product needs key-only, add
  `CONTROL_POINTER` / `CONTROL_KEY` bits then and keep `CONTROL` as their union). This is recorded as
  a deliberate simplification, not an omission.
- **`ELEVATION` is special**: it is *never* satisfied by a UGC alone or by a cached attended selection.
  The sealed mask may *carry* the `ELEVATION` bit, but `authorize` for any `ELEVATION`-class action
  additionally requires a **fresh-presence token** that this task **models but does not implement**
  (see §1.4). Without a valid fresh-presence proof, an `ELEVATION` action is denied even if the bit is
  set. This makes "the mask has ELEVATION" necessary-but-not-sufficient.
- `u32` width leaves head-room for future bits (e.g. `RECORDING`, `WAKE`, `CONTROL_KEY`) without a
  layout change; the UGC encodes the full `u32` (§2.1).

#### 1.2 Capability → channel/action mapping (the enforcement table)

Every privileged host-side action maps to exactly one required capability. This table is the
authoritative bridge between the abstract cap and the concrete operation:

| `PrivilegedAction`              | Required cap | Channel(s) it touches  |
|---------------------------------|--------------|------------------------|
| `ViewFrame` (decode/display)    | `VIEW`       | `ChannelId::Video`     |
| `InjectPointer` / `InjectKey`   | `CONTROL`    | `ChannelId::Input`     |
| `ReadClipboard` / `WriteClipboard` | `CLIPBOARD` | `ChannelId::Clipboard` |
| `StartFileTransfer` / `ReceiveFile` | `FILE`   | `ChannelId::File`      |
| `PlayAudio` (host→controller)   | `AUDIO`      | `ChannelId::Audio`     |
| `ElevatedAction(kind)`          | `ELEVATION` **+ fresh presence** | (host OS API) |

`ChannelId::Control` (the reliable control channel) carries no user payload that itself needs a cap;
it carries the authorization/UGC/kill control messages, which are gated by handshake authentication,
not by the mask.

#### 1.3 The intersection: most-restrictive of four sources

At session start the host computes:

```text
sealed_caps = device_acl_caps
            & ugc_caps               // VIEW-only default if unattended; see §2
            & attended_selection     // what the human at the host approved this session (or ALL if unattended)
            & account_policy_caps    // org/account ceiling
```

`&` is bitwise AND. **Each source is a ceiling, never a floor** — a source can only clear bits. The
type system enforces this: the only constructor takes the four `Capabilities` values and ANDs them;
there is no method that ORs caps into a sealed mask. Absent sources are represented by `Capabilities::all()`
(a neutral element of AND), never by `empty()`, so "this source imposes no restriction" is explicit and
auditable — and a *missing* source can never widen the result. (An attended-only session with no UGC
passes `Capabilities::all()` for `ugc_caps`; an unattended session passes the verified `ugc.caps`.)

#### 1.4 Fresh-presence for `ELEVATION` (modeled, not implemented)

`authorize(ElevatedAction(..))` requires, in addition to the `ELEVATION` bit, a `FreshPresence` proof:

```rust
/// Opaque proof that a human approved an elevation within a bounded recent window.
/// P3-5 models the *requirement*; the WebAuthn/FIDO2 verification is a later task (R-ELEVATION-MFA).
pub struct FreshPresence { granted_at: i64, /* opaque token bytes (deferred schema) */ }
```

`SessionAuthorizer` holds `Option<FreshPresence>`, defaulting to `None`. `authorize` checks both the
bit **and** that a `FreshPresence` exists and is within a configured freshness window (evaluated
against the injected `Clock`). P3-5 ships the gate and the deny path; the actual MFA/WebAuthn issuance
is deferred (see Follow-ups / Risk `R-ELEVATION-MFA`). Crucially, fresh-presence is **inbound host-side
state**, never a peer-supplied field — the peer cannot mint it.

#### 1.5 The seal — immutable, host-authoritative, no widen API

`SessionAuthorizer::seal(...)` consumes the four sources, computes the intersection, and stores it in a
**private, non-`pub`** field. There is:

- **no setter, no `add_capability`, no `merge`, no `widen`** — the public surface offers only
  `authorize(&self, action)` and read-only `capabilities(&self) -> Capabilities` (for the host UI to
  display what is granted). Non-escalatable = *there is literally no API path that produces a wider mask
  on a sealed authorizer.*
- **no in-band control message** that mutates the mask. The peer's only authorization-relevant input is
  the UGC presented *at handshake/session start* (which only ever *restricts*, via intersection); after
  `seal`, nothing the peer sends can change `sealed_caps`.
- The authorizer is **host-side**; the controller has its own advisory copy for UX, but the host's
  `authorize` is the ground truth that gates every actuation. A controller that lies about its caps is
  irrelevant — the host enforces independently.

A capability *reduction* mid-session (host operator revokes CONTROL live) is modeled as **re-sealing a
new authorizer** (a new, narrower mask replaces the old) or as the kill-switch — never as mutating the
existing sealed mask upward. Reduction-only live changes (AND a removal mask) are permitted as a
follow-up; they cannot violate non-escalatability because they only clear bits.

#### 1.6 The enforcement seam

```rust
impl SessionAuthorizer {
    pub fn authorize(&self, action: PrivilegedAction) -> Result<(), Denied>;
}
```

**Every** privileged host-side action — inject input, read/write clipboard, start a file transfer,
play audio, elevate — calls `authorize(action)` and proceeds only on `Ok(())`. The host shims (input
injector, clipboard bridge, file service) take an `&SessionAuthorizer` and **must** gate their public
entry points through it. `Denied` carries the attempted action and the required-vs-held caps for the
host-side audit log (a later task, §threat-model), but **never** echoes secret material and is safe to
log (UGC and caps are not secret; the host signing key is never in scope here).

### 2. UGC — Unattended Grant Certificate

The UGC mirrors the BindCert discipline of ADR-0007 §2 **exactly**: a canonical, fixed-order,
fixed-width / explicitly length-prefixed, big-endian, domain-separated, **single-valid-encoding**
signed blob. A signed structure with parsing ambiguity is an attack surface; there is exactly one valid
encoding of a given UGC.

#### 2.1 Canonical TBS ("to-be-signed") byte layout

```text
UGC_TBS (the bytes that are signed AND re-checked at verification):

  offset  size  field
  ──────  ────  ─────────────────────────────────────────────────────────────
       0    11  DOMAIN_TAG          = b"SHP-UGC\x00\x00\x00\x00"  (11 ASCII bytes,
                                      DISTINCT from b"SHP-BINDCERT" (12) and the SAS
                                      domain — see §2.2). Different length AND different
                                      bytes ⇒ no signed blob can be confused for another.
      11     1  TBS_VERSION         = 0x01
      12     1  FIELD_COUNT         = 0x05   (defensive: number of semantic fields below)
      13    32  GRANTEE_DEVICE_ID   = SHA-256(grantee Ed25519 pubkey) raw 32-byte digest
                                      (the grantee's device_id; raw digest, NOT hex — matches
                                      DeviceIdentity::fingerprint() raw form, ADR-0006/0007)
      45     4  CAPS                = u32 BE — the Capabilities bitflags granted by this UGC
      49     8  EPOCH               = u64 BE — this UGC's epoch (revocation generation)
      57     8  NOT_AFTER           = i64 BE, Unix epoch seconds (UTC), absolute expiry
      65     8  ISSUED_AT           = i64 BE, Unix epoch seconds (UTC), issuance time
                                      (anti-backdating; NOT_AFTER > ISSUED_AT enforced)
```

- Total TBS length is **73 bytes**, fixed (no variable fields → no length-prefix needed inside the TBS;
  the wire form length-prefixes the whole TBS, §2.3).
- All multi-byte integers are **big-endian**, matching SHP (LLD §3.1) and the BindCert.
- `CAPS` carries the full `u32` so unknown future bits round-trip; the verifier **masks to known bits**
  before sealing (an attacker who sets a reserved bit cannot smuggle an undefined capability — unknown
  bits are dropped by `Capabilities::from_bits_truncate`-style masking, never honored).
- `DOMAIN_TAG` + `TBS_VERSION` give domain separation. The host signing key (`Keystore::sign`, P3-1)
  signs **raw bytes with no framing**, so the *encoder* is responsible for prepending the domain tag —
  this is mandatory and is the only thing preventing a UGC signature from being replayed as a BindCert,
  SAS, or audit-receipt signature.

#### 2.2 Domain-tag distinctness (must be impossible to confuse)

| Signed structure | Domain tag (first bytes) | Length |
|------------------|--------------------------|--------|
| BindCert (ADR-0007) | `b"SHP-BINDCERT"` | 12 |
| UGC (this ADR)      | `b"SHP-UGC\x00\x00\x00\x00"` | 11 |
| SAS / PAKE confirm (ADR-0008) | distinct labels (HKDF `info`, not Ed25519-signed blobs) | — |

The UGC tag is a different length *and* different bytes from the BindCert tag, and UGC is the only
`Keystore::sign`-signed structure that is `11` bytes-prefixed — a cross-protocol signature confusion is
ruled out by construction. The implementer **must** add a conformance test that asserts the three tags
are pairwise non-prefixes of one another.

#### 2.3 Wire form (signed UGC)

```text
UGC (on the wire, inside the encrypted handshake/Control-channel payload):
    lp32(UGC_TBS)              // 4-byte BE length prefix + the 73-byte TBS
    || SIGNATURE[64]           // Ed25519 signature over EXACTLY the TBS bytes (host identity)
```

The verifier verifies over the **received TBS slice**, never a re-encode, to avoid any canonicalization
mismatch (same rule as ADR-0007 §2.2). Like the BindCert, the UGC travels **inside the encrypted
handshake/control payload**, never in the SDP/signaling — the relay never sees it (zero-knowledge).

#### 2.4 Verification — the five mandatory checks (all must pass; any failure → reject)

`Ugc::verify(host_identity, grantee_peer_identity, min_epoch, clock)` performs, **in order**:

1. **Parse panic-free / canonical** — `lp32` length within bounds, `DOMAIN_TAG` / `TBS_VERSION` /
   `FIELD_COUNT` exact, total length == `4 + 73 + 64`. Any mismatch → `MalformedUgc` (see
   §hostile-input). No `unwrap`/`panic`/slice-index-without-bounds-check on attacker bytes.
2. **Signature** — `Signature::verify(host_identity, UGC_TBS)` using `verify_strict` (ADR-0006:
   rejects small-order keys / non-canonical sigs). `host_identity` is the **pinned host
   `DeviceIdentity`** (the trust root for this host, from the keystore). Fail → `UgcBadSignature`.
3. **Grantee binding (the crux — defeats stolen-UGC replay)** — `GRANTEE_DEVICE_ID` MUST byte-equal
   `grantee_peer_identity.fingerprint()` raw digest, where `grantee_peer_identity` is the
   **authenticated Noise `peer_identity`** (`HandshakeOutcome`, ADR-0007). Compared in **constant
   time** (`subtle::ConstantTimeEq`). Mismatch → `UgcWrongGrantee`. *A stolen UGC presented by a
   different device fails here because that device cannot become the authenticated `peer_identity`
   without the grantee's non-exportable key.*
4. **Expiry** — `NOT_AFTER > clock.now_unix_secs()` **and** `ISSUED_AT <= now` (small injected skew
   tolerance) **and** `NOT_AFTER > ISSUED_AT`, against the **injected `Clock`** (no `SystemTime::now`
   in testable code). Expired / not-yet-valid / backdated → `UgcExpired`.
5. **Epoch floor (offline revocation)** — `EPOCH >= min_epoch` (the host-local floor, §3). A UGC with
   `EPOCH < min_epoch` → `UgcRevoked`.

Only if **all five** pass does `verify` return the masked `Capabilities` (`from_bits_truncate(CAPS)`),
which is then fed as `ugc_caps` into the §1.3 intersection. There is no partial-trust path; any failure
aborts the unattended grant (the session may still proceed attended if a human approves, per the
sources, but the *UGC* contributed nothing).

### 3. Epoch-floor revocation

- The host holds a **monotonic `min_epoch: u64`**, the revocation floor. `current() -> u64` reads it;
  `bump(new_floor)` sets it to `max(current, new_floor)` (monotonic — can never go backward, so a
  replayed/old "un-revoke" is impossible). `bump_min_epoch()` = `bump(current + 1)` revokes everything
  at-or-below the current epoch instantly.
- **Zero-network, fail-closed, offline-survivable.** Revocation is a *local floor check* (UGC verify
  step 5). No CRL fetch, no relay round-trip; works fully offline. The default posture is **deny**: if
  the floor store is unreadable at startup, the host treats `min_epoch` as *higher* than any plausible
  issued epoch (fail-closed), not lower.
- **Persistence (must survive restart).** A UGC's whole point is unattended access across reboots; the
  floor MUST be durable or a reboot would silently un-revoke. The **storage seam** is a
  `MinEpochStore` trait (`load() -> u64`, `persist(u64)`); the **portable slice (P3-5) ships an
  in-memory implementation** for tests/loopback, and a durable backend (host config file / OS keystore
  metadata, atomic write, monotonic-guarded) is wired by the host platform layer as a **follow-up**
  (R-EPOCH-PERSIST). The in-memory note is explicit so no one assumes durability is delivered.
- **Bump-then-reject** is the revocation primitive: bumping the floor above a previously-valid UGC's
  epoch makes that UGC fail step 5 on its *next* verification — including a re-handshake (which is why
  the kill-switch bumps the floor, §4).

### 4. Kill-switch

`SessionAuthorizer::kill(&mut self, keys: &mut SessionKeys)` performs, in order, **panic-free and
idempotent**:

1. **`keys.zeroize_all()`** (ADR-0009) — wipes both epoch key sets *and* the session PRK in RAM. After
   this, `seal()`/`open()` on any channel **fail AEAD** (`MalformedChannelFrame` / decrypt error), and
   `rekey()` cannot re-derive keys (the PRK is gone). **Consequence:** no inbound Input frame can be
   opened → **no input actuates**; no outbound frame can be sealed → the session is cryptographically
   dead. **No packet is sent and no network is needed.**
2. **`min_epoch.bump_min_epoch()`** — raises the floor above the current session's UGC epoch, so a
   peer that re-handshakes and **replays the same UGC** fails UGC verify step 5 (`UgcRevoked`). Kill is
   thus not merely "drop this session" but "this grant generation is dead."
3. **Mark the authorizer killed** — an internal `killed: bool` flag; after `kill`, `authorize(_)`
   returns `Denied::Killed` for *every* action regardless of the sealed mask (belt-and-suspenders: even
   if some action path doesn't touch the AEAD, it is still denied).

**State wiped:** all channel AEAD keys, the prior-epoch grace keys, and the session PRK (via
`zeroize_all`). **Irreversible for the session:** there is no `revive()`; recovering control requires a
fresh handshake (new ephemerals, new PRK) *and* a UGC whose epoch is above the bumped floor (i.e. a
freshly re-issued grant) or fresh attended approval. **Idempotent:** calling `kill` twice is a no-op on
the second call (`zeroize_all` is idempotent per ADR-0009; `bump` is monotonic; `killed` is already
set). **Panic-free:** no `unwrap`/`expect`; `&mut SessionKeys` is borrowed, never moved, so a double
call is well-defined.

### 5. Threat model

| Threat | How this design defeats it |
|--------|----------------------------|
| **Stolen-UGC replay** | UGC verify **step 3**: `GRANTEE_DEVICE_ID` must equal the authenticated Noise `peer_identity`. The thief cannot become that identity without the grantee's non-exportable hardware key (R-HW-KS at GA). The UGC file alone is inert. Constant-time compare avoids a fingerprint-matching timing oracle. |
| **Mid-session escalation (negotiate VIEW, grab CONTROL)** | The mask is **sealed immutable** at session start (§1.5). No setter, no merge, no in-band control message widens it. The peer's only authz input is the at-start UGC, which only ever *restricts* via intersection. `authorize` re-checks the sealed mask on **every** action. |
| **Offline revocation** | **Epoch floor** (§3): `bump_min_epoch()` revokes all sub-epoch UGCs with **zero network**, fail-closed, surviving restart (durable store seam). A UGC with `epoch < min_epoch` → `UgcRevoked`. |
| **Forged UGC** (attacker mints one) | UGC verify **step 2**: Ed25519 `verify_strict` against the **pinned host identity**. The attacker lacks the host signing key (hardware-non-exportable at GA, R-HW-KS), so cannot produce a valid signature. Domain tag (§2.2) prevents reusing some *other* host signature (BindCert/audit) as a UGC. |
| **Tampered UGC** (flip caps/epoch/expiry bits) | Any mutation of the TBS bytes breaks the signature → step 2 reject. Canonical single-encoding (§2.1) removes field-splicing / re-ordering attacks. Unknown `CAPS` bits are truncated, not honored. |
| **Wrong-grantee UGC** (valid UGC for device A, presented by device B) | Step 3 mismatch → `UgcWrongGrantee`. The UGC binds to a *specific* grantee device_id; presenting it from another authenticated identity fails. |
| **Expired / backdated UGC** | Step 4: `NOT_AFTER`/`ISSUED_AT`/skew checks against the **injected clock**. Expired or `ISSUED_AT` in the future or `NOT_AFTER <= ISSUED_AT` → `UgcExpired`. |
| **Kill-switch race** | `kill` is **local and synchronous**: `zeroize_all` wipes RAM keys before returning; any in-flight or subsequent frame fails AEAD. No network is involved, so there is no remote race to lose. The only frames that could be actuated are those already *decrypted and dispatched* before `kill` returned — bounded by the host's per-frame processing, and the injection shims also re-check `authorize` (which returns `Killed`). |
| **Kill-then-reconnect with same UGC** | `kill` bumps `min_epoch`; the replayed UGC now fails step 5 (`UgcRevoked`). Reconnect needs a *re-issued* UGC above the new floor (or fresh attended approval). |
| **Escalation via reserved/unknown cap bits** | Verifier masks `CAPS` to known bits (`from_bits_truncate`); an attacker setting bit 31 grants nothing. |
| **`ELEVATION` without a human** | `authorize(ElevatedAction)` requires the `ELEVATION` bit **and** a fresh-presence proof within the freshness window (§1.4). A cached UGC with the bit set but no fresh presence → denied. (Fresh-presence issuance deferred — R-ELEVATION-MFA.) |
| **Relay/signaling reads the grant** | The authorizer runs **host-side**; the UGC rides inside the encrypted handshake/control payload; the mask and kill decision never leave the host. The relay sees only opaque ciphertext + public fingerprints (LLD §6.3). **Zero-knowledge boundary confirmed.** |

#### 5.1 Out of scope for P3-5 (explicit — separate tasks)

- **Hash-chained audit log** (LLD §6.4, tamper-evident head-hash anchoring of every `authorize` /
  `kill` / UGC-verify event) — **OUT OF SCOPE**. P3-5 makes `Denied` carry enough context to feed such
  a log later; building the chain is a follow-up.
- **Recording-key envelope / HPKE** (LLD §6.1, ADR-0005: per-recording DEK wrapped to a recipient set,
  customer-KMS escrow) — **OUT OF SCOPE**, a separate task.
- **Durable `min_epoch` persistence backend** — seam defined; in-memory only in P3-5 (R-EPOCH-PERSIST).
- **Fresh-presence / WebAuthn-FIDO2 MFA issuance for `ELEVATION`** — gate modeled; issuance deferred
  (R-ELEVATION-MFA).
- **Hardware-non-exportable host signing key** — the UGC trust depends on it at GA (R-HW-KS, P3-1);
  P3-5 verifies against whatever `DeviceIdentity` the keystore provides (software in the portable slice).

## Consequences

- **Positive:**
  - Authentication and authorization are cleanly separated; an authenticated peer is gated on every
    privileged action by a host-authoritative, **sealed, non-escalatable** capability mask.
  - Most-restrictive intersection is enforced by the *type* (AND-only constructor, no widen API), so
    "a source can only remove caps" is a structural guarantee, not a convention.
  - The UGC mirrors the audited BindCert discipline (canonical, domain-separated, fuzzed) and binds to
    the live grantee identity → stolen-UGC replay is inert; forgery/tamper/wrong-grantee/expiry each
    have an explicit reject path.
  - Epoch-floor revocation is zero-network, fail-closed, offline-survivable; the kill-switch reuses the
    audited `zeroize_all` seam (ADR-0009) so "stop now" is instant, local, idempotent, and
    irreversible-for-the-session, and a same-UGC reconnect is also dead.
  - Zero-knowledge boundary preserved — the authorizer is host-side only.

- **Negative / trade-offs:**
  - `CONTROL` merges pointer+key; a future key-only grant needs new bits (noted, low cost).
  - `min_epoch` durability and `ELEVATION` MFA are *seams*, not implementations, in P3-5 — the
    portable slice is in-memory; a deployment must wire the durable backend and MFA before relying on
    them (Risk Register).
  - A sealed mask cannot be *raised* live; live privilege *reduction* requires re-sealing or kill. This
    is intentional (non-escalatability) but means UX "grant more mid-session" = re-handshake/re-seal.
  - Kill bumps `min_epoch`, so the operator must re-issue a UGC (new epoch) to restore unattended
    access — a deliberate fail-closed cost.

- **Follow-ups:**
  - **Hash-chained audit log** of authz/kill/UGC events (LLD §6.4). `Denied` already carries context.
  - **R-EPOCH-PERSIST:** durable, atomic, monotonic-guarded `MinEpochStore` backend per platform.
  - **R-ELEVATION-MFA:** WebAuthn/FIDO2 fresh-presence issuance + `FreshPresence` schema/verification.
  - **Recording-key envelope** (ADR-0005 / LLD §6.1) — separate task.
  - **Live reduction-only re-seal** API (AND a removal mask) for mid-session cap narrowing without kill.
  - **UGC issuance path** (host signs a UGC at enrollment, gated by enrollment-time WebAuthn) — P3-5
    delivers verify + the byte layout; the *issuer* tooling/UX is a companion task.
  - Add a `UGC_TBS` **conformance vector** + the domain-tag-distinctness test to the corpus.

## Alternatives considered

- **Mutable capability mask with an "upgrade" control message** — Rejected outright. An in-band widen
  API is the exact mid-session-escalation vector the product cannot afford (LLD §6.5). The mask is
  sealed; widening requires a fresh, separately-authorized handshake/seal.
- **Capabilities as an additive (OR) set built up from sources** — Rejected. OR-of-sources lets a
  permissive source *grant* what a restrictive one denied; the invariant is most-restrictive, which is
  AND. Modeling absent sources as `all()` (AND identity) keeps "no restriction" explicit without
  letting a missing source widen the grant.
- **Push-CRL / online revocation check** — Rejected as the primary mechanism. The host may be offline
  and the relay is untrusted; revocation must be local and fail-closed. The **epoch floor** gives
  instant, zero-network, restart-surviving revocation. (An online "re-issue stapled allow-list" is a
  complementary optimization, not the trust anchor — LLD §6.4.)
- **UGC as a JWT / X.509 / CBOR-COSE structure** — Rejected. General certificate/token formats are
  notorious parser attack surfaces (alg-confusion, optional fields, canonicalization bugs). We need one
  tiny, fixed-layout, single-valid-encoding signed blob — the same minimal-cert philosophy as the
  BindCert (ADR-0007). 73 fixed TBS bytes, one domain tag, `verify_strict`.
- **Kill-switch that just closes the transport / signals the peer** — Rejected as insufficient. A
  transport close is cooperative and network-dependent; a malicious peer or a wedged relay could ignore
  or delay it. Zeroizing the RAM keys makes the session **cryptographically** dead with no packet and
  no cooperation — the only race-free local kill.
- **Kill-switch that does NOT bump `min_epoch`** — Rejected. Without the floor bump, a killed session's
  UGC is still valid and the peer could simply re-handshake and replay it. Bumping the floor makes the
  kill cover the *grant generation*, not just the TCP/QUIC session.
- **Splitting `CONTROL` into `POINTER` and `KEY` now** — Deferred, not adopted. Both gate one channel;
  splitting doubles the matrix for no current security gain. `u32` width reserves room to add the split
  later without a layout change.
