# ADR 0007: Noise tunnel handshake and identity-bound BindCert

- **Status:** Accepted
- **Date:** 2026-06-22
- **Deciders:** security-engineer, rust-staff-engineer, network-engineer, code-reviewer
- **Resolves:** LLD §9 open item R1 ("pin the concrete Noise pattern names before Phase 3"),
  builds on ADR-0005 (SHA-256 Noise hash) and ADR-0006 (Ed25519 trust root).
- **Phase / task:** P3-2 (`IMPLEMENTATION_PLAN.md`).

## Context

Streamhaul grants **full remote control of a machine** over a hostile network through a
**zero-knowledge relay**. The authentication handshake is therefore the single most
security-sensitive component in the product: a flaw here means an attacker steers a victim's
mouse and keyboard, reads their screen, and exfiltrates their files. The relay and signaling
infrastructure are **explicitly untrusted** (LLD §6.3): they see only opaque ciphertext, public
`device_id` fingerprints, and routing metadata.

The LLD (§6.2/§6.3) fixes the shape of the solution but left the concrete primitives open:

1. The pairing handshake must **hide the controller's (initiator's) long-term identity from the
   relay**, because the relay learns *who is connecting to whom* otherwise. Post-pairing
   handshakes should be **1-RTT** (latency budget, LLD §3.4) and may reveal less because the host
   static is already pinned.
2. Device identity is **Ed25519** (ADR-0006, the trust root, hardware-non-exportable at GA). Noise
   uses **X25519** static keys for ECDH. These are *different keys on different curves*; nothing in
   raw Noise binds the X25519 static a peer presents to the Ed25519 identity the operator pinned.
   Without an explicit binding, a relay/host that controls an X25519 static can run a clean MITM:
   Noise authenticates "you are talking to whoever owns this X25519 key," not "you are talking to
   the device the operator trusts."
3. The WebRTC path (P4) authenticates media via a DTLS-SRTP fingerprint that is **delivered in the
   SDP through the untrusted signaling server**. That fingerprint must be committed under the
   trusted identity, not trusted as received.

The forces: pin **vetted, standard** Noise patterns (CLAUDE.md §7 — never roll crypto); share one
hash primitive (SHA-256) with the SAS and BindCert (ADR-0005) so we carry one digest; bind the
X25519 Noise static to the Ed25519 identity with **zero ambiguity** in the signed bytes (a parsing
ambiguity in a signed structure is an attack); keep the parser **panic-free and fuzzed** (every
handshake byte is attacker-controlled); and wrap **`snow`** (unaudited — LLD §7.3) behind a thin
seam so it can be swapped and reviewed before GA.

This ADR decides the concrete patterns, the exact `BindCert` byte layout, the identity↔Noise
binding argument, and the seam by which the handshake hands keys to P3-3 (SAS) and P3-4 (channel
key hierarchy). It is **design only**; the implementer (`rust-staff-engineer`) builds to the
companion spec in `crates/sh-crypto`.

## Decision

### 1. Concrete Noise patterns (resolves LLD §9 / R1)

| Phase | Pattern | Role assignment |
|-------|---------|-----------------|
| **First pairing** | `Noise_XK_25519_ChaChaPoly_SHA256` | initiator = controller/client; responder = host |
| **Post-pairing connect** | `Noise_IK_25519_ChaChaPoly_SHA256` | initiator = controller/client; responder = host |

- **Curve / DH:** **X25519** static and ephemeral keys (Noise `25519` token). Distinct from the
  Ed25519 identity key; the two are bound by the BindCert (§2/§3). X25519 via `x25519-dalek` 2.x
  with `zeroize`.
- **AEAD:** **ChaCha20-Poly1305** (`ChaChaPoly`). Constant-time in software on every target without
  AES-NI (mobile/ARM thin clients, LLD §1), no timing-side-channel exposure, matches the LLD §6.3
  default. **AES-256-GCM is a documented alternative** selected *only* when both peers advertise
  hardware AES (AES-NI / ARM crypto extensions) **and** a future capability flag enables it; it is
  **not** in the P3-2 scope. The pattern name string changes accordingly
  (`Noise_*_25519_AESGCM_SHA256`) and is itself bound by the prologue (§1.4), so a downgrade to a
  weaker/unwanted suite cannot be silently negotiated by the relay.
- **Hash:** **SHA-256** (`SHA256`), per ADR-0005, so the handshake hash `h`, the SAS derivation
  (P3-3), and BindCert hashing all share one primitive.

#### 1.1 Why XK at first pairing

`Noise_XK`:
- The responder's (host's) static is **known to the initiator ahead of time** (`K` = "known"), so
  the initiator can encrypt to it from the first message — appropriate for pairing, where the
  controller has just learned the host's static out-of-band (pairing code / QR / SAS channel).
- The initiator's static is transmitted **encrypted** (`X` = "transmitted", and in XK it is sent in
  message 3 under a key derived from a completed ephemeral-static DH), so the **relay never sees the
  controller's static public key** in cleartext. This is the identity-hiding property the LLD §6.2
  demands: the relay cannot build a "who pairs with whom" graph from observed statics.
- XK provides mutual authentication and forward secrecy after the handshake completes.

The cost is **1.5 RTT** (three handshake messages). That is acceptable: pairing is a rare,
human-in-the-loop, attended event (a SAS is compared), not a hot reconnect path.

#### 1.2 Why IK post-pairing

After pairing, the host's static is **pinned** in the controller's trust store (the BindCert from
the pairing run committed it), so reconnects use `Noise_IK`:
- `I` = the initiator sends its static **immediately**, encrypted to the responder's known static in
  message 1; `K` = responder static known in advance. This is **1-RTT** (LLD §3.4 budget: QUIC
  handshake ~110 ms, Noise inside it must not add a round trip).
- IK still encrypts the initiator's static to the responder's static, so a passive relay does not
  learn the initiator static in cleartext. (A relay that *is* the responder's static-holder could,
  but it cannot be — the responder static is BindCert-bound to the pinned host identity, §3.)
- IK is the standard "client reconnects to a known server" pattern; it is what WireGuard-class
  designs use, and `snow` implements it directly.

**XK-then-IK** is the deliberate sequence: pay 1.5-RTT and maximal initiator-identity hiding **once**
at pairing when a human is present, then drop to 1-RTT for every subsequent reconnect once trust is
pinned. Both directions of authentication are covered in both patterns.

#### 1.3 Suite summary (pinned)

```
Pairing : Noise_XK_25519_ChaChaPoly_SHA256
Connect : Noise_IK_25519_ChaChaPoly_SHA256
DH      : X25519            (static + ephemeral)
AEAD    : ChaCha20-Poly1305 (AES-256-GCM = HW-gated future alt, not P3-2)
Hash    : SHA-256           (shared with SAS + BindCert)
```

#### 1.4 Prologue (handshake binding / anti-downgrade)

Noise mixes the **prologue** into the handshake hash `h` before any message, so both peers MUST
agree on it byte-for-byte or every subsequent MAC fails. We bind the handshake to the SHP/session
context to defeat cross-protocol reuse and downgrade. The prologue is a **canonical,
length-prefixed, domain-separated** structure (same discipline as the BindCert, §2):

```
prologue = "SHP-NOISE\x00"                     // 10-byte ASCII domain tag (incl. NUL)
         || u8  prologue_version    (= 0x01)
         || u8  pattern_id          (0x01 = XK, 0x02 = IK)     // the negotiated pattern
         || u8  suite_id            (0x01 = 25519_ChaChaPoly_SHA256)  // AEAD/curve/hash suite
         || u16 shp_version_be      (SHP protocol version, LLD §3.1)
         || lp32(session_context)   // 4-byte BE length prefix + opaque session-binding bytes
```

- `session_context` binds the Noise run to the outer transport/session. For native QUIC it is the
  QUIC connection's TLS exporter (`quinn` `export_keying_material`, label `"shp noise binding"`),
  which **channel-binds** the Noise tunnel to *this* QUIC connection (an attacker cannot lift the
  Noise messages onto a different QUIC connection). For the loopback / P2 lab and tests it is a
  fixed test vector. For the future WebRTC path it is the DTLS exporter (defined in P4). If no
  binding is available the field is an explicit zero-length `lp32(empty)` — never omitted, so the
  layout is unambiguous.
- `pattern_id` and `suite_id` in the prologue mean a relay/MITM that tries to make the two sides run
  *different* patterns or suites produces **different `h` on each side → handshake MAC failure →
  abort**. This is the anti-downgrade guarantee.

`pattern_id`/`suite_id` are also echoed inside the capability handshake, but the prologue is the
**authenticated** copy — the capability JSON (LLD §3.1) is advisory and the prologue is the
cryptographic ground truth.

### 2. BindCert — structure, encoding, exchange, verification

`BindCert` binds, under the **Ed25519 identity signature** (the trust root), the **X25519 Noise
static** that the peer presents in *this* handshake, plus the WebRTC DTLS fingerprint commitment, a
platform-attestation placeholder, and an expiry.

```
BindCert payload (the signed bytes) =
    sign_Ed25519( identity_signing_key, BINDCERT_TBS )
```

#### 2.1 Canonical TBS ("to-be-signed") byte layout

Every field is fixed-width or explicitly length-prefixed, big-endian, in a fixed order, behind a
domain tag and a version byte. There is **exactly one** valid encoding of a given BindCert (no
optional fields, no variable ordering, no implicit lengths) — a canonical encoding is mandatory
because a signed structure with parsing ambiguity is an attack surface (signature confusion /
field-splicing).

```
BINDCERT_TBS (the bytes that are signed AND re-serialized for verification):

  offset  size  field
  ──────  ────  ─────────────────────────────────────────────────────────────
       0    12  DOMAIN_TAG          = b"SHP-BINDCERT" (ASCII, no NUL)
      12     1  TBS_VERSION         = 0x01
      13     1  FIELD_COUNT         = 0x06  (defensive: number of fields below)
      14    32  DEVICE_ID           = SHA-256(Ed25519 pubkey) raw digest (32 bytes)
                                      NOTE: raw 32-byte digest, NOT the 64-char hex
                                      fingerprint string. Hex is display-only (ADR-0006);
                                      the signed form is the raw digest.
      46    32  NOISE_STATIC_X25519 = the peer's X25519 static public key (32 bytes)
      78     1  DTLS_FPR_ALG        = 0x01 = SHA-256 ; 0x00 = none/native-only
      79    32  DTLS_FPR_COMMIT     = SHA-256 of the whole DTLS certificate (RFC 8122
                                      fingerprint, as computed and enforced by str0m), or
                                      32 zero bytes when DTLS_FPR_ALG = 0x00 (native QUIC,
                                      no DTLS). Consumed by P4-5 to pin the WebRTC
                                      fingerprint. [Amended by ADR-0014: was "SHA-256 of
                                      the DTLS certificate SPKI"; the engine exposes and
                                      enforces the whole-cert digest, so that is committed.]
     111     2  PLATFORM_ATTEST_LEN = u16 BE length L of the attestation blob (0..=4096)
     113     L  PLATFORM_ATTEST     = opaque attestation blob (schema deferred — §2.4)
   113+L     8  NOT_AFTER           = i64 BE, Unix epoch seconds (UTC), absolute expiry
   121+L     8  ISSUED_AT           = i64 BE, Unix epoch seconds (UTC), issuance time
                                      (anti-backdating; not_after > issued_at enforced)
```

- Total length is `129 + L` bytes; `L ≤ 4096` bounds the structure (DoS guard).
- All multi-byte integers are **big-endian**, matching SHP (LLD §3.1).
- `DOMAIN_TAG` + `TBS_VERSION` provide domain separation: an Ed25519 signature over a BindCert can
  never be replayed as a signature over an audit receipt, a UGC (ADR-0005), or any other signed
  structure, because every signed structure in the product carries a distinct domain tag as its
  first bytes. **This is mandatory** — the `Keystore::sign` method (P3-1) signs raw bytes with no
  framing, so the *caller* (the BindCert encoder) is responsible for the domain tag.
- `FIELD_COUNT` is a belt-and-suspenders constant the decoder asserts; a future version that adds a
  field bumps `TBS_VERSION` and `FIELD_COUNT` together.

#### 2.2 Wire form (signed BindCert)

```
BindCert (on the wire, inside the Noise handshake payload):
    lp32(BINDCERT_TBS)          // 4-byte BE length prefix + the TBS bytes above
    || SIGNATURE[64]            // Ed25519 signature over exactly the TBS bytes
```

The verifier re-derives the signed bytes by re-serializing the *parsed* TBS (or, equivalently,
verifies over the exact received TBS slice — the implementer MUST verify over the received bytes,
never a re-encode, to avoid any canonicalization mismatch; see spec §B).

#### 2.3 What each field binds, and why

| Field | Binds | Why it matters |
|-------|-------|----------------|
| `DEVICE_ID` | the Ed25519 identity (trust root) | ties the cert to the pinned identity; verifier checks this equals the identity that signed it (self-consistency) and is `is_trusted` |
| `NOISE_STATIC_X25519` | the X25519 key used in *this* Noise handshake | **the core binding**: verifier checks the live Noise static == this committed value → defeats key-substitution MITM (§3) |
| `DTLS_FPR_COMMIT` | the WebRTC DTLS cert (whole-cert SHA-256, RFC 8122; amended by ADR-0014) | lets P4-5 reject a signaling-swapped SDP fingerprint; the signed commitment, not the SDP, is authoritative |
| `PLATFORM_ATTEST` | hardware attestation (deferred) | future: proves the identity key lives in a real TPM/SE/StrongBox → defeats cloned-host with extracted-but-not-hardware key |
| `NOT_AFTER` / `ISSUED_AT` | validity window | bounds the blast radius of a leaked/stale BindCert; checked against an **injected clock** |

#### 2.4 `platform_attest` — deferred placeholder schema

`PLATFORM_ATTEST` is an **opaque, length-prefixed** field with a deferred internal schema, matching
the P3-1 hardware-keystore deferral (ADR-0006, R-HW-KS). For P3-2 it is either empty (`LEN = 0`) or
a self-describing TLV stub:

```
PLATFORM_ATTEST (when non-empty) =
    u8  attest_type        // 0x00 = none, 0x01 = tpm2_quote, 0x02 = apple_app_attest,
                           //        0x03 = play_integrity   (values reserved, not yet verified)
    u16 attest_body_len_be
    [attest_body_len] bytes  // opaque, NOT cryptographically verified in P3-2
```

**P3-2 treats `PLATFORM_ATTEST` as opaque and does NOT verify its contents.** It is signed (so it
cannot be tampered post-issuance) and carried, but normalization of TPM 2.0 quote vs Apple App
Attest vs Play Integrity into one verified schema is a **separate, later task** (LLD §9
"platform-attestation envelope"). The decoder MUST still bounds-check and reject `LEN > 4096`.
This is noted explicitly so no implementer assumes attestation is enforced yet.

#### 2.5 Exchange inside the handshake

The BindCert travels **as the Noise handshake payload**, encrypted under the handshake's running
AEAD — never in cleartext, never in the SDP/signaling:

- **XK (pairing):** the host (responder) sends its BindCert in the **payload of Noise message 2**
  (after the host's ephemeral and the first DH, so the payload is already encrypted). The controller
  (initiator) sends its BindCert in the **payload of message 3** (after its static is transmitted,
  so the relay sees neither the controller static nor its BindCert). Both BindCerts are thus
  confidential to the relay.
- **IK (connect):** the initiator's BindCert rides in the **message-1 payload** (IK encrypts the
  initiator static to the known responder static, so message 1 already has a key), and the
  responder's BindCert rides in the **message-2 payload**.

Carrying BindCert *inside* the encrypted handshake (not as a separate plaintext frame) means it is
confidential and is bound to *this* handshake's `h` — it cannot be lifted into another session.

#### 2.6 Verification (all checks mandatory; any failure → abort, zeroize, no retry-with-fallback)

On receiving the peer's BindCert, the verifier performs, **in order**:

1. **Parse panic-free**: `lp32` length within bounds, `DOMAIN_TAG`/`TBS_VERSION`/`FIELD_COUNT`
   exact, `PLATFORM_ATTEST_LEN ≤ 4096`, total length matches. Any mismatch → reject (§hostile-input).
2. **Signature**: `Signature::verify(peer_identity, BINDCERT_TBS)` using `verify_strict` (ADR-0006).
   `peer_identity` is the `DeviceIdentity` reconstructed from the BindCert's committed device key
   material as conveyed by the handshake (see spec §B for exactly which key object is used). The
   signature MUST verify; otherwise → reject.
3. **Identity self-consistency**: `DEVICE_ID` (raw digest) MUST equal `SHA-256(peer Ed25519 pubkey)`
   — the cert commits to the very identity that signed it. Mismatch → reject.
4. **Noise-static binding (the crux)**: `NOISE_STATIC_X25519` in the cert MUST byte-equal the **live
   Noise static public key** that `snow` reports for the remote peer (`get_remote_static()`).
   Compared in **constant time** (`subtle::ConstantTimeEq`). Mismatch → reject — this is the
   MITM/key-substitution defeat (§3).
5. **Expiry**: `NOT_AFTER > now()` and `ISSUED_AT ≤ now()` (with a small injected skew tolerance),
   `NOT_AFTER > ISSUED_AT`, evaluated against an **injected `Clock`** (no `SystemTime::now()` in
   testable code; deterministic tests). Expired/not-yet-valid → reject.
6. **Trust**: `peer_identity` MUST satisfy `Keystore::is_trusted` (post-pairing) **or** be presented
   to the TOFU pin path (first pairing, P3-3). Untrusted on a connect path → reject
   (`CryptoError::UntrustedPeer`).

Only if **all** pass does the handshake complete and `split()` proceed. There is no partial-trust
or downgrade-on-failure path: a failed BindCert check aborts the session and zeroizes handshake
state.

### 3. Identity ↔ Noise binding: the security argument

The Ed25519 device identity is the trust root (ADR-0006); the X25519 Noise static is bound to it by
the signed BindCert. The composite authenticated statement a verified handshake proves is:

> "The peer that completed this Noise handshake holds the X25519 static `S`, **and** an entity
> holding the Ed25519 identity `I` (which I have pinned / am pinning) signed a BindCert asserting
> *S belongs to I*, within its validity window, bound to this session's prologue."

Because the verifier checks the **live** Noise static equals the **signed** static (verification
step 4), an attacker cannot substitute its own static while replaying the victim's BindCert.

| Threat | How the binding defeats it |
|--------|----------------------------|
| **Relay / signaling MITM** | The relay carries only opaque ciphertext and the *public* fingerprint. To MITM it must present *some* X25519 static and a BindCert binding it to a *trusted* Ed25519 identity. It cannot sign such a BindCert (no identity key, hardware-non-exportable at GA), and the victim's BindCert binds the victim's static, not the relay's → step 4 mismatch → abort. |
| **WebRTC SDP-fingerprint swap** | The DTLS fingerprint is committed in `DTLS_FPR_COMMIT` under the identity signature. A signaling server that swaps the SDP fingerprint produces a value that does not match the signed commitment → P4-5 abort. The *signed* commitment, not the relayed SDP, is authoritative (LLD §6.2). |
| **Cloned-host impersonation** | The clone lacks the hardware-non-exportable Ed25519 key (ADR-0006 / R-HW-KS at GA), so it cannot mint a BindCert for the host identity. `PLATFORM_ATTEST` (when later enforced) further proves the key lives in genuine hardware, defeating a key that was somehow extracted but cannot be re-attested. |
| **Key-substitution / unknown-key-share** | The BindCert ties a *specific* X25519 static to a *specific* Ed25519 identity, and the prologue ties the run to this session. An attacker cannot get a victim to accept the attacker's static as the victim's, nor replay a BindCert into a different session (prologue/`h` mismatch). |
| **Key-compromise impersonation (KCI)** | XK and IK both authenticate the *initiator* via an ephemeral-static DH to the **responder's** static, and the BindCert binds that static to the responder identity. Compromise of the initiator's static does **not** let an attacker impersonate the *responder* to the initiator (the responder is authenticated by its BindCert-bound static + its own DH contribution). Forward secrecy from the per-handshake ephemerals limits the value of any later static compromise to sessions after the compromise, not recorded past sessions. |
| **Downgrade / cross-protocol** | `pattern_id`/`suite_id`/`shp_version` are in the authenticated prologue (§1.4); divergent choices → different `h` → MAC failure. The capability JSON is advisory only. |

#### 3.1 `snow` unaudited posture

`snow` (the Noise implementation, LLD §7.3) is **maintained but unaudited**. Mitigations:

- **Wrap it** behind the `NoiseHandshake`/`NoiseSession` seam (spec §A) so `sh-crypto` never exposes
  raw `snow` types and the implementation can be swapped without touching callers.
- **Document** the unaudited status in `SECURITY.md` (add a "Third-party crypto posture" subsection
  noting `snow` is unaudited and wrapped) and in the crate rustdoc.
- **Schedule a pre-GA security review** of `snow` (and the wrapper) as a Risk Register item; do not
  ship GA on unaudited Noise without sign-off. Pin the `snow` version exactly (like the other crypto
  deps) so an unreviewed upgrade cannot land silently; `cargo audit` must be clean.
- **Fuzz** the wrapper's untrusted-byte surface (handshake messages + BindCert) so wrapper-level
  parsing bugs are caught even if `snow` internals are not audited.

### 4. Handshake → key-hierarchy handoff (seam for P3-3 and P3-4)

When the Noise handshake completes and BindCert verification passes, the wrapper exposes a single
**`HandshakeOutcome`** that is the sole, typed seam into the rest of the key hierarchy (LLD §6.3):

```
HandshakeOutcome {
    transport:       NoiseSession,         // post-split transport-cipher state (send/recv)
    handshake_hash:  [u8; 32],             // Noise `h` after split — SHA-256 sized
    peer_identity:   DeviceIdentity,       // the verified, BindCert-bound peer identity
    role:            HandshakeRole,        // Initiator | Responder (for nonce/direction)
    pattern:         NoisePattern,         // Xk | Ik (audit / which path ran)
}
```

- **P3-3 (SAS):** derives the Short Authentication String from `handshake_hash` (`h`) — a MITM cannot
  make both sides compute the same `h` (LLD §6.2), so a matching SAS proves no MITM. P3-3 consumes
  `handshake_hash` and `DeviceIdentity::fingerprint().short()` (ADR-0006) for display. **`h` is the
  only input P3-3 needs from P3-2.**
- **P3-4 (channel key hierarchy):** takes the **two Noise transport keys** from `split()` (the send
  and receive cipher states, owned inside `NoiseSession`) plus `handshake_hash` as the HKDF salt/IKM
  context, and derives **per-channel subkeys** (HKDF-SHA-256, distinct `info` per `ChannelId`),
  rekeying **≤ 2²⁰ messages or 15 minutes** (LLD §6.3). The seam: `NoiseSession` exposes a
  **`export_keying_material(label, context, out_len)`**-style method (HKDF over the negotiated
  handshake secret, *not* the raw transport keys) so P3-4 can derive subkeys without `sh-crypto`
  leaking the raw `snow` `TransportState` or the static/ephemeral secrets. `NoiseSession` owns
  encrypt/decrypt for the base transport; P3-4 layers channel subkeys above it.

This keeps P3-2 self-contained and gives P3-3/P3-4 a typed, minimal, secret-safe drop-in surface.

## Consequences

- **Positive:**
  - Concrete patterns pinned (LLD §9 / R1 closed): `Noise_XK_25519_ChaChaPoly_SHA256` (pair),
    `Noise_IK_25519_ChaChaPoly_SHA256` (connect). One SHA-256 across handshake, SAS, BindCert.
  - The X25519 Noise static is cryptographically bound to the Ed25519 trust root; relay/SDP MITM,
    cloned-host, key-substitution, and KCI are all defeated by an explicit, canonical, signed cert.
  - Canonical length-prefixed domain-separated BindCert encoding removes signed-structure ambiguity;
    the parser is panic-free and fuzzed (every byte is hostile).
  - Prologue binds pattern/suite/version/session → anti-downgrade and channel-binding to the QUIC
    connection are cryptographic, not advisory.
  - Clean typed seam (`HandshakeOutcome`) for P3-3 (SAS from `h`) and P3-4 (HKDF channel subkeys).
  - `snow` is wrapped, version-pinned, fuzzed, documented, and scheduled for pre-GA review.

- **Negative / trade-offs:**
  - XK pairing is 1.5-RTT (vs IK 1-RTT). Accepted: pairing is rare and human-attended; reconnects
    use IK.
  - BindCert adds ~129 bytes + signature inside the handshake payload. Negligible vs the security
    gain; well within Noise message limits.
  - ChaCha20-Poly1305 over AES-256-GCM is slightly slower on AES-NI hardware. Accepted for
    constant-time uniformity across ARM thin clients; AES-256-GCM remains a HW-gated future option.
  - `snow` remains unaudited until the scheduled review; mitigated by the wrapper + fuzz + pin.
  - New dependencies: `x25519-dalek` 2.x (sanctioned, LLD §7.3), `snow` (sanctioned), and `hkdf`
    for P3-4 (sanctioned). All pinned, justified in the PR, `cargo audit` clean.

- **Follow-ups:**
  - **P3-3:** SAS from `handshake_hash`; PAKE (SPAKE2/OPAQUE) for the no-human-at-host case.
  - **P3-4:** channel key hierarchy + rekey using the `export_keying_material` seam.
  - **P4-5:** consume `DTLS_FPR_COMMIT` to pin the WebRTC fingerprint — **done (ADR-0014)**, using
    the whole-cert digest and rejecting an `ALG=NONE` downgrade for WebRTC peers. The WebRTC
    `session_context` (DTLS exporter) for the prologue is **deferred** (it conflicts with
    pin-before-handshake ordering); tracked as `R-DTLS-EXPORTER-BIND` (ADR-0014 §5).
  - **Later:** normalize and *verify* `PLATFORM_ATTEST` (TPM2/App Attest/Play Integrity) — currently
    opaque/unverified.
  - **GA:** `snow` security review; hardware keystore (R-HW-KS) so the BindCert signature lives in a
    non-exportable key; `SECURITY.md` "third-party crypto posture" subsection.
  - Add a `BINDCERT_TBS` **conformance vector** to the test corpus so any encoder change that breaks
    canonicalization is caught.

## Alternatives considered

- **`Noise_IK` for pairing too (skip XK)** — Rejected. IK sends the initiator static in message 1
  encrypted to the responder static; that is fine for hiding from a *passive* relay, but XK gives
  stronger initiator-identity hiding during the *attended pairing* moment and does not require the
  controller to commit its static before the host's ephemeral is in play. The 0.5-RTT saving is
  irrelevant for a rare attended event. Use IK only once the host static is pinned.
- **`Noise_XX` (both statics transmitted, neither known) everywhere** — Rejected for the connect
  path: XX is 1.5-RTT and does not exploit the already-pinned host static; IK's 1-RTT matters for
  reconnect latency. XX would be the fallback only if we had *no* prior host static, which is exactly
  the pairing case XK already covers better (identity hiding).
- **Bind identity to Noise via a TLS-style certificate chain (X.509)** — Rejected. X.509 parsing is a
  notorious attack surface; we need exactly one tiny, canonical, fixed-layout signed blob, not a
  general certificate format. The BindCert is a minimal domain-specific cert.
- **Reuse the Ed25519 identity key directly as the Noise static (convert to X25519)** — Rejected.
  Cross-using a signing key for DH (even via the birationally-equivalent Montgomery form) mixes key
  usages, is fragile across library versions, and forfeits the clean separation where the identity
  key *signs* and a dedicated X25519 key does *DH*. The BindCert gives the binding without key reuse.
- **AES-256-GCM as the P3-2 default AEAD** — Rejected for now. Software AES is variable-time without
  AES-NI; thin mobile/ARM clients (LLD §1) would have a timing side channel. ChaCha20-Poly1305 is
  constant-time everywhere. AES-256-GCM stays as a HW-gated, prologue-bound future option.
- **Carry BindCert in the SDP / a plaintext pre-handshake frame** — Rejected. That exposes the
  controller's identity-bearing cert to the relay (breaks identity hiding) and detaches it from the
  handshake `h` (replayable into another session). BindCert must ride *inside* the encrypted
  handshake.
- **Non-canonical / TLV-everywhere BindCert encoding** — Rejected. Optional fields and flexible
  ordering in a *signed* structure invite field-splicing and signature-confusion attacks. Fixed
  order, fixed widths, explicit length prefixes, single valid encoding.
