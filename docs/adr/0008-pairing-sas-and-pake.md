# ADR 0008: Pairing — SAS from the Noise handshake hash, TOFU pinning, and SPAKE2 PAKE codes

- **Status:** Accepted
- **Date:** 2026-06-22
- **Deciders:** security-engineer, rust-staff-engineer, code-reviewer
- **Builds on:** ADR-0005 (SHA-256 Noise hash), ADR-0006 (Ed25519 trust root, `Keystore`
  TOFU `trust_peer`/`is_trusted`, sticky-revocation note R-HW-KS), ADR-0007 (Noise handshake;
  `HandshakeOutcome.handshake_hash` is the SAS input, the X25519↔Ed25519 binding is already
  MITM-resistant).
- **Phase / task:** P3-3 (`IMPLEMENTATION_PLAN.md`). **Design only** — the implementer
  (`rust-staff-engineer`) builds to the companion spec below in `crates/sh-crypto`; this ADR then
  gates that work.
- **Resolves:** LLD §6.2 ("**SAS** for attended pairing is derived from the Noise handshake hash
  `h`; **SPAKE2/OPAQUE** PAKE over the pairing code for the no-human-at-host case") and the
  downgrade-pairing threat in LLD §6.5 ("SAS/PAKE mandatory").

## Context

Pairing is the **moment trust is created**. Before pairing, the controller and host have never met;
afterwards, the host has pinned the controller's Ed25519 identity (and vice-versa) in its TOFU
store, and every subsequent `Noise_IK` reconnect is authenticated against that pin (ADR-0007).
Everything downstream — capability enforcement, kill-switch, audit — assumes the pinned identity is
the *right* one. **If an attacker can get its own identity pinned during pairing, it owns the
machine.** Pairing is therefore the highest-value target in the product, and the relay/signaling
infrastructure that carries pairing traffic is explicitly untrusted (LLD §6.3, zero-knowledge
boundary).

ADR-0007 already makes the Noise tunnel itself MITM-resistant *given a trust anchor*: the X25519
static is bound to the Ed25519 identity by a signed `BindCert`, and on a *connect* path the peer
identity must already satisfy `Keystore::is_trusted`. But on the **first** pairing there is no pin
yet — `is_trusted` returns `false` for a never-seen identity. Something outside the cryptographic
channel must decide "this identity is the human's real host / authorized controller, pin it." That
something is **human verification (SAS)** when a person is at the host, or a **PAKE over a shared
pairing code** when no one is (unattended enrollment).

The two cases have different trust roots:

1. **Attended pairing (human at the host).** Two devices complete a Noise handshake through the
   relay. A relay MITM would have to sit between them, running *two* handshakes (one to each side)
   and splicing — but then each side's Noise handshake hash `h` differs (the relay's ephemerals are
   in the transcript, not the peer's). A **Short Authentication String derived from `h`** that both
   humans read aloud / compare on-screen will therefore **differ across a MITM**, and the human
   rejects. The human's eyes are the out-of-band channel that authenticates `h`.

2. **Unattended pairing (no human at the host).** There is no one to compare a SAS. Instead the
   operator provisions a **short, single-use pairing code** out-of-band (shown in an admin console,
   emailed, typed into the enrolling device). A **balanced PAKE (SPAKE2)** run over that code lets
   both sides prove they know the *same* code and derive a shared secret, **without ever putting the
   code (or a value brute-forceable to it) on the wire**, and **bound to the device identities** so
   the exchange cannot be relayed to a different device. PAKE success authorizes the pin.

Forces (CLAUDE.md §7): never roll crypto — SAS is one HKDF over `h`, PAKE is a single vetted crate;
treat the pairing code and every PAKE/SAS byte as **hostile input** (fuzz the parsers); a
low-entropy human secret means we must bound the **online** guessing attack and **eliminate the
offline** one; pin **only after** explicit confirmation (SAS-match or PAKE-success), never before;
and surface the R-HW-KS re-trust-after-revoke case to the operator.

This ADR decides (1) the exact SAS derivation, strength, and rendering; (2) the PAKE choice and the
concrete crate; (3) the TOFU pin policy and its revocation interaction; (4) the pairing threat
model. It is design-only.

## Decision

### 1. SAS — derived from the Noise handshake hash `h`

#### 1.1 Derivation (exact)

The SAS is computed by **HKDF-SHA-256** (shared primitive, ADR-0005/0007) over the 32-byte
`HandshakeOutcome.handshake_hash` (`h`) with a domain-separated label and **no salt**, expanding to
a small fixed number of bytes that are rendered as decimal digits:

```
PRK   = HKDF-Extract(salt = none, IKM = h[32])
sas_b = HKDF-Expand(PRK, info = b"SHP-SAS-v1\x00", L = 4)   // 4 bytes = 32 bits of expansion
code  = (u32_be(sas_b) mod 1_000_000)                       // 6 decimal digits
SAS   = zero-padded 6-digit string, grouped "NNN NNN" for display
```

- **`h` is the only input.** Both peers derive the same SAS **iff** they share the same `h`. A relay
  MITM splicing two handshakes produces two *different* `h` values (ADR-0007 §1.4: the prologue and
  both ephemerals are folded into `h`), hence two different SASs → the humans see different codes →
  reject. This is the single load-bearing property and the core test (§spec).
- **Domain separation:** the `info` label `b"SHP-SAS-v1\x00"` (NUL-terminated, versioned) guarantees
  the SAS output can never collide with the P3-4 channel-subkey export (which uses different
  length-prefixed labels via `NoiseSession::export_keying_material`). The SAS is derived **directly
  from `h`**, not via `export_keying_material` — `export_keying_material` operates on the post-split
  PRK and is reserved for *secret* key material; the SAS is *display-only public* verification data
  and is taken straight from the public `h`. Keeping them on separate derivation paths with distinct
  labels avoids any cross-purpose key/PRK reuse.

#### 1.2 Strength and rendering — 6 decimal digits (~20 bits)

**Decision: a 6-decimal-digit SAS (≈ 19.93 bits, 1 000 000 codes).** Rationale:

- **Online-MITM bound.** A SAS does not need cryptographic (128-bit) entropy. Its only job is to let
  a human detect a MITM *that has already had to commit to a transcript*. An active attacker gets
  **one** shot per pairing attempt to make its spliced `h` collide with the SAS the honest parties
  will compare; the success probability is `1 / 10^6 = 10⁻⁶` per attempt. This is the documented,
  accepted SAS security bound (cf. ZRTP §4 / RFC 6189, which standardizes a 4-digit / ~20-bit SAS;
  Signal/WhatsApp safety numbers and Matrix SAS use comparable 20–30-bit human-comparison codes).
  The bound holds **only because the human aborts on mismatch** — there is no automatic retry that
  would let the attacker re-roll (see §3 pin policy and §4 threat model).
- **Usability.** 6 digits is the familiar "verification code" shape (OTP-sized): readable aloud over
  a phone, typeable, language-neutral (no wordlist localization), and renders identically on a TUI,
  a mobile client, and a screen reader. A PGP-style wordlist (e.g. 2 words ≈ 22 bits from a 2048-word
  list) or emoji SAS would add a dependency, a localization/accessibility surface, and a
  homoglyph/look-alike comparison risk for marginal entropy gain. Decimal digits are the lowest-risk
  rendering.
- **Why not more bits.** Going to 8 digits (~26.6 bits, 10⁻⁸ per attempt) is a future, opt-in
  hardening knob (`SasFormat::EightDigit`) — the derivation is identical, only `L`/modulus change.
  We default to 6 to match user expectations and keep the comparison short; the format is **bound
  into pairing logs** so a downgrade to a shorter SAS by a malicious build is detectable. We do **not**
  go below 6.

#### 1.3 Attended-pairing flow (normative)

```
1. Controller ⇄ Host complete Noise_XK (ADR-0007), BindCert-verified on both sides.
   → both hold HandshakeOutcome { handshake_hash: h, peer_identity, ... }
2. Each side computes SAS = Sas::from_handshake_hash(&h)  and DISPLAYS it
   (alongside peer fingerprint short-form, ADR-0006, for the "who" context).
3. The human(s) COMPARE the two displayed SASs out-of-band (same room / phone call).
4a. MATCH  → human confirms → host calls Keystore::trust_peer(peer_identity)  [PIN — TOFU]
            and controller pins the host. The pin happens ONLY here, after confirm.
4b. MISMATCH (or human declines) → ABORT. Do NOT pin. Zeroize handshake state.
            Surface "verification failed — possible interception" to the operator.
```

There is **no** automatic-accept path and **no** "pin first, verify later." The handshake completing
is necessary but **not sufficient** for a pin; the human's match-confirm is the authorizing event.

### 2. PAKE for the unattended (no-human-at-host) case — **SPAKE2** via RustCrypto `spake2`

#### 2.1 Decision

Use a **balanced PAKE: SPAKE2** (Abdalla–Pointcheval), implemented by the **RustCrypto `spake2`
crate** over **Ed25519/Curve25519** (the crate's `Ed25519Group`), pinned `spake2 = "=0.4.0"`.

#### 2.2 SPAKE2 vs OPAQUE vs alternatives — why balanced SPAKE2

| Option | Class | What it protects | Fit for Streamhaul pairing |
|--------|-------|------------------|----------------------------|
| **SPAKE2** | **balanced PAKE** (both sides hold the *same* low-entropy code) | mutual proof-of-code + shared key; **no offline dictionary** for a passive or one-shot active attacker; no code/verifier on the wire | **Chosen.** Pairing is *symmetric and ephemeral*: a one-time code generated for a single enrollment, used once, discarded. Neither side needs a stored long-term verifier — exactly the balanced case. |
| **OPAQUE** | aPAKE / **asymmetric** (server stores a *verifier*, client holds the password) | additionally protects a **stored password** so a server-DB breach yields only an offline-crackable verifier, not the password | **Rejected for pairing.** OPAQUE's value is protecting a *persisted, reused* password against host-DB compromise. Our pairing code is **single-use and ephemeral** — there is no long-term verifier to steal, so OPAQUE's main benefit does not apply. It is heavier (an OPRF + envelope, more round trips and state) and the leading Rust impl (`opaque-ke`) is a larger, also-unaudited surface. Keep OPAQUE in reserve only if we ever introduce a *durable* account password (not in scope). |
| **CPace** | balanced PAKE (modern, IETF/CFRG-selected) | same class as SPAKE2, arguably cleaner symmetry, single-round | Strong technical alternative; **deferred** only because the mature, RustCrypto-maintained crate today is `spake2`. Recorded as a future swap candidate behind the same wrapper seam. |
| **Raw "send H(code)" / naive** | not a PAKE | nothing — exposes an **offline-dictionary** target | **Rejected.** Putting any value derived from the low-entropy code on the wire lets an eavesdropper brute-force 6–10 digits offline in milliseconds. A PAKE is mandatory precisely to make the only attack an *online*, rate-limitable one. |

**Core reason:** SPAKE2 gives the property we actually need — **offline-dictionary resistance over a
single-use shared code** — with the smallest vetted Rust surface. An attacker who records the PAKE
transcript learns *nothing* that lets it test code guesses offline; it must interact (online) with a
live honest party to test *one* guess per attempt, and the code is single-use + expiring (§2.4), so
the online window is tiny.

#### 2.3 Identity / handshake binding (the relay-resistance crux)

A PAKE alone proves "the other side knows the same code." It does **not** by itself prove "the other
side is the device I provisioned the code for" — without binding, a relay could shuttle a code-bearing
PAKE between the legitimate enroller and a *different* attacker device. We bind the PAKE to identity
and session three ways:

1. **Identity-bound associated data.** The SPAKE2 run uses an `id_a` / `id_b` that are the two
   devices' **Ed25519 `device_id` fingerprints** (raw 32-byte digests, ADR-0006). SPAKE2 mixes these
   identifiers into its transcript hash, so a confirmed shared key is produced **only** if both sides
   agree on the *identities* as well as the code. A relay that swaps in its own identity produces a
   key-confirmation mismatch → abort.
2. **Channel-binding to the Noise run.** The PAKE is executed **inside the established Noise tunnel**
   (after `Noise_XK` completes), and the PAKE's final **key-confirmation MAC additionally covers the
   Noise `handshake_hash` `h`** (via the confirmation `info`). This binds "knows the code" to "is the
   peer of *this* Noise handshake," so a code captured on one tunnel cannot authorize a pin on a
   different tunnel. (ADR-0007 already binds the Noise tunnel to the QUIC connection via the
   prologue/exporter, so the chain is code → PAKE → `h` → QUIC connection.)
3. **Key confirmation is mandatory.** Plain SPAKE2 outputs a shared key but does *not* confirm both
   sides derived the *same* key. We add an explicit **two-message key-confirmation step** (HKDF-SHA-256
   over the SPAKE2 output key with distinct initiator/responder labels, compared in **constant time**).
   A wrong code → different SPAKE2 key → confirmation MAC mismatch → abort, **with no information about
   *how* the code was wrong** (single online guess consumed).

#### 2.4 Pairing-code generation, format, lifetime

- **Entropy / format:** the pairing code is generated **on the host/operator side** from the
  **injected `CryptoRng`** as a uniformly random value rendered as **8 decimal digits by default
  (≈ 26.6 bits, 10⁸ codes)**, displayed grouped `NNNN-NNNN`. Unattended codes are **stronger than the
  6-digit SAS** because there is no human transcript-commit step doing the heavy lifting — the code
  *is* the whole authenticator, so we raise the online-guess work factor. (Rendering and digit count
  are a `PairingCodeFormat`; never below 8 for unattended.)
- **Single-use:** a code authorizes **exactly one** successful pin. On first PAKE success (or on
  expiry, or after a small number of failed attempts) the host **invalidates** the code. This is the
  online-guess rate limit: an attacker cannot grind 10⁸ codes because each wrong guess is one online
  round-trip and the code dies after a bounded number of failures / a short window.
- **Expiry:** every code carries a **`not_after`** (default short, e.g. minutes), checked against the
  **injected `Clock`** (no `SystemTime::now()` in testable code, per ADR-0007 convention). Expired
  code → reject before running the PAKE.
- **Lockout:** the host enforces a **max-attempts counter** per code (e.g. ≤ 5 failures) and a global
  per-host pairing rate limit, so the online attack surface is `min(max_attempts, codes_before_expiry)`
  guesses against 10⁸ — negligible success probability, and each failure is logged.
- **Confidentiality of the code:** the code is **never transmitted** (that is the whole point of a
  PAKE) — neither plaintext nor hashed. It exists only in the operator's out-of-band channel and as
  the PAKE input on each side; it is zeroized after use.

#### 2.5 PAKE success → pin

On **successful key confirmation** (both sides proved the same code, bound to both identities and to
`h`), the host calls `Keystore::trust_peer(peer_identity)` — the identity pinned is the
**BindCert-verified `peer_identity` from the Noise `HandshakeOutcome`**, *not* anything the PAKE
messages claimed. The PAKE authorizes the pin; the *thing pinned* is the cryptographically
identity-bound peer from ADR-0007. PAKE failure → **no pin**, zeroize, count the attempt.

### 3. TOFU pinning policy

- **When the pin happens — only after explicit confirmation.** A `trust_peer` call is emitted on
  **exactly two** events and never otherwise: (a) attended SAS **match-confirm** by the human, or
  (b) unattended PAKE **key-confirmation success**. Handshake completion alone (ADR-0007) does **not**
  pin — it produces a `HandshakeOutcome`, but pairing logic gates the pin behind confirmation. There
  is no "optimistic pin then verify."
- **Idempotency.** `trust_peer` is idempotent (ADR-0006/keystore contract): re-pairing an
  already-trusted identity is a no-op success, so a repeated attended/unattended pairing of the same
  device is safe and does not error.
- **Re-trust after revocation (R-HW-KS) — operator must be surfaced.** Per ADR-0006 §6 and Risk
  Register R-HW-KS, `SoftwareKeystore` permits re-trust after revoke (factory-reset / re-pair), but
  production/hardware keystores make revocation **sticky**. The pairing layer therefore, **before
  calling `trust_peer`**, queries trust/revocation state and:
  - if the peer identity was **previously revoked**, it does **not** silently re-pin — it returns a
    distinct **operator-facing signal** (`PairingOutcome::ReTrustAfterRevokeRequiresConfirmation`)
    carrying the peer fingerprint, and only proceeds to `trust_peer` after a **separate, explicit
    operator confirmation** (a distinct action from the ordinary first-pair confirm).
  - This makes the implicit re-admission from ADR-0006 §6 **visible and gated** at the pairing layer,
    satisfying the R-HW-KS constraint without changing the `Keystore::trust_peer` signature (it stays
    a policy at the pairing layer, not a trait change).
- **Operator-facing signal (definition).** The pairing layer returns a typed `PairingOutcome` enum
  (not a bare `Result`) so the UI/operator path can render the right prompt:
  `Pinned { peer }` · `Aborted { reason }` (SAS mismatch / PAKE fail / expiry) ·
  `ReTrustAfterRevokeRequiresConfirmation { peer }`. No secret bytes ever appear in any variant; only
  public fingerprints.

### 4. Threat model (pairing)

| Threat | Defeated by |
|--------|-------------|
| **MITM during attended pairing** | Relay must splice two Noise handshakes → two different `h` → two different SASs → humans compare and **reject** (§1.1). Attacker's one-shot collide chance = `10⁻⁶`; no retry (human aborts). |
| **MITM during unattended pairing** | SPAKE2 over the code + **identity-bound** `id_a/id_b` + key-confirmation **bound to `h`** (§2.3). A relay swapping identities or tunnels fails key confirmation → abort. Without the code, the relay cannot run a valid PAKE at all. |
| **Relayed / re-targeted pairing code** | The PAKE binds to both `device_id` fingerprints and to the Noise `h`; a code shuttled to a *different* attacker device produces a confirmation mismatch (the identities/`h` differ) → no pin. The code does not authorize "whoever knows it," it authorizes "the BindCert-verified peer of *this* handshake." |
| **Offline dictionary on the code** | **Eliminated.** SPAKE2 puts no code-derived value on the wire; a transcript eavesdropper cannot test guesses offline (§2.2). The only attack is online. |
| **Online dictionary on the code** | Bounded: **single-use** code + **expiry** + **max-attempts lockout** + per-host rate limit (§2.4). Effective guesses ≪ 10⁸; each is one logged round-trip. |
| **Replay of pairing / PAKE messages** | Per-pairing SPAKE2 ephemerals + key confirmation bound to `h` (which embeds per-handshake ephemerals and the QUIC exporter, ADR-0007) → a replayed PAKE transcript binds to the wrong `h` → confirmation fails. Single-use code also dies after first success. |
| **Pin-before-verify / downgrade-pairing** | Pin is gated **only** on SAS-match or PAKE-success (§3); LLD §6.5 "SAS/PAKE mandatory." No code path pins on bare handshake completion; SAS format is logged so a shorter-SAS downgrade is detectable. |
| **Re-trust-after-revoke abuse** | Pairing layer detects prior revocation and requires a **distinct operator confirmation** before re-pinning (§3, R-HW-KS) — a revoked attacker device cannot silently re-enroll. |
| **Relay zero-knowledge boundary** | The relay sees only: opaque Noise ciphertext carrying the (encrypted) PAKE messages, public `device_id` fingerprints, and routing metadata. The SAS is never transmitted (derived locally from `h`); the pairing code is never transmitted (PAKE). No session content or secret is readable by infra (LLD §6.3). |

## Consequences

- **Positive:**
  - Attended pairing gets a standard, well-understood **6-digit SAS from `h`** with the documented
    `10⁻⁶`-per-attempt MITM bound; one SHA-256/HKDF, no new rendering dependency.
  - Unattended pairing gets **offline-dictionary-resistant** SPAKE2 over a single-use, expiring,
    rate-limited code, **bound to identities and to the Noise `h`** so it cannot be relayed or
    replayed.
  - Pin happens **only** after explicit confirmation; re-trust-after-revoke is surfaced to the
    operator (R-HW-KS satisfied at the pairing layer without a trait change).
  - Typed `PairingOutcome` gives the UI a precise, secret-free signal set.
- **Negative / trade-offs:**
  - `spake2` is **unaudited** ("USE AT YOUR OWN RISK", no third-party audit) — same posture as
    `snow` (ADR-0007 §3.1): wrap it, pin it exactly, fuzz the wire surface, document in `SECURITY.md`,
    and add a **pre-GA security review** Risk Register item before any GA build uses unattended
    pairing.
  - A 6-digit SAS accepts a `10⁻⁶`-per-pairing online-MITM bound by design; the 8-digit format is the
    hardening knob if a deployment wants `10⁻⁸`.
  - Unattended pairing introduces an online-guess surface that **must** be rate-limited; if the host
    fails to enforce single-use/expiry/lockout, the online bound degrades. The spec makes these
    mandatory and testable.
  - New dependency: `spake2` (+ its `curve25519-dalek` which is already transitively present via
    `ed25519-dalek`/`x25519-dalek`).
- **Follow-ups:**
  - **GA:** `spake2` security review (Risk Register, alongside the `snow` review); `SECURITY.md`
    "Third-party crypto posture" subsection updated to list `spake2`.
  - **Later:** evaluate **CPace** as a `spake2` replacement behind the same `PakeExchange` seam if a
    mature audited crate lands; add an **8-digit SAS** opt-in for high-assurance deployments.
  - **P3-5:** the pinned identity feeds capability-mask binding and the kill-switch.
  - Add **SAS conformance vectors** (fixed `h` → fixed 6-digit SAS) and SPAKE2 conformance vectors
    (where the crate provides them) to the test corpus.

## Alternatives considered

- **OPAQUE (aPAKE) instead of SPAKE2** — Rejected for pairing. OPAQUE's benefit is protecting a
  *persisted, reused* password against a host-DB breach via a stored verifier. Our pairing code is
  **single-use and ephemeral**, so there is no durable verifier to protect; OPAQUE adds an OPRF,
  envelope, extra round trips, and a larger unaudited crate (`opaque-ke`) for a benefit we don't use.
  Reserved only if a durable account password is ever introduced.
- **CPace instead of SPAKE2** — Deferred, not rejected on the merits. CPace is a fine, modern balanced
  PAKE (CFRG-selected), but the mature RustCrypto-maintained crate today is `spake2`. Recorded as a
  future swap behind the wrapper seam.
- **Naive `send H(code || nonce)` challenge-response** — Rejected. Any code-derived value on the wire
  is an **offline-dictionary** target; 6–10 digits fall in milliseconds. A PAKE is mandatory to force
  the attack online.
- **Wordlist / emoji SAS instead of decimal digits** — Rejected for the default. Marginal entropy gain
  over 6 digits, but adds a wordlist dependency, localization + accessibility surface, and a
  homoglyph/look-alike comparison risk. Decimal digits are the lowest-risk, most portable rendering;
  a wordlist could be an optional display mode later without changing the derivation.
- **Deriving the SAS via `NoiseSession::export_keying_material`** — Rejected. That seam operates on the
  post-split secret PRK and is for *key* material; the SAS is *public* display data taken directly from
  the public handshake hash `h`. Keeping the SAS on its own HKDF-from-`h` path with a distinct
  versioned label avoids mixing public-verification and secret-key derivation purposes.
- **3-digit / 4-digit SAS** — Rejected as too weak (`10⁻³`–`10⁻⁴` per-attempt MITM bound). 6 digits is
  the floor; ZRTP-class 20 bits is the accepted reference point.
- **Pin on handshake completion, verify SAS afterwards ("optimistic pin")** — Rejected. Pinning before
  human/PAKE confirmation means a MITM whose handshake completes is pinned before the human can
  reject. The pin MUST be gated strictly behind confirmation.
- **Pairing code transmitted (even hashed) to bootstrap the PAKE** — Rejected. Defeats the entire
  purpose of a PAKE (reintroduces the offline dictionary). The code is input-only on each side and is
  never on the wire.
