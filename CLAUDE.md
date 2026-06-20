# CLAUDE.md — Streamhaul Engineering Rules

Authoritative rules for **all** development in this repository (AI-assisted and human).
These instructions OVERRIDE default behavior and MUST be followed exactly.

> If a rule here ever conflicts with convenience, the rule wins. When in doubt, stop and ask.

---

## 1. What we are building

**Streamhaul** — a next-generation, low-latency remote desktop streaming + remote-management
platform (see [`PRD.md`](./PRD.md) for the authoritative product spec). It grants **full remote
control of a machine** and moves screen, audio, input, clipboard, and files over the public internet.

**Consequence:** every line of code is security-sensitive and performance-sensitive. Treat all
network input as hostile. Treat every change as if it could take over a user's computer — because
the product can.

**Stack of record:** Rust shared core + thin per-OS shims; QUIC (native) + WebRTC (browser);
H.265/AV1/H.264; ICE/STUN/TURN; E2E crypto (rustls, Noise/`snow`, `quinn`). See `docs/adr/`.

---

## 2. PRIME DIRECTIVE — The Quality Gate (NON-NEGOTIABLE)

No change reaches `main` unless **every** step below passes, **in order**, for each completed
section of work:

1. **Design** — for any non-trivial work, consult the relevant specialist agent (§4) and/or record an ADR.
2. **Implement** the smallest coherent, reviewable section.
3. **Test** — write/extend tests alongside the code (TDD preferred). Run the full suite + lint locally.
4. **Bug pass** — run the **`bug-bot`** agent against the diff. Fix every confirmed issue. Re-run until clean.
5. **Code review** — run the **`code-reviewer`** agent against the diff. Address every finding. Re-run until satisfied.
6. **Promote** — only when **tests are green AND `bug-bot` is clean AND `code-reviewer` is satisfied**:
   commit → push to a **feature branch** → open a **PR** → CI green → merge.

**Hard prohibitions:**
- ❌ NEVER push directly to `main`.
- ❌ NEVER push code with failing, skipped, or unwritten tests.
- ❌ NEVER skip the `bug-bot` or `code-reviewer` gate, even for "tiny" changes.
- ❌ NEVER merge a red or stale PR.
- ❌ If you cannot run the tests, **stop and say so** — do not push unverified code.

Documentation-only and config-only changes still require review and CI, but may use a lighter
`bug-bot` pass (note this explicitly in the PR).

---

## 3. The Per-Section Loop (the algorithm to follow every time)

```
for each section of work:
    plan(section)                      # specialist agent / ADR if non-trivial
    repeat:
        implement(section)
        write_or_update_tests(section)
        result = run("fmt + clippy + full test suite")
    until result.all_green

    bugs = run_agent("bug-bot", diff)          # MANDATORY
    if bugs.confirmed: fix(bugs); goto repeat  # re-test after fixes

    review = run_agent("code-reviewer", diff)  # MANDATORY
    if review.actionable: address(review); goto repeat

    # crypto/auth/transport changes ALSO require:
    if touches(security_surface): run_agent("security-engineer", diff)

    commit(conventional_message)
    push(feature_branch)
    open_or_update_PR()
    wait_for(CI == green)
    merge(squash_or_rebase)            # only when all checks pass
```

Re-run tests after **every** fix from an agent — a fix is not done until the suite is green again.

---

## 4. Agent Utilization Map (use the right specialist — do not wing it)

| Task | Agent | When |
|------|-------|------|
| System/architecture design, trade-offs, ADRs | `software-architect` / `systems-design-engineer` | Before non-trivial features |
| Rust core implementation & deep review | `rust-staff-engineer` | All core/`unsafe`/concurrency work |
| Transport, QUIC, ICE/STUN/TURN, NAT | `network-engineer` | Networking changes |
| Capture/encode/decode pipeline, latency, frame pacing | `realtime-systems-engineer` | Media pipeline work |
| Crypto, auth, pairing, threat modeling | `security-engineer` | **Mandatory** for any auth/crypto/transport change |
| Test strategy, coverage, edge cases | `qa-engineer` | New subsystems, flaky tests |
| Latency/throughput/profiling | `performance-tuning-engineer` | Perf regressions or tuning |
| iOS/Android thin clients | `mobile-engineer` | Mobile client work |
| Client UI / UX | `ui-engineer` / `ux-engineer` | Viewer/desktop UI |
| CI/CD, infra, relay/signaling deploy | `devops-engineer` / `kube-staff-engineer` | Pipeline & server-side |
| **Bug hunting on the diff** | **`bug-bot`** | **MANDATORY every section (gate step 4)** |
| **Code review on the diff** | **`code-reviewer`** | **MANDATORY every section (gate step 5)** |

Run independent agents in parallel when their work doesn't depend on each other.

---

## 5. Testing Standards

- **Everything that ships is tested.** Every public behavior has tests; bug fixes add a regression test.
- **Test pyramid:** unit + integration + (for the protocol) **property tests** (`proptest`) and
  **conformance vectors**; **`loom`** for concurrency; **`cargo-fuzz`** for any parser of untrusted
  network bytes (mandatory — we decode hostile input).
- **Coverage:** target **≥ 85% line coverage** on core crates. A PR may not lower coverage.
- **Determinism:** tests must be deterministic and isolated. No network/clock/random flakiness;
  inject clocks and RNG. No `#[ignore]` without a linked tracking issue.
- **Security tests:** negative tests + fuzzing are **mandatory** for crypto, handshake, and packet parsing.
- **Cross-platform:** CI runs the suite on Linux, Windows, and macOS.

---

## 6. Code Quality Standards

- Rust 2021+. `cargo fmt --all` clean. `cargo clippy --all-targets --all-features -- -D warnings` clean (zero warnings).
- **No `unwrap()` / `expect()` / `panic!` / `todo!` in production paths.** Use `Result`; libraries use
  `thiserror`, binaries may use `anyhow`. Panics allowed only in tests.
- **`unsafe` requires** a `// SAFETY:` justification comment **and** review by `rust-staff-engineer`.
- **Public APIs are documented** with rustdoc including examples. Library crates set `#![deny(missing_docs)]`.
- Structured logging via `tracing`. **Never log secrets, keys, or session content.**
- Errors are typed, actionable, and never swallowed.
- Keep functions small and single-purpose; match the style of surrounding code.

---

## 7. Security Rules (remote-control product — treat as critical)

- **Hostile input by default:** validate and bound every field from the wire; fuzz every parser.
- **Never roll your own crypto.** Use vetted crates only (`rustls`/`aws-lc-rs`/`ring`, `snow` for Noise,
  `quinn` for QUIC, `ed25519-dalek`, `x25519-dalek`). Crypto changes require `security-engineer` review.
- **Zero-knowledge relay** is a product invariant — no change may make session content readable by
  signaling/relay infrastructure.
- **Secrets** live only in hardware-backed keystore abstractions; never in code, logs, or env dumps.
- **Dependencies:** `cargo audit` must be clean. New deps are minimized, pinned, and justified in the PR.
- **Supply chain:** signed releases, SBOM, and pinned GitHub Actions (by major version or SHA).

---

## 8. Documentation Standards

- **Docs ship with the code** in the same PR — never "later".
- **Architecture decisions** are recorded as ADRs in `docs/adr/` (copy `docs/adr/_template.md`).
- Each crate has a `README.md` and complete rustdoc. The product spec lives in `PRD.md` and stays authoritative.
- User-facing changes update `CHANGELOG.md` (Keep a Changelog format) once releases begin.
- Comments explain **why**, not what. Keep them current; stale comments are bugs.

---

## 9. Git Pipeline (professional standard)

- **Trunk:** `main` is always releasable and **protected** (no direct pushes; PR + green CI required).
- **Branch names:** `feat/…`, `fix/…`, `chore/…`, `docs/…`, `refactor/…`, `perf/…`, `test/…`, `ci/…`, `build/…`.
- **Conventional Commits** for every commit message **and** PR title
  (e.g. `feat(transport): add QUIC datagram path`). CI enforces PR titles. Use the `.gitmessage` template.
- **PRs are small and focused**, fill out the PR template, link issues, and pass the Definition of Done (§10).
- **Merge strategy:** squash or rebase to keep **linear history**. Branch must be up to date; conversations resolved.
- **Releases:** SemVer tags `vX.Y.Z`.
- **AI commits** include the trailer:
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`

---

## 10. Definition of Done (every PR must satisfy)

- [ ] Scope is small and focused; branch + PR title follow Conventional Commits.
- [ ] Tests written/updated; full suite green locally and in CI on all 3 OSes.
- [ ] `cargo fmt` + `cargo clippy -D warnings` clean.
- [ ] **`bug-bot` run on the diff; all confirmed issues fixed.**
- [ ] **`code-reviewer` run on the diff; all findings addressed.**
- [ ] Security surface? → `security-engineer` reviewed; `cargo audit` clean.
- [ ] Public APIs documented; ADR added/updated if a decision was made.
- [ ] No `unwrap/expect/panic` in production paths; no new `unsafe` without `// SAFETY:`.
- [ ] Coverage not reduced.

---

## 11. When Unsure

Do not guess on **security, crypto, or protocol** decisions. Open an ADR or a discussion and pull in
the relevant specialist agent. A correct, reviewed decision beats a fast one — this product cannot
afford a security or correctness mistake.
