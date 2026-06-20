<!-- PR title MUST follow Conventional Commits, e.g. feat(transport): add QUIC datagram path -->

## What & why

<!-- What does this change do, and why? Link issues: Closes #123 -->

## How

<!-- Key implementation notes, trade-offs, and any ADR added/updated. -->

## Definition of Done

- [ ] Scope is small and focused; branch + PR title follow Conventional Commits
- [ ] Tests written/updated; full suite green locally and in CI (Linux/Windows/macOS)
- [ ] `cargo fmt` + `cargo clippy --all-targets --all-features -- -D warnings` clean
- [ ] **`bug-bot` agent run on the diff — all confirmed issues fixed**
- [ ] **`code-reviewer` agent run on the diff — all findings addressed**
- [ ] Security surface touched? → `security-engineer` reviewed and `cargo audit` clean
- [ ] Public APIs documented (rustdoc); ADR added/updated if a decision was made
- [ ] No `unwrap/expect/panic` in production paths; no new `unsafe` without `// SAFETY:`
- [ ] Test coverage not reduced

## Screenshots / logs (if applicable)
