# Contributing to Streamhaul

Thanks for contributing. This project holds a strict quality bar because it ships a remote-control
product where correctness and security are safety-critical. Read [`CLAUDE.md`](./CLAUDE.md) — it is
the authoritative engineering rulebook and applies to everyone, human or AI.

## TL;DR workflow

```
git switch -c feat/<short-slug>          # branch off main
# ... implement a small, focused section ...
cargo fmt --all && cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace --all-features    # must be green
# run bug-bot + code-reviewer on the diff; fix everything they find
git commit                               # Conventional Commits (template provided)
git push -u origin HEAD
gh pr create                             # fill the PR template
# CI must be green, then squash/rebase merge
```

**Never push directly to `main`.** It is protected; all changes land via PR with green CI.

## Branching

Branch off `main` using a typed prefix:

| Prefix | Use |
|--------|-----|
| `feat/` | new feature |
| `fix/` | bug fix |
| `perf/` | performance |
| `refactor/` | internal change, no behavior change |
| `docs/` | documentation only |
| `test/` | tests only |
| `chore/`, `ci/`, `build/` | tooling / pipeline / build |

Keep branches and PRs **small and focused** — one logical change each.

## Commit & PR conventions

We use [Conventional Commits](https://www.conventionalcommits.org/). Both commit messages **and**
PR titles must follow the format (CI enforces PR titles):

```
<type>(<optional scope>): <summary>

feat(transport): add QUIC datagram path for native peers
fix(crypto): reject downgraded SRTP cipher suites
docs(prd): clarify adaptive-engine hysteresis
```

Enable the commit template once per clone:

```
git config commit.template .gitmessage
```

AI-assisted commits include the trailer:
`Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`

## Before you open a PR — Definition of Done

The PR template contains the full checklist. In short: tests written and green on all 3 OSes,
`fmt`/`clippy` clean, **`bug-bot` and `code-reviewer` agents run on the diff and all findings fixed**,
security-touching changes reviewed by `security-engineer` with `cargo audit` clean, docs/ADRs updated,
no `unwrap/expect/panic` in production paths, coverage not reduced.

## Quality gate (must pass to merge)

CI runs `pr-title`, `lint`, `test` (Linux/Windows/macOS), and `audit`. Merges require:
green CI, branch up to date with `main`, resolved conversations, and **linear history**
(squash or rebase merge).

Server-side enforcement of these rules lives in `.github/rulesets/main-branch-protection.json` and
is applied with `./scripts/setup-branch-protection.sh`. GitHub requires the repo to be **public** or
the owner to be on **GitHub Pro/Team** to enable rulesets on a private repo; until then CI and the
`CLAUDE.md` review gate still run on every PR.

## Security

Do not open public issues for vulnerabilities — see [`SECURITY.md`](./SECURITY.md).
