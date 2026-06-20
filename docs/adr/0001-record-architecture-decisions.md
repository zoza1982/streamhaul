# ADR 0001: Record architecture decisions

- **Status:** Accepted
- **Date:** 2026-06-19
- **Deciders:** Project maintainers

## Context

Streamhaul makes consequential, hard-to-reverse decisions about protocols, cryptography, and
platform APIs. We need a durable, reviewable record of **why** each significant choice was made so
future contributors (human and AI) don't relitigate settled questions or silently violate invariants.

## Decision

We record every significant architectural or protocol decision as a numbered **Architecture Decision
Record** (ADR) in `docs/adr/`, using `docs/adr/_template.md`. ADRs are immutable once Accepted; a
changed decision is captured in a new ADR that supersedes the old one.

## Consequences

- Positive: shared, searchable rationale; faster onboarding; fewer repeated debates.
- Negative: small overhead per decision.
- Follow-ups: link ADRs from code and PRs where a decision is exercised.

## Alternatives considered

- **Decisions only in PR descriptions** — get buried and are hard to find later.
- **A single design doc** — becomes stale and merge-conflict-prone; ADRs are append-only and atomic.
