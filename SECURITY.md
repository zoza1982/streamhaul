# Security Policy

Streamhaul grants full remote control of a machine. We take security reports extremely seriously.

## Reporting a vulnerability

**Do not open a public issue or PR for security vulnerabilities.**

Please report privately via GitHub's **[Private Vulnerability Reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)**
(Security tab → "Report a vulnerability"). If that is unavailable, contact the maintainer directly
through their GitHub profile.

Include, where possible:
- A description of the issue and its impact.
- Steps to reproduce or a proof of concept.
- Affected component(s), version(s), and platform(s).

We aim to acknowledge reports within **72 hours** and to provide a remediation timeline after triage.
Please give us a reasonable window to fix and release before any public disclosure (coordinated
disclosure). We will credit reporters who wish to be named.

## Scope (high-value areas)

- Cryptography, key handling, device identity, and pairing (the zero-knowledge guarantee).
- Transport (QUIC/WebRTC), packet parsing, and any decoding of untrusted network input.
- Authentication, authorization, session consent, and the unattended-access path.
- Privilege boundaries on the host agent (input injection, capture, elevation).

## Our commitments

- Vetted crypto libraries only; no homegrown primitives.
- All network input treated as hostile; parsers are fuzzed.
- Signaling/relay infrastructure cannot decrypt session content.
- Signed releases and an SBOM for every release.
