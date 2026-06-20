#!/usr/bin/env bash
#
# Apply the `main` branch-protection ruleset to the GitHub repo.
#
# Enforces: PR required before merge, CI checks must pass (strict/up-to-date),
# linear history, no force-push, no branch deletion, conversation resolution,
# and squash/rebase-only merges. Definition in:
#   .github/rulesets/main-branch-protection.json
#
# NOTE: GitHub requires the repo to be PUBLIC, or the owner to be on
# GitHub Pro/Team/Enterprise, to use rulesets/branch protection on private repos.
# Until then this is documentation-as-code; CI and the CLAUDE.md review gate
# already run on every PR.
#
# Usage:
#   ./scripts/setup-branch-protection.sh [owner/repo]
#
set -euo pipefail

REPO="${1:-zoza1982/streamhaul}"
DIR="$(cd "$(dirname "$0")/.." && pwd)"
SPEC="$DIR/.github/rulesets/main-branch-protection.json"

echo "Applying branch-protection ruleset to $REPO ..."
gh api -X POST "repos/$REPO/rulesets" \
  -H "Accept: application/vnd.github+json" \
  --input "$SPEC"
echo "Done. Verify under: Settings → Rules → Rulesets."
