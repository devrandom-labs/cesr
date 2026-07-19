#!/usr/bin/env bash
# Autoresearch correctness gate — CESR stream-parse.
# A NON-ZERO exit makes autoresearch log `checks_failed` and AUTO-REVERT the candidate.
# This is the only thing between "faster" and "faster + wrong".
#
# Fast subset only. The FULL single gate (`nix flake check`: clippy-as-law, taplo, deny,
# audit, the `stream` fuzz target) is too slow per-iteration — run it at
# /skill:autoresearch-finalize before producing the reviewable branch.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# Unit + integration + proptest for the two crates on the parse path; --no-fail-fast
# so all failures surface, not just the first.
cargo nextest run -p cesr-rs -p cesr-stream --no-fail-fast

echo "checks.sh OK: cesr + cesr-stream tests green"
