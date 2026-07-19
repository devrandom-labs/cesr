#!/usr/bin/env bash
# Autoresearch correctness gate — CESR Matter seam.
# A NON-ZERO exit makes autoresearch log `checks_failed` and AUTO-REVERT the
# candidate. This is the only thing standing between "faster" and "faster + wrong".
#
# Scope: fast subset covering the in-scope crates + their roundtrip proptests.
# The FULL single gate (`nix flake check`: clippy-as-law, taplo, deny, audit,
# fuzz) is intentionally NOT here — it is too slow per-iteration. It MUST be run
# at /skill:autoresearch-finalize before the reviewable branch is produced.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# Unit + integration + proptest roundtrips for the two crates in scope.
# nextest is the project's runner (per CLAUDE.md); --no-fail-fast so we see all
# failures, not just the first.
cargo nextest run -p cesr-rs -p cesr-stream --no-fail-fast

# Guard the exact invariant we're optimizing around: b64 varint + matter roundtrips.
# (Named proptests live in b64/int.rs and the matter test modules; running the two
# crates above already exercises them — this line documents the intent.)
echo "checks.sh OK: cesr + cesr-stream tests green"
