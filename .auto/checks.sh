#!/usr/bin/env bash
# Autoresearch correctness gate — CESR b64 varint codec.
# A NON-ZERO exit makes autoresearch log `checks_failed` and AUTO-REVERT the candidate.
# The int.rs proptests (roundtrip / overflow / boundary) are the real guard here — a
# faster encode that breaks roundtrip MUST revert.
#
# Fast subset only. Full single gate (`nix flake check`: clippy-as-law, taplo, deny, audit,
# fuzz) runs at /skill:autoresearch-finalize before the reviewable branch.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

cargo nextest run -p cesr-rs -p cesr-stream --no-fail-fast

echo "checks.sh OK: cesr + cesr-stream tests green"
