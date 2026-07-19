#!/usr/bin/env bash
# Autoresearch measure script — CESR full stream-parse (Groups::over).
# Emits `METRIC name=value` from criterion's median point-estimate (ns). Lower = better.
#
# Reads target/criterion/<group>/<id>/new/estimates.json (.median.point_estimate, ns)
# instead of scraping stdout — robust to ns/µs formatting and to noise.
#
# BASELINE CHECK: run once by hand. MUST print a non-zero `METRIC stream_parse_ns=…`.
# If empty, the bench invocation or the criterion glob is wrong for this workspace — fix here.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# Bench doc (crates/cesr-stream/benches/stream.rs): cargo bench --bench stream
cargo bench -p cesr-stream --bench stream -- \
  --measurement-time 2 --sample-size 30 >/dev/null 2>&1 || {
    echo "MEASURE_ERROR bench_failed_to_run" >&2; exit 1; }

# Median (ns) for the FIRST estimates.json whose path contains "criterion/<group>/".
# Trailing slash in the regex keeps `stream_parse/` from also matching
# `stream_parse_scaling/`.
median_ns() {  # $1 = exact criterion group dir name
  local f
  f=$(fd -p "criterion/$1/[^/]+/new/estimates.json" target 2>/dev/null | head -1)
  [ -n "${f:-}" ] && jq -r '.median.point_estimate' "$f" 2>/dev/null || true
}

parse=$(median_ns 'stream_parse')
scaling=$(median_ns 'stream_parse_scaling')

# Primary MUST be present — fail loudly so a bad run reverts, not logs a fake 0.
[ -n "${parse:-}" ] || { echo "MEASURE_ERROR stream_parse_estimate_missing" >&2; exit 1; }

echo "METRIC stream_parse_ns=${parse}"
[ -n "${scaling:-}" ] && echo "METRIC stream_parse_scaling_ns=${scaling}"
