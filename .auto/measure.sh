#!/usr/bin/env bash
# Autoresearch measure script — CESR Matter qb64<->qb2 seam.
# Emits `METRIC name=value` lines from criterion's median point-estimate (ns).
#
# Criterion (via codspeed-criterion-compat with cargo_bench_support) writes
# target/criterion/<group>/<id>/new/estimates.json, whose .median.point_estimate
# is in NANOSECONDS. We read that directly instead of scraping stdout (robust to
# ns/µs unit formatting). Lower = better for every metric here.
#
# BASELINE CHECK: run this once by hand first. It MUST print a non-zero
# `METRIC matter_decode_ns=…`. If it prints nothing, the bench invocation or the
# criterion path glob below is wrong for this workspace — fix it before looping.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# Run only the matter bench. --measurement-time/--sample-size trimmed so the loop
# is fast; criterion still yields a stable median. Adjust if variance is high.
# NOTE: the bench doc (crates/cesr-stream/benches/matter.rs) documents:
#   cargo bench --bench matter
# (the `stream` feature named in the doc no longer exists on cesr-stream; the
# bench only needs the default `std` features, which enable the qb2 module.)
cargo bench -p cesr-stream --bench matter -- \
  --measurement-time 2 --sample-size 30 >/dev/null 2>&1 || {
    echo "MEASURE_ERROR bench_failed_to_run" >&2; exit 1; }

# Pull the median (ns) for a given criterion group; prints nothing if absent.
median_ns() {  # $1 = group name substring
  local f
  f=$(fd -p "criterion/.*${1}.*/new/estimates.json" target 2>/dev/null | head -1)
  [ -n "${f:-}" ] && jq -r '.median.point_estimate' "$f" 2>/dev/null || true
}

dec=$(median_ns 'matter_decode')
enc=$(median_ns 'matter_encode')
q64=$(median_ns 'qb64_to_qb2')
q2=$(median_ns 'qb2_to_qb64')

# Primary metric MUST be present — fail loudly so a bad run reverts rather than
# silently logging a zero "win".
[ -n "${dec:-}" ] || { echo "MEASURE_ERROR matter_decode_estimate_missing" >&2; exit 1; }

echo "METRIC matter_decode_ns=${dec}"
[ -n "${enc:-}" ] && echo "METRIC matter_encode_ns=${enc}"
[ -n "${q64:-}" ] && echo "METRIC qb64_to_qb2_ns=${q64}"
[ -n "${q2:-}"  ] && echo "METRIC qb2_to_qb64_ns=${q2}"
