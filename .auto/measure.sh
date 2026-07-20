#!/usr/bin/env bash
# Autoresearch measure script — CESR b64 varint codec (encode_int/decode_int).
# Emits `METRIC name=value` from criterion's median point-estimate (ns). Lower = better.
#
# Reads target/criterion/<group>/.../new/estimates.json (.median.point_estimate, ns).
# The two *_hot groups are single-input (criterion writes .../new/ directly, no id segment),
# so the glob below tolerates both "<group>/new" and "<group>/<id>/new".
#
# BASELINE CHECK: run once by hand. MUST print a non-zero `METRIC b64_encode_ns=…`.
# If empty, the bench isn't compiling/producing output yet — fix crates/cesr/benches/b64_int.rs
# (and confirm the [[bench]] entry in crates/cesr/Cargo.toml) before looping.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

cargo bench -p cesr-rs --bench b64_int -- \
  --measurement-time 2 --sample-size 30 >/dev/null 2>&1 || {
    echo "MEASURE_ERROR bench_failed_to_run" >&2; exit 1; }

median_ns() {  # $1 = criterion group name
  local f
  f=$(fd -p "criterion/$1/.*new/estimates.json" target 2>/dev/null | head -1)
  [ -n "${f:-}" ] && jq -r '.median.point_estimate' "$f" 2>/dev/null || true
}

enc=$(median_ns 'b64_encode_hot')
dec=$(median_ns 'b64_decode_hot')

# Primary MUST exist — fail loudly so a broken bench reverts rather than logging a fake win.
[ -n "${enc:-}" ] || { echo "MEASURE_ERROR b64_encode_estimate_missing" >&2; exit 1; }

echo "METRIC b64_encode_ns=${enc}"
[ -n "${dec:-}" ] && echo "METRIC b64_decode_ns=${dec}"
