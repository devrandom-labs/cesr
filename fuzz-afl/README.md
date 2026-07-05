# cesr-fuzz-afl

Second fuzzing harness for `cesr`, using [afl.rs](https://github.com/rust-fuzz/afl.rs)
(`cargo-afl`, AFL++). Complements the bolero/libFuzzer harness in `../fuzz` by adding
**CMPLOG** comparison coverage (input-to-state substitution), which excels at CESR's
verbatim byte gates (selector/derivation code-table lookups).

## Isolated workspace

Its own Cargo workspace (empty `[workspace]` table). The `afl` dependency — whose
`build.rs` pulls in AFL++ — is kept out of the stable `cesr-fuzz-replay` graph
(`../fuzz` + `../fuzz-common`), so `nix flake check` never needs the AFL++ toolchain.

## Toolchain

Runs on **stable** Rust (afl.rs 0.18 instruments via AFL++'s `afl-clang-fast`, not
unstable rustc flags). No nightly. CMPLOG is **default-on**. Real instrumented runs
require Linux x86_64 — AFL++ on Apple Silicon only supports non-instrumented fuzzing,
so CMPLOG runs in CI.

> **Note:** plain `cargo build` cannot link an afl.rs binary on any platform — the
> `afl` library crate does not ship the AFL++ runtime; only `cargo afl build` (from
> the `cargo-afl` CLI, after a one-time `cargo afl config --build`) supplies the link
> flags for the `__afl_fuzz_*` symbols. Always build these bins with `cargo afl build`.

## Shared target bodies

Each `src/bin/<target>.rs` wraps a function from the `fuzz-common` crate — the same
body the bolero target runs. Bin names match the bolero target names so both engines
read/write the single `corpus-<target>` CI artifact.

## Local run (Linux x86_64)

```bash
cargo install cargo-afl --version '^0.18' --locked
cargo afl config --build
cd fuzz-afl
cargo afl build --release --bin matter_from_qb64
mkdir -p seeds && printf 'A' > seeds/seed0
cargo afl fuzz -V 60 -i seeds -o out target/release/matter_from_qb64
```

## Design

Full rationale: [`docs/superpowers/specs/2026-07-05-80-cmplog-afl-harness-design.md`](../docs/superpowers/specs/2026-07-05-80-cmplog-afl-harness-design.md).
