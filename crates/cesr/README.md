# cesr

[![CodSpeed](https://img.shields.io/endpoint?url=https://codspeed.io/badge.json)](https://app.codspeed.io/devrandom-labs/cesr?utm_source=badge)

CESR primitive encoding and cryptography for Rust. This is the substrate crate
in the [five-crate workspace](../../README.md); framing, KERI vocabulary,
wire bodies and the KERI state fold live in their own crates. It supports
`no_std` with allocation and `wasm32-unknown-unknown`.

> **Status: `0.x`, active development.** The API may change as cesr moves toward
> parity with the current `keripy` reference and is tuned for zero-copy and
> performance. Pin a tag and upgrade deliberately. Development guidelines and the
> mandatory rules live in [`CLAUDE.md`](../CLAUDE.md).

Code-table coverage is tracked by `tools/keripy-sync/` in its generated
[report](docs/keripy-parity/report.md). Table coverage does not establish
parser, cryptographic or state-machine parity; the
[capability matrix](../../docs/capability-matrix.md) and
[parity ledger](../../docs/keripy-parity/ledger.md) state those separately.

## Modules & Features

| Feature | Surface | Implies |
| --- | --- | --- |
| `b64` | URL-safe Base64 and qb64/qb2 conversion | `alloc` |
| `core` | CESR code tables, Matter, Indexer and version grammar | `b64` |
| `crypto` | signing, verification, digests and salty custody substrate | `core` |
| `std` | Standard-library support | `alloc` |

Defaults: `std`, `core`, `b64`. A no-feature build has no primitive modules;
the smallest useful profile is `b64`, which enables allocation. `core` and
`crypto` work without `std`. The current `crypto` feature resolves Argon2 and
all supported signing suites; the linked WASM result depends on what the
consumer calls. [A17 measurements](../../docs/audits/2026-09-30-a17-matrix.md)
distinguish dependency resolution from linked size.

## Usage

Published to crates.io as **`cesr-rs`** (the bare `cesr` name is taken) — the
library is still imported as `cesr`:

```toml
[dependencies]
cesr-rs = { version = "0.12", features = ["crypto"] }
# To keep the dependency key as `cesr`:
# cesr = { package = "cesr-rs", version = "0.12", features = ["crypto"] }
```

```rust
use cesr::Matter;          // flagship types at the crate root
use cesr::prelude::*;      // or bring the common traits + types in at once
```

## Examples

Runnable, self-verifying examples in [`examples/`](examples/):

| Example | What it shows | Run |
|---------|---------------|-----|
| [`encode_primitive`](examples/encode_primitive.rs) | qb64 encode ↔ decode round-trip of a `Matter` | `cargo run -p cesr-rs --example encode_primitive` |
| [`keypair_sign_verify`](examples/keypair_sign_verify.rs) | generate an Ed25519 key, sign and verify, and reject a tampered message | `cargo run -p cesr-rs --example keypair_sign_verify --features crypto` |
| [`incept_aid`](../keri-codec/examples/incept_aid.rs) (keri-codec) | incept a KERI identifier; the self-addressing prefix equals the event SAID, verified on deserialize | `cargo run -p keri-codec --example incept_aid` |
| [`multisig_threshold_icp`](../keri-codec/examples/multisig_threshold_icp.rs) (keri-codec) | incept a multi-key identifier with simple (M-of-N) and weighted signing thresholds | `cargo run -p keri-codec --example multisig_threshold_icp` |

## no_std / WASM

The crate compiles on `wasm32-unknown-unknown` and in no_std mode. Disable
default features and select `core` or `crypto`; each pulls in `alloc` through
`b64`:

```toml
cesr-rs = { version = "0.12", default-features = false, features = ["core"] }
```

## Building

`nix flake check` is the single gate (clippy, fmt, taplo, audit, deny, nextest, doctest, wasm32, no_std) plus repo hygiene (actionlint, yamllint, shellcheck, deadnix, nixfmt, typos). Use `nix develop` to enter the dev shell, and `nix fmt` to format the flake. The dev shell builds `statix` with its (upstream-broken) test suite skipped, so `nix develop`/direnv instantiate cleanly.

Releases are automated by [release-plz](https://release-plz.dev): a push to `main`
that touches `src/`, `Cargo.toml`, or `Cargo.lock` opens/updates a release PR;
merging it cuts the version, tag, GitHub release, and crates.io publish. The
release workflow can also be run manually (`Actions → Release → Run workflow`) to
refresh the release PR after changes the path filter intentionally skips.

## Benchmarks

Micro-benchmarks live in [`benches/`](./benches) and use
[criterion](https://github.com/criterion-rs/criterion.rs). The `base64` suite
requires `core`; the `b64_int` suite requires `b64`.

```bash
nix develop --command cargo bench -p cesr-rs --bench base64
nix develop --command cargo bench -p cesr-rs --bench b64_int
```

Criterion writes HTML/CSV
results under `target/criterion/` and, on a second run, reports the delta versus
the previous run.

Performance is tracked continuously in CI with
[CodSpeed](https://codspeed.io): the
[`.github/workflows/codspeed.yml`](../.github/workflows/codspeed.yml) workflow
builds the criterion suites with `cargo codspeed` and runs them under CodSpeed's
CPU-simulation instrument on every push to `main` and pull request, surfacing
per-benchmark deltas directly on the PR. The benchmarks use the
[`codspeed-criterion-compat`](https://crates.io/crates/codspeed-criterion-compat)
drop-in, so the same code runs locally with plain `cargo bench` and in CI under
instrumentation.

## Fuzzing

Fuzz targets live in [`fuzz/`](../fuzz) and use [bolero](https://github.com/camshaft/bolero)
to exercise the decode and parse surface: `Matter`, `Indexer`, the CESR stream
parsers (v1 and v2), and the qb64↔qb2 roundtrip. The 13 domain targets plus a
wiring-check smoke target cover every public entry point that accepts untrusted bytes.

Corpus replay runs on **stable** — no nightly required:

```bash
nix develop --command bash -c "cd fuzz && cargo test"
```

This is included in `nix flake check` as the `cesr-fuzz-replay` check, so committed
corpus files and any saved crash inputs are re-exercised on every PR. Coverage-guided
deep fuzzing (libFuzzer + AddressSanitizer, nightly) runs on a schedule via
[`.github/workflows/fuzz.yml`](../.github/workflows/fuzz.yml).

See [`fuzz/README.md`](../fuzz/README.md) for the full target table, corpus layout,
crash reproduction steps, and deep-fuzz commands.

## Security

Found a vulnerability? **Do not open a public issue.** Report it privately via
GitHub's [Report a vulnerability](https://github.com/devrandom-labs/cesr/security/advisories/new)
form. See [`SECURITY.md`](../SECURITY.md) for the full policy, supported versions,
and response expectations.

Supply-chain integrity is enforced in CI by `cargo audit` + `cargo deny`, watched
continuously by Dependabot, and first-party code is scanned by CodeQL. Dependabot
groups minor/patch updates and leaves **major** dependency bumps for deliberate,
reviewed adoption (a major crypto/encoding bump can ripple into the public API) —
but security advisories always open their own PR regardless.

## Roadmap

The current [work queue](../../docs/TODO.md) and
[capability matrix](../../docs/capability-matrix.md) govern the foundation work.
The older [strategy](../../docs/strategy.md) is historical context.
