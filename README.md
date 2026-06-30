# cesr
CESR + KERI primitives for Rust as a single feature-gated crate (modules: core/crypto/stream/utils/keri/serder). no_std/WASM-capable.

`cesr` consolidates six previously separate crates (`cesr-utils`, `cesr-core`, `cesr-crypto`, `cesr-stream`, `keri-core`, `keri-serder`) into one crate with independent feature gates per module. Public API paths are preserved verbatim — `cesr_core::Matter` becomes `cesr::core::Matter`. No behavior or signature changed in the extraction.

> **Status: `0.x`, active development.** The API may change as cesr moves toward
> parity with the current `keripy` reference and is tuned for zero-copy and
> performance. Pin a tag and upgrade deliberately. Development guidelines and the
> mandatory rules live in [`CLAUDE.md`](./CLAUDE.md).

Parity with keripy is tracked automatically: a weekly watcher
(`tools/keripy-sync/`) diffs keripy's CESR code tables against cesr's and refreshes
[`docs/keripy-parity/report.md`](./docs/keripy-parity/report.md) via PR; gap rows
become [`keripy-sync`](https://github.com/devrandom-labs/cesr/labels/keripy-sync)
issues.

## Modules & Features

| Module   | Feature  | Internal deps              | Origin crate     |
|----------|----------|----------------------------|------------------|
| `utils`  | `utils`  | —                          | `cesr-utils`     |
| `core`   | `core`   | `utils`                    | `cesr-core`      |
| `crypto` | `crypto` | `core`                     | `cesr-crypto`    |
| `stream` | `stream` | `core`, `utils`            | `cesr-stream`    |
| `keri`   | `keri`   | `core`                     | `keri-core`      |
| `serder` | `serder` | `keri`, `crypto`, `stream` | `keri-serder`    |

Default features: `["std", "core", "utils"]`.

## Usage

Published to crates.io as **`cesr-rs`** (the bare `cesr` name is taken) — the
library is still imported as `cesr`:

```toml
[dependencies]
cesr-rs = { version = "0.1", features = ["keri", "serder"] }
# or, to keep the dependency key as `cesr`:
# cesr = { package = "cesr-rs", version = "0.1", features = ["keri", "serder"] }
```

```rust
use cesr::core::matter::matter::Matter; // import name is always `cesr`
```

Or pin a git tag directly:

```toml
[dependencies]
cesr-rs = { git = "https://github.com/devrandom-labs/cesr", tag = "v0.1.0", features = ["keri", "serder"] }
```

## no_std / WASM

The crate builds on `wasm32-unknown-unknown` and bare-metal no_std targets. Disable default features and select the modules you need plus `alloc`:

```toml
cesr = { git = "https://github.com/devrandom-labs/cesr", tag = "v0.1.0", default-features = false, features = ["alloc", "core", "keri"] }
```

## Building

`nix flake check` is the single gate (clippy, fmt, taplo, audit, deny, nextest, doctest, wasm32, no_std) plus repo hygiene (actionlint, yamllint, shellcheck, deadnix, nixfmt, typos). Use `nix develop` to enter the dev shell, and `nix fmt` to format the flake.

Releases are automated by [release-plz](https://release-plz.dev): a push to `main`
that touches `src/`, `Cargo.toml`, or `Cargo.lock` opens/updates a release PR;
merging it cuts the version, tag, GitHub release, and crates.io publish. The
release workflow can also be run manually (`Actions → Release → Run workflow`) to
refresh the release PR after changes the path filter intentionally skips.

## Security

Found a vulnerability? **Do not open a public issue.** Report it privately via
GitHub's [Report a vulnerability](https://github.com/devrandom-labs/cesr/security/advisories/new)
form. See [`SECURITY.md`](./SECURITY.md) for the full policy, supported versions,
and response expectations.

Supply-chain integrity is enforced in CI by `cargo audit` + `cargo deny`, watched
continuously by Dependabot, and first-party code is scanned by CodeQL. Dependabot
groups minor/patch updates and leaves **major** dependency bumps for deliberate,
reviewed adoption (a major crypto/encoding bump can ripple into the public API) —
but security advisories always open their own PR regardless.
