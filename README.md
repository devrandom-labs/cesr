# cesr
CESR + KERI primitives for Rust as a single feature-gated crate (modules: core/crypto/stream/utils/keri/serder). no_std/WASM-capable. Extracted from agency; shared by bombay, agency, nexus.

`cesr` consolidates six previously separate agency crates (`cesr-utils`, `cesr-core`, `cesr-crypto`, `cesr-stream`, `keri-core`, `keri-serder`) into one crate with independent feature gates per module. Public API paths are preserved verbatim — `cesr_core::Matter` becomes `cesr::core::Matter`. No behavior or signature changed in the extraction.

## Modules & Features

| Module   | Feature  | Internal deps              | Was agency crate |
|----------|----------|----------------------------|------------------|
| `utils`  | `utils`  | —                          | `cesr-utils`     |
| `core`   | `core`   | `utils`                    | `cesr-core`      |
| `crypto` | `crypto` | `core`                     | `cesr-crypto`    |
| `stream` | `stream` | `core`, `utils`            | `cesr-stream`    |
| `keri`   | `keri`   | `core`                     | `keri-core`      |
| `serder` | `serder` | `keri`, `crypto`, `stream` | `keri-serder`    |

Default features: `["std", "core", "utils"]`.

## Usage

Add to `Cargo.toml` with a pinned git tag:

```toml
[dependencies]
cesr = { git = "https://github.com/devrandom-labs/cesr", tag = "v0.1.0", features = ["keri", "serder"] }
```

## no_std / WASM

The crate builds on `wasm32-unknown-unknown` and bare-metal no_std targets. Disable default features and select the modules you need plus `alloc`:

```toml
cesr = { git = "https://github.com/devrandom-labs/cesr", tag = "v0.1.0", default-features = false, features = ["alloc", "core", "keri"] }
```

## Building

`nix flake check` is the single gate (clippy, fmt, taplo, audit, deny, nextest, doctest, wasm32, no_std). Use `nix develop` to enter the dev shell.
