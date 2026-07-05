# cesr workspace

A two-crate Cargo workspace:

- [`cesr/`](cesr) — **cesr-rs**: CESR + KERI cryptographic primitives (no_std/WASM-capable). The stable, frozen-surface foundation. See [`cesr/README.md`](cesr/README.md).
- [`keri/`](keri) — **keri-rs**: sans-io KERI core (key-state, escrow, validation) built on `cesr`'s public API. Under active development.

The crates version independently: `cesr-rs` holds a stable surface while `keri-rs` iterates. Both are gated by a single `nix flake check`.

Licensed under MIT OR Apache-2.0.
