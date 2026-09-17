---
name: local-dev
description: Stand up and verify a working local dev environment for the cesr Rust workspace without Nix — rustup + cargo-nextest + taplo + cargo-deny, mirroring the nix flake check gate with cargo equivalents.
---

# local-dev — cesr onboarding record (2026-09-17)

Durable record of the LOCAL-DEV onboarding run on sandbox `cmp_jc3uef2q`.
Outcome: `dev_stack_healthy: true`, all evidence captured, snapshot
`y7jdcnvnws7693y7gr9p:default` built 2026-09-17T15:29:18Z.

## What the repo needs

- **Rust 1.95.0 stable**, pinned by `rust-toolchain.toml` (rustup honors it
  automatically inside the repo). No nightly, no `#![feature]` gates.
- Components: `rustfmt`, `clippy`, `llvm-tools-preview`; target
  `wasm32-unknown-unknown` (both listed in `rust-toolchain.toml`).
- Tools the gate uses: `cargo-nextest`, `taplo`, `cargo-deny`, `cargo-audit`
  (audit binary not needed if `cargo deny check` advisories pass — same rustsec
  advisory DB).
- **Nothing else**: no services, no databases, no env vars, no secrets. It is a
  pure library workspace.

## Environment bring-up (no Nix available in sandbox)

The authoritative gate is `nix flake check` (CLAUDE.md). The onboarding sandbox
has no Nix, so the gate was mirrored with cargo-native equivalents — 12 of the
flake's checks reproduced locally, all green.

Install sequence (fresh Debian sandbox, ~2 min):

```bash
curl -sSf https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init -o /tmp/rustup-init
/tmp/rustup-init -y --profile minimal --default-toolchain 1.95.0
source "$HOME/.cargo/env"
rustup component add rustfmt clippy llvm-tools-preview --toolchain 1.95.0
rustup target add wasm32-unknown-unknown --toolchain 1.95.0
curl -LsSf https://get.nexte.st/latest/linux | tar zxf - -C "$HOME/.cargo/bin"   # cargo-nextest
# taplo + cargo-deny: quickinstall 404s; fetch release binaries directly
curl -sL -o taplo.gz https://github.com/tamasfe/taplo/releases/latest/download/taplo-linux-x86_64.gz
curl -sL -o deny.tar.gz https://github.com/EmbarkStudios/cargo-deny/releases/download/0.20.2/cargo-deny-0.20.2-x86_64-unknown-linux-musl.tar.gz
# extract both into ~/.cargo/bin
cargo fetch   # note: takes NO --all-features flag
```

## Verification sequence (mirrors `nix flake check`)

| Gate check | Local equivalent | Onboarding result |
|---|---|---|
| cesr-clippy | `cargo clippy --all-features --all-targets -- --deny warnings` | 0 warnings |
| cesr-fmt | `cargo fmt --all -- --check` | clean |
| cesr-toml-fmt | `taplo format --check` | 10 files clean |
| cesr-deny | `cargo deny check` | advisories/bans/licenses/sources ok |
| cesr-nextest | `cargo nextest run --all-features` | 2397/2397 passed, 0 skipped |
| cesr-doctest | `cargo test --all-features --doc` | ok (3 passed, 6 ignored) |
| cesr-doc | `cargo doc --all-features --no-deps` | exit 0 |
| cesr-wasm | 6 gate-exact wasm32 builds (5 crates no-default-features + `direct_mode` example `--features wire`) | all ok |
| cesr-nostd | 5 gate-exact `--no-default-features` builds | all ok |
| cesr-fuzz-replay | `(cd fuzz && cargo test --no-fail-fast)` | all targets ok |
| cesr-version-owner | gawk tripwire over `crates/*/src` minus `core/version.rs` (script in flake.nix) | ok |
| cesr-keri-boundary | rg for `internals|test-utils` in `crates/keri/Cargo.toml` | ok |

Primary user flow: `cargo run -p keri-rs --example direct_mode --features wire`
— two in-memory parties run the full KERI protocol; all 7 phases pass.

NOT mirrored locally (nix-only): `cesr-audit` (cargo-audit binary; deny's
advisories cover the same DB), `cesr-actionlint`, `cesr-yaml`, `cesr-shellcheck`,
`cesr-deadnix`, `cesr-nixfmt`, `cesr-typos`, `cesr-fn-ratchet`. CI runs the full
set; for local work the table above is the meaningful inner loop.

## Gotchas

- **Long cargo runs**: wrap in `tmux new-session -d -s <name> 'bash -c "<cmd> >
  /tmp/x.log 2>&1; echo EXIT=$? >> /tmp/x.log"'` and poll. The redirect MUST be
  inside the quoted command string — a redirect outside applies to tmux's own
  stdout and the log stays empty. Foreground `sleep > 60s` is blocked by the
  tool; poll in ≤50s chunks or end the turn.
- **`fuzz/Cargo.lock` drift**: `(cd fuzz && cargo test)` rewrites the committed
  lock (it pins keri-codec 0.7.0; the crate is 0.8.0). Restore with
  `git checkout -- fuzz/Cargo.lock` unless deliberately updating it.
- Two cargo processes serialize on the target-dir lock — run checks one at a
  time or accept the wait.
- `just` is the inner-loop runner (`just test`/`clippy`/`fmt`/`doctest`) but is
  not installed in the sandbox; the raw cargo commands above are equivalent.
- `.githooks/` only fires if `core.hooksPath` is configured; pre-commit runs
  actionlint only when workflow files change.

## Quick health check (post-snapshot)

```bash
cargo run -p keri-rs --example direct_mode --features wire   # ~7s warm
cargo nextest run --all-features -p cesr-rs                  # fast subset
cargo fmt --all -- --check
```
