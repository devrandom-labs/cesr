# cesr — agent guide

Repo: **devrandom-labs/cesr** — a five-crate Cargo workspace of CESR (Composable
Event Streaming Representation) and KERI (Key Event Receipt Infrastructure)
primitives. Every crate is no_std/WASM-capable. Pure libraries: **no services,
no database, no network, no env vars required** for local dev.

## Stack

| Layer | Choice |
|---|---|
| Language | Rust, edition 2024, pinned **stable 1.95.0** (`rust-toolchain.toml` — single source of truth; bump in lockstep with `rust-version` in `Cargo.toml`. No nightly, no `#![feature]`) |
| Build | cargo workspace — 5 members under `crates/`, resolver 3 |
| Test runner | cargo-nextest (unit + integration) + `cargo test --doc` (doctests) |
| Lint | clippy: `all` + `pedantic` + `nursery` at deny + restriction suite (`[workspace.lints]` is the law — never relax without approval); rustfmt; taplo (TOML) |
| Supply chain | cargo-deny (advisories/bans/licenses/sources), cargo-audit |
| Dev shell | Nix flake (`nix develop` or direnv `use flake`) provides every tool; `nix flake check` is the authoritative gate |
| Extra targets | `wasm32-unknown-unknown`, no_std + `alloc` |
| Task runner | `just` (see `justfile` — inner loop only) |

## Commands

| Task | Command |
|---|---|
| Build everything | `cargo build --all-features --all-targets` |
| Full test suite | `cargo nextest run --all-features` (= `just test`) |
| Fast tests (skips slow crypto proptests) | `cargo nextest run --all-features -E 'not test(keypair::tests::prop)'` (= `just test-fast`) |
| Doctests | `cargo test --all-features --doc` (= `just doctest`) |
| Clippy (exact gate invocation) | `cargo clippy --all-features --all-targets -- --deny warnings` (= `just clippy`) |
| Format check | `cargo fmt --all -- --check` (= `just fmt`) |
| TOML format check | `taplo format --check` |
| Dependency/advisory gates | `cargo deny check` |
| WASM check (per crate; exact sets in `flake.nix` `cesr-wasm`) | e.g. `cargo build -p cesr-rs --target wasm32-unknown-unknown --no-default-features --features alloc,core,b64,crypto` |
| no_std check (per crate; exact sets in `flake.nix` `cesr-nostd`) | e.g. `cargo build -p cesr-rs --no-default-features --features alloc,core,b64` |
| Fuzz corpus replay | `(cd fuzz && cargo test --no-fail-fast)` |
| Flagship protocol example | `cargo run -p keri-rs --example direct_mode --features wire` |
| Full gate (needs Nix) | `nix flake check` — clippy, fmt, taplo, audit, deny, nextest, doctest, wasm, no_std, tripwires. The ONLY pre-push command per CLAUDE.md |

## Env vars

None. Pure computation — no secrets, databases, or services. (CI-only secrets like
`RELEASE_PLZ_APP_*`/`CARGO_REGISTRY_TOKEN` are GitHub Actions inputs, never local.)

## Codebase map

See [codebase-map.md](codebase-map.md). Crates: `cesr` (substrate: b64/core/crypto)
→ `cesr-stream` (framing) → `keri-events` (vocabulary) → `keri-codec` (JSON codec,
read/write spine) → `keri` (sans-io protocol core).

## Local verification

### Local Verification Summary (onboarding run, 2026-09-17)

`dev_stack_healthy: true` — evidence captured on sandbox `cmp_jc3uef2q`:

- build: `cargo build --all-features --all-targets` — exit 0
- tests: `cargo nextest run --all-features` — **2397/2397 passed**, 0 skipped (43s)
- doctests: `cargo test --all-features --doc` — ok (3 passed, 6 ignored)
- clippy: `--all-features --all-targets -- --deny warnings` — 0 warnings
- fmt: `cargo fmt --all -- --check` — clean
- taplo: `taplo format --check` — 10 TOML files clean
- cargo-deny: advisories, bans, licenses, sources — all ok
- wasm32: all 5 crates (gate-exact feature sets) + `direct_mode` example — built
- no_std: all 5 crates (gate-exact feature sets) — built
- fuzz corpus replay: `(cd fuzz && cargo test --no-fail-fast)` — all targets ok
- spine tripwires: version-owner, keri-boundary — ok
- primary flow: `cargo run -p keri-rs --example direct_mode --features wire` —
  all 7 protocol phases pass (inception, exchange, pre-rotation, delegation,
  agent signing, revocation-by-abandonment, escrow + duplicity)

Not runnable in the onboarding sandbox (Nix absent; CI runs them via
`nix flake check`): cargo-audit binary, actionlint, yamllint, shellcheck,
deadnix, nixfmt, typos, fn-ratchet.

## Sandbox snapshot

- Captured **2026-09-17T15:29:18Z** from sandbox computer `cmp_jc3uef2q`
  (`obvious computers snapshot`).
- e2b template: `y7jdcnvnws7693y7gr9p:default` — boots a warm dev sandbox.
- Contents: rustup + pinned 1.95.0 toolchain (rustfmt, clippy, llvm-tools,
  wasm32 target), cargo-nextest 0.9.145, taplo 0.10.0, cargo-deny 0.20.2 in
  `~/.cargo/bin`; repo at `~/work/cesr` with a warm 3.8 GB `target/` cache.
- Quick health check after restore: `cargo run -p keri-rs --example direct_mode
  --features wire` (≈7s warm), then `cargo nextest run --all-features -p cesr-rs`.

## Guidance docs

- **CLAUDE.md** — the repo's law: build/verification, MANDATORY import style,
  clippy policy, error handling (thiserror unions), testing categories,
  conventional commits, versioning. Read it first.
- README.md — crate map + the `direct_mode` flagship example ("KERI without a
  database").
- docs/ — strategy, keripy-parity reports; .plans/ — numbered spec-driven plans.
- SECURITY.md — security policy.

## Repo policy

See [config.yml](config.yml): default branch `main`, squash merge (GitHub also
allows merge-commit and rebase — none enforced). Human approval is required
before a default-branch setup PR merges.
