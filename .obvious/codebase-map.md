# cesr — codebase map

Five-crate Rust workspace (66.6k lines of Rust) implementing CESR/KERI primitives.
Dependency direction: cesr → cesr-stream / keri-events → keri-codec → keri (codec
opt-in behind keri's `wire` feature). All published crates live under `crates/`
and version independently; the fuzz workspaces at the root are isolated
(non-member) Cargo workspaces.

| Path | Role |
|---|---|
| `crates/cesr` | `cesr-rs` — CESR primitive substrate: `src/b64` (Base64 alphabet/integer math), `src/core` (code tables, Matter/Counter/Indexer, version grammar — `core/version.rs` is the single owner of the version-string wire grammar), `src/crypto` (ed25519/secp256k1 keypair + signature math). 56 source files; examples, benches, proptest regressions, per-crate docs |
| `crates/cesr-stream` | `cesr_stream` — stream framing: counters, groups, cold-start detection, `TextStream`, `CesrMessage`; optional `async` (tokio-util) feature; examples + 3 benches |
| `crates/keri-events` | `keri_events` — the KERI vocabulary: events, seals, thresholds, `Identifier`, `Toad` (pure data, no serialization; `internals` feature exposes all-field constructors for keri-codec) |
| `crates/keri-codec` | `keri_codec` — events ↔ canonical JSON with SAID; read/write spine `EventMessage::parse` / `frame_v1`; 18 integration tests incl. the keripy differential corpus under `tests/` |
| `crates/keri` | `keri-rs` — sans-io KERI core: `state.rs` (K1 key-state fold), `registry.rs` (K2 registry/credential-state fold), `delegation.rs` (K4), `duplicity.rs` (K3), `custody.rs` (K7), `receipt.rs`, `authority.rs`, `wire.rs`; flagship `examples/direct_mode.rs` end-to-end protocol proof |
| `fuzz/` | isolated bolero fuzz workspace (own Cargo.lock) with committed corpus seeds; replay via `(cd fuzz && cargo test)` |
| `fuzz-afl/` | AFL-based fuzz workspace (own Cargo.lock) |
| `fuzz-common/` | shared fuzz-harness code (own Cargo.lock) |
| `scripts/` | Python generators for the keripy parity/differential corpora; `KERIPY_PIN` pins the oracle commit |
| `tools/keripy-sync/` | `sync.py` — weekly CESR code-table parity report generator |
| `docs/` | strategy, keripy-parity reports, cross-crate duplication audit |
| `.plans/` | numbered spec-driven development plans (issue specs) |
| `.github/workflows/` | CI = `nix flake check`; plus CodeQL, CodSpeed benches, llvm-cov coverage, nightly deep-fuzz, keripy-diff/sync, release-plz, crate-reserve workflows |
| `.githooks/` | pre-commit (actionlint on workflow changes), pre-push, post-merge |
| repo root | `Cargo.toml` (workspace + strict lints), `flake.nix` (crane/fenix gate), `justfile` (inner loop), `rust-toolchain.toml` (pinned 1.95.0), `deny.toml`, `taplo.toml`, `_typos.toml`, `free-fn-budget.toml`, `clippy.toml`, `CLAUDE.md` (engineering law), `SECURITY.md`, `NOTICE` |
