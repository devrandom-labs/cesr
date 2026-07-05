# cesr-fuzz

Fuzzing harness for the `cesr` crate. Targets cover the decode and parse surface
across `core` (Matter, Indexer), `stream` (group/message parsers, version strings),
and `utils` (qb64↔qb2 roundtrip).

## Isolated workspace

This directory is its own Cargo workspace (the empty `[workspace]` table in
`Cargo.toml`). That keeps bolero and its transitive dependencies out of the main
crate's dependency graph, audit surface, and `cargo deny` checks. The main `cesr`
crate remains a single crate — this workspace is a peer, not a member.

## Running on stable (corpus replay + bounded random)

No nightly toolchain required. `cargo test` drives bolero's `DefaultEngine`, which:

1. Replays all committed corpus files under `fuzz/tests/__fuzz__/<target>/corpus/`.
2. Runs approximately 350 000 bounded random inputs per target.

```bash
cd fuzz && cargo test
```

To narrow to a single test module or target:

```bash
# all targets in one module
cd fuzz && cargo test --test matter

# single target
cd fuzz && cargo test --test matter -- matter_from_qb64
```

This replay run is included in `nix flake check` as the `cesr-fuzz-replay` check,
so corpus coverage is verified on every PR without nightly.

## Deep fuzzing (nightly, coverage-guided)

Coverage-guided fuzzing under libFuzzer + AddressSanitizer requires nightly Rust and
`cargo-bolero`. Nightly is only needed for this deep path — the corpus replay above
stays on stable. Pass the toolchain explicitly (CI pins a dated nightly; see
`.github/workflows/fuzz.yml`):

```bash
cargo install cargo-bolero
rustup toolchain install nightly --component llvm-tools-preview
```

Fuzz a single target for two minutes, with comparison coverage (value profile) on:

```bash
RUSTUP_TOOLCHAIN=nightly cargo bolero test <target> --sanitizer address --engine libfuzzer \
  -E=-use_value_profile=1 -E=-max_total_time=120
```

`-use_value_profile=1` enables libFuzzer's value profile: bolero's libFuzzer build
already compiles in `trace-cmp` instrumentation, so this runtime flag lets the fuzzer
climb CESR's exact-byte gates (code-table lookups, magic/version prefixes) that plain
edge coverage cannot guess. Each `-E=<arg>` (or `--engine-args`) passes one argument
directly to libFuzzer; `-E` is repeatable. Do not put libFuzzer arguments after `--`.

After a run, minimize the corpus in place (this is libFuzzer `-merge=1`):

```bash
cargo bolero reduce <target> --engine libfuzzer
```

A scheduled CI workflow (`.github/workflows/fuzz.yml`) runs each target under this
configuration nightly, minimizes the corpus, and persists it as an artifact so
coverage compounds night over night.

## Corpus and crash layout

```
fuzz/tests/__fuzz__/<target>/corpus/   # seed + discovered interesting inputs
fuzz/tests/__fuzz__/<target>/crashes/  # inputs that produced a crash or hang (created on first crash)
```

Committed seed files live in `corpus/`. The `crashes/` directory does not exist
until a crash is found and saved there. The `DefaultEngine` replays both directories
on every `cargo test` run, so any saved crash is automatically re-exercised on
stable.

## Reproducing a crash

Save the crashing input into `fuzz/tests/__fuzz__/<target>/crashes/` and run:

```bash
cd fuzz && cargo test --test <module> -- <target>
```

`<module>` is the filename without `.rs` (e.g. `matter`, `stream`). bolero replays
every file in the `crashes/` directory as part of the normal test run — no special
flags needed.

## Targets

| Module       | Target                          | What it exercises                              |
|--------------|---------------------------------|------------------------------------------------|
| `matter.rs`  | `matter_from_qb64`              | `Matter` decode from base-64 text              |
| `matter.rs`  | `matter_from_qb2`               | `Matter` decode from base-2 binary             |
| `matter.rs`  | `matter_roundtrip`              | qb64 → Matter → qb64 round-trip stability      |
| `indexer.rs` | `indexer_from_qb64`             | `Indexer` decode from base-64 text             |
| `indexer.rs` | `indexer_from_qb2`              | `Indexer` decode from base-2 binary            |
| `stream.rs`  | `stream_parse_group`            | CESR v1 group parse                            |
| `stream.rs`  | `stream_parse_group_v2`         | CESR v2 group parse                            |
| `stream.rs`  | `stream_groups`                 | v1 multi-group stream parse                    |
| `stream.rs`  | `stream_groups_v2`              | v2 multi-group stream parse                    |
| `stream.rs`  | `stream_parse_message`          | full CESR message parse                        |
| `stream.rs`  | `stream_parse_version_string`   | CESR v1 version-string parse                   |
| `stream.rs`  | `stream_parse_version_string_v2`| CESR v2 version-string parse                   |
| `binary.rs`  | `qb64_qb2_roundtrip`            | qb64↔qb2 conversion round-trip                 |
| `smoke.rs`   | `smoke`                         | Harness wiring check (not a domain target)     |

## Design

Full design rationale (why bolero, the stable-replay strategy, scheduler setup) is
in [`docs/superpowers/specs/2026-06-30-p0.2-fuzzing-design.md`](../docs/superpowers/specs/2026-06-30-p0.2-fuzzing-design.md).

The harness has already found and fixed a real bug: a DoS panic in
`from_qualified_base2` (issue #43), surfaced by the `matter_from_qb2` target
during development.
