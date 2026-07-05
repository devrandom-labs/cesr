# AFL++/CMPLOG Second Fuzzing Harness — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a second, AFL++-native fuzzing harness (via `afl.rs`/`cargo-afl`) that reaches CMPLOG comparison-coverage on CESR's verbatim byte gates, complementing #45's libFuzzer value-profile leg.

**Architecture:** Three crates. A new `fuzz-common` lib holds the 12 byte-in target bodies as `pub fn(&[u8])` (single source of truth). The existing `fuzz/` bolero crate is refactored to call them. A new isolated `fuzz-afl/` workspace holds one `afl::fuzz!` binary per target, depending on `afl` + `fuzz-common`. The `afl` dependency (whose `build.rs` compiles AFL++ C) is physically absent from the stable `cesr-fuzz-replay` graph.

**Tech Stack:** Rust (edition 2024, stable 1.95.0), `afl` 0.18.2 (`cargo-afl`), `bolero` 0.13 (existing), GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-07-05-80-cmplog-afl-harness-design.md`

---

## File Structure

```
fuzz-common/
  Cargo.toml              NEW  lib crate, own workspace root (empty [workspace]); dep: cesr (path, features=["stream"])
  src/lib.rs              NEW  12 pub fn <target>(data: &[u8]); one #[cfg(test)] smoke test
fuzz/
  Cargo.toml             EDIT add fuzz-common path dep
  tests/matter.rs        EDIT matter_from_qb64/qb2 call fuzz_common; matter_roundtrip unchanged (bolero-only)
  tests/indexer.rs       EDIT both call fuzz_common
  tests/stream.rs        EDIT all 7 call fuzz_common
  tests/binary.rs        EDIT qb64_qb2_roundtrip calls fuzz_common
fuzz-afl/
  Cargo.toml             NEW  isolated workspace (empty [workspace]); deps: afl, fuzz-common (path); 12 [[bin]]
  src/bin/<target>.rs    NEW  12 files, each fn main(){ afl::fuzz!(|d| fuzz_common::<t>(d)); }
  README.md              NEW  how to build/run the AFL leg locally
.github/workflows/
  fuzz.yml               EDIT add `deep-fuzz-afl` job (stable, matrix of 12 targets)
fuzz/README.md           EDIT cross-reference the second harness
```

The 12 shared target names (identical across `fuzz-common`, `fuzz/`, `fuzz-afl/`, and the CI matrix, so both engines share the `corpus-<target>` artifact):
`matter_from_qb64`, `matter_from_qb2`, `indexer_from_qb64`, `indexer_from_qb2`, `stream_parse_group`, `stream_parse_group_v2`, `stream_groups`, `stream_groups_v2`, `stream_parse_message`, `stream_parse_version_string`, `stream_parse_version_string_v2`, `qb64_qb2_roundtrip`.

`matter_roundtrip` is deliberately **excluded** from the shared set (needs structured `[u8; 32]` generation; stays bolero-only, body unchanged).

---

## Task 1: `fuzz-common` shared lib crate

**Files:**
- Create: `fuzz-common/Cargo.toml`
- Create: `fuzz-common/src/lib.rs`

- [ ] **Step 1: Create the crate manifest**

Create `fuzz-common/Cargo.toml`:

```toml
# Shared fuzz-target bodies, consumed by BOTH the bolero crate (fuzz/) and the
# afl.rs crate (fuzz-afl/). Its own workspace root (empty [workspace]) so it does
# not try to join a parent workspace. Depends only on cesr — NO fuzzing-engine
# deps — so it is safe to sit in the stable `cesr-fuzz-replay` dependency graph.
[workspace]

[package]
name = "fuzz-common"
version = "0.0.0"
edition = "2024"
rust-version = "1.95.0"
publish = false
license = "MIT OR Apache-2.0"

[dependencies]
cesr = { package = "cesr-rs", path = "..", features = ["stream"] }
```

- [ ] **Step 2: Write the shared target bodies**

Create `fuzz-common/src/lib.rs`. Each function is the exact body of the corresponding existing bolero closure, lifted verbatim. All `use` imports at the top (the import-style hooks apply to `src/` dirs).

```rust
//! Shared fuzz-target bodies for the `cesr` parse surface.
//!
//! Each `pub fn` takes raw bytes and drives one CESR decoder/parser. A panic is
//! a finding (a parser must never panic on untrusted input). These functions are
//! the single source of truth for both engines: the bolero crate (`fuzz/`) calls
//! them from `check!().for_each(...)`, and the afl.rs crate (`fuzz-afl/`) calls
//! them from `afl::fuzz!(...)`.

use cesr::core::indexer::IndexerBuilder;
use cesr::core::matter::builder::MatterBuilder;
use cesr::stream::{
    groups, groups_v2, parse_group, parse_group_v2, parse_message, parse_version_string,
    parse_version_string_v2, qb2_to_qb64, qb64_to_qb2,
};

pub fn matter_from_qb64(data: &[u8]) {
    let _ = MatterBuilder::new().from_qualified_base64(data);
}

pub fn matter_from_qb2(data: &[u8]) {
    let _ = MatterBuilder::new().from_qualified_base2(data);
}

pub fn indexer_from_qb64(data: &[u8]) {
    let _ = IndexerBuilder::new().from_qb64(data);
}

pub fn indexer_from_qb2(data: &[u8]) {
    let _ = IndexerBuilder::new().from_qb2(data);
}

pub fn stream_parse_group(data: &[u8]) {
    let _ = parse_group(data);
}

pub fn stream_parse_group_v2(data: &[u8]) {
    let _ = parse_group_v2(data);
}

pub fn stream_groups(data: &[u8]) {
    for item in groups(data) {
        let _ = item;
    }
}

pub fn stream_groups_v2(data: &[u8]) {
    for item in groups_v2(data) {
        let _ = item;
    }
}

pub fn stream_parse_message(data: &[u8]) {
    let _ = parse_message(data);
}

pub fn stream_parse_version_string(data: &[u8]) {
    let _ = parse_version_string(data);
}

pub fn stream_parse_version_string_v2(data: &[u8]) {
    let _ = parse_version_string_v2(data);
}

pub fn qb64_qb2_roundtrip(data: &[u8]) {
    let Ok(qb2) = qb64_to_qb2(data) else {
        return;
    };
    let Ok(qb64) = qb2_to_qb64(&qb2) else {
        panic!("qb2 from a valid qb64 must convert back to qb64");
    };
    let Ok(qb2_again) = qb64_to_qb2(&qb64) else {
        panic!("re-encoded qb64 must convert back to qb2");
    };
    assert_eq!(qb2, qb2_again, "qb2->qb64->qb2 must be stable");
}

#[cfg(test)]
mod tests {
    use super::*;

    // Proves every shared body is wired to a real cesr decoder (not a stub) and
    // returns without panic on empty input — the boundary case both engines hit
    // first. Each call would fail the build if the underlying cesr symbol were
    // renamed or removed.
    #[test]
    fn all_targets_accept_empty_without_panic() {
        matter_from_qb64(&[]);
        matter_from_qb2(&[]);
        indexer_from_qb64(&[]);
        indexer_from_qb2(&[]);
        stream_parse_group(&[]);
        stream_parse_group_v2(&[]);
        stream_groups(&[]);
        stream_groups_v2(&[]);
        stream_parse_message(&[]);
        stream_parse_version_string(&[]);
        stream_parse_version_string_v2(&[]);
        qb64_qb2_roundtrip(&[]);
    }
}
```

- [ ] **Step 3: Verify it builds and the smoke test passes**

Run:
```bash
nix develop --command bash -c "cd fuzz-common && cargo test"
```
Expected: compiles; `all_targets_accept_empty_without_panic` PASSes (1 test).

If any `cesr::...` path is wrong, this fails at compile with an unresolved-import error — fix the import to match the current `cesr` API before proceeding.

- [ ] **Step 4: Stage the new crate (nix requires staged files)**

Run:
```bash
git add fuzz-common/Cargo.toml fuzz-common/src/lib.rs
```

- [ ] **Step 5: Commit**

```bash
git commit -m "$(cat <<'EOF'
test(#80): fuzz-common shared target bodies for both fuzz engines

Single source of truth for the 12 byte-in parse targets, consumed by the
bolero crate and the incoming afl.rs crate. Deps: cesr only.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Refactor `fuzz/` bolero tests to call `fuzz-common`

**Files:**
- Modify: `fuzz/Cargo.toml`
- Modify: `fuzz/tests/matter.rs`
- Modify: `fuzz/tests/indexer.rs`
- Modify: `fuzz/tests/stream.rs`
- Modify: `fuzz/tests/binary.rs`

- [ ] **Step 1: Add the fuzz-common dependency**

In `fuzz/Cargo.toml`, under `[dependencies]`, add the path dep alongside the existing `bolero`/`cesr` lines:

```toml
fuzz-common = { path = "../fuzz-common" }
```

- [ ] **Step 2: Rewrite `fuzz/tests/indexer.rs`**

Replace the whole file with:

```rust
//! Fuzz targets for the `Indexer` (indexed-signature) decode surface.

#[test]
fn indexer_from_qb64() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::indexer_from_qb64(input));
}

#[test]
fn indexer_from_qb2() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::indexer_from_qb2(input));
}
```

- [ ] **Step 3: Rewrite `fuzz/tests/stream.rs`**

Replace the whole file with:

```rust
//! Fuzz targets for the `stream` parse surface — counter-led groups, the
//! `groups()` iterator (broadest), and message/version-string parsers.

#[test]
fn stream_parse_group() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::stream_parse_group(input));
}

#[test]
fn stream_parse_group_v2() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::stream_parse_group_v2(input));
}

#[test]
fn stream_groups() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::stream_groups(input));
}

#[test]
fn stream_groups_v2() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::stream_groups_v2(input));
}

#[test]
fn stream_parse_message() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::stream_parse_message(input));
}

#[test]
fn stream_parse_version_string() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::stream_parse_version_string(input));
}

#[test]
fn stream_parse_version_string_v2() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::stream_parse_version_string_v2(input));
}
```

- [ ] **Step 4: Rewrite `fuzz/tests/binary.rs`**

Replace the whole file with:

```rust
//! Fuzz target for the qb64<->qb2 binary conversions.

#[test]
fn qb64_qb2_roundtrip() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::qb64_qb2_roundtrip(input));
}
```

- [ ] **Step 5: Edit `fuzz/tests/matter.rs` — delegate the two decode targets, keep `matter_roundtrip` as-is**

Replace the whole file with (note: `matter_roundtrip` keeps its structured `[u8; 32]` body and its own `cesr` imports — it stays bolero-only):

```rust
//! Fuzz targets for the `Matter` decode/encode surface.
//!
//! The two byte-in decode targets delegate to `fuzz-common` (shared with the
//! afl.rs harness). `matter_roundtrip` uses bolero's structured `[u8; 32]`
//! generator and stays bolero-only.

use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::MatterCode;

#[test]
fn matter_from_qb64() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::matter_from_qb64(input));
}

#[test]
fn matter_from_qb2() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::matter_from_qb2(input));
}

#[test]
fn matter_roundtrip() {
    // Ed25519N ('B') is a fixed-size code with a 32-byte raw — the canonical
    // choice for a clean encode -> decode round-trip.
    bolero::check!()
        .with_type::<[u8; 32]>()
        .for_each(|raw| {
            let Ok(builder) = MatterBuilder::new()
                .with_code(MatterCode::Ed25519N)
                .with_raw(&raw[..])
            else {
                return;
            };
            let Ok(matter) = builder.build() else { return };

            let qb64 = matter.to_qb64b();

            let Ok(decoded) = MatterBuilder::new().from_qualified_base64(&qb64[..]) else {
                panic!("re-decoding self-encoded Matter must succeed");
            };
            assert_eq!(
                decoded.raw(),
                &raw[..],
                "qb64 round-trip must preserve raw bytes",
            );
        });
}
```

- [ ] **Step 6: Verify the stable replay is still green**

Run:
```bash
nix develop --command bash -c "cd fuzz && cargo test"
```
Expected: all target tests PASS (corpus + bounded-random replay unchanged). This proves the extraction preserved behavior — the tests exercise the same corpus files against the same logic, now routed through `fuzz-common`.

- [ ] **Step 7: Stage and commit**

```bash
git add fuzz/Cargo.toml fuzz/tests/matter.rs fuzz/tests/indexer.rs fuzz/tests/stream.rs fuzz/tests/binary.rs
git commit -m "$(cat <<'EOF'
refactor(#80): route bolero targets through fuzz-common

The 12 byte-in target bodies now live once in fuzz-common; the bolero
tests call them. matter_roundtrip stays bolero-only (structured [u8;32]).
Corpus replay unchanged.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: `fuzz-afl/` crate with 12 afl.rs binaries

**Files:**
- Create: `fuzz-afl/Cargo.toml`
- Create: `fuzz-afl/src/bin/<target>.rs` (12 files)

- [ ] **Step 1: Create the manifest**

Create `fuzz-afl/Cargo.toml`. One `[[bin]]` per shared target; `panic = "abort"` in the fuzz profile is the AFL++-recommended setting so a panic is caught as a crash.

```toml
# afl.rs (AFL++/CMPLOG) harness. Its OWN workspace root (empty [workspace]) so the
# `afl` dependency — whose build.rs compiles AFL++ C — never enters the stable
# `cesr-fuzz-replay` graph (fuzz/ + fuzz-common). Exercised only by the scheduled
# `deep-fuzz-afl` CI job, never by `nix flake check`.
[workspace]

[package]
name = "cesr-fuzz-afl"
version = "0.0.0"
edition = "2024"
rust-version = "1.95.0"
publish = false
license = "MIT OR Apache-2.0"

[dependencies]
afl = "0.18"
fuzz-common = { path = "../fuzz-common" }

[[bin]]
name = "matter_from_qb64"
path = "src/bin/matter_from_qb64.rs"

[[bin]]
name = "matter_from_qb2"
path = "src/bin/matter_from_qb2.rs"

[[bin]]
name = "indexer_from_qb64"
path = "src/bin/indexer_from_qb64.rs"

[[bin]]
name = "indexer_from_qb2"
path = "src/bin/indexer_from_qb2.rs"

[[bin]]
name = "stream_parse_group"
path = "src/bin/stream_parse_group.rs"

[[bin]]
name = "stream_parse_group_v2"
path = "src/bin/stream_parse_group_v2.rs"

[[bin]]
name = "stream_groups"
path = "src/bin/stream_groups.rs"

[[bin]]
name = "stream_groups_v2"
path = "src/bin/stream_groups_v2.rs"

[[bin]]
name = "stream_parse_message"
path = "src/bin/stream_parse_message.rs"

[[bin]]
name = "stream_parse_version_string"
path = "src/bin/stream_parse_version_string.rs"

[[bin]]
name = "stream_parse_version_string_v2"
path = "src/bin/stream_parse_version_string_v2.rs"

[[bin]]
name = "qb64_qb2_roundtrip"
path = "src/bin/qb64_qb2_roundtrip.rs"

[profile.release]
panic = "abort"
```

- [ ] **Step 2: Create the 12 binary files**

Each file is four lines. Create all twelve under `fuzz-afl/src/bin/`:

`fuzz-afl/src/bin/matter_from_qb64.rs`:
```rust
fn main() {
    afl::fuzz!(|data: &[u8]| fuzz_common::matter_from_qb64(data));
}
```

`fuzz-afl/src/bin/matter_from_qb2.rs`:
```rust
fn main() {
    afl::fuzz!(|data: &[u8]| fuzz_common::matter_from_qb2(data));
}
```

`fuzz-afl/src/bin/indexer_from_qb64.rs`:
```rust
fn main() {
    afl::fuzz!(|data: &[u8]| fuzz_common::indexer_from_qb64(data));
}
```

`fuzz-afl/src/bin/indexer_from_qb2.rs`:
```rust
fn main() {
    afl::fuzz!(|data: &[u8]| fuzz_common::indexer_from_qb2(data));
}
```

`fuzz-afl/src/bin/stream_parse_group.rs`:
```rust
fn main() {
    afl::fuzz!(|data: &[u8]| fuzz_common::stream_parse_group(data));
}
```

`fuzz-afl/src/bin/stream_parse_group_v2.rs`:
```rust
fn main() {
    afl::fuzz!(|data: &[u8]| fuzz_common::stream_parse_group_v2(data));
}
```

`fuzz-afl/src/bin/stream_groups.rs`:
```rust
fn main() {
    afl::fuzz!(|data: &[u8]| fuzz_common::stream_groups(data));
}
```

`fuzz-afl/src/bin/stream_groups_v2.rs`:
```rust
fn main() {
    afl::fuzz!(|data: &[u8]| fuzz_common::stream_groups_v2(data));
}
```

`fuzz-afl/src/bin/stream_parse_message.rs`:
```rust
fn main() {
    afl::fuzz!(|data: &[u8]| fuzz_common::stream_parse_message(data));
}
```

`fuzz-afl/src/bin/stream_parse_version_string.rs`:
```rust
fn main() {
    afl::fuzz!(|data: &[u8]| fuzz_common::stream_parse_version_string(data));
}
```

`fuzz-afl/src/bin/stream_parse_version_string_v2.rs`:
```rust
fn main() {
    afl::fuzz!(|data: &[u8]| fuzz_common::stream_parse_version_string_v2(data));
}
```

`fuzz-afl/src/bin/qb64_qb2_roundtrip.rs`:
```rust
fn main() {
    afl::fuzz!(|data: &[u8]| fuzz_common::qb64_qb2_roundtrip(data));
}
```

- [ ] **Step 3: Verify all 12 bins compile+link**

**Correction (discovered at implementation time):** plain `cargo build` does NOT link an
afl.rs binary on any platform — the `afl` library crate's `build.rs` does not compile the
AFL++ runtime; it is `cargo afl build` (from the `cargo-afl` CLI) that supplies the link
flags for the `__afl_fuzz_*` symbols. So the wiring must be verified with `cargo afl build`
after a one-time `cargo afl config --build`:

```bash
cargo install cargo-afl --version '^0.18' --locked
cargo afl config --build
nix develop --command bash -c "cd fuzz-afl && cargo afl build --bins"
```
Expected: all 12 binaries compile and link. (`cargo-afl` is not in the Nix devshell; it is
installed to `~/.cargo/bin`.) This is verification-only; the crate's committed state is
unchanged.

- [ ] **Step 4: Add a `.gitignore` for afl output**

Create `fuzz-afl/.gitignore`:
```
/target
/out
```

- [ ] **Step 5: Stage and commit**

```bash
git add fuzz-afl/Cargo.toml fuzz-afl/src/bin/ fuzz-afl/.gitignore
git commit -m "$(cat <<'EOF'
test(#80): afl.rs harness — 12 CMPLOG binaries mirroring bolero targets

Isolated workspace so the afl (AFL++ C) dependency stays out of the
stable cesr-fuzz-replay graph. Each bin wraps the shared fuzz-common fn.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: CI job — `deep-fuzz-afl` in `.github/workflows/fuzz.yml`

**Files:**
- Modify: `.github/workflows/fuzz.yml`

- [ ] **Step 1: Append the new job**

Add this job to `.github/workflows/fuzz.yml` under `jobs:` (a sibling of the existing `deep-fuzz` job). It runs on **stable** (afl.rs needs no nightly), matrices over the 12 shared targets, and shares the `corpus-<target>` artifact with the libFuzzer job.

```yaml
  deep-fuzz-afl:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      actions: read # gh run download of the previous night's shared corpus artifact
    strategy:
      fail-fast: false
      matrix:
        target:
          - matter_from_qb64
          - matter_from_qb2
          - indexer_from_qb64
          - indexer_from_qb2
          - stream_parse_group
          - stream_parse_group_v2
          - stream_groups
          - stream_groups_v2
          - stream_parse_message
          - stream_parse_version_string
          - stream_parse_version_string_v2
          - qb64_qb2_roundtrip
    env:
      # AFL++ refuses to run under a locked-down CI sandbox without these.
      AFL_SKIP_CPUFREQ: "1"
      AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES: "1"
      AFL_NO_AFFINITY: "1"
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      # afl.rs 0.18 builds on STABLE — no nightly pin (unlike the libFuzzer leg).
      - name: Install stable toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Install cargo-afl
        # Pin to the 0.18.x series matching the `afl` lib dep in fuzz-afl/Cargo.toml.
        run: cargo install cargo-afl --version '^0.18' --locked --force

      - name: Build AFL++ runtime
        # cargo-afl vendors AFL++; this compiles the instrumentation runtime once.
        run: cargo afl config --build

      - name: Restore shared corpus (seed dir)
        # Seed the AFL leg from the SAME per-target artifact the libFuzzer leg grows,
        # so value-profile finds seed CMPLOG and vice-versa. First-ever run: none yet.
        continue-on-error: true
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          mkdir -p "seeds/${{ matrix.target }}"
          run_id="$(gh run list --workflow fuzz.yml --branch main --status success --limit 1 --json databaseId --jq '.[0].databaseId // empty' 2>/dev/null || true)"
          if [ -n "$run_id" ]; then
            gh run download "$run_id" \
              --name "corpus-${{ matrix.target }}" \
              --dir "seeds/${{ matrix.target }}" || true
          fi
          # AFL requires a non-empty input dir; plant a 1-byte seed if none restored.
          if [ -z "$(ls -A "seeds/${{ matrix.target }}" 2>/dev/null)" ]; then
            printf 'A' > "seeds/${{ matrix.target }}/seed0"
          fi

      - name: Build CMPLOG-instrumented target
        working-directory: fuzz-afl
        run: cargo afl build --release --bin ${{ matrix.target }}

      - name: Fuzz ${{ matrix.target }} (AFL++/CMPLOG)
        working-directory: fuzz-afl
        # CMPLOG is default-on in afl.rs. -V bounds wall-clock; the run exits 0 at
        # the limit. Tee output so the next step can confirm CMPLOG engaged.
        run: |
          cargo afl fuzz \
            -V ${{ github.event.inputs.duration || '120' }} \
            -i ../seeds/${{ matrix.target }} \
            -o out \
            target/release/${{ matrix.target }} 2>&1 | tee afl.log

      - name: Confirm CMPLOG engaged
        working-directory: fuzz-afl
        # Acceptance criterion: prove CMPLOG is active. afl-fuzz reports it in the
        # startup banner / stats. Fail the job if no CMPLOG evidence is found.
        run: |
          if grep -iq 'cmplog' afl.log; then
            echo "CMPLOG confirmed engaged."
          else
            echo "::error::CMPLOG not detected in afl-fuzz output"
            exit 1
          fi

      - name: Fold discoveries into shared corpus + minimize
        if: success()
        working-directory: fuzz-afl
        # Merge AFL's queue back into the seed set, then minimize with the native
        # cargo-afl cmin (bolero reduce cannot drive AFL). Result re-seeds both engines.
        run: |
          cp -f out/default/queue/* ../seeds/${{ matrix.target }}/ 2>/dev/null || true
          mkdir -p ../corpus-min/${{ matrix.target }}
          cargo afl cmin \
            -i ../seeds/${{ matrix.target }} \
            -o ../corpus-min/${{ matrix.target }} \
            target/release/${{ matrix.target }} || \
            cp -rf ../seeds/${{ matrix.target }}/* ../corpus-min/${{ matrix.target }}/

      - name: Upload shared corpus
        if: success()
        uses: actions/upload-artifact@v4
        with:
          name: corpus-${{ matrix.target }}
          path: corpus-min/${{ matrix.target }}/
          retention-days: 90
          if-no-files-found: ignore
          overwrite: true

      - name: Upload crashes
        # AFL++ does NOT exit on crash (unlike libFuzzer): it logs to
        # out/default/crashes/ and keeps fuzzing to the -V bound, exiting 0. So
        # if: failure() would never fire — upload on always(). The dir only exists
        # after a real crash; if-no-files-found: ignore covers the clean case.
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: crashes-afl-${{ matrix.target }}
          path: fuzz-afl/out/default/crashes/
          if-no-files-found: ignore
```

- [ ] **Step 2: Lint the workflow**

Run:
```bash
nix develop --command bash -c "actionlint .github/workflows/fuzz.yml"
```
Expected: no output (clean). `actionlint` is provided by the flake. Fix any reported syntax/expression errors. The full CMPLOG run itself is validated by the first scheduled/`workflow_dispatch` execution on `main` (cannot run locally on macOS — spec §4).

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/fuzz.yml
git commit -m "$(cat <<'EOF'
ci(#80): nightly AFL++/CMPLOG matrix leg on stable

Second fuzz engine parallel to the libFuzzer leg. Shares the per-target
corpus artifact (cross-pollinates value-profile <-> CMPLOG), confirms
CMPLOG engaged, minimizes via cargo afl cmin, uploads crashes per engine.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Docs + final gate

**Files:**
- Create: `fuzz-afl/README.md`
- Modify: `fuzz/README.md`

- [ ] **Step 1: Write the AFL harness README**

Create `fuzz-afl/README.md`:

```markdown
# cesr-fuzz-afl

Second fuzzing harness for `cesr`, using [afl.rs](https://github.com/rust-fuzz/afl.rs)
(`cargo-afl`, AFL++). Complements the bolero/libFuzzer harness in `../fuzz` by adding
**CMPLOG** comparison coverage (input-to-state substitution), which excels at CESR's
verbatim byte gates (selector/derivation code-table lookups).

## Isolated workspace

Its own Cargo workspace (empty `[workspace]` table). The `afl` dependency — whose
`build.rs` compiles AFL++ (C) — is kept out of the stable `cesr-fuzz-replay` graph
(`../fuzz` + `../fuzz-common`), so `nix flake check` never needs a C toolchain.

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

## Local (Linux x86_64)

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
```

- [ ] **Step 2: Cross-reference from the bolero README**

In `fuzz/README.md`, immediately after the top `# cesr-fuzz` paragraph, add:

```markdown
> **Second harness:** a parallel AFL++/CMPLOG harness lives in [`../fuzz-afl`](../fuzz-afl).
> It shares target bodies via the `fuzz-common` crate and the same per-target corpus
> artifacts, adding comparison coverage on CESR's verbatim byte gates.
```

- [ ] **Step 3: Run the full gate**

Run:
```bash
nix flake check
```
Expected: green. Confirms the stable path is untouched — `fuzz-common` added no external deps, `fuzz-afl` is not part of the gate, and the refactored bolero replay (`cesr-fuzz-replay`) still passes. If `nix flake check` complains about untracked files, `git add` the new files first (they must be staged for nix to see them).

- [ ] **Step 4: Stage and commit**

```bash
git add fuzz-afl/README.md fuzz/README.md
git commit -m "$(cat <<'EOF'
docs(#80): document the AFL++/CMPLOG second harness

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 5: Push and open the PR**

```bash
git push -u origin feat-80-cmplog-afl-harness
gh pr create --repo devrandom-labs/cesr --fill --base main
```

The PR description must call out (per CLAUDE.md active-development discipline): a new second fuzz harness, no changes to the stable gate or public crate API, and that CMPLOG validation happens on the first scheduled/dispatch CI run (not locally).

---

## Self-Review notes

- **Spec coverage:** afl.rs targets mirroring bolero (Task 3) ✅; CMPLOG confirmed (Task 4 step "Confirm CMPLOG engaged") ✅; CI matrix leg + crash/corpus artifacts (Task 4) ✅; `cargo afl cmin` fold into shared artifact (Task 4) ✅; `nix flake check` stays green (Task 5 step 3) ✅; three-crate isolation (Tasks 1–3) ✅.
- **Excluded target:** `matter_roundtrip` documented as bolero-only in Task 2 step 5 and the File Structure header — consistent with the spec's Target set.
- **Type/name consistency:** the 12 target names are identical across `fuzz-common` fns, `fuzz/` tests, `fuzz-afl/` bins, and the CI matrix — required for the shared `corpus-<target>` artifact.
- **Open risks (from spec):** `cargo afl config --build` / `system-config` behavior on GitHub runners and stable-toolchain build success are validated at first CI run; documented in the spec's Risks section. The `cmin` step has a `|| cp` fallback so a cmin hiccup does not fail the night.
```

