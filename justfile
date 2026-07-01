# cesr dev tasks — fast, multi-threaded local iteration.
#
# These recipes run the cargo-native equivalents of the gate's code checks
# incrementally (nextest already parallelizes across all cores). They are the
# INNER LOOP only.
#
# `nix flake check` (recipe `gate`) remains the authoritative pre-commit gate:
# it additionally runs audit, deny, taplo, wasm, no_std, typos, and the lint
# suite that these recipes do not. Run `just gate` before committing/pushing.

# Feature set the gate uses for nextest/clippy. `--all-features` also turns on
# the test-only features (test-utils/internals/async) the lib tests need to compile.
all := "--all-features"

# List recipes.
default:
    @just --list

# Multi-threaded test run (nextest, all features) — mirrors the gate's nextest.
test *ARGS:
    cargo nextest run {{all}} {{ARGS}}

# Fast run: skips the slow crypto proptests at run time (compile stays cached).
test-fast *ARGS:
    cargo nextest run {{all}} -E 'not test(keypair::tests::prop)' {{ARGS}}

# Doctests (nextest cannot run these; the gate runs them as a separate check).
doctest:
    cargo test {{all}} --doc

# Clippy, exactly as the gate invokes it.
clippy:
    cargo clippy {{all}} --all-targets -- --deny warnings

# Rustfmt check.
fmt:
    cargo fmt --all -- --check

# Cargo-native bulk of the gate, fast & incremental. NOT a commit gate — see `gate`.
check: fmt clippy test doctest

# Background watcher: re-runs clippy+tests on file change (via bacon).
watch:
    bacon

# The authoritative full gate. Run this before committing or pushing.
gate:
    nix flake check
