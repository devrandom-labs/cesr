# 259 — widen Seal::Event/Seal::Last identifier to basic-or-self-addressing

Execution tier: k3. Detailed step code: `docs/superpowers/plans/2026-07-30-seal-identifier-widening.md` — follow its code blocks verbatim where given.

## Context

`Seal::Event.i` / `Seal::Last.i` are `BasicPrefix` (`Matter<VerKeyCode>`,
`crates/keri-events/src/seal.rs:26-38`). A keripy delegation-anchor seal
carries `i` = the delegated dip prefix — self-addressing (`E…`, `DigestCode`).
The lift (`crates/keri-codec/src/codec/seal.rs:111-118`) targets `BasicPrefix`
and errors; no opaque fallback at lift stage → whole event fails to
deserialize. Fix: widen both fields to `Identifier<'a>`
(`crates/keri-events/src/identifier.rs:16`). `FromWire<&'a str> for Identifier`
(`crates/keri-codec/src/codec/field.rs:108`) and `Encode for Identifier`
(`crates/keri-codec/src/codec.rs:90`) already exist — lift and writer route
through them by type inference once the field type changes.

Invariants:
- Wire bytes unchanged for existing basic-prefix seals (writer emits inner
  qb64 either way) — round-trip byte identity must hold.
- `Seal::Back.bi` stays `BasicPrefix` (backers are non-transferable basic).
- Breaking change, `keri-events` + `keri-codec`: note in both CHANGELOGs.
- Import style: no inline `use`, no fully-qualified construction (hooks
  enforce).

## Steps

1. SEQUENTIAL. `crates/keri-events/src/seal.rs`: change `Event.i` and
   `Last.i` to `Identifier<'a>`; update the two `into_static` arms
   (`Identifier::into_static` exists); fix the `use` line; fix in-crate
   construction sites (`rg -n "Seal::Event|Seal::Last" crates/keri-events`).
   Doc comments per the detailed plan Task 2. Outcome:
   `cargo check -p keri-events` clean.
2. SEQUENTIAL — depends on 1. Add the two round-trip tests from detailed-plan
   Task 1 to the `tests` module of `crates/keri-codec/src/codec/seal.rs`
   (`event_seal_with_self_addressing_identifier_round_trips`,
   `last_seal_with_self_addressing_identifier_round_trips`), adapting imports
   and helper names to that module. Do NOT run them (sandbox); they compile
   under `cargo check --tests`.
3. SEQUENTIAL — depends on 1. Downstream sweep, disjoint file groups; run the
   sweep grep first:
   `rg -ln "Seal::Event|Seal::Last" crates fuzz fuzz-common fuzz-afl 2>/dev/null`
   (pre-flight CHECK result: zero matches outside `crates/` — the fuzz
   workspaces need no changes; skip them if the grep agrees).
   Construction sites: wrap as `Identifier::Basic(prefix)`. Match sites that
   need more than rebinding (from pre-flight CHECK):
   - `crates/keri-codec/src/deserialize.rs:904,911` — assert `*ev_i.code()` /
     `*last_i.code()`: `Identifier` has no `.code()`; match
     `Identifier::Basic(p)` first, then assert on `p.code()`.
   - `crates/keri-codec/src/codec/event.rs:1326,1328` — `i.to_qb64()`:
     `Identifier` has no `to_qb64`; use the in-module helper
     `identifier_qb64` (event.rs:1313) which already dispatches the arms.
   - `crates/keri-codec/tests/../deserialize/reference.rs:1127,1141` —
     `qb64(&i)` helper is Matter-typed; match the `Identifier::Basic` arm or
     widen the helper locally.
   Lift arms in `codec/seal.rs:111-118` need NO code change (inference lands
   on `FromWire<&str> for Identifier`). Sub-groups may go to parallel
   subagents ONLY if file sets are disjoint (sonic-suitable, mechanical):
   3a. `crates/keri-codec/src/**`.
   3b. `crates/keri-codec/tests/**`.
4. SEQUENTIAL — depends on 3a. `crates/keri-codec/src/event_strategies.rs:225-256`:
   the seal strategy is a tuple-driven `match variant { 3 => Seal::Event
   { i: Fixture::prefixer(b) }, … }` — NOT `prop_oneof!`; ignore the detailed
   plan's snippet here. Extend the generated tuple with an arm selector
   (e.g. a `bool`) so `Event.i`/`Last.i` produce both `Identifier::Basic`
   (existing `Fixture::prefixer`) and `Identifier::SelfAddressing` (a
   said/digest fixture — reuse whatever the strategy file already generates
   for `Said`), keeping the round-trip property over both arms.
5. SEQUENTIAL — depends on all. CHANGELOG entries (`crates/keri-events/CHANGELOG.md`,
   `crates/keri-codec/CHANGELOG.md`) under Unreleased: breaking, one line each
   per detailed plan Task 4.

## Verification (sandbox-safe — NO cargo test / nextest, they hang)

- `cargo check --workspace --all-targets`
- `cargo clippy --workspace --all-targets` (god-level lints are law; fix code,
  never add `#[allow]` without reason)
- For each matched non-member workspace dir (fuzz*, examples): `cargo check`
  inside it.
- Tests run later via `nix flake check` (Claude drives; unsandboxed).

## Out of scope

- `Seal::Back`, `Seal::Source`, other seal variants.
- Any keri-rs (`crates/keri`) change.
- No commits — leave the tree dirty; Claude reviews and commits.
- No lint-level or clippy.toml changes; no rustfmt config changes.
