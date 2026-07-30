# Seal Identifier Widening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Widen `Seal::Event.i` and `Seal::Last.i` from `BasicPrefix` to `Identifier` so real keripy delegation seals (self-addressing `E…` prefixes) parse.

**Architecture:** Type change in `keri-events`, lift/strategy updates in `keri-codec`. The codec's `FromWire<&str> for Identifier` (field.rs:108) and `Encode for Identifier` (codec.rs:90) already exist — the lift and writer route through them once the field type changes. Prerequisite for K3 (#89): the cascade matches seal `(i,s,d)` against delegated-event `Identifier`s.

**Tech Stack:** Rust workspace crates `keri-events`, `keri-codec`. Gate: `nix flake check` via pre-push hook.

**Bug being fixed:** `Field::new("i", i).decode()` in `FromWire<ParsedSeal> for Seal` targets `BasicPrefix` (`Matter<VerKeyCode>`). A keripy delegation-anchor seal carries `i` = the delegated dip prefix, which is self-addressing (`DigestCode`, `E…`). The lift errors and there is no opaque fallback at lift stage — the whole event fails to deserialize.

---

### Task 1: Failing round-trip test

**Files:**
- Test: `crates/keri-codec/src/codec/seal.rs` (in-module `tests`)

- [ ] **Step 1: Write the failing test**

In the existing `#[cfg(test)] mod tests` of `crates/keri-codec/src/codec/seal.rs` (it already has `make_prefixer`/`make_saider`-style helpers — reuse them), add:

```rust
/// A delegation-anchor seal carries a self-addressing delegate prefix
/// (keripy: dip prefix = SAID, code `E`). Encode → decode must round-trip
/// it as `Identifier::SelfAddressing`, not fail the lift.
#[test]
fn event_seal_with_self_addressing_identifier_round_trips() {
    let seal = Seal::Event {
        i: Identifier::SelfAddressing(make_saider()),
        s: Number::new(3),
        d: make_saider(),
    };
    let mut out = Vec::new();
    seal.encode(&mut out);
    let mut sc = Scanner::new(core::str::from_utf8(&out).unwrap());
    let parsed = ParsedSeal::decode(&mut sc).unwrap();
    let lifted = Seal::from_wire("a", parsed).unwrap();
    let Seal::Event { i, s, d } = &lifted else {
        panic!("expected Seal::Event, got a different variant");
    };
    assert!(matches!(i, Identifier::SelfAddressing(_)));
    assert_eq!(s.value(), 3);
    assert_eq!(d, &make_saider());
    let mut out2 = Vec::new();
    lifted.encode(&mut out2);
    assert_eq!(out, out2);
}

#[test]
fn last_seal_with_self_addressing_identifier_round_trips() {
    let seal = Seal::Last {
        i: Identifier::SelfAddressing(make_saider()),
    };
    let mut out = Vec::new();
    seal.encode(&mut out);
    let mut sc = Scanner::new(core::str::from_utf8(&out).unwrap());
    let parsed = ParsedSeal::decode(&mut sc).unwrap();
    let lifted = Seal::from_wire("a", parsed).unwrap();
    assert!(
        matches!(&lifted, Seal::Last { i: Identifier::SelfAddressing(_) })
    );
    let mut out2 = Vec::new();
    lifted.encode(&mut out2);
    assert_eq!(out, out2);
}
```

Adjust helper names/imports to what the module's test section actually uses (`Identifier` needs importing there; `Scanner` import path is whatever `ParsedSeal`'s existing tests use).

- [ ] **Step 2: Run — expect compile failure**

Run: `nix develop --command cargo nextest run -p keri-codec seal`
Expected: FAIL to compile — `Seal::Event.i` / `Seal::Last.i` expect `BasicPrefix`, got `Identifier`. This is the type-level proof of the gap.

### Task 2: Widen the type in keri-events

**Files:**
- Modify: `crates/keri-events/src/seal.rs` (Seal::Event.i, Seal::Last.i, into_static)
- Modify: any in-crate construction sites (`rg -n "Seal::Event|Seal::Last" crates/keri-events`)

- [ ] **Step 1: Change the two fields**

```rust
    /// Event seal — fully identifies an event by prefix, sequence number, and digest.
    Event {
        /// Prefix of the identifier — basic or self-addressing (a delegated
        /// identifier's prefix is its inception SAID).
        i: Identifier<'a>,
        /// Sequence number of the event.
        s: Number,
        /// Digest of the event.
        d: Said<'a>,
    },
    /// Last-event seal — references the latest event for a given prefix.
    Last {
        /// Prefix of the identifier — basic or self-addressing.
        i: Identifier<'a>,
    },
```

Update the `use` line (`Identifier` instead of / alongside `BasicPrefix` — keep `BasicPrefix` if `Back.bi` still needs it) and the two `into_static` arms (`Identifier::into_static` exists).

- [ ] **Step 2: Fix keri-events construction sites**

`rg -n "Seal::Event|Seal::Last" crates/keri-events` — wrap existing `BasicPrefix` values as `Identifier::Basic(prefix)`.

- [ ] **Step 3: Build keri-events**

Run: `nix develop --command cargo build -p keri-events`
Expected: clean.

### Task 3: Fix all downstream construction/match sites

**Files (blast radius — grep, don't trust this list):**
- Modify: `crates/keri-codec/src/codec/seal.rs` (lift arms — types now infer `Identifier`; test fixtures)
- Modify: `crates/keri-codec/src/builder/ixn.rs`, `crates/keri-codec/src/codec/event.rs`, `crates/keri-codec/src/deserialize.rs`, `crates/keri-codec/src/deserialize/reference.rs`, `crates/keri-codec/src/serialize.rs`, `crates/keri-codec/src/event_strategies.rs`, `crates/keri-codec/src/keripy_parity/seal_events.rs`, `crates/keri-codec/src/keripy_parity/codex.rs`
- Modify: `crates/keri-codec/benches/serder.rs`, `crates/keri-codec/tests/serder_allocation.rs`
- Check: `fuzz/`, `fuzz-common/`, `fuzz-afl/`, `examples/` (`rg -n "Seal::Event|Seal::Last" fuzz fuzz-common fuzz-afl examples benches` — separate workspaces, easy to miss)

- [ ] **Step 1: Sweep the workspace**

Run: `rg -ln "Seal::Event|Seal::Last" crates fuzz fuzz-common fuzz-afl examples benches 2>/dev/null`

For each construction site: `i: prefix.into()`-style `BasicPrefix` values become `i: Identifier::Basic(prefix)`. For each match site: bind `i` as `Identifier` (add `Identifier::Basic`/`SelfAddressing` handling where the code inspected the prefix). The codec lift arms need no code change if type inference routes to `FromWire<&str> for Identifier` — verify the `i` lifts in `codec/seal.rs:111-118` now resolve there.

- [ ] **Step 2: Extend the proptest strategy**

In `crates/keri-codec/src/event_strategies.rs`, wherever the seal strategy generates `i`, generate both arms:

```rust
prop_oneof![
    basic_prefix_strategy().prop_map(Identifier::Basic),
    said_strategy().prop_map(Identifier::SelfAddressing),
]
```

(adapt to the file's actual strategy names — the point is the round-trip property now covers `E…` seal identifiers).

- [ ] **Step 3: Run the Task 1 tests + full test suites**

Run: `nix develop --command cargo nextest run -p keri-codec -p keri-events`
Expected: PASS, including the two Task 1 tests.

### Task 4: CHANGELOG, commit, PR

- [ ] **Step 1: CHANGELOG entries**

`crates/keri-events/CHANGELOG.md` + `crates/keri-codec/CHANGELOG.md` under Unreleased: breaking — `Seal::Event.i`/`Seal::Last.i` widened `BasicPrefix` → `Identifier`; fixes deserialization failure on delegation-anchor seals with self-addressing prefixes.

- [ ] **Step 2: Commit + push + PR**

```bash
git add -A
git commit -m "fix(keri-events)!: widen seal identifier to basic-or-self-addressing"
git push -u origin <branch>
gh pr create --fill && gh pr merge --auto --squash
```

Pre-push hook runs `nix flake check` (needs committed state — commit first, never check a dirty tree).

## Self-review notes

- Spec coverage: single-concern fix, both variants (`Event`, `Last`) covered; `Back.bi` deliberately untouched (backers are non-transferable basic prefixes by definition).
- No placeholders; the only "adapt to actual names" instructions are grep-anchored, not hand-waves.
