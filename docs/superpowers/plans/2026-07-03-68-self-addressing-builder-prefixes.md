# Self-Addressing Builder Prefixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the event builders emit self-addressing (transferable) identifier prefixes so a real `icp → ixn → rot` KEL chain (and a self-addressing delegated inception) is constructible through the public API — closing the write-path/read-path parity gap in #68.

**Architecture:** The event structs and read path already speak `Identifier`; only the builder *setters* narrow to `Prefixer` (key-coded) and then `.into()` to `Identifier::Basic`. Widen three setters to `impl Into<Identifier<'static>>`, add a `SerializedEvent::identifier()` bridge to carry an inception's SAID-prefix forward, and derive `Clone` on `Matter`/`Identifier` so one identifier value can feed multiple downstream events. No wire-format or event-struct changes. Witnesses stay `Prefixer` (read path + keripy mandate them non-transferable).

**Tech Stack:** Rust 2024, `stable 1.95.0`, no_std/alloc-capable, feature-gated (`serder`). Single gate: `nix flake check`.

**Reference:** Spec at `docs/superpowers/specs/2026-07-03-68-self-addressing-builder-prefixes-design.md`.

---

## File Structure

**Modify:**
- `src/core/matter/matter.rs` — derive `Clone` on `Matter`.
- `src/keri/identifier.rs` — derive `Clone` on `Identifier`; add a clone test.
- `src/serder/serialize.rs` — add `SerializedEvent::identifier()`; import `Identifier`; add a test.
- `src/serder/builder/rot.rs` — widen `prefix` setter + field; drop `.into()` in `build()`; add self-addressing test.
- `src/serder/builder/ixn.rs` — widen `prefix` setter + field; drop `.into()` in `build()`; add self-addressing test.
- `src/serder/builder/dip.rs` — widen `delegator` setter + field; drop `.into()` in `build()`; add self-addressing test.
- `Cargo.toml` — two new `[[example]]` entries.
- `CHANGELOG.md` — note the breaking change + additions.

**Create:**
- `tests/kel_chain.rs` — round-trip `icp → ixn → rot` and delegated-inception chain tests.
- `examples/kel_chain.rs` — runnable `icp → ixn → rot` walk-through (closes #32 #5).
- `examples/delegated_inception.rs` — runnable self-addressing `dip` (closes #32 #6).

**Conventions (verified in-repo):**
- Public paths: `cesr::Identifier`, `cesr::{InceptionBuilder, ...}` prelude re-exports, `cesr::keri::{InceptionEvent, InteractionEvent, RotationEvent, DelegatedInceptionEvent}`, `cesr::serder::{KeriDeserialize, KeriSerialize}`, `cesr::stream::encode::matter_to_qb64`.
- Event accessors: `.prefix() -> &Identifier<'static>` (icp/rot/ixn), `.delegator() -> &Identifier<'static>` (dip), `.said() -> &Saider<'static>`, `.prior_event_said() -> &Saider<'static>`.
- `SerializedEvent`: `.as_bytes()`, `.said() -> &Saider`, `.prefix() -> Option<&Saider>`, `.ilk() -> Ilk`.
- Builder typestates: rot `prefix → prior_event_said → keys → build`; ixn `prefix → prior_event_said → build`; dip `keys → delegator → build`; icp `keys → build`.
- `Identifier` has `From<Prefixer>` (→ Basic), `From<Saider>` (→ SelfAddressing), `as_prefixer()`, `as_saider()`, manual `PartialEq`/`Eq`.
- **The single gate is `nix flake check`** — run everything inside the nix dev shell: `nix develop --command bash -c "<cmd>"`. New/untracked files must be `git add`ed before `nix flake check` (the flake checks the staged tree).

---

## Task 1: Derive `Clone` on `Matter` and `Identifier`

**Files:**
- Modify: `src/core/matter/matter.rs:16`
- Modify: `src/keri/identifier.rs:15`
- Test: `src/keri/identifier.rs` (test module at bottom)

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` block at the bottom of `src/keri/identifier.rs` (after the existing `equality` test):

```rust
    #[test]
    fn clone_preserves_variant_and_value() {
        let id = Identifier::from(make_saider());
        let cloned = id.clone();
        assert!(cloned.as_saider().is_some(), "clone keeps SelfAddressing variant");
        assert!(id == cloned, "clone equals the original");

        let basic = Identifier::from(make_prefixer());
        let basic_cloned = basic.clone();
        assert!(basic == basic_cloned, "clone equals the original (Basic)");
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `nix develop --command bash -c "cargo test --features serder --lib keri::identifier::tests::clone_preserves_variant_and_value"`
Expected: FAIL to compile — `error[E0599]: no method named 'clone' found for enum 'Identifier'` (and, once you look, `Matter` is not `Clone` either).

- [ ] **Step 3: Derive `Clone` on `Matter`**

In `src/core/matter/matter.rs`, add the derive immediately above the struct (line 16). It currently reads:

```rust
/// A CESR-encoded primitive with typed code `C`, a raw payload, and an optional soft field.
pub struct Matter<'a, C: CesrCode> {
```

Change to:

```rust
/// A CESR-encoded primitive with typed code `C`, a raw payload, and an optional soft field.
#[derive(Clone)]
pub struct Matter<'a, C: CesrCode> {
```

(All code enums derive `Copy + Clone`, so the auto-generated `where C: Clone` bound holds. Cloning a `Cow::Borrowed` stays borrowed — no forced allocation.)

- [ ] **Step 4: Derive `Clone` on `Identifier`**

In `src/keri/identifier.rs`, the enum currently reads (lines 9-20):

```rust
/// In KERI, identifiers created with basic derivation use the public key as
/// the prefix (e.g., Ed25519 code `D`), while self-addressing identifiers
/// use the SAID of the inception event (e.g., `Blake3_256` code `E`).
pub enum Identifier<'a> {
```

Add the derive directly above `pub enum`:

```rust
/// use the SAID of the inception event (e.g., `Blake3_256` code `E`).
#[derive(Clone)]
pub enum Identifier<'a> {
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `nix develop --command bash -c "cargo test --features serder --lib keri::identifier::tests::clone_preserves_variant_and_value"`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/core/matter/matter.rs src/keri/identifier.rs
git commit -m "feat(#68): derive Clone on Matter and Identifier

Enables owned Identifier<'static> values to be reused across a KEL
chain. Clone is opt-in; borrowed Cow clones stay borrowed."
```

---

## Task 2: Add the `SerializedEvent::identifier()` bridge

**Files:**
- Modify: `src/serder/serialize.rs:27` (import) and `:92` (new method after `prefix()`)
- Test: `src/serder/serialize.rs` (test module at bottom)

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` block at the bottom of `src/serder/serialize.rs`:

```rust
    #[test]
    fn identifier_bridges_inception_prefix() {
        use crate::keri::Identifier;
        use crate::serder::builder::icp::InceptionBuilder;
        use crate::core::matter::builder::MatterBuilder;
        use crate::core::matter::code::VerKeyCode;

        let verfer = MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(alloc::borrow::Cow::<[u8]>::Owned(alloc::vec![7u8; 32]))
            .unwrap()
            .build()
            .unwrap();

        let icp = InceptionBuilder::new().keys(alloc::vec![verfer]).build().unwrap();

        let id = icp.identifier().expect("inception exposes a self-addressing identifier");
        match id {
            Identifier::SelfAddressing(ref saider) => {
                assert_eq!(saider.raw(), icp.prefix().unwrap().raw(), "identifier wraps the prefix SAID");
            }
            Identifier::Basic(_) => panic!("inception identifier must be self-addressing"),
        }
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `nix develop --command bash -c "cargo test --features serder --lib serder::serialize::tests::identifier_bridges_inception_prefix"`
Expected: FAIL to compile — `error[E0599]: no method named 'identifier' found for struct 'SerializedEvent'`.

- [ ] **Step 3: Import `Identifier` in serialize.rs**

Line 27 currently reads:

```rust
use crate::keri::{Ilk, KeriEvent, Seal};
```

Change to:

```rust
use crate::keri::{Identifier, Ilk, KeriEvent, Seal};
```

- [ ] **Step 4: Add the `identifier()` method**

In `src/serder/serialize.rs`, inside `impl<E> SerializedEvent<E>`, immediately after the `prefix()` method (which ends at line 92 with `}`), add:

```rust
    /// The identifier prefix as an [`Identifier`], if this event carries a
    /// self-addressing prefix (inception or delegated inception).
    ///
    /// This is the ergonomic bridge for building a self-addressing KEL chain:
    /// feed the returned value into [`RotationBuilder::prefix`] /
    /// [`InteractionBuilder::prefix`] to construct the next event without
    /// re-parsing the serialized JSON. Returns `None` for `rot`/`ixn` events,
    /// which do not store a self-addressing prefix (their identifier is carried
    /// forward from the inception).
    ///
    /// [`RotationBuilder::prefix`]: crate::serder::builder::rot::RotationBuilder::prefix
    /// [`InteractionBuilder::prefix`]: crate::serder::builder::ixn::InteractionBuilder::prefix
    #[must_use]
    pub fn identifier(&self) -> Option<Identifier<'static>> {
        self.prefix.clone().map(Identifier::SelfAddressing)
    }
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `nix develop --command bash -c "cargo test --features serder --lib serder::serialize::tests::identifier_bridges_inception_prefix"`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/serder/serialize.rs
git commit -m "feat(#68): add SerializedEvent::identifier() bridge

Carries an inception's self-addressing prefix forward as an owned
Identifier for chaining rot/ixn events without re-parsing JSON."
```

---

## Task 3: Widen `RotationBuilder::prefix` to accept `Identifier`

**Files:**
- Modify: `src/serder/builder/rot.rs:12` (import), `:46` (field), `:82,84` (setter), `:253` (build)
- Test: `src/serder/builder/rot.rs` (test module)

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` block in `src/serder/builder/rot.rs` (the helpers `make_verfer`, `make_saider`, and `make_prefixer` already exist there; `make_saider()` returns a `Blake3_256` `Saider`):

```rust
    #[test]
    fn build_rotation_with_self_addressing_prefix() {
        // A digest-coded Saider stands in for a real inception SAID prefix.
        let result = RotationBuilder::new()
            .prefix(make_saider())
            .prior_event_said(make_saider())
            .keys(vec![make_verfer()])
            .build()
            .unwrap();

        assert_eq!(result.ilk(), crate::keri::Ilk::Rot);
        // Deserialize and assert the "i" round-trips as self-addressing.
        let parsed = crate::serder::deserialize::deserialize_rotation(result.as_bytes()).unwrap();
        assert!(
            parsed.prefix().as_saider().is_some(),
            "rotation prefix must decode as self-addressing"
        );
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `nix develop --command bash -c "cargo test --features serder --lib serder::builder::rot::tests::build_rotation_with_self_addressing_prefix"`
Expected: FAIL to compile — `.prefix(make_saider())` gives `expected 'Prefixer<'_>', found 'Matter<'_, DigestCode>'` (the setter still takes `Prefixer`).

- [ ] **Step 3: Import `Identifier`**

Line 12 currently reads:

```rust
use crate::keri::{ConfigTrait, RotationEvent, Seal};
```

Change to:

```rust
use crate::keri::{ConfigTrait, Identifier, RotationEvent, Seal};
```

- [ ] **Step 4: Change the field type**

Line 46 currently reads:

```rust
    prefix: Option<Prefixer<'static>>,
```

Change to:

```rust
    prefix: Option<Identifier<'static>>,
```

- [ ] **Step 5: Widen the setter**

The `prefix` setter (lines 81-84) currently reads:

```rust
    /// Set the identifier prefix (required).
    pub fn prefix(self, prefix: Prefixer<'static>) -> RotationBuilder<NeedsPriorSaid> {
        RotationBuilder {
            prefix: Some(prefix),
```

Change to:

```rust
    /// Set the identifier prefix (required). Accepts a basic (`Prefixer`) or
    /// self-addressing (`Saider`) prefix, or an `Identifier` directly.
    pub fn prefix(self, prefix: impl Into<Identifier<'static>>) -> RotationBuilder<NeedsPriorSaid> {
        RotationBuilder {
            prefix: Some(prefix.into()),
```

- [ ] **Step 6: Drop the `.into()` in `build()`**

Line 253 (inside `RotationEvent::new(...)`) currently reads:

```rust
            prefix.into(),
```

Change to:

```rust
            prefix,
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `nix develop --command bash -c "cargo test --features serder --lib serder::builder::rot"`
Expected: PASS — both the new test and the pre-existing `build_minimal_rotation` (which calls `.prefix(make_prefixer())`; `Prefixer: Into<Identifier>` keeps it compiling).

- [ ] **Step 8: Commit**

```bash
git add src/serder/builder/rot.rs
git commit -m "feat(#68)!: RotationBuilder::prefix accepts Identifier

BREAKING: prefix() param widens Prefixer<'static> ->
impl Into<Identifier<'static>>. Existing Prefixer callers keep
compiling; self-addressing rotation prefixes are now expressible."
```

---

## Task 4: Widen `InteractionBuilder::prefix` to accept `Identifier`

**Files:**
- Modify: `src/serder/builder/ixn.rs:12` (import), `:42` (field), `:62,64` (setter), `:126` (build)
- Test: `src/serder/builder/ixn.rs` (test module)

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` block in `src/serder/builder/ixn.rs`. First confirm the module's existing test helpers; it has `make_prefixer()` and a Saider helper. If a Blake3_256 `Saider` helper is not present, add this one alongside the others:

```rust
    fn make_said_prefix() -> crate::core::primitives::Saider<'static> {
        crate::core::matter::builder::MatterBuilder::new()
            .with_code(crate::core::matter::code::DigestCode::Blake3_256)
            .with_raw(alloc::borrow::Cow::<[u8]>::Owned(vec![5u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }
```

Then add the test:

```rust
    #[test]
    fn build_interaction_with_self_addressing_prefix() {
        let result = InteractionBuilder::new()
            .prefix(make_said_prefix())
            .prior_event_said(make_said_prefix())
            .build()
            .unwrap();

        assert_eq!(result.ilk(), crate::keri::Ilk::Ixn);
        let parsed = crate::serder::deserialize::deserialize_interaction(result.as_bytes()).unwrap();
        assert!(
            parsed.prefix().as_saider().is_some(),
            "interaction prefix must decode as self-addressing"
        );
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `nix develop --command bash -c "cargo test --features serder --lib serder::builder::ixn::tests::build_interaction_with_self_addressing_prefix"`
Expected: FAIL to compile — `.prefix(make_said_prefix())` gives a type mismatch (`Saider` vs expected `Prefixer`).

- [ ] **Step 3: Import `Identifier`**

Line 12 currently reads:

```rust
use crate::keri::{InteractionEvent, Seal};
```

Change to:

```rust
use crate::keri::{Identifier, InteractionEvent, Seal};
```

- [ ] **Step 4: Change the field type**

Line 42 currently reads:

```rust
    prefix: Option<Prefixer<'static>>,
```

Change to:

```rust
    prefix: Option<Identifier<'static>>,
```

- [ ] **Step 5: Widen the setter**

Lines 61-64 currently read:

```rust
    /// Set the identifier prefix (required).
    pub fn prefix(self, prefix: Prefixer<'static>) -> InteractionBuilder<NeedsPriorSaid> {
        InteractionBuilder {
            prefix: Some(prefix),
```

Change to:

```rust
    /// Set the identifier prefix (required). Accepts a basic (`Prefixer`) or
    /// self-addressing (`Saider`) prefix, or an `Identifier` directly.
    pub fn prefix(self, prefix: impl Into<Identifier<'static>>) -> InteractionBuilder<NeedsPriorSaid> {
        InteractionBuilder {
            prefix: Some(prefix.into()),
```

- [ ] **Step 6: Drop the `.into()` in `build()`**

Line 126 (inside `InteractionEvent::new(...)`) currently reads:

```rust
            prefix.into(),
```

Change to:

```rust
            prefix,
```

- [ ] **Step 7: Check whether `Prefixer` is still used in ixn.rs**

After the field type change, `Prefixer` may no longer be referenced in `src/serder/builder/ixn.rs` (ixn has no witness fields). Run:

Run: `nix develop --command bash -c "cargo build --features serder 2>&1 | grep -A2 'unused import' || echo NO_UNUSED"`
If it reports `Prefixer` unused, edit line 11 from `use crate::core::primitives::{Prefixer, Saider, Seqner};` to `use crate::core::primitives::{Saider, Seqner};`. If it prints `NO_UNUSED`, leave the import as-is.

- [ ] **Step 8: Run the tests to verify they pass**

Run: `nix develop --command bash -c "cargo test --features serder --lib serder::builder::ixn"`
Expected: PASS — new test plus pre-existing interaction tests.

- [ ] **Step 9: Commit**

```bash
git add src/serder/builder/ixn.rs
git commit -m "feat(#68)!: InteractionBuilder::prefix accepts Identifier

BREAKING: prefix() param widens Prefixer<'static> ->
impl Into<Identifier<'static>>."
```

---

## Task 5: Widen `DelegatedInceptionBuilder::delegator` to accept `Identifier`

**Files:**
- Modify: `src/serder/builder/dip.rs:13` (import), `:45` (field), `:98,101` (setter), `:211` (build)
- Test: `src/serder/builder/dip.rs` (test module)

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` block in `src/serder/builder/dip.rs`. The module already has helpers (`make_verfer`, `make_prefixer`). Add a Blake3_256 `Saider` helper if not present:

```rust
    fn make_said_delegator() -> crate::core::primitives::Saider<'static> {
        crate::core::matter::builder::MatterBuilder::new()
            .with_code(crate::core::matter::code::DigestCode::Blake3_256)
            .with_raw(alloc::borrow::Cow::<[u8]>::Owned(vec![6u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }
```

Then add the test:

```rust
    #[test]
    fn build_dip_with_self_addressing_delegator() {
        let result = DelegatedInceptionBuilder::new()
            .keys(vec![make_verfer()])
            .delegator(make_said_delegator())
            .build()
            .unwrap();

        assert_eq!(result.ilk(), crate::keri::Ilk::Dip);
        let parsed =
            crate::serder::deserialize::deserialize_delegated_inception(result.as_bytes()).unwrap();
        assert!(
            parsed.delegator().as_saider().is_some(),
            "delegator must decode as self-addressing"
        );
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `nix develop --command bash -c "cargo test --features serder --lib serder::builder::dip::tests::build_dip_with_self_addressing_delegator"`
Expected: FAIL to compile — `.delegator(make_said_delegator())` gives a type mismatch (`Saider` vs expected `Prefixer`).

- [ ] **Step 3: Import `Identifier`**

Line 13 currently reads:

```rust
use crate::keri::{ConfigTrait, DelegatedInceptionEvent, InceptionEvent, Seal};
```

Change to:

```rust
use crate::keri::{ConfigTrait, DelegatedInceptionEvent, Identifier, InceptionEvent, Seal};
```

- [ ] **Step 4: Change the field type**

Line 45 currently reads:

```rust
    delegator: Option<Prefixer<'static>>,
```

Change to:

```rust
    delegator: Option<Identifier<'static>>,
```

- [ ] **Step 5: Widen the setter**

Lines 96-101 currently read:

```rust
impl DelegatedInceptionBuilder<NeedsDelegator> {
    /// Set the delegator prefix (required).
    pub fn delegator(self, delegator: Prefixer<'static>) -> DelegatedInceptionBuilder<Ready> {
        DelegatedInceptionBuilder {
            keys: self.keys,
            delegator: Some(delegator),
```

Change to:

```rust
impl DelegatedInceptionBuilder<NeedsDelegator> {
    /// Set the delegator prefix (required). Accepts a basic (`Prefixer`) or
    /// self-addressing (`Saider`) delegator, or an `Identifier` directly.
    pub fn delegator(self, delegator: impl Into<Identifier<'static>>) -> DelegatedInceptionBuilder<Ready> {
        DelegatedInceptionBuilder {
            keys: self.keys,
            delegator: Some(delegator.into()),
```

- [ ] **Step 6: Drop the `.into()` in `build()`**

Line 211 currently reads:

```rust
        let event = DelegatedInceptionEvent::new(inception, delegator.into());
```

Change to:

```rust
        let event = DelegatedInceptionEvent::new(inception, delegator);
```

- [ ] **Step 7: Verify `Prefixer` is still used (witnesses field)**

`dip.rs` keeps `witnesses: Vec<Prefixer<'static>>`, so the `Prefixer` import stays needed. Confirm no unused-import warning:

Run: `nix develop --command bash -c "cargo build --features serder 2>&1 | grep 'unused import' || echo NO_UNUSED"`
Expected: `NO_UNUSED`.

- [ ] **Step 8: Run the tests to verify they pass**

Run: `nix develop --command bash -c "cargo test --features serder --lib serder::builder::dip"`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add src/serder/builder/dip.rs
git commit -m "feat(#68)!: DelegatedInceptionBuilder::delegator accepts Identifier

BREAKING: delegator() param widens Prefixer<'static> ->
impl Into<Identifier<'static>>. Delegator may now be a
self-addressing (transferable) AID, matching keripy's PreDex."
```

---

## Task 6: Round-trip KEL chain integration test

**Files:**
- Create: `tests/kel_chain.rs`

- [ ] **Step 1: Write the failing test**

Create `tests/kel_chain.rs` with the full round-trip chain. The file-level `#![cfg(feature = "serder")]` makes it compile to nothing under reduced feature sets (matches `tests/frozen_surface.rs` convention).

```rust
//! Round-trip parity test for self-addressing KEL chains (#68).
//!
//! Builds a real `icp -> ixn -> rot` chain where every event's identifier
//! prefix (`i`) equals the inception SAID, serializes + deserializes each
//! event, and asserts the chain is internally consistent. This is the test
//! whose absence let the write-path/read-path parity gap exist.
#![cfg(feature = "serder")]

use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::{DigestCode, VerKeyCode};
use cesr::keri::{Identifier, InteractionEvent, RotationEvent};
use cesr::serder::{
    deserialize_inception, deserialize_interaction, deserialize_rotation,
    DelegatedInceptionBuilder, InceptionBuilder, InteractionBuilder, RotationBuilder,
};

fn verfer(byte: u8) -> cesr::core::primitives::Verfer<'static> {
    MatterBuilder::new()
        .with_code(VerKeyCode::Ed25519)
        .with_raw(vec![byte; 32])
        .unwrap()
        .build()
        .unwrap()
}

fn diger(byte: u8) -> cesr::core::primitives::Diger<'static> {
    MatterBuilder::new()
        .with_code(DigestCode::Blake3_256)
        .with_raw(vec![byte; 32])
        .unwrap()
        .build()
        .unwrap()
}

#[test]
fn icp_ixn_rot_chain_shares_self_addressing_prefix() {
    // 1. Inception: produces a self-addressing prefix (i == d).
    let icp = InceptionBuilder::new().keys(vec![verfer(1)]).build().unwrap();
    let id = icp
        .identifier()
        .expect("inception exposes a self-addressing identifier");
    assert!(matches!(id, Identifier::SelfAddressing(_)));

    // The inception's own "i" decodes back to the same identifier.
    let icp_parsed = deserialize_inception(icp.as_bytes()).unwrap();
    assert_eq!(*icp_parsed.prefix(), id, "icp i decodes to the inception SAID");

    // 2. Interaction at sn=1, prior = inception SAID, same identifier.
    let ixn = InteractionBuilder::new()
        .prefix(id.clone())
        .prior_event_said(icp.said().clone())
        .sn(1)
        .build()
        .unwrap();
    let ixn_parsed: InteractionEvent = deserialize_interaction(ixn.as_bytes()).unwrap();
    assert_eq!(*ixn_parsed.prefix(), id, "ixn i equals the inception identifier");
    assert_eq!(
        ixn_parsed.prior_event_said().raw(),
        icp.said().raw(),
        "ixn prior points at the inception SAID"
    );

    // 3. Rotation at sn=2, prior = interaction SAID, same identifier.
    let rot = RotationBuilder::new()
        .prefix(id.clone())
        .prior_event_said(ixn.said().clone())
        .keys(vec![verfer(2)])
        .sn(2)
        .next_keys(vec![diger(3)])
        .build()
        .unwrap();
    let rot_parsed: RotationEvent = deserialize_rotation(rot.as_bytes()).unwrap();
    assert_eq!(*rot_parsed.prefix(), id, "rot i equals the inception identifier");
    assert_eq!(
        rot_parsed.prior_event_said().raw(),
        ixn.said().raw(),
        "rot prior points at the interaction SAID"
    );
}

#[test]
fn delegated_inception_self_addressing_delegator_round_trips() {
    // A self-addressing delegator (a transferable AID) is now expressible.
    let delegator = MatterBuilder::new()
        .with_code(DigestCode::Blake3_256)
        .with_raw(vec![9u8; 32])
        .unwrap()
        .build()
        .unwrap();
    let delegator_id = Identifier::SelfAddressing(delegator);

    let dip = DelegatedInceptionBuilder::new()
        .keys(vec![verfer(1)])
        .delegator(delegator_id.clone())
        .build()
        .unwrap();

    let parsed =
        cesr::serder::deserialize_delegated_inception(dip.as_bytes()).unwrap();
    assert_eq!(
        *parsed.delegator(),
        delegator_id,
        "di decodes back to the self-addressing delegator"
    );
}
```

- [ ] **Step 2: Verify the public re-export paths used by the test**

The test imports builders and `deserialize_*` from `cesr::serder`. Confirm these names are re-exported there:

Run: `nix develop --command bash -c "grep -rn 'InceptionBuilder\|deserialize_inception\|deserialize_delegated_inception' src/serder/mod.rs"`
Expected: lines showing `pub use` of the builders and `deserialize_*` functions. If a name is exported under a different path (e.g. `cesr::serder::builder::icp::InceptionBuilder`), adjust the `use` in the test to match what the grep shows. Do not guess — use the path the grep confirms.

- [ ] **Step 3: Run the test to verify it passes**

Run: `nix develop --command bash -c "cargo test --features serder --test kel_chain"`
Expected: PASS (both tests). If it fails to compile on an import path, fix per Step 2's grep output and re-run.

- [ ] **Step 4: Commit**

```bash
git add tests/kel_chain.rs
git commit -m "test(#68): round-trip icp->ixn->rot self-addressing KEL chain

The safeguard that would have caught the write/read parity gap:
every event's i equals the inception SAID and round-trips."
```

---

## Task 7: Runnable examples (closes #32 #5/#6)

**Files:**
- Create: `examples/kel_chain.rs`
- Create: `examples/delegated_inception.rs`
- Modify: `Cargo.toml` (two `[[example]]` entries)

- [ ] **Step 1: Create `examples/kel_chain.rs`**

Modeled on `examples/incept_aid.rs` (same imports/style). Examples may use `?`/`expect` for brevity.

```rust
//! Build a self-addressing KEL chain: inception -> interaction -> rotation.
//!
//! Every event's identifier prefix (`i`) is the SAID of the *inception* event,
//! carried forward verbatim — the same way keripy and signify-ts chain a KEL.
//! `SerializedEvent::identifier()` hands the inception's self-addressing prefix
//! to each subsequent builder without re-parsing JSON.
//!
//! Run with:
//! ```text
//! cargo run --example kel_chain --features serder
//! ```

#![allow(
    clippy::print_stdout,
    reason = "runnable example: it prints each event in the chain"
)]

use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::{DigestCode, VerKeyCode};
use cesr::{InceptionBuilder, InteractionBuilder, RotationBuilder};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // Deterministic keys so the chain is reproducible across runs.
    let icp_key = MatterBuilder::new()
        .with_code(VerKeyCode::Ed25519)
        .with_raw([0x11u8; 32].to_vec())?
        .build()?;

    // 1. Inception establishes the identifier. Its prefix is self-addressing.
    let icp = InceptionBuilder::new().keys(vec![icp_key]).build()?;
    let id = icp
        .identifier()
        .ok_or("inception must expose a self-addressing identifier")?;
    println!("icp:\n{}\n", String::from_utf8_lossy(icp.as_bytes()));

    // 2. Interaction anchors data under the same identifier at sn=1.
    let ixn = InteractionBuilder::new()
        .prefix(id.clone())
        .prior_event_said(icp.said().clone())
        .sn(1)
        .build()?;
    println!("ixn:\n{}\n", String::from_utf8_lossy(ixn.as_bytes()));

    // 3. Rotation rotates to new keys under the same identifier at sn=2.
    let rot_key = MatterBuilder::new()
        .with_code(VerKeyCode::Ed25519)
        .with_raw([0x22u8; 32].to_vec())?
        .build()?;
    let next_key = MatterBuilder::new()
        .with_code(DigestCode::Blake3_256)
        .with_raw([0x33u8; 32].to_vec())?
        .build()?;
    let rot = RotationBuilder::new()
        .prefix(id)
        .prior_event_said(ixn.said().clone())
        .keys(vec![rot_key])
        .sn(2)
        .next_keys(vec![next_key])
        .build()?;
    println!("rot:\n{}\n", String::from_utf8_lossy(rot.as_bytes()));

    println!("KEL chain built: every event shares the inception's self-addressing prefix.");
    Ok(())
}
```

- [ ] **Step 2: Create `examples/delegated_inception.rs`**

```rust
//! Build a delegated inception (`dip`) with a self-addressing delegator.
//!
//! A delegated identifier names its delegator in the `di` field. keripy allows
//! any valid prefix code there (basic *or* self-addressing); this example uses a
//! transferable (self-addressing) delegator AID — now expressible after #68.
//!
//! Run with:
//! ```text
//! cargo run --example delegated_inception --features serder
//! ```

#![allow(
    clippy::print_stdout,
    reason = "runnable example: it prints the delegated inception event"
)]

use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::{DigestCode, VerKeyCode};
use cesr::keri::Identifier;
use cesr::DelegatedInceptionBuilder;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let key = MatterBuilder::new()
        .with_code(VerKeyCode::Ed25519)
        .with_raw([0x11u8; 32].to_vec())?
        .build()?;

    // The delegator is a transferable (self-addressing) AID — a digest prefix.
    let delegator = MatterBuilder::new()
        .with_code(DigestCode::Blake3_256)
        .with_raw([0x44u8; 32].to_vec())?
        .build()?;

    let dip = DelegatedInceptionBuilder::new()
        .keys(vec![key])
        .delegator(Identifier::SelfAddressing(delegator))
        .build()?;

    println!(
        "delegated inception:\n{}",
        String::from_utf8_lossy(dip.as_bytes())
    );
    Ok(())
}
```

- [ ] **Step 3: Register the examples in `Cargo.toml`**

After the existing `multisig_threshold_icp` `[[example]]` entry (`Cargo.toml:154-156`), add:

```toml
[[example]]
name = "kel_chain"
required-features = ["serder"]

[[example]]
name = "delegated_inception"
required-features = ["serder"]
```

- [ ] **Step 4: Run both examples to verify they work**

Run: `nix develop --command bash -c "cargo run --example kel_chain --features serder && cargo run --example delegated_inception --features serder"`
Expected: both print their serialized events and exit 0 (no panic).

- [ ] **Step 5: Format TOML**

Run: `nix develop --command bash -c "taplo fmt Cargo.toml"`
Expected: no error (idempotent if already formatted).

- [ ] **Step 6: Commit**

```bash
git add examples/kel_chain.rs examples/delegated_inception.rs Cargo.toml
git commit -m "docs(#68): runnable KEL-chain and delegated-inception examples

Closes #32 examples #5 and #6 — a real icp->ixn->rot chain and a
self-addressing delegated inception, now that the builders can emit
self-addressing prefixes."
```

---

## Task 8: CHANGELOG and full gate

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Read the current CHANGELOG head**

Run: `nix develop --command bash -c "head -30 CHANGELOG.md"`
Expected: shows the `Unreleased`/top section format. Match its exact heading style in the next step.

- [ ] **Step 2: Add CHANGELOG entries**

Under the top `Unreleased` section (create the `### Changed` / `### Added` subsections if the file's convention uses them; otherwise match the existing bullet style), add:

```markdown
### Changed
- **BREAKING** (#68): `RotationBuilder::prefix`, `InteractionBuilder::prefix`, and
  `DelegatedInceptionBuilder::delegator` now take `impl Into<Identifier<'static>>`
  instead of `Prefixer<'static>`. Existing `Prefixer` call sites keep compiling
  (`Prefixer: Into<Identifier>`); self-addressing (transferable) prefixes and
  delegators are now expressible, closing the write-path/read-path parity gap.

### Added
- `SerializedEvent::identifier() -> Option<Identifier<'static>>` — bridges an
  inception's self-addressing prefix to the next event in a KEL chain (#68).
- `Clone` for `Matter` (and all primitive aliases) and `Identifier` (#68).
- Examples `kel_chain` and `delegated_inception` (#68; closes #32 #5/#6).
```

- [ ] **Step 3: Commit the CHANGELOG**

```bash
git add CHANGELOG.md
git commit -m "docs(#68): changelog for self-addressing builder prefixes"
```

- [ ] **Step 4: Run the full gate**

Run: `nix develop --command bash -c "git add -A && nix flake check"`
Expected: all checks pass (clippy, fmt, taplo, audit, deny, nextest across feature combos, doctest, wasm build, no_std build). `git add -A` first so the flake sees the new example/test files in the staged tree.

- [ ] **Step 5: If the gate fails, fix and re-run**

Common issues and fixes:
- **clippy `use_self` / import ordering** in edited files — apply clippy's suggested fix; imports stay at file top (project rule).
- **Unused `Prefixer` import in `ixn.rs`** — remove per Task 4 Step 7.
- **doctest** — the examples aren't doctests, but if a doc-comment code block newly fails, mark illustrative snippets ` ```ignore ` (existing builders already do).
Re-run Step 4 until green. Do not relax any lint (project rule: `[lints]` is law).

---

## Self-Review

**Spec coverage:**
- Widen `rot`/`ixn`/`dip` setters → Tasks 3, 4, 5. ✅
- Drop `.into()` in each `build()` → Tasks 3/4/5 steps. ✅
- Witnesses untouched → confirmed (only `prefix`/`delegator` fields change; witness fields left as `Vec<Prefixer>`). ✅
- `SerializedEvent::identifier()` bridge → Task 2. ✅
- `Clone` on `Matter` + `Identifier` → Task 1. ✅
- Round-trip chain test + delegated variant → Task 6. ✅
- Basic path preserved → pre-existing builder tests kept (Task 3/4/5 note `.prefix(make_prefixer())` still compiles). ✅
- Setter-ergonomics (accepts Prefixer, Saider, Identifier) → exercised across Tasks 3-6 (Prefixer via existing tests, Saider via new unit tests, Identifier via Task 6 `id.clone()`). ✅
- Examples `kel_chain` + `delegated_inception` → Task 7. ✅
- CHANGELOG breaking-change note → Task 8. ✅
- Single gate `nix flake check` → Task 8 Step 4. ✅

**Placeholder scan:** No TBD/TODO; every code step shows full code. ✅

**Type consistency:** `identifier()` returns `Option<Identifier<'static>>` (Task 2) and is consumed as such in Tasks 6/7. Setter param `impl Into<Identifier<'static>>` consistent across Tasks 3-5. Field type `Option<Identifier<'static>>` consistent. `deserialize_*` free functions used consistently (verified to exist at `src/serder/deserialize.rs`). Event accessors `.prefix()`/`.delegator()`/`.prior_event_said()`/`.said()` match the verified signatures. ✅

**Open verification points flagged for the implementer** (each has an in-task check step, not a guess):
- Exact `cesr::serder` re-export paths for builders/`deserialize_*` → Task 6 Step 2 greps and adjusts.
- Whether `Prefixer` becomes an unused import in `ixn.rs` → Task 4 Step 7 checks.
- CHANGELOG heading convention → Task 8 Step 1 reads first.
