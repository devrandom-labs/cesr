# keri-events Role Newtypes + #193 Close — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace keri-events' keripy-named cesr aliases (`Verfer`/`Diger`/`Saider`/`Prefixer`) with distinct, spec-named role newtypes (`VerifyingKey`/`Digest`/`Said`/`BasicPrefix`) that the compiler keeps un-swappable, then propagate through keri-codec and close the two remaining #193 boxes.

**Architecture:** Role is a domain-layer concept (not on the wire), so the newtypes live in `keri-events`, each wrapping a `cesr::core::matter::Matter<'a, C>` with `Deref` read-through. `cesr` stays pure substrate. keri-events + keri-codec land in one PR (keri-codec constructs keri-events structs, so the workspace can't compile split). cesr-stream needs no code change. `Ilk`/`Verser`/event-model consolidation are deferred (see the design spec).

**Tech Stack:** Rust 2024, no_std + alloc, `cesr::core::matter::Matter`, `thiserror`, `proptest`. Gate: `nix flake check`.

**Spec:** `docs/superpowers/specs/2026-07-26-keri-events-role-newtypes-design.md`

**Verification rule (repo law):** the ONLY gate is `nix develop --command cargo <x>` for fast local checks and `nix flake check` before commit/push. Never raw `cargo`. Per [[verification-nix-flake-check-only]] and [[dont-block-on-local-gate]], don't foreground-poll the full gate; use targeted `cargo nextest`/`cargo build` inside `nix develop` for task-level checks, and let the pre-push hook run the full gate.

---

## Naming map (single source of truth for every s/// in this plan)

| old (cesr alias) | new (keri-events newtype) | inner Matter code | wire fields |
|---|---|---|---|
| `Verfer<'a>` | `VerifyingKey<'a>` | `VerKeyCode` | `k` (current keys) |
| `Diger<'a>` | `Digest<'a>` | `DigestCode` | `n` (next-key digests), `p` (prior) |
| `Saider<'a>` | `Said<'a>` | `DigestCode` | `d` (SAID) |
| `Prefixer<'a>` | `BasicPrefix<'a>` | `VerKeyCode` | `i`/`bi` (basic AID prefix), `b`/`ba`/`br` (witnesses) |

`Number`, `Verser`, `Identifier`, `Seal`, `Ilk` are **unchanged** this pass.

> Note on witnesses: witness prefixes are basic AID prefixes → `BasicPrefix`. `p` (prior-event said) and `n` (next-key digests) are digests → `Digest`. `d` is the event's own SAID → `Said`. This matches the current alias mapping (`Diger` for `n`/`p`, `Saider` for `d`), so the split is: `Diger→Digest`, `Saider→Said`, both `DigestCode` but distinct roles.

---

## Task 1: Role newtype module in keri-events

**Files:**
- Create: `crates/keri-events/src/primitive.rs`
- Modify: `crates/keri-events/src/lib.rs` (add `mod primitive;` + `pub use`)

- [ ] **Step 1: Write the module with all four newtypes**

Create `crates/keri-events/src/primitive.rs`:

```rust
//! Role-distinct KERI primitive newtypes over cesr [`Matter`].
//!
//! CESR encodes a value's *code family* (e.g. `VerKeyCode`) but not its
//! *role*: a verification key (`k`) and a basic AID prefix (`i`) share
//! `VerKeyCode`, and a next-key digest (`n`) and a SAID (`d`) share
//! `DigestCode`. As bare `Matter<C>` those pairs are the same Rust type and
//! swap silently. These newtypes make the role a compile-time fact — a
//! [`VerifyingKey`] cannot be assigned where a [`BasicPrefix`] is expected.
//!
//! Each is a transparent wrapper: `Deref` gives read-through access to the
//! inner [`Matter`] (code, raw, qb64…), and encoding routes through that
//! inner value so wire bytes are identical to the pre-newtype representation.

use cesr::core::matter::code::{DigestCode, VerKeyCode};
use cesr::core::matter::matter::Matter;
use core::ops::Deref;

macro_rules! role_newtype {
    ($(#[$m:meta])* $name:ident, $code:ty) => {
        $(#[$m])*
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $name<'a>(Matter<'a, $code>);

        impl<'a> $name<'a> {
            /// Wrap a `Matter` in this role. Naming the role here is the
            /// safety checkpoint — the conversion site must state intent.
            #[must_use]
            pub const fn from_matter(inner: Matter<'a, $code>) -> Self {
                Self(inner)
            }

            /// The underlying CESR primitive.
            #[must_use]
            pub const fn as_matter(&self) -> &Matter<'a, $code> {
                &self.0
            }

            /// Detach from the source buffer by owning the inner primitive.
            #[must_use]
            pub fn into_static(self) -> $name<'static> {
                $name(self.0.into_static())
            }
        }

        impl<'a> Deref for $name<'a> {
            type Target = Matter<'a, $code>;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl<'a> From<Matter<'a, $code>> for $name<'a> {
            fn from(inner: Matter<'a, $code>) -> Self {
                Self(inner)
            }
        }
    };
}

role_newtype!(
    /// Verification key (`k`) — verifies signatures. keripy `Verfer`.
    VerifyingKey, VerKeyCode
);
role_newtype!(
    /// Next-key commitment or prior-event digest (`n`, `p`). keripy `Diger`.
    Digest, DigestCode
);
role_newtype!(
    /// Self-addressing identifier (`d`) — the event's SAID. keripy `Saider`.
    Said, DigestCode
);
role_newtype!(
    /// Basic AID prefix / witness prefix (`i`, `bi`, `b`). keripy `Prefixer`.
    BasicPrefix, VerKeyCode
);
```

- [ ] **Step 2: Export from lib.rs**

In `crates/keri-events/src/lib.rs`, after the module declarations (near line 36) add:

```rust
/// Role-distinct KERI primitive newtypes over cesr `Matter`.
pub mod primitive;
```

and in the `pub use` block (near line 44) add:

```rust
pub use primitive::{BasicPrefix, Digest, Said, VerifyingKey};
```

- [ ] **Step 3: Write the distinctness + round-through tests**

Append to `crates/keri-events/src/primitive.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::borrow::Cow;
    use cesr::core::matter::builder::MatterBuilder;

    fn verkey_matter() -> Matter<'static, VerKeyCode> {
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(alloc::vec![0u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn digest_matter() -> Matter<'static, DigestCode> {
        MatterBuilder::new()
            .with_code(DigestCode::Blake3_256)
            .with_raw(Cow::<[u8]>::Owned(alloc::vec![0u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    #[test]
    fn deref_reads_through_to_inner_code() {
        let vk = VerifyingKey::from_matter(verkey_matter());
        assert_eq!(*vk.code(), VerKeyCode::Ed25519); // via Deref
        assert_eq!(*vk.as_matter().code(), VerKeyCode::Ed25519);
    }

    #[test]
    fn into_static_preserves_value() {
        let d = Digest::from_matter(digest_matter());
        let owned: Digest<'static> = d.clone().into_static();
        assert_eq!(d, owned);
        assert_eq!(*owned.code(), DigestCode::Blake3_256);
    }

    #[test]
    fn same_family_roles_are_distinct_types() {
        // Compile-time proof: VerifyingKey and BasicPrefix both wrap
        // Matter<VerKeyCode>, but are NOT interchangeable. This fn only
        // type-checks because the parameter types differ; if the newtypes
        // ever collapse to an alias, the second call is a type error.
        fn takes_key(_: &VerifyingKey<'_>) {}
        fn takes_prefix(_: &BasicPrefix<'_>) {}
        let key = VerifyingKey::from_matter(verkey_matter());
        let prefix = BasicPrefix::from_matter(verkey_matter());
        takes_key(&key);
        takes_prefix(&prefix);
        // takes_key(&prefix); // <- would NOT compile; that is the guarantee.
    }
}
```

Add `extern crate alloc;`-scoped `use alloc::vec;` at top of the test module if `alloc::vec!` isn't already reachable (it is via the crate-level `extern crate alloc`).

- [ ] **Step 4: Verify the crate compiles + tests pass**

Run: `nix develop --command cargo nextest run -p keri-events primitive`
Expected: PASS (3 tests). If `MatterBuilder`/`with_code` signatures differ, fix the helper to match the existing `make_*` helpers in `crates/keri-events/src/event/inception.rs:178`.

- [ ] **Step 5: Commit**

```bash
git add crates/keri-events/src/primitive.rs crates/keri-events/src/lib.rs
git commit -m "feat(keri-events): role-distinct primitive newtypes (VerifyingKey/Digest/Said/BasicPrefix) (#193)"
```

---

## Task 2: Retype `Identifier`

**Files:**
- Modify: `crates/keri-events/src/identifier.rs`

- [ ] **Step 1: Swap the variant inner types**

In `crates/keri-events/src/identifier.rs`:
- Change import `use cesr::core::primitives::{Prefixer, Saider};` → `use crate::primitive::{BasicPrefix, Said};`
- `Basic(Prefixer<'a>)` → `Basic(BasicPrefix<'a>)`
- `SelfAddressing(Saider<'a>)` → `SelfAddressing(Said<'a>)`
- `as_prefixer(&self) -> Option<&Prefixer<'a>>` → `as_prefixer(&self) -> Option<&BasicPrefix<'a>>` (keep the method name for now; call-site churn is out of scope — rename in a follow-up if desired)
- `as_saider(&self) -> Option<&Saider<'a>>` → `-> Option<&Said<'a>>`
- `From<Prefixer<'a>>` → `From<BasicPrefix<'a>>`; `From<Saider<'a>>` → `From<Said<'a>>`
- `is_transferable`: `p.code().is_transferable()` still works via `Deref`. Leave as-is.
- `into_static`: `p.into_static()` now calls `BasicPrefix::into_static` (inherent) — unchanged syntax.

- [ ] **Step 2: Fix the test helpers**

In the `#[cfg(test)] mod tests`, the `make_prefixer()`/`make_saider()` helpers currently return `Prefixer`/`Saider`. Wrap their result:
```rust
fn make_prefixer() -> BasicPrefix<'static> {
    BasicPrefix::from_matter(
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
            .unwrap()
            .build()
            .unwrap(),
    )
}
```
Apply the same wrap to `make_non_transferable_prefixer` (→ `BasicPrefix`) and `make_saider` (→ `Said`). Assertions like `*p.code()` still work via `Deref`.

- [ ] **Step 2b: Run test to verify it fails first (if TDD-strict)**

Before editing, `nix develop --command cargo build -p keri-events` shows the pre-change baseline compiles. After Step 1 (before Step 2) it will fail to compile in tests — that failure is expected and fixed by Step 2.

- [ ] **Step 3: Verify**

Run: `nix develop --command cargo nextest run -p keri-events identifier`
Expected: PASS (all `identifier` tests green).

- [ ] **Step 4: Commit**

```bash
git add crates/keri-events/src/identifier.rs
git commit -m "refactor(keri-events): Identifier over BasicPrefix/Said newtypes (#193)"
```

---

## Task 3: Retype `Seal`

**Files:**
- Modify: `crates/keri-events/src/seal.rs`

- [ ] **Step 1: Swap field types**

In `crates/keri-events/src/seal.rs`:
- Import: `use cesr::core::primitives::{Number, Prefixer, Saider, Verser};` → `use cesr::core::primitives::{Number, Verser}; use crate::primitive::{BasicPrefix, Said};`
- Every `Saider<'a>` field (`d`, `rd`) → `Said<'a>`
- Every `Prefixer<'a>` field (`i`, `bi`) → `BasicPrefix<'a>`
- `s: Number` and `t: Verser<'a>` unchanged.
- `into_static`: each `.into_static()` call now resolves to the newtype's inherent `into_static` — syntax unchanged.

- [ ] **Step 2: Fix test helpers**

`make_saider()` → returns `Said<'static>` (wrap with `Said::from_matter(...)`); `make_prefixer()` → `BasicPrefix<'static>`. `make_verser()` unchanged. Assertions via `Deref` unchanged.

- [ ] **Step 3: Verify**

Run: `nix develop --command cargo nextest run -p keri-events seal`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/keri-events/src/seal.rs
git commit -m "refactor(keri-events): Seal fields over BasicPrefix/Said newtypes (#193)"
```

---

## Task 4: Retype the event structs (inception, rotation, interaction, delegation)

**Files:**
- Modify: `crates/keri-events/src/event/inception.rs`
- Modify: `crates/keri-events/src/event/rotation.rs`
- Modify: `crates/keri-events/src/event/interaction.rs`
- Modify: `crates/keri-events/src/event/delegation.rs`
- Modify: `crates/keri-events/src/event/mod.rs`

- [ ] **Step 1: inception.rs — struct + `new` + getters + into_static**

Apply the naming map to `crates/keri-events/src/event/inception.rs`:
- Import line 9: drop `Diger, Prefixer, Saider, Verfer` from the cesr import; keep `Number`. Add `use crate::primitive::{Digest, Said, VerifyingKey, BasicPrefix};`. Keep `use cesr::core::matter::matter::Matter;` **only if** still referenced (see into_static below) — otherwise remove.
- Struct fields (lines 21-26): `said: Said<'a>`, `keys: Vec<VerifyingKey<'a>>`, `next_keys: Vec<Digest<'a>>`, `witnesses: Vec<BasicPrefix<'a>>`.
- `new(...)` params (lines 44-49): same substitutions.
- Getters: `said(&self) -> &Said<'a>`; `keys(&self) -> &[VerifyingKey<'a>]`; `next_keys(&self) -> &[Digest<'a>]`; `witnesses(&self) -> &[BasicPrefix<'a>]`.
- `into_static` (lines 145-166): replace `.map(Matter::into_static)` with the newtype method:
  - `keys: self.keys.into_iter().map(VerifyingKey::into_static).collect()`
  - `next_keys: self.next_keys.into_iter().map(Digest::into_static).collect()`
  - `witnesses: self.witnesses.into_iter().map(BasicPrefix::into_static).collect()`
  - `said: self.said.into_static()`
  - Once `Matter::into_static` is no longer referenced, delete the `use cesr::core::matter::matter::Matter;` import to avoid an unused-import denial.

- [ ] **Step 2: inception.rs — test helpers**

In `#[cfg(test)] mod tests`: `make_verfer()` → `VerifyingKey<'static>` (wrap `VerifyingKey::from_matter(...)`), `make_diger()` → `Digest`, `make_saider()` → `Said`, `make_prefixer()` → `BasicPrefix`. Constructor calls (`InceptionEvent::new(...)`) keep the same argument expressions — the helpers now return the right newtype. `make_prefixer().into()` at line 217/263 still works (`Identifier: From<BasicPrefix>`).

- [ ] **Step 3: rotation.rs — same pattern**

`crates/keri-events/src/event/rotation.rs`: `said`/`prior_event_said` → `Said`; `keys` → `Vec<VerifyingKey>`; `next_keys` → `Vec<Digest>`; `witness_additions`/`witness_removals` → `Vec<BasicPrefix>`. Fix `new`, getters, `into_static` (same `.map(<Newtype>::into_static)` swap), imports, and test helpers exactly as Task 4 Steps 1-2.

- [ ] **Step 4: interaction.rs — same pattern**

`crates/keri-events/src/event/interaction.rs`: `said` and `prior_event_said` → `Said<'a>`; `anchors: Vec<Seal<'a>>` unchanged. Fix `new`, getters, `into_static`, imports, test helpers.

- [ ] **Step 5: delegation.rs**

`crates/keri-events/src/event/delegation.rs`: `DelegatedInceptionEvent` composes `InceptionEvent` + `delegator: Identifier` — no direct primitive fields, so only fix test helpers if they build primitives directly. `DelegatedRotationEvent` newtypes `RotationEvent` — likewise. Update any `use cesr::core::primitives::{...}` in tests to the newtypes.

- [ ] **Step 6: event/mod.rs**

`crates/keri-events/src/event/mod.rs`: `KeriEvent` holds the event structs (no direct primitives) — no field changes. Fix the `#[cfg(test)]` helpers `make_prefixer/make_saider/make_verfer/make_diger` (lines 70-104) to return + wrap the newtypes, exactly as Task 4 Step 2.

- [ ] **Step 7: Verify keri-events fully**

Run: `nix develop --command cargo nextest run -p keri-events`
Expected: PASS (all keri-events tests). Then no_std probe:
`nix develop --command cargo build -p keri-events --no-default-features --features alloc`
Expected: builds.

- [ ] **Step 8: Commit**

```bash
git add crates/keri-events/src/event/
git commit -m "refactor(keri-events): event structs over role newtypes (#193)"
```

---

## Task 5: keri-codec read/lift layer — `parse_qb64_*` + `FromWire`/`Field`

**Files:**
- Modify: `crates/keri-codec/src/deserialize/reference.rs`
- Modify: `crates/keri-codec/src/codec/field.rs`

- [ ] **Step 1: `parse_qb64_*` return newtypes (reference.rs)**

In `crates/keri-codec/src/deserialize/reference.rs`:
- `parse_qb64_prefixer` (line 39) → return `BasicPrefix<'a>`: after narrowing to `Matter<VerKeyCode>`, wrap `BasicPrefix::from_matter(...)`.
- `parse_qb64_verfer` (line 78, currently aliases prefixer) → return `VerifyingKey<'a>`: it must now wrap `VerifyingKey`, so it can no longer just delegate to `parse_qb64_prefixer` (different newtype). Give it its own body that narrows to `Matter<VerKeyCode>` then `VerifyingKey::from_matter`.
- `parse_qb64_diger` (line 82) → `Digest<'a>` (`Digest::from_matter`).
- `parse_qb64_saider` (line 91, currently aliases diger) → `Said<'a>`: own body, `Said::from_matter`.
- `*_array` variants (534/550/566) → `Vec<BasicPrefix>` / `Vec<VerifyingKey>` / `Vec<Digest>` respectively.
- `Identifier::Basic(...)`/`SelfAddressing(...)` construction (66/75): wrap the narrowed Matter in `BasicPrefix`/`Said` before the `Identifier::` variant.
- Update the import (line 16) accordingly and add `use keri_events::primitive::{BasicPrefix, Digest, Said, VerifyingKey};`.
- Seal parsing (734-787): `parse_qb64_prefixer`/`parse_qb64_saider` now yield `BasicPrefix`/`Said`, matching the retyped `Seal` fields — no further change at those sites.

- [ ] **Step 2: `FromWire`/`Field` impls (codec/field.rs)**

In `crates/keri-codec/src/codec/field.rs`:
- The generic `FromWire<&'a str> for Matter<'a, C>` (line 93) stays — it's the substrate lift.
- `FromWire<&'a str> for Identifier` (line 107): wrap the VerKey branch in `BasicPrefix`, the Digest branch in `Said` (lines 110/112).
- Add `FromWire<&'a str>` impls (or thin wrappers) for `VerifyingKey`, `Digest`, `Said`, `BasicPrefix` that lift via the `Matter<C>` impl then `::from_matter`. This lets `Field::each("k", …).decode::<Vec<VerifyingKey>>()` work through the existing `Vec<T>` blanket (line 139).
- Update the test import at line 156 to the newtypes.

- [ ] **Step 3: Verify the lift layer compiles**

Run: `nix develop --command cargo build -p keri-codec`
Expected: still failing at deserialize.rs / builders (fixed in Tasks 6-7). The reference.rs + field.rs modules themselves must be internally consistent. If `narrow::<C>()` / `FromWire` signatures differ, follow the existing `Matter<C>` impl as the template.

- [ ] **Step 4: Commit (after Task 6 compiles — see note)**

Do not commit a non-compiling crate. Combine the commit with Task 6.

---

## Task 6: keri-codec deserialize + seal construction + builders + serialize

**Files:**
- Modify: `crates/keri-codec/src/deserialize.rs`
- Modify: `crates/keri-codec/src/codec/seal.rs`
- Modify: `crates/keri-codec/src/builder/{icp,rot,dip,drt,ixn,establishment,witness}.rs`
- Modify: `crates/keri-codec/src/serialize.rs`

- [ ] **Step 1: deserialize.rs lift sites + constructor calls**

`crates/keri-codec/src/deserialize.rs`:
- Import (line 24): drop `Diger, Prefixer, Verfer` from the cesr import (keep `Number`); add `use keri_events::primitive::{BasicPrefix, Digest, Said, VerifyingKey};`.
- The `Field::…decode::<Diger>()` / `decode::<Vec<Verfer>>()` / `decode::<Vec<Prefixer>>()` sites (250-305) → `decode::<Digest>()` / `Vec<VerifyingKey>` / `Vec<BasicPrefix>`. The `d` field decodes to `Said` (it feeds `said`), while `n`/`p` decode to `Digest`. Confirm each `Field::new("d", …)` maps to `Said` and `Field::new("p", …)`/`Field::each("n", …)` map to `Digest` per the naming map.
- Constructor calls (249/283/301 etc.) need no change once the decoded values are the right newtype.
- Test helpers (446-473) `make_*` → wrap in newtypes.

- [ ] **Step 2: codec/seal.rs**

`crates/keri-codec/src/codec/seal.rs`: `lift_diger`/`lift_prefixer` helpers (used at 102-124) must now yield `Said`/`BasicPrefix` to match `Seal` fields. Wrap at the lift helper. Update test imports (252) + helpers (255/264).

- [ ] **Step 3: builders**

For each of `builder/icp.rs`, `rot.rs`, `dip.rs`, `drt.rs`, `ixn.rs`, `establishment.rs`, `witness.rs`:
- Change setter/param/field types per the naming map: `keys: Vec<Verfer<'static>>` → `Vec<VerifyingKey<'static>>`; `next_keys: Vec<Diger<'static>>` → `Vec<Digest<'static>>`; witness params `Vec<Prefixer<'static>>` → `Vec<BasicPrefix<'static>>`; `prior_event_said: Saider<'static>` → `Said<'static>`.
- Imports: drop the cesr `primitives` names, add the keri_events newtypes.
- `dummy_saider(...)` / internal construction (icp.rs:173, dip.rs:206) → wrap in `Said`.
- Test helpers (icp.rs:210+, rot.rs:309+, drt.rs:318+, dip.rs:240+, ixn.rs:168+) → wrap.

- [ ] **Step 4: serialize.rs**

`crates/keri-codec/src/serialize.rs`: `SerializedEvent.said`/`prefix` are `Saider<'static>`/`Option<Saider<'static>>` → `Said<'static>`/`Option<Said<'static>>`. `identifier()` (line 375) maps `Saider` → `Identifier::SelfAddressing`; that now takes `Said` — matches the retyped `Identifier`. `EventRef::said_code()` reads `e.said().code()` via `Deref` — unchanged. Update import (line 14) + test helpers (461-488).

- [ ] **Step 5: Verify keri-codec compiles + unit tests**

Run: `nix develop --command cargo nextest run -p keri-codec`
Expected: PASS. The spine byte-identity + keripy differential tests here are the wire-freeze guard — they MUST stay green (newtypes are `Deref`-transparent, so bytes are unchanged).

- [ ] **Step 6: Commit**

```bash
git add crates/keri-codec/src/
git commit -m "refactor(keri-codec): construct events over keri-events role newtypes (#193)"
```

---

## Task 7: keri-codec tests, proptest strategies, examples, benches

**Files:**
- Modify: `crates/keri-codec/src/event_strategies.rs`
- Modify: `crates/keri-codec/src/traits.rs` (test import line 52)
- Modify: `crates/keri-codec/src/keripy_parity/validation.rs`
- Modify: `crates/keri-codec/tests/common/mod.rs`, `tests/spine_write.rs`
- Modify: `crates/keri-codec/benches/serder.rs`, `tests/serder_allocation.rs`
- Modify: `crates/keri-codec/examples/multisig_threshold_icp.rs`

- [ ] **Step 1: proptest strategy builders**

`crates/keri-codec/src/event_strategies.rs`: `prefixer(raw)` (28) → return `BasicPrefix<'static>`; `saider(raw)` (41) → `Said<'static>`. Add `verfer`/`diger` producers returning `VerifyingKey`/`Digest` if the `IcpSpec`/`RotSpec` `build()` (270/317) constructs keys/next_keys — wrap their outputs so `InceptionEvent::new`/`RotationEvent::new` type-check.

- [ ] **Step 2: keripy_parity + tests/common + spine_write**

Update `validation.rs` (28/56/64/72) — `parse_qb64_*_array` now yield the newtype `Vec`s; assertions read via `Deref`. Update `tests/common/mod.rs:32` and `tests/spine_write.rs:23` imports to the newtypes (note `Siger`/`Signer` stay from cesr — only `Verfer`→`VerifyingKey` etc. change). Update `benches/serder.rs:20`, `tests/serder_allocation.rs:24`, `examples/multisig_threshold_icp.rs:23`.

- [ ] **Step 3: Verify everything green (targeted)**

Run: `nix develop --command cargo nextest run -p keri-codec` and `nix develop --command cargo test -p keri-codec --doc`
Expected: PASS. Run the example: `nix develop --command cargo run -p keri-codec --example multisig_threshold_icp` — expected: runs clean.

- [ ] **Step 4: Commit**

```bash
git add crates/keri-codec/
git commit -m "test(keri-codec): update fixtures/strategies/examples to role newtypes (#193)"
```

---

## Task 8: cesr-stream — confirm + tick (no code change)

**Files:** none (verification only). Design finding: cesr-stream is already tight (0 owned keripy names, 0 free `pub fn`, no frame-size dup — killed in #199).

- [ ] **Step 1: Confirm no keripy-owned names / no dup remains**

Run: `rg -n 'pub (type|struct|enum) (Verfer|Diger|Saider|Prefixer|Cigar|Matter|Counter|Indexer)' crates/cesr-stream/src`
Expected: no matches (all are cesr re-exports, not owned).

- [ ] **Step 2: Confirm free-fn budget unchanged**

Run: `rg -n 'cesr-stream' free-fn-budget.toml`
Expected: budget `0`. No new free fns introduced.

- [ ] **Step 3: No commit** (nothing changed). Note in the PR body: "cesr-stream design-review pass: no restructure needed — #199's `frame_size` work already removed the redundancy; surface confirmed tight."

---

## Task 9: Close-out — CHANGELOG, ratchet, gate, #193

**Files:**
- Modify: `CHANGELOG.md` (keri-events + keri-codec sections)
- Modify: `free-fn-budget.toml` (only if a per-module free-fn count dropped)

- [ ] **Step 1: CHANGELOG**

Add under keri-events + keri-codec: the breaking rename (cesr aliases `Verfer/Diger/Saider/Prefixer` no longer used by keri-events; new `keri_events::primitive::{VerifyingKey, Digest, Said, BasicPrefix}` newtypes; event/seal/identifier field types changed — a breaking public-API change per the active-development rule). Note the two deferrals (`Ilk`→`MessageType`; event-model consolidation).

- [ ] **Step 2: Ratchet re-baseline**

If any module's free `pub fn` count dropped (e.g. `parse_qb64_verfer`/`parse_qb64_saider` gained bodies but count is unchanged; check reference.rs), lower the budget in `free-fn-budget.toml` to match. Never raise. Run the tripwire: `nix build '.#checks.aarch64-darwin.cesr-fn-ratchet'` (adjust arch).

- [ ] **Step 3: Full gate**

Commit all pending, then push — the pre-push hook runs the gate. Per [[dont-block-on-local-gate]] and [[never-pipe-gate-commands]], do not foreground-poll `nix flake check`; if running it directly, redirect to a file and echo `$?`:
```bash
nix flake check > /tmp/gate.log 2>&1; echo "exit: $?"
```
Expected: exit 0 (clippy, fmt, taplo, audit, deny, nextest across feature combos, doctest, wasm, no_std, version-owner, fn-ratchet all green).

- [ ] **Step 4: PR + close #193**

Open the PR (base `main`), body: describe the breaking newtype rename, the compile-time role-safety win, cesr-stream no-op finding, and the two deferrals. Tick the `keri-events` and `cesr-stream` boxes in #193. Attach to CESR project board per [[always-attach-issues-to-cesr-board]]. Use the `joeldsouzax` gh account per [[gh-account-for-devrandom]]. `gh pr merge --auto` after the gate.

---

## Self-Review

- **Spec coverage:** newtypes (Task 1) ✓, Identifier (2) ✓, Seal (3) ✓, events (4) ✓, keri-codec lift (5) ✓, construction/builders/serialize (6) ✓, tests/strategies/examples (7) ✓, cesr-stream tick (8) ✓, Ilk/Verser/event-model deferrals recorded in spec (not implemented — correct) ✓, close-out (9) ✓.
- **Placeholder scan:** the mechanical retype tasks reference exact file:line inventories from the investigation; the novel code (newtype module, distinctness test, parse_qb64 bodies) is shown in full. No "TBD"/"handle edge cases".
- **Type consistency:** newtype names identical throughout (`VerifyingKey`/`Digest`/`Said`/`BasicPrefix`); `from_matter`/`into_static`/`as_matter` method names consistent; `d`→`Said`, `n`/`p`→`Digest`, `k`→`VerifyingKey`, `i`/`bi`/`b`/`ba`/`br`→`BasicPrefix` applied uniformly.
- **Risk note:** the `d` (Said) vs `n`/`p` (Digest) split is the one place to be careful — both are `DigestCode`, so a wrong pick compiles but mislabels. The keripy differential + spine byte-identity tests (Task 6 Step 5) catch a wire-visible error; the compile-time distinctness only guards *role*, not which-digest-field, so double-check each `Field::new("d"/"p"/"n", …)` decode target against the map.
