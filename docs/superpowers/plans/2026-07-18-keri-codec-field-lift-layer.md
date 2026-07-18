# keri-codec FromWire/Field Lift Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the ~32 private free `fn`s of the keri-codec read-path "lift" layer (Parsed* wire-view → domain type) and the `primitives.rs` write helpers with one typed, composable vocabulary — a `FromWire` lift trait and a `Field` newtype that carries the JSON field name with the value.

**Architecture:** Add a crate-internal `FromWire<'a, W>` trait (lift: wire-view `W` → domain type, tagging errors with the field) plus a `Field<'a, W>(field, value)` newtype whose `.decode::<T>()` dispatches to `T::from_wire`. Impls are keyed by target type, co-located with each type's existing scan/encode code (der principle from #202). One generic `Matter<C>` impl collapses all six qb64 `parse_qb64_*` functions; one `Vec<T>` blanket collapses all four `*_from_parsed` collectors. The three-layer pipeline (scan → SAID-verify → lift) and byte-identity are unchanged; the write side reuses the existing `Encode` trait.

**Tech Stack:** Rust 2024, no_std/alloc, `cesr`/`keri-events` domain types, `thiserror` errors, `cargo nextest` inside `nix develop`, `nix flake check` as the gate.

**Spec:** `docs/superpowers/specs/2026-07-18-keri-codec-field-lift-layer-design.md`

---

## Ground rules for every task

- **Gate command (per task, final step):** `nix flake check` — run it, never pipe it to `head`/`tail` (masks exit code / SIGPIPE-kills it). Redirect to a file and echo `$?` if you need to inspect:
  `nix flake check > /tmp/gate.log 2>&1; echo "exit=$?"`
- **Inner-loop (fast, within a task):** `nix develop --command cargo nextest run -p keri-codec <filter>`.
- **Byte-identity is law:** the keripy differential corpus and spine byte-identity suites must stay green on every task. They run inside `nix flake check`.
- **Import style:** all `use` at file top, no inline `use`, no fully-qualified construction paths (enforced by `.githooks/`).
- **The existing `deserialize.rs` roundtrip/tamper/boundary tests call the public `Deserialize` surface** — they must stay green *unchanged* through every task. Do not edit them except where a task explicitly says so.

## File structure

- **Create** `crates/keri-codec/src/codec/field.rs` — `FromWire` trait, `Field` newtype, the generic `Matter<C>` qb64 impl, `Identifier`, `SequenceNumber`, `u32`-from-`ParsedCount`, `ConfigTrait`, and the `Vec<T>` blanket; plus `map_qb64_error` (moved from `deserialize.rs`).
- **Modify** `crates/keri-codec/src/codec.rs` — declare `pub(crate) mod field;`.
- **Modify** `crates/keri-codec/src/codec/seal.rs` — add `impl FromWire for Seal` (lift, was `seal_from_parsed`); derive `Copy` on `ParsedSeal` (in `codec/event.rs`).
- **Modify** `crates/keri-codec/src/codec/threshold.rs` — add `impl FromWire for SigningThreshold` (was `tholder_from_parsed` + `parse_weight`) and `impl FromWire for u32` from `&ParsedCount` (was `witness_threshold_wire`).
- **Modify** `crates/keri-codec/src/codec/event.rs` — derive `Copy` on `ParsedSeal`; migrate the writer's `to_qb64_string` callsites (Task 6).
- **Modify** `crates/keri-codec/src/deserialize.rs` — migrate each `build_*` body to the `Field` pipeline (Tasks 2–5); delete the dead free `fn` pile (Task 7).
- **Delete** `crates/keri-codec/src/primitives.rs` — its two `pub fn`s become `Encode`/`Field` (Task 6); update `lib.rs`/module decl.
- **Modify** `free-fn-budget.toml` — `keri-codec = 51` → `49` (Task 7).

---

## Task 1: `FromWire` trait, `Field` newtype, and the primitive impls

**Files:**
- Create: `crates/keri-codec/src/codec/field.rs`
- Modify: `crates/keri-codec/src/codec.rs` (add `pub(crate) mod field;`)
- Modify: `crates/keri-codec/src/codec/event.rs` (derive `Copy` on `ParsedSeal`)

This task lands the vocabulary and proves it by migrating the smallest orchestrator, `build_interaction`, which exercises `Identifier`, `SequenceNumber`, `Matter<DigestCode>`, and the seal `Vec` blanket. Old free fns are **not** deleted yet (they still serve the other `build_*`); they die in Task 7.

- [ ] **Step 1: Derive `Copy` on `ParsedSeal`**

In `crates/keri-codec/src/codec/event.rs`, find the `ParsedSeal` enum (all variants hold only `&'a str`) and add `Copy` to its derive list:

```rust
#[derive(Debug, Clone, Copy)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) enum ParsedSeal<'a> { /* unchanged */ }
```

If `#[derive(Debug)]` is currently the only derive, replace it with `#[derive(Debug, Clone, Copy)]`. Do not change the variants.

- [ ] **Step 2: Write `codec/field.rs` with the trait, newtype, and impls**

Create `crates/keri-codec/src/codec/field.rs`:

```rust
//! The lift layer: scanned wire-views (`W`) → domain types, the third pipeline
//! stage (scan → SAID-verify → **lift**). Each [`FromWire`] impl replaces a
//! bespoke `parse_qb64_*`/`*_from_parsed` free function; [`Field`] carries the
//! JSON field name with the value so it is never a loose positional argument.
//!
//! Lift runs *after* SAID verification, over borrowed scan-stage views — it
//! cannot run earlier because it consumes the views the verified scan produced.

#[cfg(feature = "alloc")]
use alloc::{format, string::ToString, vec::Vec};

use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::{CesrCode, DigestCode, VerKeyCode};
use cesr::core::matter::error::MatterBuildError;
use cesr::core::matter::matter::Matter;
use keri_events::{ConfigTrait, Identifier, SequenceNumber};

use crate::codec::threshold::ParsedCount;
use crate::error::SerderError;

/// Lift a scanned wire-view `W` into `Self`, tagging any failure with the JSON
/// `field` it came from.
pub(crate) trait FromWire<'a, W>: Sized {
    /// Lift `wire` into `Self`.
    ///
    /// # Errors
    ///
    /// Returns [`SerderError`] (with `field`) when `wire` is not this type's
    /// valid domain form.
    fn from_wire(field: &'static str, wire: W) -> Result<Self, SerderError>;
}

/// A wire value tagged with the JSON field it belongs to.
pub(crate) struct Field<'a, W>(pub(crate) &'static str, pub(crate) W, core::marker::PhantomData<&'a ()>);

impl<'a, W> Field<'a, W> {
    /// Tag `value` with `field`.
    pub(crate) const fn new(field: &'static str, value: W) -> Self {
        Self(field, value, core::marker::PhantomData)
    }

    /// Lift into `T`.
    ///
    /// # Errors
    ///
    /// Propagates the [`FromWire`] impl's error, tagged with this field.
    pub(crate) fn decode<T: FromWire<'a, W>>(self) -> Result<T, SerderError> {
        T::from_wire(self.0, self.1)
    }
}

impl<'a, W: Copy> Field<'a, &'a [W]> {
    /// Tag a slice for list lift.
    pub(crate) const fn each(field: &'static str, items: &'a [W]) -> Self {
        Self(field, items, core::marker::PhantomData)
    }
}

/// Map a qb64 build error to the field-tagged codec error (moved verbatim from
/// `deserialize.rs`).
pub(crate) fn map_qb64_error(field: &'static str, err: MatterBuildError) -> SerderError {
    match err {
        MatterBuildError::Validation(source) => SerderError::InvalidPrimitive { field, source },
        MatterBuildError::Parsing(source) => SerderError::UnparseablePrimitive { field, source },
    }
}

// One impl for every qb64 Matter primitive — `Verfer`≡`Prefixer` (VerKeyCode),
// `Saider`≡`Diger` (DigestCode), `Verser` (VerserCode) are all `Matter<'a, C>`,
// so type-keyed narrow does what six `parse_qb64_*` fns did by hand.
impl<'a, C: CesrCode> FromWire<'a, &'a str> for Matter<'a, C> {
    fn from_wire(field: &'static str, s: &'a str) -> Result<Self, SerderError> {
        MatterBuilder::new()
            .from_qualified_base64(s.as_bytes())
            .map_err(|e| map_qb64_error(field, e))?
            .narrow::<C>()
            .map_err(|source| SerderError::InvalidPrimitive { field, source })
    }
}

// A KERI prefix is a verkey (basic) or a digest (self-addressing); try VerKey,
// fall back to Digest (was `parse_qb64_identifier`).
impl<'a> FromWire<'a, &'a str> for Identifier<'a> {
    fn from_wire(field: &'static str, s: &'a str) -> Result<Self, SerderError> {
        if let Ok(basic) = Matter::<VerKeyCode>::from_wire(field, s) {
            return Ok(Identifier::Basic(basic));
        }
        Matter::<DigestCode>::from_wire(field, s).map(Identifier::SelfAddressing)
    }
}

// Sequence number: lowercase hex u128 (was `parse_sn`).
impl<'a> FromWire<'a, &'a str> for SequenceNumber {
    fn from_wire(field: &'static str, s: &'a str) -> Result<Self, SerderError> {
        let n = u128::from_str_radix(s, 16).map_err(|_| SerderError::InvalidPrimitive {
            field,
            source: cesr::core::matter::error::ValidationError::UnknownMatterCode(format!(
                "invalid hex {field}: {s}"
            )),
        })?;
        Ok(SequenceNumber::new(n))
    }
}

// Config traits (was `config_from_parsed`, via the Vec blanket).
impl<'a> FromWire<'a, &'a str> for ConfigTrait {
    fn from_wire(field: &'static str, s: &'a str) -> Result<Self, SerderError> {
        // UnknownIlk replicates the tolerant-path behavior kept for parity.
        let _ = field;
        ConfigTrait::from_code(s).map_err(|_| SerderError::UnknownIlk(s.to_string()))
    }
}

// The list collapse: one blanket for every `Vec<&str>`/`Vec<ParsedSeal>` field,
// replacing all four `*_from_parsed` collectors.
impl<'a, W: Copy, T: FromWire<'a, W>> FromWire<'a, &'a [W]> for Vec<T> {
    fn from_wire(field: &'static str, items: &'a [W]) -> Result<Self, SerderError> {
        items.iter().copied().map(|w| T::from_wire(field, w)).collect()
    }
}
```

> Note: adjust the `ValidationError` import to a top-of-file `use` rather than the inline path shown above if the import-style hook flags it — the inline path is shown only to name the exact type. Add `use cesr::core::matter::error::ValidationError;` at the top and use `ValidationError::UnknownMatterCode`.

- [ ] **Step 3: Declare the module**

In `crates/keri-codec/src/codec.rs`, add alongside the other `pub(crate) mod` declarations:

```rust
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) mod field;
```

- [ ] **Step 4: Write failing unit tests for the primitive impls**

Append to `crates/keri-codec/src/codec/field.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::borrow::Cow;
    use cesr::core::matter::code::{DigestCode, VerKeyCode};
    use cesr::core::primitives::{Diger, Verfer};

    fn verfer_qb64() -> alloc::string::String {
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(alloc::vec![0u8; 32]))
            .unwrap()
            .build()
            .unwrap()
            .to_qb64()
    }

    #[test]
    fn matter_lift_narrows_to_target_code() {
        let s = verfer_qb64();
        let v: Verfer = Field::new("k", s.as_str()).decode().unwrap();
        assert_eq!(*v.code(), VerKeyCode::Ed25519);
    }

    #[test]
    fn matter_lift_wrong_code_is_typed_error() {
        let s = verfer_qb64(); // a verkey, ask for a digest
        let err = Field::new("d", s.as_str()).decode::<Diger>().unwrap_err();
        assert!(matches!(err, SerderError::InvalidPrimitive { field: "d", .. }));
    }

    #[test]
    fn sn_lift_hex() {
        let n: SequenceNumber = Field::new("s", "ff").decode().unwrap();
        assert_eq!(n.value(), 255);
    }

    #[test]
    fn sn_lift_rejects_non_hex() {
        let err = Field::new("s", "zz").decode::<SequenceNumber>().unwrap_err();
        assert!(matches!(err, SerderError::InvalidPrimitive { field: "s", .. }));
    }

    #[test]
    fn vec_blanket_empty_one_and_malformed() {
        let ok = verfer_qb64();
        let empty: Vec<Verfer> = Field::each("k", &[] as &[&str]).decode().unwrap();
        assert!(empty.is_empty());

        let one: Vec<Verfer> = Field::each("k", &[ok.as_str()]).decode().unwrap();
        assert_eq!(one.len(), 1);

        let bad = Field::each("k", &[ok.as_str(), "not-qb64"]).decode::<Vec<Verfer>>();
        assert!(matches!(bad, Err(SerderError::InvalidPrimitive { field: "k", .. })
            | Err(SerderError::UnparseablePrimitive { field: "k", .. })));
    }
}
```

- [ ] **Step 5: Run the new tests to verify they fail (compile first)**

Run: `nix develop --command cargo nextest run -p keri-codec field::tests`
Expected: FAILs to compile until Steps 2–3 are saved; once saved, the four tests PASS. (If they compile and pass immediately, that is the intended end state of Steps 2–5 — the "failing" phase is the pre-Step-2 state.)

- [ ] **Step 6: Migrate `build_interaction` to the `Field` pipeline**

In `crates/keri-codec/src/deserialize.rs`, replace the body of `build_interaction` (currently using `parse_qb64_identifier`, `parse_sn`, `parse_qb64_diger`, `anchors_from_parsed`) with:

```rust
fn build_interaction<'a>(p: &ParsedIxn<'a>) -> Result<InteractionEvent<'a>, SerderError> {
    Ok(InteractionEvent::new(
        Field::new("i", p.prefix).decode::<Identifier>()?,
        SequenceNumber::new(parse_sn(p.sn)?), // replaced next line — see below
        Field::new("d", p.said.value).decode::<Diger>()?,
        Field::new("p", p.prior).decode::<Diger>()?,
        Field::each("a", &p.anchors).decode::<Vec<Seal>>()?,
    ))
}
```

Then replace the `sn` line to use the lift too:

```rust
        Field::new("s", p.sn).decode::<SequenceNumber>()?,
```

Add the imports at the top of `deserialize.rs`: `use crate::codec::field::Field;` (and `FromWire` is used only via `Field::decode`, so no direct import needed). Confirm `Diger`, `Seal`, `Identifier`, `SequenceNumber` are already imported (they are).

> Note: `p.prefix` here is a `&'a str` (interaction prefix is a plain span). If it is a `Spanned`, use `p.prefix.value`. Verify against `ParsedIxn`'s definition in `codec/event.rs` and use `.value` if needed.

- [ ] **Step 7: Verify `build_interaction`'s existing roundtrip test still passes**

Run: `nix develop --command cargo nextest run -p keri-codec roundtrip_ixn deserialize_event_dispatches_ixn`
Expected: PASS (byte-identical behavior; the public roundtrip is unchanged).

- [ ] **Step 8: Full gate**

Run: `nix flake check > /tmp/gate.log 2>&1; echo "exit=$?"`
Expected: `exit=0`. If clippy flags the temporary co-existence of old + new (e.g. `parse_qb64_diger` now has fewer callers but is still used elsewhere), that is fine — it is still used by `build_rotation`/`build_inception`.

- [ ] **Step 9: Commit**

```bash
git add crates/keri-codec/src/codec/field.rs crates/keri-codec/src/codec.rs \
        crates/keri-codec/src/codec/event.rs crates/keri-codec/src/deserialize.rs
git commit -m "feat(keri-codec): FromWire lift trait + Field newtype; migrate build_interaction"
```

---

## Task 2: `SigningThreshold` and `u32`-count lift (threshold.rs), migrate `build_rotation`

**Files:**
- Modify: `crates/keri-codec/src/codec/threshold.rs` (add two `FromWire` impls)
- Modify: `crates/keri-codec/src/deserialize.rs` (`build_rotation`)

- [ ] **Step 1: Write failing unit tests in `threshold.rs`**

Append to the `#[cfg(test)] mod tests` in `crates/keri-codec/src/codec/threshold.rs`:

```rust
use crate::codec::field::Field;
use keri_events::SigningThreshold;

#[test]
fn signing_threshold_lift_simple_hex() {
    let pt = ParsedTholder::decode(&mut Scanner::new(b"\"2\"")).unwrap();
    let t: SigningThreshold = Field::new("kt", &pt).decode().unwrap();
    assert_eq!(t, SigningThreshold::Simple(2));
}

#[test]
fn count_lift_u32_hex() {
    let pc = ParsedCount::decode(&mut Scanner::new(b"\"a\"")).unwrap();
    let n: u32 = Field::new("bt", &pc).decode().unwrap();
    assert_eq!(n, 10);
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `nix develop --command cargo nextest run -p keri-codec threshold::tests::signing_threshold_lift_simple_hex threshold::tests::count_lift_u32_hex`
Expected: FAIL to compile — `FromWire` not implemented for `SigningThreshold`/`u32` from these views.

- [ ] **Step 3: Add the two `FromWire` impls**

In `crates/keri-codec/src/codec/threshold.rs`, add these imports at the top (`use crate::codec::field::FromWire;`, `use keri_events::{SigningThreshold, WeightedThreshold};`, and the error types already present), then add:

```rust
impl<'a> FromWire<'a, &'a ParsedTholder<'a>> for SigningThreshold {
    fn from_wire(field: &'static str, t: &'a ParsedTholder<'a>) -> Result<Self, SerderError> {
        match t {
            ParsedTholder::Hex(s) => Ok(SigningThreshold::Simple(
                u64::from_str_radix(s, 16).map_err(|_| threshold_num_err(field, s))?,
            )),
            ParsedTholder::Number(s) => Ok(SigningThreshold::Simple(
                s.parse::<u64>().map_err(|_| threshold_num_err(field, s))?,
            )),
            ParsedTholder::Weighted(clauses) => {
                let nested: Vec<Vec<(u64, u64)>> = clauses
                    .iter()
                    .map(|clause| clause.iter().map(|w| parse_weight(field, w)).collect())
                    .collect::<Result<_, SerderError>>()?;
                WeightedThreshold::from_nested(nested)
                    .map(SigningThreshold::Weighted)
                    .map_err(|source| SerderError::SigningThresholdOutOfRange { field, source })
            }
        }
    }
}

impl<'a> FromWire<'a, &'a ParsedCount<'a>> for u32 {
    fn from_wire(field: &'static str, c: &'a ParsedCount<'a>) -> Result<Self, SerderError> {
        let n: u128 = match c {
            ParsedCount::Hex(s) => u128::from_str_radix(s, 16).map_err(|_| count_err(field, s))?,
            ParsedCount::Number(s) => s.parse::<u128>().map_err(|_| count_err(field, s))?,
        };
        u32::try_from(n).map_err(|_| count_err(field, &format!("{n} exceeds u32::MAX")))
    }
}

fn threshold_num_err(field: &'static str, s: &str) -> SerderError {
    SerderError::InvalidPrimitive {
        field,
        source: ValidationError::UnknownMatterCode(format!("invalid threshold: {s}")),
    }
}

fn count_err(field: &'static str, s: &str) -> SerderError {
    SerderError::InvalidPrimitive {
        field,
        source: ValidationError::UnknownMatterCode(format!("invalid count: {s}")),
    }
}

fn parse_weight(field: &'static str, s: &str) -> Result<(u64, u64), SerderError> {
    if let Some((num_s, den_s)) = s.split_once('/') {
        let num = num_s.parse::<u64>().map_err(|_| threshold_num_err(field, s))?;
        let den = den_s.parse::<u64>().map_err(|_| threshold_num_err(field, s))?;
        if den == 0 {
            return Err(threshold_num_err(field, s));
        }
        Ok((num, den))
    } else {
        Ok((s.parse::<u64>().map_err(|_| threshold_num_err(field, s))?, 1))
    }
}
```

> These four helpers are private `fn`s inside `threshold.rs` — they do **not** count against the fn-ratchet (which counts only `pub`/`pub(crate)`/`pub(super)`). `parse_weight` here supersedes the one in `deserialize.rs`, which is deleted in Task 7.
> Add `use cesr::core::matter::error::ValidationError;` at the top if not present.

- [ ] **Step 4: Run to verify tests pass**

Run: `nix develop --command cargo nextest run -p keri-codec threshold::tests`
Expected: PASS (new tests + existing threshold tests).

- [ ] **Step 5: Migrate `build_rotation`**

In `deserialize.rs`, rewrite `build_rotation` to use the pipeline. The cross-field checks (`check_form_consistency`, `check_thresholds_well_formed`) stay — they are not single-field lifts. Replace the per-field parsing:

```rust
fn build_rotation<'a>(p: &ParsedRot<'a>) -> Result<RotationEvent<'a>, SerderError> {
    let form = threshold_form_of(&p.witness_threshold);
    check_form_consistency("kt", &p.threshold, form)?;
    check_form_consistency("nt", &p.next_threshold, form)?;
    let keys = Field::each("k", &p.keys).decode::<Vec<Verfer>>()?;
    let threshold = Field::new("kt", &p.threshold).decode::<SigningThreshold>()?;
    let next_keys = Field::each("n", &p.next_keys).decode::<Vec<Diger>>()?;
    let next_threshold = Field::new("nt", &p.next_threshold).decode::<SigningThreshold>()?;
    check_thresholds_well_formed(&threshold, keys.len(), &next_threshold, next_keys.len())?;
    Ok(RotationEvent::new(
        Field::new("i", p.prefix).decode::<Identifier>()?,
        Field::new("s", p.sn).decode::<SequenceNumber>()?,
        Field::new("d", p.said.value).decode::<Diger>()?,
        Field::new("p", p.prior).decode::<Diger>()?,
        keys,
        threshold,
        next_keys,
        next_threshold,
        Field::each("ba", &p.witness_additions).decode::<Vec<Prefixer>>()?,
        Field::each("br", &p.witness_removals).decode::<Vec<Prefixer>>()?,
        Toad::from_wire(Field::new("bt", &p.witness_threshold).decode::<u32>()?),
        Field::each("a", &p.anchors).decode::<Vec<Seal>>()?,
        form,
    ))
}
```

> `p.prefix`/`p.prior` may be `&str` or `Spanned` — use `.value` where the type is `Spanned` (check `ParsedRot`). `Verfer`/`Prefixer`/`Diger` are the `Matter<C>` aliases; the generic impl covers them.

- [ ] **Step 6: Run rotation roundtrip + gate**

Run: `nix develop --command cargo nextest run -p keri-codec roundtrip_rot roundtrip_drt deserialize_event_dispatches_rot`
Expected: PASS.
Run: `nix flake check > /tmp/gate.log 2>&1; echo "exit=$?"`
Expected: `exit=0`.

- [ ] **Step 7: Commit**

```bash
git add crates/keri-codec/src/codec/threshold.rs crates/keri-codec/src/deserialize.rs
git commit -m "feat(keri-codec): FromWire for SigningThreshold + count; migrate build_rotation"
```

---

## Task 3: `Seal` lift (seal.rs), migrate `build_inception` + config

**Files:**
- Modify: `crates/keri-codec/src/codec/seal.rs` (add `impl FromWire for Seal`)
- Modify: `crates/keri-codec/src/deserialize.rs` (`build_inception`)

- [ ] **Step 1: Write a failing unit test for `Seal` lift in `seal.rs`**

Append to the `#[cfg(test)] mod tests` in `crates/keri-codec/src/codec/seal.rs`:

```rust
use crate::codec::field::Field;
use keri_events::Seal;

#[test]
fn seal_lift_digest_variant() {
    let ps = ParsedSeal::decode(&mut Scanner::new(
        br#"{"d":"EAAA______________________________________A"}"#,
    ));
    // Use whatever golden qb64 digest the existing seal tests use; assert the
    // lifted variant:
    let ps = ps.expect("valid digest seal");
    let seal: Seal = Field::new("a", ps).decode().unwrap();
    assert!(matches!(seal, Seal::Digest { .. }));
}
```

> Replace the digest qb64 with a valid one already used in `seal.rs` tests (grep for an existing `Seal::Digest` golden). The point is that `Field::new("a", parsed_seal).decode::<Seal>()` yields the right variant.

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop --command cargo nextest run -p keri-codec seal::tests::seal_lift_digest_variant`
Expected: FAIL to compile — `FromWire` not implemented for `Seal`.

- [ ] **Step 3: Add `impl FromWire for Seal`**

Move the body of `seal_from_parsed` (from `deserialize.rs`) into `seal.rs` as the impl. `ParsedSeal` is `Copy`, so take it by value:

```rust
impl<'a> FromWire<'a, ParsedSeal<'a>> for Seal<'a> {
    fn from_wire(field: &'static str, seal: ParsedSeal<'a>) -> Result<Self, SerderError> {
        match seal {
            ParsedSeal::Digest { d } => Ok(Seal::Digest { d: Field::new("d", d).decode()? }),
            ParsedSeal::Root { rd } => Ok(Seal::Root { rd: Field::new("rd", rd).decode()? }),
            ParsedSeal::Source { s, d } => Ok(Seal::Source {
                s: Field::new("s", s).decode()?,
                d: Field::new("d", d).decode()?,
            }),
            ParsedSeal::Event { i, s, d } => Ok(Seal::Event {
                i: Field::new("i", i).decode()?,
                s: Field::new("s", s).decode()?,
                d: Field::new("d", d).decode()?,
            }),
            ParsedSeal::Last { i } => Ok(Seal::Last { i: Field::new("i", i).decode()? }),
            ParsedSeal::Back { bi, d } => Ok(Seal::Back {
                bi: Field::new("bi", bi).decode()?,
                d: Field::new("d", d).decode()?,
            }),
            ParsedSeal::Kind { t, d } => Ok(Seal::Kind {
                t: Field::new("t", t).decode()?,
                d: Field::new("d", d).decode()?,
            }),
            // Scanner already proved this is one well-formed compact object.
            ParsedSeal::Opaque { raw } => Ok(Seal::Opaque(keri_events::OpaqueSeal::new_unchecked(raw))),
        }
    }
}
```

Add imports at the top of `seal.rs`: `use crate::codec::field::{Field, FromWire};`, `use keri_events::Seal;`, and confirm `SequenceNumber`, `Prefixer`, `Saider`, `Verser` resolve via the generic `Matter<C>` impl (they are `Matter<C>` aliases — the `.decode()?` with the field's target type infers). The seal field types (`Saider` for `d`/`rd`, `Prefixer` for `i`/`bi`, `Verser` for `t`, `SequenceNumber` for `s`) are inferred from `Seal`'s variant field types, so no turbofish is needed.

- [ ] **Step 4: Run to verify it passes**

Run: `nix develop --command cargo nextest run -p keri-codec seal::tests`
Expected: PASS.

- [ ] **Step 5: Migrate `build_inception` (and config via the blanket)**

In `deserialize.rs`, rewrite `build_inception`. `bt`→`Toad::exact` keeps the witness count; config uses the `ConfigTrait` blanket:

```rust
fn build_inception<'a>(p: &ParsedIcp<'a>) -> Result<InceptionEvent<'a>, SerderError> {
    let form = threshold_form_of(&p.witness_threshold);
    check_form_consistency("kt", &p.threshold, form)?;
    check_form_consistency("nt", &p.next_threshold, form)?;
    let witnesses = Field::each("b", &p.witnesses).decode::<Vec<Prefixer>>()?;
    let witness_threshold = Toad::exact(
        Field::new("bt", &p.witness_threshold).decode::<u32>()?,
        witnesses.len(),
    )?;
    let keys = Field::each("k", &p.keys).decode::<Vec<Verfer>>()?;
    let threshold = Field::new("kt", &p.threshold).decode::<SigningThreshold>()?;
    let next_keys = Field::each("n", &p.next_keys).decode::<Vec<Diger>>()?;
    let next_threshold = Field::new("nt", &p.next_threshold).decode::<SigningThreshold>()?;
    check_thresholds_well_formed(&threshold, keys.len(), &next_threshold, next_keys.len())?;
    Ok(InceptionEvent::new(
        Field::new("i", p.prefix.value).decode::<Identifier>()?,
        Field::new("s", p.sn).decode::<SequenceNumber>()?,
        Field::new("d", p.said.value).decode::<Diger>()?,
        keys,
        threshold,
        next_keys,
        next_threshold,
        witnesses,
        witness_threshold,
        Field::each("c", &p.config).decode::<Vec<ConfigTrait>>()?,
        Field::each("a", &p.anchors).decode::<Vec<Seal>>()?,
        form,
    ))
}
```

Import `ConfigTrait` if not already imported (it is). Confirm the config JSON field key is `"c"` against `codec/event.rs`; adjust if the writer uses a different key.

- [ ] **Step 6: Run inception roundtrips + gate**

Run: `nix develop --command cargo nextest run -p keri-codec roundtrip_icp roundtrip_config_traits roundtrip_weighted_threshold roundtrip_all_seal_types`
Expected: PASS.
Run: `nix flake check > /tmp/gate.log 2>&1; echo "exit=$?"`
Expected: `exit=0`.

- [ ] **Step 7: Commit**

```bash
git add crates/keri-codec/src/codec/seal.rs crates/keri-codec/src/deserialize.rs
git commit -m "feat(keri-codec): FromWire for Seal; migrate build_inception + config"
```

---

## Task 4: Migrate the delegated builders

**Files:**
- Modify: `crates/keri-codec/src/deserialize.rs` (`build_delegated_inception`)

`build_delegated_rotation` already delegates to `build_rotation` (migrated in Task 2); `build_delegated_inception` delegates to `build_inception` (Task 3) plus a `di` delegator field.

- [ ] **Step 1: Migrate `build_delegated_inception`**

```rust
fn build_delegated_inception<'a>(
    p: &ParsedDip<'a>,
) -> Result<DelegatedInceptionEvent<'a>, SerderError> {
    Ok(DelegatedInceptionEvent::new(
        build_inception(&p.icp)?,
        Field::new("di", p.delegator).decode::<Identifier>()?,
    ))
}
```

> `p.delegator` may be `&str` or `Spanned` — use `.value` if it is `Spanned` (check `ParsedDip`).

- [ ] **Step 2: Run delegated roundtrips**

Run: `nix develop --command cargo nextest run -p keri-codec roundtrip_dip roundtrip_drt`
Expected: PASS.

- [ ] **Step 3: Full gate**

Run: `nix flake check > /tmp/gate.log 2>&1; echo "exit=$?"`
Expected: `exit=0`.

- [ ] **Step 4: Commit**

```bash
git add crates/keri-codec/src/deserialize.rs
git commit -m "feat(keri-codec): migrate delegated builders to Field pipeline"
```

---

## Task 5: Verify the full read path is on `Field`; delete dead read-path free fns

**Files:**
- Modify: `crates/keri-codec/src/deserialize.rs` (delete migrated free fns)

- [ ] **Step 1: Confirm no `build_*`/seal path references the old lift fns**

Run: `rg -n 'parse_qb64_|_from_parsed|seal_from_parsed|tholder_from_parsed|witness_threshold_wire|config_from_parsed|\bparse_sn\b|\bparse_weight\b' crates/keri-codec/src/deserialize.rs`
Expected: matches ONLY on the `fn` definitions themselves (and possibly `#[cfg(test)]` uses). If any non-test production caller remains, migrate it before deleting.

- [ ] **Step 2: Delete the now-unused free fns**

Remove from `deserialize.rs`: `parse_qb64_prefixer`, `parse_qb64_identifier`, `parse_qb64_verfer`, `parse_qb64_diger`, `parse_qb64_saider`, `parse_qb64_verser`, `map_qb64_error` (now in `field.rs`), `parse_sn`, `parse_weight`, `tholder_from_parsed`, `witness_threshold_wire`, `seal_from_parsed`, `config_from_parsed`, `verfers_from_parsed`, `prefixers_from_parsed`, `digers_from_parsed`, `anchors_from_parsed`, and `infer_digest_code` **only if** it is unused (it is used by SAID verification — keep it if `verify_*` still calls it).

> Keep: `threshold_form_of`, `check_form_consistency`, `check_thresholds_well_formed`, `validate_threshold` (cross-field/context logic, not single-field lifts), and the `verify_*` SAID functions.

- [ ] **Step 3: Fix any `#[cfg(test)]` references**

If deserialize.rs's own tests referenced deleted fns (e.g. `parse_weight` unit tests), move those assertions to the new home: the `parse_weight` boundary tests (`parse_weight_rejects_zero_denominator`, etc.) move to `threshold.rs`'s test module and call the threshold lift via `Field::new("kt", &ParsedTholder::Weighted(...)).decode::<SigningThreshold>()` (the SUT is now the impl). Preserve the zero-denominator bug-probe.

- [ ] **Step 4: Gate**

Run: `nix flake check > /tmp/gate.log 2>&1; echo "exit=$?"`
Expected: `exit=0`. Clippy `dead_code`/`unused` must be clean — this is the proof the read path is fully migrated.

- [ ] **Step 5: Commit**

```bash
git add crates/keri-codec/src/deserialize.rs crates/keri-codec/src/codec/threshold.rs
git commit -m "refactor(keri-codec): delete dead read-path lift free fns"
```

---

## Task 6: Write side — dissolve `primitives.rs` into `Encode`/`Field`

**Files:**
- Modify: `crates/keri-codec/src/codec.rs` (add `Encode for Matter<C>` single-value + `Identifier`)
- Modify: `crates/keri-codec/src/codec/event.rs`, `codec/seal.rs` (rewire `to_qb64_string`/`identifier_to_qb64_string` callsites)
- Delete: `crates/keri-codec/src/primitives.rs`
- Modify: `crates/keri-codec/src/lib.rs` (remove `mod primitives;` / re-exports)

- [ ] **Step 1: Add single-value `Encode` impls in `codec.rs`**

The slice impl `impl<C: CesrCode> Encode for [Matter<'_, C>]` already exists and calls `to_qb64_string`. Add the single-value forms and inline the qb64 render (drop the `to_qb64_string` indirection):

```rust
impl<C: CesrCode> Encode for Matter<'_, C> {
    fn encode(&self, out: &mut Vec<u8>) {
        JsonWriter::write_str(out, &self.to_qb64());
    }
}

impl Encode for Identifier<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Identifier::Basic(p) => p.encode(out),
            Identifier::SelfAddressing(s) => s.encode(out),
        }
    }
}
```

Update the existing slice impl to call `self.iter()` with `JsonWriter::write_str(out, &m.to_qb64())` directly (remove the `to_qb64_string` call). Add `use keri_events::Identifier;` at the top of `codec.rs`.

- [ ] **Step 2: Rewire callsites off `to_qb64_string`/`identifier_to_qb64_string`**

Run: `rg -n 'to_qb64_string|identifier_to_qb64_string' crates/keri-codec/src -g '!*/tests*' -g '!*test*'`
For each production callsite in `codec/event.rs`/`codec/seal.rs`, replace:
- `to_qb64_string(m)` → `m.to_qb64()` (when a `String` is needed) or route through `<Matter as Encode>::encode` where the writer appends a field.
- `identifier_to_qb64_string(id)` → `<Identifier as Encode>::encode` at the field-emit, or a small local `id.to_qb64()`-equivalent via the `Encode` path.

> Keep behavior byte-identical: `to_qb64_string` was just `matter.to_qb64()`, so this is a mechanical de-indirection. Test-module callsites can keep a local helper or call `.to_qb64()` directly.

- [ ] **Step 3: Delete `primitives.rs` and its module wiring**

Delete `crates/keri-codec/src/primitives.rs`. In `crates/keri-codec/src/lib.rs`, remove `mod primitives;` (or `pub mod primitives;`) and any `pub use primitives::...` re-exports. Move the two `primitives.rs` unit tests (`verfer_to_qb64_string`, `saider_to_qb64_string`) into `codec.rs`'s test module, asserting via the new `Encode` impl (`let mut o = Vec::new(); verfer.encode(&mut o); assert_eq!(o, b"\"D...\"");`).

- [ ] **Step 4: Gate**

Run: `nix flake check > /tmp/gate.log 2>&1; echo "exit=$?"`
Expected: `exit=0`.

- [ ] **Step 5: Commit**

```bash
git add -A crates/keri-codec/src
git commit -m "refactor(keri-codec): dissolve primitives.rs into Encode/Field write path"
```

---

## Task 7: Re-baseline the fn-ratchet and final verification

**Files:**
- Modify: `free-fn-budget.toml`

- [ ] **Step 1: Recount the keri-codec ratchet**

Run: `rg -o --no-filename '^pub(\(crate\)|\(super\))? fn ' crates/keri-codec/src -g '*.rs' | wc -l`
Expected: `49` (the two `primitives.rs` `pub fn`s are gone). If the number differs, use the actual number — but it must be `< 51` (only-down rule).

- [ ] **Step 2: Lower the budget to the exact new count**

In `free-fn-budget.toml`, change `keri-codec = 51` to the recounted number (expected `49`).

- [ ] **Step 3: Confirm the composability win (informational)**

Run: `rg -c '^fn ' crates/keri-codec/src/deserialize.rs`
Expected: substantially fewer than the pre-refactor 32 (the lift pile is gone; only `build_*`, `verify_*`, `check_*`, `threshold_form_of` remain).

- [ ] **Step 4: Final full gate**

Run: `nix flake check > /tmp/gate.log 2>&1; echo "exit=$?"`
Expected: `exit=0`. This runs clippy, fmt, taplo, audit, deny, nextest across feature combos, doctests, wasm build, no_std build, the version-owner tripwire, and the fn-ratchet — the single source of truth that the refactor is byte-identical and green.

- [ ] **Step 5: Commit**

```bash
git add free-fn-budget.toml
git commit -m "chore(keri-codec): re-baseline fn-ratchet 51 -> 49 after lift-layer refactor"
```

---

## Self-review checklist (completed by plan author)

- **Spec coverage:** `FromWire` trait ✓ (T1), `Field` newtype ✓ (T1), generic `Matter<C>` collapse ✓ (T1), `Identifier`/`SequenceNumber`/`ConfigTrait` ✓ (T1), `Vec` blanket ✓ (T1), threshold read-only lift ✓ (T2), `Seal` lift co-located in seal.rs ✓ (T3), write side reuses `Encode` + `primitives.rs` dissolves ✓ (T6), co-location per type ✓ (T1–T3), ratchet re-baseline ✓ (T7), invariants (byte-identity, ordering, error field-tagging) enforced via the unchanged public tests + gate on every task ✓.
- **Refinement beyond spec:** `bt`→`Toad` is lifted as bare `u32` (build_* wraps with witness-count context); cross-field checks (`check_*`) stay in the orchestrator. Documented in T2/T3.
- **Type consistency:** `FromWire::from_wire(field, wire)`, `Field::new`/`Field::each`/`Field::decode` names used identically across T1–T6. `Matter<C>` aliases (`Verfer`/`Prefixer`/`Diger`/`Saider`/`Verser`) all resolve through the one generic impl.
- **Placeholders:** none — every step has concrete code or an exact command. The two "verify `.value` vs `&str`" notes are genuine per-field-type confirmations against `codec/event.rs`, not deferred work.
