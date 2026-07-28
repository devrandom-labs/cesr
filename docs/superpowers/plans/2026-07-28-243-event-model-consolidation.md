# #243 Event-Model Consolidation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Delete the `drt.rs`/`dip.rs` builder twins by parameterizing the rotation and inception type-state chains over a sealed delegation-kind marker; wire bytes and domain types unchanged.

**Architecture:** `keri-codec` only. One `RotationBuilder<State, Kind>` chain (Kind ∈ {`Direct`, `Delegated`}, both ZSTs; `Kind::seal` picks `rot` vs `drt` wrap). One `InceptionBuilder<State, Kind>` chain (inception's `Delegated` carries the `delegator` `Identifier`, supplied at `DelegatedInceptionBuilder::new(delegator)` — the `NeedsDelegator` mid-state dies). `DelegatedRotationBuilder`/`DelegatedInceptionBuilder` become type aliases. Spec: `docs/superpowers/specs/2026-07-28-243-event-model-consolidation-design.md`.

**Tech Stack:** Rust 1.95 stable, sealed-trait type-state pattern (existing `EventBuilderState`/`sealed::Sealed` in `crates/keri-codec/src/builder.rs`), nextest via nix devshell.

**Verification law (repo rules):** dev-loop smoke = `nix develop --command cargo nextest run -p keri-codec`; the real gate is `nix flake check`, which runs on push via the pre-push hook — do NOT foreground-poll it locally. Wire behavior is frozen: the keripy differential corpus (`keripy_parity/`) must pass untouched except the two listed call sites.

**Branch:** `refactor/243-event-model-consolidation` (already exists, spec committed).

**API breaks (both called out in CHANGELOG, Task 3):**
1. `DelegatedInceptionBuilder::new(delegator)` replaces the `.keys(..).delegator(..)` chain step; the `Default` impl for `DelegatedInceptionBuilder` is removed (a delegator is required).
2. Type-state structs reshape (`#[doc(hidden)]`, not nameable downstream — mechanical).

---

### Task 1: Parameterize the rotation family — `rot.rs` absorbs `drt.rs`

**Files:**
- Modify: `crates/keri-codec/src/builder.rs` (shared `Direct` marker; drop `mod drt`; re-export alias from `rot`)
- Modify: `crates/keri-codec/src/builder/rot.rs` (Kind parameter, `RotationKind` trait, `Delegated` marker, generic `build()`, delegated test submodule)
- Delete: `crates/keri-codec/src/builder/drt.rs`

- [ ] **Step 1.1: Add the shared `Direct` marker to `builder.rs`**

In `crates/keri-codec/src/builder.rs`, directly after the `mod sealed { ... }` block (line ~53), add:

```rust
/// Direct (non-delegated) kind marker shared by the establishment builder
/// families: seals a rotation under `rot` and an inception under `icp`.
#[doc(hidden)]
pub struct Direct;

impl sealed::Sealed for Direct {}
```

In the same file, delete the two lines declaring the drt module:

```rust
/// Delegated rotation event builder.
pub(crate) mod drt;
```

and change the re-exports

```rust
pub use drt::DelegatedRotationBuilder;
...
pub use rot::RotationBuilder;
```

to

```rust
pub use rot::{DelegatedRotationBuilder, RotationBuilder};
```

(keep the `dip`/`icp`/`ixn` lines untouched — Task 2 handles inception).

- [ ] **Step 1.2: Rewrite `rot.rs` production code — parameterized chain**

Replace the production portion of `crates/keri-codec/src/builder/rot.rs` (everything before `#[cfg(test)]`) with the following. The five state structs (`NeedsPrefix`, `NeedsPriorSaid`, `NeedsKeys`, `NeedsPriorWitnesses`, `Ready`) and their `Sealed` impls are byte-identical to today's — only the builder struct, its impls, and the new Kind machinery change. Imports: keep today's list, add `use core::marker::PhantomData;` and `DelegatedRotationEvent` to the `keri_events` import:

```rust
use keri_events::{DelegatedRotationEvent, Identifier, RotationEvent, Seal};
```

and import the shared marker alongside the existing `super` items:

```rust
use super::{Direct, EventBuilderState, dummy_saider};
```

New Kind machinery (place after the `Ready` state struct, before the builder struct):

```rust
/// Delegated-kind marker: seals the rotation in a
/// [`DelegatedRotationEvent`], emitting the `drt` tag. A delegated rotation
/// stores no delegator — it is established at inception and resolved from
/// the KEL.
#[doc(hidden)]
pub struct Delegated;

impl Sealed for Delegated {}

/// Which wire tag the finished rotation seals under: `rot` (direct) or
/// `drt` (delegated). Sealed — the two kinds are a closed set. `pub`
/// because it bounds the public builder struct, same pattern as
/// [`EventBuilderState`].
pub trait RotationKind: Sealed {
    /// Event label used in [`BuilderError::SnBelowMinimum`].
    const LABEL: &'static str;

    /// Wrap the validated rotation in its event type and serialize it.
    fn seal(rotation: RotationEvent<'static>) -> Result<SerializedEvent, CodecError>;
}

impl RotationKind for Direct {
    const LABEL: &'static str = "rotation";

    fn seal(rotation: RotationEvent<'static>) -> Result<SerializedEvent, CodecError> {
        rotation.serialize()
    }
}

impl RotationKind for Delegated {
    const LABEL: &'static str = "delegated rotation";

    fn seal(rotation: RotationEvent<'static>) -> Result<SerializedEvent, CodecError> {
        DelegatedRotationEvent::new(rotation).serialize()
    }
}
```

Builder struct + alias (replaces today's `RotationBuilder` struct; keep today's doc comment on the builder, extend the "Required fields" doc to note the alias):

```rust
#[must_use]
pub struct RotationBuilder<State = NeedsPrefix, Kind = Direct>
where
    State: EventBuilderState,
    Kind: RotationKind,
{
    state: State,
    kind: PhantomData<Kind>,
}

/// Builder for delegated rotation events (`drt`): the same chain, defaults,
/// and validation as [`RotationBuilder`]; only the final wrap differs.
///
/// # Examples
///
/// ```ignore
/// let result = DelegatedRotationBuilder::new()
///     .prefix(prefixer)
///     .prior_event_said(saider)
///     .keys(vec![verfer])
///     .prior_witnesses(vec![])
///     .build()?;
/// ```
pub type DelegatedRotationBuilder<State = NeedsPrefix> = RotationBuilder<State, Delegated>;
```

Chain impls — every existing impl block gains `<K: RotationKind>` and threads `kind: PhantomData`; method bodies otherwise identical to today's. Written out in full:

```rust
impl<K: RotationKind> RotationBuilder<NeedsPrefix, K> {
    /// Create a new rotation builder awaiting the identifier prefix.
    pub const fn new() -> Self {
        Self {
            state: NeedsPrefix,
            kind: PhantomData,
        }
    }

    /// Set the identifier prefix (required). Accepts a basic (`Prefixer`) or
    /// self-addressing (`Saider`) prefix, or an `Identifier` directly.
    pub fn prefix(
        self,
        prefix: impl Into<Identifier<'static>>,
    ) -> RotationBuilder<NeedsPriorSaid, K> {
        RotationBuilder {
            state: NeedsPriorSaid {
                prefix: prefix.into(),
            },
            kind: PhantomData,
        }
    }
}

impl<K: RotationKind> Default for RotationBuilder<NeedsPrefix, K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: RotationKind> RotationBuilder<NeedsPriorSaid, K> {
    /// Set the prior event SAID (required).
    pub fn prior_event_said(self, said: Said<'static>) -> RotationBuilder<NeedsKeys, K> {
        let NeedsPriorSaid { prefix } = self.state;
        RotationBuilder {
            state: NeedsKeys {
                prefix,
                prior_event_said: said,
            },
            kind: PhantomData,
        }
    }
}

impl<K: RotationKind> RotationBuilder<NeedsKeys, K> {
    /// Set the new signing keys (required).
    pub fn keys(
        self,
        keys: Vec<VerifyingKey<'static>>,
    ) -> RotationBuilder<NeedsPriorWitnesses, K> {
        let NeedsKeys {
            prefix,
            prior_event_said,
        } = self.state;
        RotationBuilder {
            state: NeedsPriorWitnesses {
                prefix,
                prior_event_said,
                key_configuration: KeyConfiguration::new(keys),
            },
            kind: PhantomData,
        }
    }
}

impl<K: RotationKind> RotationBuilder<NeedsPriorWitnesses, K> {
    /// Set the prior witness set the removals/additions rotate (required —
    /// pass an empty `Vec` for an identifier with no current witnesses).
    ///
    /// Validation-only input mirroring keripy `rotate(wits=...)`: the prior
    /// set never appears in the serialized event, but the cut/add set
    /// relations and the default witness threshold are functions of it.
    pub fn prior_witnesses(
        self,
        prior_witnesses: Vec<BasicPrefix<'static>>,
    ) -> RotationBuilder<Ready, K> {
        let NeedsPriorWitnesses {
            prefix,
            prior_event_said,
            key_configuration,
        } = self.state;
        RotationBuilder {
            state: Ready {
                prefix,
                prior_event_said,
                key_configuration,
                witness_rotation: WitnessRotation::new(prior_witnesses),
                sn: 1,
                anchors: Vec::new(),
                said_code: DigestCode::Blake3_256,
            },
            kind: PhantomData,
        }
    }
}
```

The `Ready` impl: all setters keep today's exact bodies and docs (`sn`, `threshold`, `next_keys`, `next_threshold`, `witness_removals`, `witness_additions`, `witness_threshold`, `anchors`, `said_code`, `threshold_form`) inside `impl<K: RotationKind> RotationBuilder<Ready, K>`. `build()` keeps today's doc comment (error list identical) with this body:

```rust
    pub fn build(self) -> Result<SerializedEvent, CodecError> {
        let Ready {
            prefix,
            prior_event_said,
            key_configuration,
            witness_rotation,
            sn,
            anchors,
            said_code,
        } = self.state;

        if sn == 0 {
            return Err(BuilderError::SnBelowMinimum(K::LABEL).into());
        }

        let authority = key_configuration.validate()?;
        let witnesses = witness_rotation.validate()?;

        let rotation = RotationEvent::new(
            prefix,
            Number::new(sn),
            Said::from_matter(dummy_saider(said_code)?),
            prior_event_said,
            authority.keys,
            authority.threshold,
            authority.next_keys,
            authority.next_threshold,
            witnesses.additions,
            witnesses.removals,
            witnesses.threshold,
            anchors,
            authority.threshold_form,
        );

        K::seal(rotation)
    }
```

`const`-ness note: `new()` stays `const`. If clippy's `missing_const_for_fn` (nursery) demands `const` on a chain method the compiler accepts, add it; never `#[allow]`.

- [ ] **Step 1.3: Move the Delegated-specific tests into `rot.rs`, delete `drt.rs`**

Append inside `rot.rs`'s existing `mod tests` a nested submodule holding the **8 kept** drt tests, copied **verbatim** from today's `crates/keri-codec/src/builder/drt.rs` test module (bodies unchanged — they already use `DelegatedRotationBuilder::new()`, whose call shape is identical under the alias):

```rust
    /// Delegated (`drt`) kind: only what the Delegated seal path can observe —
    /// tag, wrap, label, and the drt read path. Validation invariants are
    /// Kind-independent (one generic `build()`) and tested once above.
    mod delegated {
        use super::*;

        // copied verbatim from drt.rs:
        // - build_minimal_delegated_rotation
        // - said_code_selects_digest
        // - build_delegated_rotation_with_self_addressing_prefix
        // - build_with_all_options
        // - roundtrip
        // - sn_zero_rejected            (asserts the "delegated rotation" LABEL)
        // - default_impl
        // - witness_change_roundtrip
    }
```

(The executor pastes the 8 full test fns from drt.rs — do not retype them. The helper fns `make_prefixer`, `make_prefixer_tag`, `make_saider`, `make_verfer`, `make_diger` already exist in rot.rs's outer `mod tests` and are visible via `use super::*`; drt.rs's copies of `make_prefixer_tag` must come along only if rot.rs's tests lack it — check: rot.rs already has witness tests using tagged prefixers, so it exists. `use crate::traits::Deserialize;` and `use keri_events::toad::ToadError;` — `ToadError` is NOT needed (all toad tests dropped); `Deserialize` is needed by the kept roundtrip tests and is already imported in rot.rs's tests.)

The **12 dropped** drt tests (validation duplicates, canonical copies live in rot.rs's outer test mod): `threshold_default_majority`, `empty_keys_rejected`, `duplicate_prior_witnesses_rejected`, `duplicate_witness_removals_rejected`, `duplicate_witness_additions_rejected`, `removal_not_prior_witness_rejected`, `addition_already_prior_witness_rejected`, `overlapping_removal_and_addition_rejected`, `toad_exceeding_new_witness_set_rejected`, `toad_zero_with_witnesses_rejected`, `toad_nonzero_without_witnesses_rejected`, `toad_defaults_to_ample_of_post_rotation_set`.

Then delete the file:

```bash
git rm crates/keri-codec/src/builder/drt.rs
```

- [ ] **Step 1.4: Smoke-test the rotation family**

Run:

```bash
nix develop --command cargo nextest run -p keri-codec 2>&1 | tail -5
```

Expected: all tests pass (count drops by 12 — the dropped duplicates). If `rot::` or `drt`-related failures appear, fix before committing. Also expect the keripy parity tests (`keripy_parity::validation`) green — `DelegatedRotationBuilder`'s call shape is unchanged.

- [ ] **Step 1.5: Commit**

```bash
git add -A crates/keri-codec/src/builder.rs crates/keri-codec/src/builder/rot.rs crates/keri-codec/src/builder/drt.rs
git commit -m "refactor(keri-codec)!: #243 rot/drt builder twin -> RotationBuilder<State, Kind>

One type-state chain; Kind::seal picks the rot/drt wrap. drt.rs deleted;
12 duplicated validation tests dropped (canonical in rot.rs).

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Parameterize the inception family — `icp.rs` absorbs `dip.rs` + call-site updates

**Files:**
- Modify: `crates/keri-codec/src/builder/icp.rs` (Kind parameter, `InceptionKind` trait, data-bearing `Delegated`, delegated test submodule)
- Modify: `crates/keri-codec/src/builder.rs` (drop `mod dip`; re-export alias from `icp`)
- Modify: `crates/keri-codec/src/keripy_parity/validation.rs:164-166` (new `DelegatedInceptionBuilder::new(delegator)` signature)
- Modify: `crates/keri-codec/examples/delegated_inception.rs:34-37` (same)
- Delete: `crates/keri-codec/src/builder/dip.rs`

Must be ONE commit — the workspace does not compile with the API changed but call sites stale.

- [ ] **Step 2.1: Rewrite `icp.rs` production code**

Imports: add `DelegatedInceptionEvent` to the `keri_events` line and `Direct` to the `super` line:

```rust
use keri_events::{ConfigTrait, DelegatedInceptionEvent, Identifier, InceptionEvent, Seal};
use super::{Direct, EventBuilderState, dummy_saider};
```

(No `PhantomData` here — inception's Kind is a real field.) Keep `NeedsKeys` and `Ready` state structs exactly as they are. After `Ready`'s `Sealed` impl, add:

```rust
/// Delegated-kind marker carrying the delegator prefix: seals the inception
/// in a [`DelegatedInceptionEvent`], emitting the `dip` tag and its `di`
/// field.
#[doc(hidden)]
pub struct Delegated {
    delegator: Identifier<'static>,
}

impl Sealed for Delegated {}

/// Which wire tag the finished inception seals under: `icp` (direct) or
/// `dip` (delegated). Sealed — the two kinds are a closed set. `pub`
/// because it bounds the public builder struct, same pattern as
/// [`EventBuilderState`].
pub trait InceptionKind: Sealed {
    /// Wrap the validated inception in its event type and serialize it.
    fn seal(self, inception: InceptionEvent<'static>) -> Result<SerializedEvent, CodecError>;
}

impl InceptionKind for Direct {
    fn seal(self, inception: InceptionEvent<'static>) -> Result<SerializedEvent, CodecError> {
        inception.serialize()
    }
}

impl InceptionKind for Delegated {
    fn seal(self, inception: InceptionEvent<'static>) -> Result<SerializedEvent, CodecError> {
        DelegatedInceptionEvent::new(inception, self.delegator).serialize()
    }
}
```

Builder struct + alias + entry points (replaces today's struct and `new`/`keys`/`Default` impls; keep today's builder doc comment, and note only `keys` is required for direct, `delegator` moves to `new` for delegated):

```rust
#[must_use]
pub struct InceptionBuilder<State = NeedsKeys, Kind = Direct>
where
    State: EventBuilderState,
    Kind: InceptionKind,
{
    state: State,
    kind: Kind,
}

/// Builder for delegated inception events (`dip`): the same chain, defaults,
/// and validation as [`InceptionBuilder`]; the delegator is supplied up
/// front and the final wrap adds the `di` field.
///
/// # Examples
///
/// ```ignore
/// let result = DelegatedInceptionBuilder::new(delegator)
///     .keys(vec![verfer])
///     .build()?;
/// ```
pub type DelegatedInceptionBuilder<State = NeedsKeys> = InceptionBuilder<State, Delegated>;

impl InceptionBuilder<NeedsKeys, Direct> {
    /// Create a new inception builder awaiting signing keys.
    pub const fn new() -> Self {
        Self {
            state: NeedsKeys,
            kind: Direct,
        }
    }
}

impl Default for InceptionBuilder<NeedsKeys, Direct> {
    fn default() -> Self {
        Self::new()
    }
}

impl DelegatedInceptionBuilder<NeedsKeys> {
    /// Create a new delegated inception builder; the delegator prefix is
    /// required up front. Accepts a basic (`Prefixer`) or self-addressing
    /// (`Saider`) delegator, or an `Identifier` directly.
    pub fn new(delegator: impl Into<Identifier<'static>>) -> Self {
        Self {
            state: NeedsKeys,
            kind: Delegated {
                delegator: delegator.into(),
            },
        }
    }
}

impl<K: InceptionKind> InceptionBuilder<NeedsKeys, K> {
    /// Set the signing keys (required).
    pub fn keys(self, keys: Vec<VerifyingKey<'static>>) -> InceptionBuilder<Ready, K> {
        InceptionBuilder {
            state: Ready {
                key_configuration: KeyConfiguration::new(keys),
                witness_configuration: WitnessConfiguration::new(),
                config: Vec::new(),
                anchors: Vec::new(),
                said_code: DigestCode::Blake3_256,
            },
            kind: self.kind,
        }
    }
}
```

(`keys` loses `const` — it moves the generic `kind` field; if the compiler accepts `const` here, keep it, clippy `missing_const_for_fn` will say so.)

Setters: today's exact bodies and docs (`threshold`, `next_keys`, `next_threshold`, `witnesses`, `witness_threshold`, `config`, `anchors`, `said_code`, `threshold_form`) inside `impl<K: InceptionKind> InceptionBuilder<Ready, K>`. `build()` keeps today's doc comment with this body:

```rust
    pub fn build(self) -> Result<SerializedEvent, CodecError> {
        let Ready {
            key_configuration,
            witness_configuration,
            config,
            anchors,
            said_code,
        } = self.state;

        let authority = key_configuration.validate()?;
        let (witnesses, witness_threshold) = witness_configuration.validate()?;

        let inception = InceptionEvent::new(
            Identifier::SelfAddressing(Said::from_matter(dummy_saider(said_code)?)),
            Number::new(0),
            Said::from_matter(dummy_saider(said_code)?),
            authority.keys,
            authority.threshold,
            authority.next_keys,
            authority.next_threshold,
            witnesses,
            witness_threshold,
            config,
            anchors,
            authority.threshold_form,
        );

        self.kind.seal(inception)
    }
```

- [ ] **Step 2.2: Move Delegated-specific tests into `icp.rs`, delete `dip.rs`**

Nested submodule inside icp.rs's `mod tests`, holding the **6 kept** dip tests copied from `crates/keri-codec/src/builder/dip.rs`, each with its builder chain updated from `DelegatedInceptionBuilder::new().keys(K).delegator(D)` to `DelegatedInceptionBuilder::new(D).keys(K)` (only that reordering — assertions unchanged):

```rust
    /// Delegated (`dip`) kind: only what the Delegated seal path can observe —
    /// tag, `di` field, wrap, and the dip read path. Validation invariants
    /// are Kind-independent (one generic `build()`) and tested once above.
    mod delegated {
        use super::*;

        // copied from dip.rs (chain reordered to new(delegator).keys(..)):
        // - build_minimal_delegated_inception
        // - build_dip_with_self_addressing_delegator
        // - said_code_selects_digest_for_said_and_prefix
        // - build_with_all_options
        // - roundtrip
        // - self_addressing_prefix
    }
```

Helper check: dip's tests use `make_prefixer`/`make_verfer`/`make_diger`/`make_saider`-style helpers and `BasicPrefix` — icp.rs's outer test mod imports only `Digest`/`VerifyingKey` primitives; bring over from dip.rs whatever helper fns and `use keri_events::primitive::BasicPrefix;` the six kept tests actually reference, placing shared helpers in the outer `mod tests` if icp lacks them, and drop the rest. `use crate::traits::Deserialize;` is needed by `roundtrip` (icp tests already import it).

The **7 dropped** dip tests: `threshold_default_majority`, `empty_keys_rejected`, `duplicate_witnesses_rejected`, `toad_exceeding_witness_count_rejected`, `toad_zero_with_witnesses_rejected`, `toad_nonzero_without_witnesses_rejected` (canonical copies in icp.rs's outer test mod), plus `default_impl` (the `Default` impl for the delegated alias is gone — delegator is a required constructor argument; the icp `default_impl` test covers Direct).

Then:

```bash
git rm crates/keri-codec/src/builder/dip.rs
```

In `crates/keri-codec/src/builder.rs`, delete:

```rust
/// Delegated inception event builder.
pub(crate) mod dip;
```

and change

```rust
pub use dip::DelegatedInceptionBuilder;
...
pub use icp::InceptionBuilder;
```

to

```rust
pub use icp::{DelegatedInceptionBuilder, InceptionBuilder};
```

- [ ] **Step 2.3: Update the two external call sites**

`crates/keri-codec/src/keripy_parity/validation.rs` — in `replay_delcept` (line ~164), change:

```rust
    let mut b = DelegatedInceptionBuilder::new()
        .keys(verfers(p))
        .delegator(delegator(p));
```

to:

```rust
    let mut b = DelegatedInceptionBuilder::new(delegator(p)).keys(verfers(p));
```

`crates/keri-codec/examples/delegated_inception.rs` (line ~34), change:

```rust
    let dip = DelegatedInceptionBuilder::new()
        .keys(vec![key.into()])
        .delegator(Identifier::SelfAddressing(delegator.into()))
        .build()?;
```

to:

```rust
    let dip = DelegatedInceptionBuilder::new(Identifier::SelfAddressing(delegator.into()))
        .keys(vec![key.into()])
        .build()?;
```

- [ ] **Step 2.4: Smoke-test the whole crate + example**

```bash
nix develop --command cargo nextest run -p keri-codec 2>&1 | tail -5
nix develop --command cargo build -p keri-codec --examples 2>&1 | tail -3
```

Expected: all tests pass (count drops by 7), examples compile. The keripy differential corpus (`keripy_parity::validation` delcept replay) must be green — it proves the reordered call produces byte-identical output.

- [ ] **Step 2.5: Commit**

```bash
git add -A crates/keri-codec/src/builder.rs crates/keri-codec/src/builder/icp.rs crates/keri-codec/src/builder/dip.rs crates/keri-codec/src/keripy_parity/validation.rs crates/keri-codec/examples/delegated_inception.rs
git commit -m "refactor(keri-codec)!: #243 icp/dip builder twin -> InceptionBuilder<State, Kind>

Delegator moves to DelegatedInceptionBuilder::new(delegator) — still
compile-time-required, via signature instead of the NeedsDelegator state.
dip.rs deleted; 7 duplicated validation tests dropped; Default for the
delegated alias removed.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: CHANGELOG, gate, PR

**Files:**
- Modify: `crates/keri-codec/CHANGELOG.md`

- [ ] **Step 3.1: CHANGELOG entry**

Add at the top of `crates/keri-codec/CHANGELOG.md`, matching the file's existing heading style (release-plz maintains version sections — put this under the unreleased/topmost area following whatever pattern the file uses):

```markdown
### ⚠️ Breaking changes — #243 event-model consolidation

- `DelegatedRotationBuilder` and `DelegatedInceptionBuilder` are now type
  aliases of the parameterized `RotationBuilder<State, Kind>` /
  `InceptionBuilder<State, Kind>` chains — one type-state chain per event
  family; validation-rule drift between a tag and its delegated twin is now
  a compile error.
- `DelegatedInceptionBuilder::new(delegator)` replaces the
  `.keys(..).delegator(..)` chain step (delegator still compile-time
  required, via the constructor). Its `Default` impl is removed.
- Wire output is byte-identical for all four tags (keripy differential
  corpus unchanged).
```

- [ ] **Step 3.2: Commit, push (gate runs on push via hook)**

```bash
git add crates/keri-codec/CHANGELOG.md
git commit -m "docs(keri-codec): #243 changelog for builder consolidation

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
git push -u origin refactor/243-event-model-consolidation
```

Expected: pre-push hook runs `nix flake check` on the committed tree — clippy (god-level), fmt, taplo, audit, deny, nextest all-features, doctests, wasm, no_std, version-owner, fn-ratchet. Do not bypass; if the hook rejects, fix and re-push. (fn-ratchet: no free `pub fn` added — `seal` is a trait method.)

- [ ] **Step 3.3: PR**

```bash
gh pr create --repo devrandom-labs/cesr \
  --title "refactor(keri-codec)!: #243 event-model consolidation — rot/drt + icp/dip builder twins" \
  --body "$(cat <<'EOF'
Closes #243. Per spec `docs/superpowers/specs/2026-07-28-243-event-model-consolidation-design.md`.

**What:** deletes `builder/drt.rs` and `builder/dip.rs`; each event family gets one type-state chain parameterized over a sealed delegation-kind marker (`RotationBuilder<State, Kind>`, `InceptionBuilder<State, Kind>`); `Delegated*Builder` names survive as type aliases.

**Issue re-map:** of #243's three bullets, the doubled `.ilk()` map was killed by #242 and the parse layer already shared `ParsedRot` — the builder layer was the only remaining twin. Domain types untouched (`DelegatedRotationEvent` newtype stays — load-bearing for the keri-rs fold match).

**⚠️ Breaking (MINOR bump per 0.x):**
- `DelegatedInceptionBuilder::new(delegator)` replaces `.keys(..).delegator(..)`; `Default` for the delegated alias removed.
- Builder type-state internals reshaped (`#[doc(hidden)]`).

**Wire law:** byte output identical for all four tags; keripy differential corpus untouched except the one delcept call-site reorder in `keripy_parity/validation.rs`.

**Tests:** 19 wholesale-duplicated validation tests dropped (each invariant now tested once, canonical in the Direct chain — validation is provably Kind-independent, single generic `build()`); Delegated-specific tests (tag, wrap, label, read path) kept in nested `mod delegated`.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
gh pr merge --auto --squash
```

(Use the `joeldsouzax` gh account if a permissions error appears: `gh auth switch --user joeldsouzax`.)

---

## Self-Review (done at plan time)

- **Spec coverage:** rotation family ✔ (Task 1), inception family ✔ (Task 2), test canonicalization ✔ (Steps 1.3/2.2), API break callout ✔ (Task 3), non-goals respected (no domain/keri-events/keri-rs edits anywhere).
- **Type consistency:** `RotationKind::seal` is a static method (ZST kinds); `InceptionKind::seal(self, ..)` takes self by value (Delegated carries the delegator). `Direct` is defined once in `builder.rs` and implements both kind traits (impls live in each family's file). Labels `"rotation"`/`"delegated rotation"` match the existing `SnBelowMinimum` assertions verbatim.
- **Placeholder scan:** the two "copied verbatim" test lists name every test fn explicitly and its source file; no TBDs.
