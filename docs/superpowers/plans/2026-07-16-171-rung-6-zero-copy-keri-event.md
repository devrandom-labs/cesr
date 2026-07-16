# Rung 6 — Zero-copy `KeriEvent<'a>` Implementation Plan (#129, #171)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Relax the five KERI event structs + `KeriEvent`/`Seal`/`OpaqueSeal` from owned-`'static` to borrowed `<'a>` (Vec lists — spec amendment), make `deserialize_*` return events borrowing the input, and relax keri-rs signatures (bundling the pending `Toad`/by-value-`sn()` cleanup).

**Architecture:** Lifetime changes are atomic per type layer, so tasks stage bottom-up: (1) `Seal<'a>`/`OpaqueSeal<'a>` with downstream pinned `<'static>`; (2) event structs `<'a>` with downstream pinned; (3) the read path drops `into_static()` and returns borrows; (4) keri-rs relaxes + bundled cleanup; (5) CHANGELOG/gate/PR. Every commit compiles and passes the full suite. Covariance (the reason Vec beat Cow) is pinned by compile-time probe tests.

**Tech Stack:** Rust 1.95, no_std+alloc (`cesr::keri` uses `core::`/`alloc::` only). Spec: `docs/superpowers/specs/2026-07-16-171-rung-6-zero-copy-keri-event-design.md` (read the Amendment block first).

**Branch:** `171-zero-copy-keri-event` (exists, off main @ `422f77f`).

**Fast dev loop:** `nix develop --command cargo nextest run -p cesr-rs -p keri-rs --all-features > /tmp/r6-test.log 2>&1; echo "exit: $?"` — NEVER pipe gate/test commands; always redirect + echo $?.

**Invariants after every task:** all tests green including `keripy_parity` corpora (byte-identity law), the 5 structural-oracle proptests, `*_strict_equals_reference`; god-clippy clean; `cargo fmt --check` clean. **Zero wire bytes change in this entire rung.**

---

### Task 1: `Seal<'a>` + `OpaqueSeal<'a>` (downstream pinned `'static`)

**Files:**
- Modify: `cesr/src/keri/seal.rs` (enum + OpaqueSeal + new tests)
- Modify: `cesr/src/keri/event/{inception,rotation,interaction}.rs` (field/accessor pins: `Vec<Seal>` → `Vec<Seal<'static>>`, `&[Seal]` → `&[Seal<'static>]`, `Vec<Seal>` params likewise)
- Modify: `cesr/src/serder/deserialize.rs` (`seal_from_parsed` return type pin)
- Modify: `cesr/src/serder/serialize/json.rs` (`write_seal(buf, seal: &Seal<'_>)` — elided lifetime suffices)
- Modify: `cesr/src/serder/event_strategies.rs` (`opaque(pick) -> OpaqueSeal<'static>`, `build_seal -> Seal<'static>`)
- Anywhere else the compiler flags a bare `Seal`/`OpaqueSeal` in type position (tests included): write `<'static>` or `<'_>` per position.

- [ ] **Step 1: Reshape `OpaqueSeal`** (seal.rs:77-100). The struct, `new`, and a new `into_static`:

```rust
/// … (keep the existing doc comment verbatim) …
#[derive(Debug, Clone)]
pub struct OpaqueSeal<'a>(Cow<'a, str>);

impl<'a> OpaqueSeal<'a> {
    /// Validate and wrap a compact-JSON object payload.
    ///
    /// # Errors
    ///
    /// Returns [`OpaqueSealError`] when `raw` is not exactly one well-formed
    /// compact JSON object.
    pub fn new(raw: impl Into<Cow<'a, str>>) -> Result<Self, OpaqueSealError> {
        let raw = raw.into();
        let len = scan_object(raw.as_bytes())?;
        if len != raw.len() {
            return Err(OpaqueSealError::TrailingBytes { offset: len });
        }
        Ok(Self(raw))
    }

    /// The verbatim JSON object text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Detach from the source buffer by owning the payload.
    #[must_use]
    pub fn into_static(self) -> OpaqueSeal<'static> {
        OpaqueSeal(Cow::Owned(self.0.into_owned()))
    }
}
```
Add `Cow` to the alloc import at the top: `use alloc::{borrow::Cow, string::String, vec, vec::Vec};` (keep `String` only if still referenced; drop if the compiler says unused). `impl Into<Cow<'a, str>>` keeps every existing `OpaqueSeal::new(String)` call site compiling unchanged, and lets the read path pass `&'a str` later.

- [ ] **Step 2: Reshape `Seal`** (seal.rs:16-65). Every variant's Matters get `'a`; add `Clone` (required later by nothing in this rung, but `Seal` values are cloned in tests via event construction — add it with `Debug`: check first whether `Seal` currently derives anything; the file shows no derive on `Seal`, so add none unless the compiler demands it — YAGNI):

```rust
pub enum Seal<'a> {
    /// Digest seal — anchors a single hash.
    Digest {
        /// The digest value.
        d: Saider<'a>,
    },
    /// Root seal — anchors a Merkle tree root.
    Root {
        /// The root digest.
        rd: Saider<'a>,
    },
    /// Source seal — references a prior event by sequence number and digest.
    Source {
        /// Sequence number of the source event.
        s: SequenceNumber,
        /// Digest of the source event.
        d: Saider<'a>,
    },
    /// Event seal — fully identifies an event by prefix, sequence number, and digest.
    Event {
        /// Prefix of the identifier.
        i: Prefixer<'a>,
        /// Sequence number of the event.
        s: SequenceNumber,
        /// Digest of the event.
        d: Saider<'a>,
    },
    /// Last-event seal — references the latest event for a given prefix.
    Last {
        /// Prefix of the identifier.
        i: Prefixer<'a>,
    },
    /// Registrar-backer seal — nontransferable backer prefix plus a digest
    /// of the anchored backer metadata (keripy `SealBack`).
    Back {
        /// Backer identifier prefix.
        bi: Prefixer<'a>,
        /// Digest of the anchored backer metadata.
        d: Saider<'a>,
    },
    /// Typed digest seal — a version/type tag plus a SAID (keripy `SealKind`).
    Kind {
        /// Type of the digest.
        t: Verser<'a>,
        /// The digest value.
        d: Saider<'a>,
    },
    /// A non-codex anchor preserved verbatim.
    Opaque(OpaqueSeal<'a>),
}

impl Seal<'_> {
    /// Detach from the source buffer by owning every contained primitive.
    #[must_use]
    pub fn into_static(self) -> Seal<'static> {
        match self {
            Self::Digest { d } => Seal::Digest { d: d.into_static() },
            Self::Root { rd } => Seal::Root { rd: rd.into_static() },
            Self::Source { s, d } => Seal::Source { s, d: d.into_static() },
            Self::Event { i, s, d } => Seal::Event {
                i: i.into_static(),
                s,
                d: d.into_static(),
            },
            Self::Last { i } => Seal::Last { i: i.into_static() },
            Self::Back { bi, d } => Seal::Back {
                bi: bi.into_static(),
                d: d.into_static(),
            },
            Self::Kind { t, d } => Seal::Kind {
                t: t.into_static(),
                d: d.into_static(),
            },
            Self::Opaque(raw) => Seal::Opaque(raw.into_static()),
        }
    }
}
```

- [ ] **Step 3: Pin downstream.** Run `nix develop --command cargo check -p cesr-rs --all-features --all-targets > /tmp/r6-t1-check.log 2>&1; echo "exit: $?"` and fix every "missing lifetime" error the compiler lists by writing `<'static>` in storage positions (event struct fields/params/accessors, `event_strategies` return types, `seal_from_parsed -> Result<Seal<'static>, _>` with its `OpaqueSeal::new((*raw).to_owned())` body unchanged) and `<'_>` in transient reference positions (`write_seal(buf: &mut Vec<u8>, seal: &Seal<'_>)`, `write_seal_array(… seals: &[Seal<'_>])` — note: a slice of `Seal<'_>` in an argument elides fine). The existing `seal_is_send_sync_static` test re-targets `Seal<'static>`:

```rust
    #[test]
    fn seal_is_send_sync_static() {
        fn assert_send_sync_static<T: Send + Sync + 'static>() {}
        assert_send_sync_static::<Seal<'static>>();
        assert_send_sync_static::<OpaqueSeal<'static>>();
    }
```

- [ ] **Step 4: Covariance probe test** (in seal.rs `mod tests` — the reason Vec beat Cow, pinned forever):

```rust
    /// Compile-time probe: `Seal` must stay covariant in its lifetime — a
    /// longer-lived seal coerces to a shorter one. If a future field makes
    /// it invariant (e.g. a `Cow<'a, [T<'a>]>` — see the rung-6 spec
    /// amendment), this stops compiling.
    #[test]
    fn seal_is_covariant() {
        fn coerce<'short>(s: &'short Seal<'static>) -> &'short Seal<'short> {
            s
        }
        let seal = Seal::Last { i: make_prefixer() };
        let _ = coerce(&seal);
    }
```
(Reuse the module's existing `make_*` helpers; if seal.rs tests lack a `make_prefixer`, copy the 8-line MatterBuilder helper from `cesr/src/keri/event/inception.rs:151-158`.)

- [ ] **Step 5: Full suite + fmt + clippy, then commit**

```bash
nix develop --command cargo nextest run -p cesr-rs -p keri-rs --all-features > /tmp/r6-t1.log 2>&1; echo "exit: $?"
nix develop --command cargo clippy -p cesr-rs --all-features --all-targets > /tmp/r6-t1c.log 2>&1; echo "exit: $?"
nix develop --command cargo fmt --check -p cesr-rs > /tmp/r6-t1f.log 2>&1; echo "exit: $?"
git add -A && git commit -m "refactor(keri)!: Seal and OpaqueSeal gain a lifetime; opaque payload is Cow (#129, #171)

Downstream pins to <'static> pending the event-struct relaxation.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Event structs `<'a>` + `KeriEvent<'a>` (downstream pinned `'static`)

**Files:**
- Modify: `cesr/src/keri/event/inception.rs`, `rotation.rs`, `interaction.rs`, `delegation.rs`, `mod.rs`
- Modify (pins only, compiler-driven): `cesr/src/serder/serialize.rs` (`EventRef`, `SerializedEvent` uses, probe fns), `cesr/src/serder/serialize/{icp,rot,ixn,dip,drt,json}.rs`, `cesr/src/serder/deserialize.rs` (`build_*` return pins), `cesr/src/serder/traits.rs`, `cesr/src/serder/builder/*.rs`, `cesr/src/serder/event_strategies.rs`, `keri/src/state.rs`, `keri/src/authority.rs` (write `<'static>`/`<'_>` where the compiler demands — real relaxation is Tasks 3–4), benches/tests as flagged.

- [ ] **Step 1: Reshape `InceptionEvent`** (inception.rs:18-141). Struct + constructor + accessors + `into_static`:

```rust
/// An inception event that creates a new KERI identifier.
pub struct InceptionEvent<'a> {
    prefix: Identifier<'a>,
    sn: SequenceNumber,
    said: Saider<'a>,
    keys: Vec<Verfer<'a>>,
    threshold: SigningThreshold,
    next_keys: Vec<Diger<'a>>,
    next_threshold: SigningThreshold,
    witnesses: Vec<Prefixer<'a>>,
    witness_threshold: Toad,
    config: Vec<ConfigTrait>,
    anchors: Vec<Seal<'a>>,
    threshold_form: ThresholdForm,
}

impl<'a> InceptionEvent<'a> {
    // new(): SAME body; every `'static` in the signature becomes `'a`
    // (prefix: Identifier<'a>, said: Saider<'a>, keys: Vec<Verfer<'a>>,
    //  next_keys: Vec<Diger<'a>>, witnesses: Vec<Prefixer<'a>>,
    //  anchors: Vec<Seal<'a>>). Keep #[cfg(feature = "internals")],
    //  #[must_use], the too_many_arguments allow, and `const`.

    // Accessors: same bodies; return types swap 'static → 'a:
    //   prefix() -> &Identifier<'a>      said() -> &Saider<'a>
    //   keys() -> &[Verfer<'a>]          next_keys() -> &[Diger<'a>]
    //   witnesses() -> &[Prefixer<'a>]   anchors() -> &[Seal<'a>]
    // Scalar accessors (sn, thresholds, witness_threshold, config,
    // threshold_form) are unchanged.

    /// Detach from the source buffer by owning every contained primitive.
    #[must_use]
    pub fn into_static(self) -> InceptionEvent<'static> {
        InceptionEvent {
            prefix: self.prefix.into_static(),
            sn: self.sn,
            said: self.said.into_static(),
            keys: self.keys.into_iter().map(Matter::into_static).collect(),
            threshold: self.threshold,
            next_keys: self.next_keys.into_iter().map(Matter::into_static).collect(),
            next_threshold: self.next_threshold,
            witnesses: self.witnesses.into_iter().map(Matter::into_static).collect(),
            witness_threshold: self.witness_threshold,
            config: self.config,
            anchors: self.anchors.into_iter().map(Seal::into_static).collect(),
            threshold_form: self.threshold_form,
        }
    }
}
```
(`Matter::into_static` needs `use crate::core::matter::matter::Matter;` at the top of the file — or call method syntax `.map(|k| k.into_static())`, which needs no import; use the closure form.)

- [ ] **Step 2: Same transformation for the other four.** Field tables (all Matters/Identifier/Seal swap `'static`→`'a`; scalars unchanged; each gets `into_static` in the same shape):
  - `RotationEvent<'a>` (rotation.rs): `prefix: Identifier<'a>`, `sn`, `said: Saider<'a>`, `prior_event_said: Saider<'a>`, `keys: Vec<Verfer<'a>>`, `threshold`, `next_keys: Vec<Diger<'a>>`, `next_threshold`, `witness_additions: Vec<Prefixer<'a>>`, `witness_removals: Vec<Prefixer<'a>>`, `witness_threshold`, `anchors: Vec<Seal<'a>>`, `threshold_form`.
  - `InteractionEvent<'a>` (interaction.rs): `prefix: Identifier<'a>`, `sn`, `said: Saider<'a>`, `prior_event_said: Saider<'a>`, `anchors: Vec<Seal<'a>>`.
  - `DelegatedInceptionEvent<'a>` (delegation.rs): `inception: InceptionEvent<'a>`, `delegator: Identifier<'a>`; `into_static` maps both.
  - `DelegatedRotationEvent<'a>` (delegation.rs): `rotation: RotationEvent<'a>`; `into_static` maps it.
  - `KeriEvent<'a>` (mod.rs:24-48): variants wrap the `<'a>` types; `ilk()` unchanged; add:

```rust
    /// Detach from the source buffer by owning every contained primitive.
    #[must_use]
    pub fn into_static(self) -> KeriEvent<'static> {
        match self {
            Self::Inception(e) => KeriEvent::Inception(e.into_static()),
            Self::Rotation(e) => KeriEvent::Rotation(e.into_static()),
            Self::Interaction(e) => KeriEvent::Interaction(e.into_static()),
            Self::DelegatedInception(e) => KeriEvent::DelegatedInception(e.into_static()),
            Self::DelegatedRotation(e) => KeriEvent::DelegatedRotation(e.into_static()),
        }
    }
```
  `DelegatedInceptionEvent::into_static` body: `DelegatedInceptionEvent { inception: self.inception.into_static(), delegator: self.delegator.into_static() }` — note these structs construct via `Self { … }` on the `'static` instantiation; if field-init from a differently-parameterized `Self` complains, name the type explicitly as shown for `InceptionEvent`.

- [ ] **Step 3: Covariance probe + static-assertion tests.** In each of the four event files' `mod tests` (inception/rotation/interaction/delegation) and mod.rs, re-target `is_send_sync_static` to `<'static>` (e.g. `assert_send_sync_static::<InceptionEvent<'static>>();`) and add one covariance probe per file, same shape as Task 1's, e.g. in inception.rs:

```rust
    /// Compile-time probe: the event must stay covariant in its lifetime
    /// (a `&Event<'static>` coerces to `&Event<'short>`). Vec lists keep
    /// this true; a `Cow<'a, [T<'a>]>` field would break it — see the
    /// rung-6 spec amendment.
    #[test]
    fn inception_event_is_covariant() {
        fn coerce<'short>(
            e: &'short InceptionEvent<'static>,
        ) -> &'short InceptionEvent<'short> {
            e
        }
        let event = InceptionEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(0),
            make_saider(),
            vec![make_verfer()],
            SigningThreshold::Simple(1),
            vec![make_diger()],
            SigningThreshold::Simple(1),
            vec![],
            Toad::exact(0, 0).unwrap(),
            vec![],
            vec![],
            ThresholdForm::HexString,
        );
        let _ = coerce(&event);
    }
```
(rotation/interaction/delegation/mod.rs versions use their existing `make_*` fixture helpers; `KeriEvent` probe wraps `KeriEvent::Inception(make_inception())`.)

- [ ] **Step 4: Compiler-driven downstream pinning.** `cargo check --all-targets` and fix every missing-lifetime error. Rules per position:
  - **Storage of owned events** (builder `SerializedEvent<XEvent>` type params in `builder/*.rs`, `SerializedEvent` docs): write `<'static>`.
  - **Transient references** (fn params in `serialize/{icp,…}.rs` entry fns, `json.rs` renderers, `EventRef` variants, `KeyState::seed(icp: &'e InceptionEvent)` etc. in keri-rs, deserialize `build_*` returns): prefer `<'_>` where elision works; where a named lifetime is required to compile, use the surrounding one — but in this task do NOT relax keri-rs semantics: writing `<'static>` there is fine and expected (Task 4 relaxes).
  - `EventRef<'e>` variants become `Inception(&'e InceptionEvent<'e>)` etc. — callers' `&InceptionEvent<'static>` coerce via the covariance this rung pins. `EventRef::said_code`/`is_double_said`/`From<&'e KeriEvent<'e>>` bodies unchanged.
  - `traits.rs`: `impl KeriSerialize for InceptionEvent<'_>` — implement generically (`impl<'a> KeriSerialize for InceptionEvent<'a>` if elision is rejected); `KeriDeserialize` impls STAY on `<'static>`-instantiated Self (`impl KeriDeserialize for InceptionEvent<'static>`) with bodies unchanged for now (they still return owned — Task 3 rewires).
  - `event_strategies.rs` builders return `<'static>` types.

- [ ] **Step 5: Full suite (both crates) + clippy + fmt; commit**

```bash
nix develop --command cargo nextest run -p cesr-rs -p keri-rs --all-features > /tmp/r6-t2.log 2>&1; echo "exit: $?"
nix develop --command cargo clippy -p cesr-rs --all-features --all-targets > /tmp/r6-t2c.log 2>&1; echo "exit: $?"
nix develop --command cargo fmt --check -p cesr-rs -p keri-rs > /tmp/r6-t2f.log 2>&1; echo "exit: $?"
git add -A && git commit -m "refactor(keri)!: event structs and KeriEvent gain a lifetime parameter (#129, #171)

Vec lists keep the events covariant (probe tests pin it); downstream still
constructs and consumes <'static> — the read path borrows next.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```
Confirm in the log: keripy corpora + oracle proptests green (zero wire bytes).

---

### Task 3: Read path returns borrowed events

**Files:**
- Modify: `cesr/src/serder/deserialize.rs` (entry fns, `build_*`, `parse_qb64_*`, `seal_from_parsed`)
- Modify: `cesr/src/serder/traits.rs` (`KeriDeserialize` impl bodies)
- Modify: `cesr/tests/serder_allocation.rs` (pin re-derive if changed)
- Test: new tests in `cesr/src/serder/deserialize.rs` `mod tests`

- [ ] **Step 1: Write the borrow-proof and into_static tests first** (deserialize.rs `mod tests`; the module has `use super::*` and builds events via `event_strategies`):

```rust
    /// The one genuine JSON-path borrow: an opaque seal's verbatim payload
    /// points into the input buffer, not a fresh allocation.
    #[test]
    fn parsed_opaque_seal_borrows_the_input_buffer() {
        let event = build_ixn((
            (true, [0; 32]),
            1,
            [1; 32],
            [2; 32],
            vec![(7, [3; 32], [4; 32], 0)], // selector 7 = Opaque (pool)
        ));
        let bytes = serialize_interaction(&event).unwrap();
        let parsed = deserialize_interaction(bytes.as_bytes()).unwrap();
        let [Seal::Opaque(opaque)] = parsed.anchors() else {
            panic!("expected exactly the one opaque anchor");
        };
        let payload = opaque.as_str();
        let raw = bytes.as_bytes();
        let raw_range = raw.as_ptr() as usize..raw.as_ptr() as usize + raw.len();
        assert!(
            raw_range.contains(&(payload.as_ptr() as usize)),
            "opaque payload must borrow from the input buffer"
        );
    }

    /// into_static detaches: the owned event outlives the buffer and
    /// re-serializes byte-identically.
    #[test]
    fn into_static_detaches_and_reserializes_identically() {
        let event = build_icp((
            (false, [0; 32]),
            0,
            [1; 32],
            vec![[2; 32]],
            (true, 1, vec![]),
            vec![[3; 32]],
            (true, 1, vec![]),
            vec![[4; 32]],
            1,
            vec![true],
            vec![(7, [5; 32], [6; 32], 0)],
        ));
        let bytes = serialize_inception(&event).unwrap();
        let detached = {
            let scoped = bytes.as_bytes().to_vec();
            deserialize_inception(&scoped).unwrap().into_static()
            // `scoped` drops here — `detached` must not borrow it, or this
            // does not compile. That compile is the assertion.
        };
        let again = serialize_inception(&detached).unwrap();
        assert_eq!(bytes.as_bytes(), again.as_bytes());
    }
```
(`Seal` needs importing into the test module if not glob-reachable; the compiler will say. `(7, …)` uses `SealSpec` selector 7 = Opaque per event_strategies.rs:99-109. If `Toad::exact(1, 1)` validation rejects the icp spec's `bt=1` with one witness — it accepts — keep as shown.)

- [ ] **Step 2: Verify they fail** (compile error: `into_static` exists but `deserialize_inception` returns `'static` so the borrow test's pointer assert FAILS — the opaque payload is owned today):

```bash
nix develop --command cargo nextest run -p cesr-rs --all-features -E 'test(parsed_opaque_seal_borrows) or test(into_static_detaches)' > /tmp/r6-t3-fail.log 2>&1; echo "exit: $?"
```
Expected: `parsed_opaque_seal_borrows_the_input_buffer` FAILS on the pointer-containment assert (payload currently `to_owned()`); the into_static test may already pass (that's fine — it pins behavior).

- [ ] **Step 3: Borrow the conversion layer.** In deserialize.rs:
  - `parse_qb64_prefixer/_identifier/_verfer/_diger/_saider/_verser` (lines ~453-513): add `<'a>`, take `s: &'a str`, return `…<'a>`, and DELETE every `.into_static()` call (the narrow result is returned directly; for `parse_qb64_identifier`, both arms drop `into_static`).
  - `verfers_from_parsed/prefixers_from_parsed/digers_from_parsed` (~403-425): `<'a>`, take `items: &[&'a str]`, return `Vec<…<'a>>`.
  - `seal_from_parsed` (~355-391): `<'a>`, take `seal: &ParsedSeal<'a>`, return `Seal<'a>`; the Opaque arm becomes:

```rust
        ParsedSeal::Opaque { raw } => Ok(Seal::Opaque(
            OpaqueSeal::new(*raw)
                .map_err(|source| SerderError::InvalidAnchor { offset: 0, source })?,
        )),
```
  (`*raw` is `&'a str`; `impl Into<Cow<'a, str>>` from Task 1 accepts it — the doc comment above the arm about defensive re-validation stays.)
  - `anchors_from_parsed` (~427-429): `<'a>` threading.
  - `build_inception/build_rotation/build_interaction/build_delegated_inception` (~194-255): `<'a>`, take `p: &ParsedIcp<'a>` etc., return `…Event<'a>`.
  - Entry fns (~57-171): `pub fn deserialize_event(raw: &[u8]) -> Result<KeriEvent<'_>, SerderError>` and the five typed fns likewise `…<'_>`. Bodies unchanged.
  - Module doc (deserialize.rs top): add one sentence — returned events borrow `raw`; qb64 decode still allocates per primitive (the borrow covers `soft` fields and opaque-seal payloads; see the rung-6 spec §1) — so nobody mistakes this for a JSON-path performance feature.

- [ ] **Step 4: Rewire `KeriDeserialize`** (traits.rs). Impl bodies gain `.map(…into_static…)`; the trait and its docs are unchanged (spec §3.2 decision — trait stays owned-returning, borrowed forms via the free fns). Example (repeat the pattern for all six impls):

```rust
impl KeriDeserialize for InceptionEvent<'static> {
    fn deserialize(raw: &[u8]) -> Result<Self, SerderError> {
        crate::serder::deserialize::deserialize_inception(raw).map(InceptionEvent::into_static)
    }
}
```
(`KeriEvent` impl maps `KeriEvent::into_static`.) Add a doc line to the trait: "Implemented for the `'static` event instantiations; parsing borrows internally and detaches via `into_static` (near-free — decoded payloads are already owned). To keep the borrow, use the free `deserialize_*` fns."

- [ ] **Step 5: Run the new tests (now pass), the allocation pin, and the full suite**

```bash
nix develop --command cargo nextest run -p cesr-rs --all-features -E 'test(parsed_opaque_seal_borrows) or test(into_static_detaches)' > /tmp/r6-t3-pass.log 2>&1; echo "exit: $?"
nix develop --command cargo nextest run -p cesr-rs --features serder --test serder_allocation > /tmp/r6-t3-alloc.log 2>&1; echo "exit: $?"
```
If `deserialize_allocation_count_is_pinned` (35) fails: read the actual — the opaque-borrow and dropped `into_static` may LOWER it (fixture has no opaque seal, and `into_static` was already ~free, so expect unchanged; the icp fixture's `Identifier` double-parse is untouched). Re-derive per the test's own doc ("re-derive deliberately"): update the const AND its doc comment with the new derivation. Never bump blindly; if it RISES, STOP — that's a regression, report BLOCKED.

```bash
nix develop --command cargo nextest run -p cesr-rs -p keri-rs --all-features > /tmp/r6-t3.log 2>&1; echo "exit: $?"
nix develop --command cargo clippy -p cesr-rs --all-features --all-targets > /tmp/r6-t3c.log 2>&1; echo "exit: $?"
nix develop --command cargo fmt --check -p cesr-rs > /tmp/r6-t3f.log 2>&1; echo "exit: $?"
```
Corpora + oracle + `*_strict_equals_reference` must be green (byte identity). Note: keri-rs still compiles because its call sites hold the returned events in local scopes where `'a` unifies with `'static` usage — if any keri-rs test breaks on lifetimes here, pin it locally with `into_static()` and leave a `// relaxed in the next commit` note.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(serder)!: deserialize_* return events borrowing the input (#129, #171)

The build layer drops into_static; Matter soft fields and opaque-seal
payloads borrow the buffer (the only JSON-path borrows — decode still
allocates, stated in the module doc). KeriDeserialize stays owned-returning
via near-free into_static.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: keri-rs relaxation + bundled Toad/sn cleanup

**Files:**
- Modify: `keri/src/state.rs`, `keri/src/authority.rs` (+ any keri/src file the compiler flags)
- Tests: `keri/tests/differential.rs` must stay green untouched

- [ ] **Step 1: Relax the `'static` pins.** In state.rs/authority.rs every `…<'static>` inside a `&'e`/field position becomes `<'e>` (covariance lets callers pass longer-lived events/slices):
  - `Signed<'e>`: `pub event: &'e KeriEvent<'e>` (callers' `&KeriEvent<'static>` coerce).
  - `KeyState<'e>` fields: `latest_said: &'e Saider<'e>`, `keys: &'e [Verfer<'e>]`, `next_keys: &'e [Diger<'e>]`, `witnesses: Cow<'e, [Prefixer<'e>]>`, `delegator: Option<&'e Prefixer<'e>>`, and the `prefix`/`said` fields likewise. Accessor return types follow.
  - Method params: `seed(icp: &'e InceptionEvent<'e>, …)`, `rotate(rot: &'e RotationEvent<'e>, …)`, `interact(ixn: &'e InteractionEvent<'e>, …)`, `rotated(…, witnesses: Vec<Prefixer<'e>>)`, `check_chains_onto(…, prior_said: &Saider<'_>)` — follow the compiler; the bodies are unchanged.
  - `Authority<'e>`: `keys: &'e [Verfer<'e>]`, `new(keys: &'e [Verfer<'e>], …)`; `Commitment<'e>`: `next_digests: &'e [Diger<'e>]`.

- [ ] **Step 2: Bundled cleanup A — `witness_threshold: u32` → `Toad`** (state.rs:89,144-145,207,226,271,289):

```rust
    // field:
    witness_threshold: Toad,

    // accessor (doc: "Witness agreement threshold."):
    #[must_use]
    pub const fn witness_threshold(&self) -> Toad {
        self.witness_threshold
    }
```
Construction sites store the event's `Toad` directly: `witness_threshold: icp.witness_threshold()` (seed, :226) and `witness_threshold: rot.witness_threshold()` (rotated, :289). The `check_witness_threshold(…, icp.witness_threshold().value())` call sites (:207/:271) are unchanged (they already pass `.value()`). `use cesr::keri::Toad;` joins the existing cesr::keri import list. Any keri-rs caller of `state.witness_threshold()` gains `.value()` if it needs the number — the compiler lists them.

- [ ] **Step 3: Bundled cleanup B — `sn()` by-value** (state.rs:104):

```rust
    /// Sequence number of the latest event.
    #[must_use]
    pub const fn sn(&self) -> SequenceNumber {
        self.sn
    }
```
Call sites doing `state.sn().value()` keep compiling (method on value); any `&state.sn()` patterns the compiler flags lose the `&`.

- [ ] **Step 4: Full suite (fold differentials are the proof), clippy, fmt; commit**

```bash
nix develop --command cargo nextest run -p keri-rs --all-features > /tmp/r6-t4.log 2>&1; echo "exit: $?"
nix develop --command cargo nextest run -p cesr-rs --all-features > /tmp/r6-t4b.log 2>&1; echo "exit: $?"
nix develop --command cargo clippy -p keri-rs --all-features --all-targets > /tmp/r6-t4c.log 2>&1; echo "exit: $?"
nix develop --command cargo fmt --check -p keri-rs > /tmp/r6-t4f.log 2>&1; echo "exit: $?"
git add -A && git commit -m "refactor(keri-rs)!: fold consumes borrowed events; Toad + by-value sn (#129, #171)

KeyState/Signed/Authority/Commitment drop the <'static> pins (covariant
events coerce); bundled vocabulary cleanup pending since rungs 1-2:
witness_threshold is a Toad, sn() returns by value.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```
Escalation rule (spec §3.4): if any single-lifetime signature refuses to compile, add a second lifetime ONLY at that site, with a `// two lifetimes: <compiler reason>` comment, and list it in the report/PR.

---

### Task 5: CHANGELOG, gate, PR

**Files:**
- Modify: `cesr/CHANGELOG.md`, `keri/CHANGELOG.md` (check it exists; if not, cesr's only)

- [ ] **Step 1: CHANGELOG entries.** Match existing style; content:

```markdown
### Breaking (rung 6 of #171 — zero-copy KeriEvent, closes #129)

- `InceptionEvent`, `RotationEvent`, `InteractionEvent`, `DelegatedInceptionEvent`,
  `DelegatedRotationEvent`, `KeriEvent`, `Seal`, and `OpaqueSeal` gain a lifetime
  parameter (`<'a>`); code naming them bare writes `<'static>` or `<'_>`. All gain
  `into_static()`. Events are covariant (compile-probed): Vec lists were chosen
  over #129's original `Cow` lists after a rustc variance probe showed `Cow`'s
  `ToOwned` projection makes the events invariant.
- `deserialize_event` / `deserialize_*` return events borrowing the input buffer;
  `KeriDeserialize` still returns owned events (near-free `into_static`). qb64
  decode still allocates — the borrow covers Matter `soft` fields and opaque-seal
  payloads; the payoff is a future qb2 reader (event shape is now ready).
- keri-rs: `KeyState`/`Signed`/`Authority`/`Commitment` signatures drop `'static`
  pins; `KeyState::witness_threshold()` returns `Toad` (was `u32`);
  `KeyState::sn()` returns `SequenceNumber` by value. No wire bytes changed.
```

- [ ] **Step 2: Commit, gate on committed state, push, PR**

```bash
git add -A && git commit -m "docs(changelog): rung 6 breaking changes (#129, #171)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
nohup bash -c 'nix flake check > /tmp/r6-flake.log 2>&1; echo "FLAKE EXIT: $?" >> /tmp/r6-flake.log' > /dev/null 2>&1 &
```
Watch for the `FLAKE EXIT` line (until-loop in background); expect 0. On failure: read the log, fix, commit, re-run. Then (gh account `joeldsouzax`):

```bash
git push -u origin 171-zero-copy-keri-event
gh pr create --title "feat(keri,serder)!: rung 6 — zero-copy KeriEvent<'a> (#129, #171)" --body "$(cat <<'EOF'
Rung 6 of #171 — the final numbered rung. Closes #129.

Spec: docs/superpowers/specs/2026-07-16-171-rung-6-zero-copy-keri-event-design.md (read the Amendment block); plan: docs/superpowers/plans/2026-07-16-171-rung-6-zero-copy-keri-event.md.

## Breaking
- Event types, `KeriEvent`, `Seal`, `OpaqueSeal` gain `<'a>` + `into_static()`; `deserialize_*` return borrowed events; keri-rs signatures drop `'static` pins; bundled cleanup: `KeyState::witness_threshold() -> Toad`, `sn()` by value.

## Deviation from #129 (compiler-verified)
#129 scoped `Cow<'a, [T]>` lists. A rustc variance probe showed `Cow`'s `ToOwned` projection makes the event types invariant in `'a` (no `&'e Event<'static>` → `&'e Event<'e>` coercion), which would force two-lifetime signatures onto `EventRef`/`Signed`. Vec lists keep the events covariant (pinned by per-type compile probes) and preserve the element-level qb2 zero-copy payoff in `Matter<'a>`. Whole-list borrowing at construction is the only capability given up; it had no caller.

## Honest framing
API shape, not performance: qb64 decode still allocates (Matter raw is owned by construction). Today's borrows: Matter `soft` fields + opaque-seal payloads (pointer-containment test). The payoff is the future qb2/CESR-native reader card, which spawns after this merges.

## Not breaking
Zero wire bytes changed — keripy corpora, structural-oracle, and fixpoint suites green on every commit; `deserialize_allocation_count` pin re-derived, not bumped.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Post-merge follow-ups** (after human review + squash-merge, not before): epic #171 progress comment (all six rungs done — remaining: qb2 reader card, keri-rs escrow arc); spawn the qb2/CESR-native reader issue referencing spec §1; update the session memory.
