# Rung 5 — Single JSON Writer Implementation Plan (#171)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the buffer-direct JSON emitter the only writer, delete the `serde_json`-tree backend and its splice machinery, and demote `serde`/`serde_json` to dev-dependencies — with zero wire-byte change.

**Architecture:** The trait-based backend seam (`EventSerializer`/`SerdeJson`/`DirectJson`/`serialize_with`) collapses into an inherent `SerializationKind::render` dispatch (enum method, exhaustive match, fail-loud non-JSON arms) over a single `json::render` free fn. Orchestration (dummy-SAID → size-patch → digest → SAID-patch) is already backend-agnostic and survives as `serialize_event`. Coverage: the existing `*_strict_equals_reference` proptests already assert write→read→write fixpoint; a new serde_json structural oracle replaces the retired cross-backend differential.

**Tech Stack:** Rust 1.95 stable, thiserror, proptest, nix flake gate. Spec: `docs/superpowers/specs/2026-07-16-171-rung-5-single-json-writer-design.md`.

**Branch:** `171-single-json-writer` (already created off `origin/main` @ `4dd8828`).

**Fast dev loop** (per task): `nix develop --command cargo nextest run -p cesr-rs --all-features`
**Full gate** (end only, on COMMITTED state): `nix flake check` — never piped; redirect to a file and `echo $?`.

**Invariants that hold after every task:**
- All 1683+ tests green, including `keripy_parity` corpora (26-vector byte-identity) and `keri/tests/differential.rs`.
- Zero wire bytes change anywhere in this rung. Any corpus diff = STOP, real regression.
- Import style: all `use` at top of file (hooks enforce; test modules exempt but keep tidy).

---

### Task 1: Rename `SerKind` → `SerializationKind`

De-jargonizing rename matching rungs 1–4 (`Tholder`→`SigningThreshold`, `Seqner`→`SequenceNumber`). Sites: `version.rs` (14), `deserialize/reference.rs` (2), `deserialize/canonical.rs` (2). No behavior change.

**Files:**
- Modify: `cesr/src/serder/version.rs`
- Modify: `cesr/src/serder/deserialize/reference.rs`
- Modify: `cesr/src/serder/deserialize/canonical.rs`

- [ ] **Step 1: Mechanical rename**

```bash
cd /Users/joel/Code/devrandom/cesr
sd '\bSerKind\b' 'SerializationKind' cesr/src/serder/version.rs cesr/src/serder/deserialize/reference.rs cesr/src/serder/deserialize/canonical.rs
```

- [ ] **Step 2: Verify no site missed and none invented**

```bash
rg -n '\bSerKind\b' cesr keri --glob '!target' -g '*.rs'
```
Expected: no matches.

- [ ] **Step 3: Build + test**

```bash
nix develop --command cargo nextest run -p cesr-rs --all-features
```
Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "refactor(serder)!: rename SerKind to SerializationKind (#171)

De-abbreviation consistent with the rungs 1-4 naming arc. Public type
(reachable via cesr::serder::version) — breaking, called out in CHANGELOG
at the end of the rung.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: `UnsupportedSerializationKind` error + `SerializationKind::render` dispatch + `serialize_event`

New plumbing lands alongside the old (nothing deleted yet). The free `render` fn is extracted from `DirectJson::render`; the trait impl delegates to it so the cross-backend proptests keep guarding both paths until deletion.

**Files:**
- Modify: `cesr/src/serder/error.rs`
- Modify: `cesr/src/serder/serialize/direct.rs` (extract free fn)
- Modify: `cesr/src/serder/serialize.rs` (impl block + `serialize_event` + tests)

- [ ] **Step 1: Write the failing tests** (in `cesr/src/serder/serialize.rs` `mod tests`, after `event_ref_from_keri_event_preserves_variant`; `probe_icp_event`/`probe_ixn_event` already exist there)

```rust
#[test]
fn non_json_kinds_fail_loud_with_typed_error() {
    let ixn = probe_ixn_event();
    let placeholder = "#".repeat(44);
    for kind in [
        SerializationKind::Cbor,
        SerializationKind::Mgpk,
        SerializationKind::Cesr,
    ] {
        let mut buf = Vec::new();
        let result = kind.render(EventRef::Interaction(&ixn), &placeholder, &mut buf);
        let Err(SerderError::UnsupportedSerializationKind(k)) = result else {
            panic!("expected UnsupportedSerializationKind for {kind:?}");
        };
        assert_eq!(k, kind);
        assert!(buf.is_empty(), "unsupported kind must not write");
    }
}

// Temporary cross-check; deleted with the SerdeJson backend in Task 6.
#[test]
fn serialize_event_matches_reference_backend() {
    let icp = probe_icp_event();
    let via_new = serialize_event(EventRef::Inception(&icp)).unwrap();
    let via_ref = serialize_with(&SerdeJson, EventRef::Inception(&icp)).unwrap();
    assert_eq!(via_new.as_bytes(), via_ref.as_bytes());
    assert_eq!(
        to_qb64_string(via_new.said()),
        to_qb64_string(via_ref.said())
    );
}
```

- [ ] **Step 2: Run to verify they fail**

```bash
nix develop --command cargo nextest run -p cesr-rs --all-features -E 'test(non_json_kinds) or test(serialize_event_matches)'
```
Expected: FAIL to compile (`render`/`serialize_event`/`UnsupportedSerializationKind` not defined) — that is the failing state for a compile-time-checked language.

- [ ] **Step 3: Add the error variant** (`cesr/src/serder/error.rs`)

Add to the top-of-file imports:

```rust
use crate::serder::version::SerializationKind;
```

Add the variant after `InvalidVersionString` (keep `Json` — it dies in Task 6):

```rust
    /// A serialization kind with no body codec. Only JSON events can be
    /// written today; the strict reader enforces the same limit on the
    /// read path (non-JSON version strings are rejected), so this is the
    /// write-path half of one invariant.
    #[error("no body codec for serialization kind {}", .0.as_str())]
    UnsupportedSerializationKind(SerializationKind),
```

- [ ] **Step 4: Extract the free render fn** (`cesr/src/serder/serialize/direct.rs`)

Move the body of `DirectJson::render` (the `match event { ... }` at direct.rs:44-61) into a free fn directly below the trait impl, and make the trait impl delegate:

```rust
impl EventSerializer for DirectJson {
    fn render(
        &self,
        event: EventRef<'_>,
        said_placeholder: &str,
        buf: &mut Vec<u8>,
    ) -> Result<EventLayout, SerderError> {
        render(event, said_placeholder, buf)
    }
}

/// Render one event's canonical JSON body into `buf` (appending),
/// reporting the backpatchable slot layout. Slots are recorded by
/// construction as the writer emits them — never by re-scanning.
pub(crate) fn render(
    event: EventRef<'_>,
    said_placeholder: &str,
    buf: &mut Vec<u8>,
) -> Result<EventLayout, SerderError> {
    match event {
        EventRef::Inception(e) => render_icp(buf, e, said_placeholder, "icp", None),
        EventRef::Rotation(e) => render_rot(buf, e, said_placeholder, "rot"),
        EventRef::Interaction(e) => render_ixn(buf, e, said_placeholder),
        EventRef::DelegatedInception(e) => {
            let delegator = identifier_to_qb64_string(e.delegator());
            render_icp(buf, e.inception(), said_placeholder, "dip", Some(&delegator))
        }
        EventRef::DelegatedRotation(e) => render_rot(buf, e.rotation(), said_placeholder, "drt"),
    }
}
```

- [ ] **Step 5: Add the dispatch + orchestration** (`cesr/src/serder/serialize.rs`)

Extend the version import at the top of the file:

```rust
use crate::serder::version::{SerializationKind, VERSION_SIZE_MAX};
```

Insert after the `SerdeJson` impl (before `serialize_with`):

```rust
impl SerializationKind {
    /// Render `event`'s body in this serialization kind into `buf`
    /// (appending), reporting the backpatchable slot layout.
    ///
    /// The inherent impl lives here — not in `version.rs` — so the version
    /// module stays free of event/render knowledge; the enum is the domain
    /// type, rendering is serialize-module behavior.
    ///
    /// # Errors
    ///
    /// Returns [`SerderError::UnsupportedSerializationKind`] for kinds with
    /// no body codec (everything but JSON today — mirroring the strict
    /// reader, which rejects non-JSON version strings), or any render error.
    pub(crate) fn render(
        self,
        event: EventRef<'_>,
        said_placeholder: &str,
        buf: &mut Vec<u8>,
    ) -> Result<EventLayout, SerderError> {
        match self {
            Self::Json => direct::render(event, said_placeholder, buf),
            Self::Cbor | Self::Mgpk | Self::Cesr => {
                Err(SerderError::UnsupportedSerializationKind(self))
            }
        }
    }
}

/// Serialize an event through the single canonical writer: render once with
/// a placeholder SAID and zero-size version string, backpatch the measured
/// size in place, compute the SAID over the size-corrected bytes, and
/// splice it into the reported slot(s).
///
/// The SAID digest algorithm is the event's own ([`EventRef::said_code`]) —
/// not a hardcoded Blake3-256 — so parsed events re-serialize under their
/// original code and builders can select any [`DigestCode`].
///
/// # Errors
///
/// Returns [`SerderError`] if rendering fails or the event exceeds the
/// version string's size capacity.
pub(crate) fn serialize_event(event: EventRef<'_>) -> Result<SerializedEvent, SerderError> {
    let digest_code = event.said_code();
    let placeholder = said_placeholder(digest_code)?;

    let mut buf = Vec::new();
    let layout = SerializationKind::Json.render(event, &placeholder, &mut buf)?;

    let size = buf.len();
    let size_u32 = u32::try_from(size)
        .ok()
        .filter(|s| *s <= VERSION_SIZE_MAX)
        .ok_or(SerderError::VersionStringOverflow {
            field: "size",
            max: VERSION_SIZE_MAX,
        })?;
    patch_slot(
        &mut buf,
        &layout.size_slot,
        format!("{size_u32:06x}").as_bytes(),
    )?;

    let said = compute_digest(&buf, digest_code)?;
    let said_qb64 = to_qb64_string(&said);
    patch_slot(&mut buf, &layout.said_slot, said_qb64.as_bytes())?;

    let prefix = layout
        .prefix_slot
        .as_ref()
        .map(|slot| {
            patch_slot(&mut buf, slot, said_qb64.as_bytes())?;
            Ok::<_, SerderError>(said.clone())
        })
        .transpose()?;

    Ok(SerializedEvent {
        raw: buf,
        said,
        prefix,
        ilk: event.ilk(),
        size,
        event: (),
    })
}
```

- [ ] **Step 6: Run the new tests + full suite**

```bash
nix develop --command cargo nextest run -p cesr-rs --all-features
```
Expected: PASS, including the two new tests.

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat(serder): SerializationKind::render dispatch + serialize_event orchestration (#171)

Kind dispatch as an inherent enum method (closed set, exhaustive match,
fail-loud UnsupportedSerializationKind for CBOR/MGPK/CESR — mirroring the
strict reader). Old trait seam untouched; flip lands next.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: THE FLIP — the five entry fns render through the direct writer

After this commit, all production writes go through `json::render`. The cross-backend proptests (still alive) plus the 26-vector keripy corpora prove the swap is byte-invisible.

**Files:**
- Modify: `cesr/src/serder/serialize/icp.rs:12-15,34-36`
- Modify: `cesr/src/serder/serialize/rot.rs` (same pattern)
- Modify: `cesr/src/serder/serialize/ixn.rs` (same pattern)
- Modify: `cesr/src/serder/serialize/dip.rs` (same pattern)
- Modify: `cesr/src/serder/serialize/drt.rs` (same pattern)

- [ ] **Step 1: Repoint each entry fn.** In `icp.rs`, the `super` import block (lines 12-15) becomes:

```rust
use super::{
    AnchorJson, EventBody, EventRef, SerializedEvent, matters_to_json_array, seal_to_json,
    serialize_event, tholder_to_json, toad_json,
};
```

and the entry fn body (line 35) becomes:

```rust
pub fn serialize_inception(event: &InceptionEvent) -> Result<SerializedEvent, SerderError> {
    serialize_event(EventRef::Inception(event))
}
```

Apply the identical two-line change in the other four files — drop `SerdeJson`/`serialize_with` from the `super` import, add `serialize_event`, and swap the call:

| File | Entry fn body becomes |
|---|---|
| `rot.rs` | `serialize_event(EventRef::Rotation(event))` |
| `ixn.rs` | `serialize_event(EventRef::Interaction(event))` |
| `dip.rs` | `serialize_event(EventRef::DelegatedInception(event))` |
| `drt.rs` | `serialize_event(EventRef::DelegatedRotation(event))` |

(`render_json`/`build_*_json` and their imports stay for now — the `SerdeJson` trait impl still calls them; they die in Task 6.)

- [ ] **Step 2: Full suite — this is the flip's proof**

```bash
nix develop --command cargo nextest run -p cesr-rs --all-features
nix develop --command cargo nextest run -p keri-rs --all-features
```
Expected: ALL green — specifically `keripy_parity::events` (26 vectors, byte-identical), the five `*_backends_byte_identical` proptests, the five `*_strict_equals_reference` proptests, and `keri` fold differentials. Any corpus diff = STOP.

- [ ] **Step 3: Commit**

```bash
git add -A && git commit -m "refactor(serder): production write path renders through the direct writer (#171)

Byte-invisible by proof: cross-backend proptests and the 26-vector keripy
byte-identity corpora are green across the flip.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: Structural-oracle proptests

The independent content check that replaces the cross-backend differential's role: parse the writer's output with `serde_json` (an implementation sharing zero code with the writer) and compare against a `Value` tree built independently in test code from the domain fields. Catches classes the old differential was blind to (both backends shared `weight_to_string`). Byte-level canonical form (field order, framing) is covered by the fixpoint assertions in `*_strict_equals_reference` (deserialize.rs:1695 etc.) and the corpora.

The strategies emit `ThresholdForm::HexString` only, so the oracle encodes hex form; integer-form (`intive`) rendering is pinned by the rung-3 tests and the corpora.

**Files:**
- Modify: `cesr/src/serder/serialize/direct.rs` (test module; the file moves to `json.rs` in Task 7 and these tests move with it)

- [ ] **Step 1: Add oracle helpers to `mod tests`** (after the existing `weighted` helper). Add these imports to the test module's import block:

```rust
    use crate::serder::primitives::identifier_to_qb64_string;
    use crate::serder::serialize::{
        SerializedEvent, serialize_delegated_inception, serialize_delegated_rotation,
        serialize_inception, serialize_interaction, serialize_rotation,
    };
    use serde_json::{Value, json};
```

Then the helpers:

```rust
    // ------------------------------------------------------------------
    // Structural oracle: an INDEPENDENT rendering of each event as a
    // serde_json::Value tree, built from domain fields in test code. The
    // writer's output must parse (via serde_json — no shared code with the
    // writer) to exactly this tree. `fraction` deliberately re-states the
    // weight-rendering rule rather than calling `weight_to_string`; that
    // duplication IS the oracle. Byte-level canonical form (field order,
    // framing) is asserted by the fixpoint tests and keripy corpora, which
    // Value equality cannot see.
    // ------------------------------------------------------------------

    fn fraction(num: u64, den: u64) -> String {
        if den != 0 && (num == 0 || num == den) {
            format!("{}", num / den)
        } else {
            format!("{num}/{den}")
        }
    }

    fn hex_tholder(t: &SigningThreshold) -> Value {
        match t {
            SigningThreshold::Simple(n) => Value::String(format!("{n:x}")),
            SigningThreshold::Weighted(w) => {
                let clauses: Vec<Value> = w
                    .clauses()
                    .map(|clause| {
                        Value::Array(
                            clause
                                .iter()
                                .map(|(n, d)| Value::String(fraction(*n, *d)))
                                .collect(),
                        )
                    })
                    .collect();
                match <[Value; 1]>::try_from(clauses) {
                    Ok([single]) => single,
                    Err(clauses) => Value::Array(clauses),
                }
            }
        }
    }

    fn qb64_values<C: CesrCode>(matters: &[Matter<'_, C>]) -> Value {
        Value::Array(
            matters
                .iter()
                .map(|m| Value::String(to_qb64_string(m)))
                .collect(),
        )
    }

    fn seal_value(seal: &Seal) -> Value {
        match seal {
            Seal::Digest { d } => json!({"d": to_qb64_string(d)}),
            Seal::Root { rd } => json!({"rd": to_qb64_string(rd)}),
            Seal::Source { s, d } => json!({"s": s.to_string(), "d": to_qb64_string(d)}),
            Seal::Event { i, s, d } => {
                json!({"i": to_qb64_string(i), "s": s.to_string(), "d": to_qb64_string(d)})
            }
            Seal::Last { i } => json!({"i": to_qb64_string(i)}),
            Seal::Back { bi, d } => json!({"bi": to_qb64_string(bi), "d": to_qb64_string(d)}),
            Seal::Kind { t, d } => json!({"t": to_qb64_string(t), "d": to_qb64_string(d)}),
            Seal::Opaque(raw) => serde_json::from_str(raw.as_str())
                .expect("OpaqueSeal payloads are valid JSON by construction"),
        }
    }

    fn seal_values(seals: &[Seal]) -> Value {
        Value::Array(seals.iter().map(seal_value).collect())
    }

    // `v`, `d`, and (for double-SAID events) `i` are backpatched by the
    // orchestration, so they are taken from the output rather than the
    // event; the circularity is closed by the dedicated size assertion in
    // each proptest and SAID verification in the fixpoint tests.
    fn expected_icp_tree(e: &InceptionEvent, out: &SerializedEvent, ilk: &str) -> Value {
        let prefix = match e.prefix() {
            Identifier::SelfAddressing(_) => to_qb64_string(out.said()),
            Identifier::Basic(p) => to_qb64_string(p),
        };
        json!({
            "v": format!("KERI10JSON{:06x}_", out.size()),
            "t": ilk,
            "d": to_qb64_string(out.said()),
            "i": prefix,
            "s": e.sn().to_string(),
            "kt": hex_tholder(e.threshold()),
            "k": qb64_values(e.keys()),
            "nt": hex_tholder(e.next_threshold()),
            "n": qb64_values(e.next_keys()),
            "bt": format!("{:x}", e.witness_threshold().value()),
            "b": qb64_values(e.witnesses()),
            "c": Value::Array(
                e.config().iter().map(|c| Value::String(c.code().to_owned())).collect()
            ),
            "a": seal_values(e.anchors()),
        })
    }

    fn expected_rot_tree(e: &RotationEvent, out: &SerializedEvent, ilk: &str) -> Value {
        json!({
            "v": format!("KERI10JSON{:06x}_", out.size()),
            "t": ilk,
            "d": to_qb64_string(out.said()),
            "i": identifier_to_qb64_string(e.prefix()),
            "s": e.sn().to_string(),
            "p": to_qb64_string(e.prior_event_said()),
            "kt": hex_tholder(e.threshold()),
            "k": qb64_values(e.keys()),
            "nt": hex_tholder(e.next_threshold()),
            "n": qb64_values(e.next_keys()),
            "bt": format!("{:x}", e.witness_threshold().value()),
            "br": qb64_values(e.witness_removals()),
            "ba": qb64_values(e.witness_additions()),
            "a": seal_values(e.anchors()),
        })
    }
```

- [ ] **Step 2: Add the five oracle proptests** (inside the existing `proptest! { #![proptest_config(ProptestConfig::with_cases(64))] ... }` block):

```rust
        #[test]
        fn icp_output_matches_independent_tree(spec in icp_strategy()) {
            let event = build_icp(spec);
            let out = serialize_inception(&event).unwrap();
            prop_assert_eq!(out.size(), out.as_bytes().len());
            let got: Value = serde_json::from_slice(out.as_bytes()).unwrap();
            prop_assert_eq!(got, expected_icp_tree(&event, &out, "icp"));
        }

        #[test]
        fn rot_output_matches_independent_tree(spec in rot_strategy()) {
            let event = build_rot(spec);
            let out = serialize_rotation(&event).unwrap();
            prop_assert_eq!(out.size(), out.as_bytes().len());
            let got: Value = serde_json::from_slice(out.as_bytes()).unwrap();
            prop_assert_eq!(got, expected_rot_tree(&event, &out, "rot"));
        }

        #[test]
        fn ixn_output_matches_independent_tree(spec in ixn_strategy()) {
            let event = build_ixn(spec);
            let out = serialize_interaction(&event).unwrap();
            prop_assert_eq!(out.size(), out.as_bytes().len());
            let got: Value = serde_json::from_slice(out.as_bytes()).unwrap();
            let expected = json!({
                "v": format!("KERI10JSON{:06x}_", out.size()),
                "t": "ixn",
                "d": to_qb64_string(out.said()),
                "i": identifier_to_qb64_string(event.prefix()),
                "s": event.sn().to_string(),
                "p": to_qb64_string(event.prior_event_said()),
                "a": seal_values(event.anchors()),
            });
            prop_assert_eq!(got, expected);
        }

        #[test]
        fn dip_output_matches_independent_tree(
            spec in icp_strategy(),
            delegator in any::<IdSpec>(),
        ) {
            let dip = DelegatedInceptionEvent::new(build_icp(spec), build_identifier(delegator));
            let out = serialize_delegated_inception(&dip).unwrap();
            prop_assert_eq!(out.size(), out.as_bytes().len());
            let got: Value = serde_json::from_slice(out.as_bytes()).unwrap();
            let mut expected = expected_icp_tree(dip.inception(), &out, "dip");
            expected.as_object_mut().unwrap().insert(
                "di".to_owned(),
                Value::String(identifier_to_qb64_string(dip.delegator())),
            );
            prop_assert_eq!(got, expected);
        }

        #[test]
        fn drt_output_matches_independent_tree(spec in rot_strategy()) {
            let drt = DelegatedRotationEvent::new(build_rot(spec));
            let out = serialize_delegated_rotation(&drt).unwrap();
            prop_assert_eq!(out.size(), out.as_bytes().len());
            let got: Value = serde_json::from_slice(out.as_bytes()).unwrap();
            prop_assert_eq!(got, expected_rot_tree(drt.rotation(), &out, "drt"));
        }
```

- [ ] **Step 3: Prove the oracle can fail.** Temporarily change `"kt"` to `"kt_broken"` in `expected_icp_tree`, run:

```bash
nix develop --command cargo nextest run -p cesr-rs --all-features -E 'test(icp_output_matches)'
```
Expected: FAIL with a Value mismatch. Revert the sabotage, re-run, expected: PASS.

- [ ] **Step 4: Full suite green, then commit**

```bash
nix develop --command cargo nextest run -p cesr-rs --all-features
git add -A && git commit -m "test(serder): structural-oracle proptests over the builder-reachable event space (#171)

Independent serde_json Value-tree comparison per ilk — content coverage
that survives the cross-backend differential's retirement; catches
shared-helper bugs the two-backend comparison was blind to.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: Repoint every consumer off `SerdeJson`/`serialize_with`/`DirectJson`

After this task the deleted symbols have no callers outside `serialize.rs`/`direct.rs` themselves, so Task 6 compiles under `--all-targets`.

**Files:**
- Modify: `cesr/src/serder/deserialize.rs:1656,1689,1702,1714,1728,1741,1760`
- Modify: `cesr/benches/serder.rs`
- Modify: `cesr/tests/serder_allocation.rs`

- [ ] **Step 1: deserialize.rs test repoint.** Replace the import at line 1656:

```rust
        use crate::serder::serialize::{EventRef, SerdeJson, serialize_with};
```
with nothing (delete it — `serialize_inception` etc. are already in scope in this test module; verify with the compiler in step 4). Replace the six call sites:

| Line | Old | New |
|---|---|---|
| 1689 | `serialize_with(&SerdeJson, EventRef::Inception(&event)).unwrap()` | `serialize_inception(&event).unwrap()` |
| 1702 | `serialize_with(&SerdeJson, EventRef::Rotation(&event)).unwrap()` | `serialize_rotation(&event).unwrap()` |
| 1714 | `serialize_with(&SerdeJson, EventRef::Interaction(&event)).unwrap()` | `serialize_interaction(&event).unwrap()` |
| 1728 | `serialize_with(&SerdeJson, EventRef::DelegatedInception(&dip)).unwrap()` | `serialize_delegated_inception(&dip).unwrap()` |
| 1741 | `serialize_with(&SerdeJson, EventRef::DelegatedRotation(&drt)).unwrap()` | `serialize_delegated_rotation(&drt).unwrap()` |
| 1760 | `serialize_with(&SerdeJson, EventRef::Interaction(&event)).unwrap()` | `serialize_interaction(&event).unwrap()` |

If any of the five serialize fns is not yet in scope, add the needed names to the existing `use crate::serder::serialize::{...}` import in the enclosing test module rather than a new inline import.

- [ ] **Step 2: Bench rework** (`cesr/benches/serder.rs`). Keep the CodSpeed series names `icp_direct`/`ixn16_direct` (continuity); the `*_serde_json` series end — call that out in the PR. Header doc comment (lines 1-7) becomes:

```rust
//! Event-serialization benchmarks.
//!
//! Measures the production entry points (`serialize_inception` /
//! `serialize_interaction`) over the single direct JSON writer, plus the
//! strict-reader deserialize path. Fixtures are deterministic (fixed raw
//! bytes) for stable `CodSpeed` input.
```

Import line 27 becomes:

```rust
use cesr::serder::{deserialize_event, serialize_inception, serialize_interaction};
```

`bench_serialize` (lines 99-117) becomes:

```rust
fn bench_serialize(c: &mut Criterion) {
    let icp = fixture_icp();
    let ixn = fixture_ixn();

    let mut group = c.benchmark_group("serder_serialize");
    group.bench_function("icp_direct", |b| {
        b.iter(|| serialize_inception(black_box(&icp)));
    });
    group.bench_function("ixn16_direct", |b| {
        b.iter(|| serialize_interaction(black_box(&ixn)));
    });
    group.finish();
}
```

In `bench_deserialize` (line 121), the setup becomes:

```rust
    let Ok(serialized) = serialize_inception(&icp) else {
        unreachable!("fixture_icp always serializes")
    };
```

- [ ] **Step 3: Allocation test rework** (`cesr/tests/serder_allocation.rs`). Import line 29 becomes:

```rust
use cesr::serder::{deserialize_event, serialize_inception};
```

Replace `direct_backend_allocates_strictly_less_than_serde_json` (lines 109-133) with a pinned absolute count, mirroring `deserialize_allocation_count_is_pinned`:

```rust
/// Exact allocation count for serializing `fixture_icp` through the single
/// direct writer: the output buffer's growth plus per-field qb64/hex string
/// materialization. Deterministic for a fixed fixture; a change means the
/// write path's allocation shape changed — re-derive deliberately, don't
/// just bump the number.
const SERIALIZE_ALLOCS: usize = 0; // placeholder — pinned in the next step

#[test]
fn serialize_allocation_count_is_pinned() {
    let event = fixture_icp();

    // Warm once so lazy one-time setup does not skew the delta.
    let _ = serialize_inception(&event).unwrap();

    let (out, allocs) = measure(|| serialize_inception(&event).unwrap());
    drop(out);

    assert_eq!(
        allocs, SERIALIZE_ALLOCS,
        "serialize_inception allocation count changed — the direct writer \
         must stay at buffer growth plus per-field string materialization; \
         a rise means an intermediate tree or render crept back in"
    );
}
```

And in `deserialize_allocation_count_is_pinned` (line 151), the setup becomes:

```rust
    let serialized = serialize_inception(&event).expect("fixture serializes");
```
(`DESERIALIZE_ALLOCS` stays 35 — same bytes, same read path.)

- [ ] **Step 4: Pin the real count.** Run the test, read the actual from the failure message, set `SERIALIZE_ALLOCS` to it (and delete the `// placeholder` comment), re-run green:

```bash
nix develop --command cargo nextest run -p cesr-rs --test serder_allocation
```

- [ ] **Step 5: Verify no external caller remains, then full suite + commit**

```bash
rg -n 'SerdeJson|DirectJson|serialize_with\b|EventSerializer' cesr keri fuzz fuzz-afl fuzz-common --glob '!target' -g '*.rs' -l
```
Expected: only `cesr/src/serder/serialize.rs` and `cesr/src/serder/serialize/direct.rs`.

```bash
nix develop --command cargo nextest run -p cesr-rs --all-features
nix develop --command cargo check -p cesr-rs --all-features --benches --tests
git add -A && git commit -m "test(serder): repoint benches, allocation pin, and read-path tests to the single writer (#171)

Comparative allocation test becomes a pinned absolute count (the serde_json
baseline is about to be deleted). CodSpeed series icp_direct/ixn16_direct
continue; the *_serde_json series end.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---### Task 6: THE DELETION — tree writer, trait seam, splice search, `Json` error variant

Everything the spec's §3 table lists. `patch_slot` STAYS (backend-agnostic orchestration). `weight_to_string` moves into `direct.rs`.

**Files:**
- Modify: `cesr/src/serder/serialize.rs` (bulk deletion + test replacement)
- Modify: `cesr/src/serder/serialize/direct.rs` (receives `weight_to_string`; test adaptations)
- Modify: `cesr/src/serder/serialize/{icp,rot,ixn,dip,drt}.rs` (tree render paths)
- Modify: `cesr/src/serder/error.rs` (`Json` variant → `#[cfg(test)] ReferenceJson`)
- Modify: `cesr/src/serder/mod.rs:47-51` (re-exports)

- [ ] **Step 1: error.rs — replace the `Json` variant.** The production `Json(#[from] serde_json::Error)` variant's only production producers die in this task, but the `#[cfg(test)]` tolerant reference oracle (`deserialize/reference.rs`) still `?`-propagates `serde_json::Error` (reference.rs:42,67,632 among others). Per the crate's "test-only escape hatches are `#[cfg(test)]`" rule, replace the variant in place:

```rust
    /// JSON parse/render failure inside the test-only tolerant reference
    /// oracle (`deserialize::reference`). Test builds only — production
    /// code has no `serde_json` dependency.
    #[cfg(test)]
    #[error("reference-oracle JSON error: {0}")]
    ReferenceJson(#[from] serde_json::Error),
```

The `#[from]` keeps every `?` site in `reference.rs` compiling unchanged. (Verify thiserror propagates the `#[cfg(test)]` to the generated `From` impl: step 8's plain `cargo build` compiles without `cfg(test)`, so a leak fails there. Fallback if it does not propagate: drop `#[from]` from the variant and write a `#[cfg(test)] impl From<serde_json::Error> for SerderError` manually next to the enum.) Grep for stragglers that name the old variant:

```bash
rg -n 'SerderError::Json\b' cesr keri --glob '!target' -g '*.rs'
```
Expected: no matches (the two doc-comment references at serialize.rs:516 die with `seal_to_json` below).

- [ ] **Step 2: serialize.rs production deletions.** Delete, in order (line numbers are pre-deletion anchors):
  - `use serde::ser::SerializeMap;`, `use serde::{Serialize, Serializer};`, `use serde_json::value::RawValue;`, `use serde_json::{Map, Value};` (lines 34-37)
  - `pub use direct::DirectJson;` (line 45)
  - `trait EventSerializer` + its doc (165-187) — fold the load-bearing contract sentence ("must carry a zero-size version string and `said_placeholder` in every SAID slot; every render must be byte-identical for the same event") into `SerializationKind::render`'s doc
  - `struct SerdeJson` + `impl EventSerializer for SerdeJson` (189-210)
  - `fn serialize_with` + doc (212-275)
  - `ZERO_SIZE_VSTRING`/`VSTRING_OFFSET`/`SIZE_OFFSET_IN_VSTRING`/`SIZE_WIDTH` consts (277-284)
  - `fn extend_with_layout` (286-343)
  - `fn abs_range` (345-354)
  - `fn find_subslice` (356-363)
  - `enum AnchorJson` + impl (458-475), `struct EventBody` + impl (477-507), `fn seal_to_json` (509-558), `fn tholder_to_json` (560-603), `fn toad_json` (605-614), `fn matters_to_json_array` (629-638)
  - `fn weight_to_string` (616-627) — MOVE to `direct.rs` (next step), do not delete outright
  - Demote `EventLayout` (line 156): `pub struct EventLayout` → `pub(crate) struct EventLayout`; keep its `pub` fields; update its doc line 153-154 to say "when the writer's `render` returns" instead of naming `EventSerializer::render`.

- [ ] **Step 3: Move `weight_to_string` into `direct.rs`** (below `write_toad`), unchanged except visibility (only `write_weight_clause` uses it now):

```rust
/// Render one weight fraction the way keripy's `Tholder.sith` does: whole
/// values collapse to their integer string (`0`, `1`), everything else stays
/// `num/den`. A zero denominator is malformed (rejected by both
/// `SigningThreshold::check_well_formed` and the deserializer) but must render as a
/// plain fraction rather than dividing by zero.
fn weight_to_string(num: u64, den: u64) -> String {
    if den != 0 && (num == 0 || num == den) {
        format!("{}", num / den)
    } else {
        format!("{num}/{den}")
    }
}
```

In `direct.rs` line 19, the import becomes:

```rust
use super::{EventLayout, EventRef};
```
and delete the (now former) `impl EventSerializer for DirectJson` block plus `pub struct DirectJson` and its doc (lines 28-63's struct + delegating impl from Task 2) — only the free `render` fn remains.

- [ ] **Step 4: Per-ilk file cleanup.** In each of `icp.rs`, `rot.rs`, `ixn.rs`, `dip.rs`, `drt.rs`:
  - Delete `render_json`, `build_*_json`, and (icp only) `prefix_json_value` + `struct IcpFields` (and each file's equivalent fields struct if present)
  - Delete `use serde_json::{Map, Value};` and shrink the `super` import to what remains: `use super::{EventRef, SerializedEvent, serialize_event};`
  - Delete `use crate::serder::version::VersionString;` where it was only used by `render_json`
  - Keep every entry fn and every test (tests use `serde_json::from_slice` — fine, `serde_json` stays as a dev-dependency)

- [ ] **Step 5: serialize.rs test replacements.**
  - Delete: `tholder_zero_denominator_renders_without_panicking` (646), `tholder_to_json_weighted_boundary_values` (854), `weight_to_string_exact_mapping` (868 — moves to direct.rs next step), the `HostileBackend` block + five `hostile_backend_*` tests (1003-1100), the `extend_with_layout` test block (1103-1169), `serde_json_render_into_prefilled_buffer_reports_absolute_slots` (1171-1199), and the Task-2 temporary `serialize_event_matches_reference_backend`
  - Keep: the opaque-scanner proptests (1202-1290; they test `OpaqueSeal` vs serde_json as dev-dep), `serialize_dispatches_*`, `event_ref_*`, `non_json_kinds_fail_loud_with_typed_error`
  - Add direct `patch_slot` unit tests (the SUT the hostile-backend tests were really exercising, now tested without a stub):

```rust
    // patch_slot — the backpatch safety boundary: any layout inconsistency
    // must surface as a typed error, never a panic or silent corruption.

    #[test]
    fn patch_slot_overwrites_exact_window() {
        let mut buf = b"aaaaaa".to_vec();
        patch_slot(&mut buf, &(2..4), b"XY").unwrap();
        assert_eq!(&buf, b"aaXYaa");
    }

    #[test]
    fn patch_slot_out_of_bounds_is_rejected() {
        let mut buf = vec![0u8; 4];
        let result = patch_slot(&mut buf, &(2..8), b"XXXXXX");
        assert!(matches!(
            result,
            Err(SerderError::InvalidEventLayout("slot out of bounds"))
        ));
    }

    #[test]
    fn patch_slot_reversed_range_is_rejected() {
        let mut buf = vec![0u8; 8];
        let result = patch_slot(&mut buf, &(6..2), b"");
        assert!(matches!(
            result,
            Err(SerderError::InvalidEventLayout("slot out of bounds"))
        ));
    }

    #[test]
    fn patch_slot_wrong_width_is_rejected() {
        let mut buf = vec![0u8; 8];
        let result = patch_slot(&mut buf, &(0..4), b"XX");
        assert!(matches!(
            result,
            Err(SerderError::InvalidEventLayout(
                "slot width does not match replacement"
            ))
        ));
    }
```

- [ ] **Step 6: direct.rs test adaptations.**
  - Test-module imports: drop `SerdeJson, serialize_with` from the `super::super` import; add `deserialize_event` alongside the existing `deserialize_inception`; drop unused `EventRef` if nothing references it after adaptation (compiler will say)
  - Delete `assert_backends_identical` (414) and the five `*_backends_byte_identical` proptests (433-464)
  - Adapt `empty_weighted_thresholds_are_byte_identical_across_backends` (500) into exact-string unit tests of the single writer (canonical location for the flatten/nest/empty invariants, replacing the deleted `tholder_to_json` tests):

```rust
    #[test]
    fn write_tholder_empty_weighted_shapes() {
        // Boundary shapes the strategies under-sample: an empty clause list
        // and a single empty clause both flatten to "[]"; two empty clauses
        // stay nested.
        for (kt, expected) in [
            (weighted(vec![]), "[]"),
            (weighted(vec![vec![]]), "[]"),
            (weighted(vec![vec![], vec![]]), "[[],[]]"),
        ] {
            let mut buf = Vec::new();
            write_tholder(&mut buf, &kt, ThresholdForm::HexString);
            assert_eq!(core::str::from_utf8(&buf).unwrap(), expected);
        }
    }

    #[test]
    fn write_tholder_zero_denominator_renders_without_panicking() {
        // Bug probe (ported from the deleted tholder_to_json test): a (0, 0)
        // weight previously hit `0 / 0` and panicked. Malformed weights must
        // render as a plain fraction; rejection happens at parse/validation.
        let tholder = weighted(vec![vec![(0, 0), (1, 0)]]);
        let mut buf = Vec::new();
        write_tholder(&mut buf, &tholder, ThresholdForm::HexString);
        assert_eq!(core::str::from_utf8(&buf).unwrap(), r#"["0/0","1/0"]"#);
    }

    #[test]
    fn write_tholder_single_clause_flattens_and_multi_nests() {
        let single = weighted(vec![vec![(1, 2), (1, 2)]]);
        let mut buf = Vec::new();
        write_tholder(&mut buf, &single, ThresholdForm::HexString);
        assert_eq!(core::str::from_utf8(&buf).unwrap(), r#"["1/2","1/2"]"#);

        let multi = weighted(vec![vec![(1, 2)], vec![(1, 1)]]);
        let mut buf = Vec::new();
        write_tholder(&mut buf, &multi, ThresholdForm::HexString);
        assert_eq!(core::str::from_utf8(&buf).unwrap(), r#"[["1/2"],["1"]]"#);
    }
```

  - Move `weight_to_string_exact_mapping` (from serialize.rs:868) here verbatim — it now tests a private fn of this module.
  - Adapt `direct_render_into_prefilled_buffer_reports_absolute_slots` (528): `DirectJson.render(...)` → `render(EventRef::Interaction(&event), &placeholder, &mut buf)` (free fn via `use super::*`).
  - Adapt `direct_output_verifies_through_unchanged_read_path` (544): `serialize_with(&DirectJson, EventRef::Inception(&event))` → `serialize_inception(&event)` (import already added in Task 4).
  - Adapt `back_kind_and_opaque_seals_byte_identical_and_verbatim` (569) — verbatim emission plus fixpoint through the strict reader replaces the backend comparison:

```rust
    #[test]
    fn back_kind_and_opaque_seals_render_verbatim_and_fixpoint() {
        use crate::core::matter::builder::MatterBuilder;
        use crate::core::matter::code::VerserCode;
        use crate::keri::OpaqueSeal;
        use crate::serder::traits::KeriSerialize;

        // The reviewer counterexample: a Value round-trip rewrites `1e2` as
        // `100.0` and the `é` escape as a raw `é` — the writer must emit the
        // validated payload untouched, and the strict reader must hand it
        // back byte-identical.
        let payload = "{\"x\":1e2,\"u\":\"\\u00e9\"}";
        let verser = MatterBuilder::new()
            .from_qualified_base64(b"YKERIBAA")
            .unwrap()
            .narrow::<VerserCode>()
            .unwrap()
            .into_static();
        let event = InteractionEvent::new(
            Identifier::Basic(prefixer([0; 32])),
            SequenceNumber::new(1),
            saider([1; 32]),
            saider([2; 32]),
            vec![
                Seal::Back {
                    bi: prefixer([3; 32]),
                    d: saider([4; 32]),
                },
                Seal::Kind {
                    t: verser,
                    d: saider([5; 32]),
                },
                Seal::Opaque(OpaqueSeal::new(payload.to_owned()).unwrap()),
            ],
        );
        let out = serialize_interaction(&event).unwrap();
        let text = core::str::from_utf8(out.as_bytes()).unwrap();
        assert!(
            text.contains(payload),
            "opaque payload must be emitted verbatim: {text}"
        );
        let parsed = deserialize_event(out.as_bytes()).unwrap();
        let again = parsed.serialize().unwrap();
        assert_eq!(out.as_bytes(), again.as_bytes());
    }
```

- [ ] **Step 7: mod.rs re-export update** (`cesr/src/serder/mod.rs:47-51`):

```rust
pub use serialize::{
    EventRef, SerializedEvent, serialize, serialize_delegated_inception,
    serialize_delegated_rotation, serialize_inception, serialize_interaction, serialize_rotation,
};
```

- [ ] **Step 8: Full suite; fix what the compiler finds; commit**

```bash
nix develop --command cargo build -p cesr-rs --all-features
nix develop --command cargo nextest run -p cesr-rs --all-features
nix develop --command cargo nextest run -p keri-rs --all-features
nix develop --command cargo doc -p cesr-rs --all-features --no-deps 2>&1 | rg -i 'warning|error'; echo "exit: $?"
```
Expected: the plain (non-test) build proves the `#[cfg(test)]` variant and its `serde_json` reference don't leak into production compilation; tests green; `cargo doc` clean (remaining broken intra-doc links get fixed in Task 7's doc rewrite — if any surface here in files this task touched, fix them now).

```bash
git add -A && git commit -m "refactor(serder)!: delete the serde_json tree writer and backend seam (#171)

Removes EventSerializer, SerdeJson, DirectJson, serialize_with, the
Value-tree render paths, and the find_subslice splice search; EventLayout
demotes to pub(crate); SerderError::Json becomes the cfg(test)-only
ReferenceJson (its sole producer is the test-only tolerant oracle).
patch_slot stays (backend-agnostic orchestration) and gains direct unit
tests replacing the HostileBackend stub suite.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 7: Rename `direct.rs` → `json.rs`; typed `Ilk`; kind-parameterized head; docs

"Direct" was defined by contrast to the deleted tree writer. The module goes private (nothing public remains in it), named for the kind it emits. Two correctness upgrades while the file is open: `Ilk` replaces the stringly ilk params, and `write_head` takes the kind instead of hardcoding `keri_json_v1()`. Byte-identity: `Ilk::code()` returns the same strings; `VersionString::new(Keri, 1, 0, kind, 0)` renders identically to `keri_json_v1()` for JSON — corpora verify.

**Files:**
- Rename: `cesr/src/serder/serialize/direct.rs` → `cesr/src/serder/serialize/json.rs`
- Modify: `cesr/src/serder/serialize.rs` (module decl, dispatch, header docs)

- [ ] **Step 1: Rename and rewire**

```bash
git mv cesr/src/serder/serialize/direct.rs cesr/src/serder/serialize/json.rs
```

In `serialize.rs`: replace lines 15-16 (`/// Direct serialization backend ...` + `pub mod direct;`) with:

```rust
/// Canonical JSON body writer (the `SerializationKind::Json` codec).
mod json;
```

and in `SerializationKind::render`: `direct::render` → `json::render`. The fn's visibility in `json.rs` becomes `pub(super)` (private module; visible exactly to `serialize.rs`, per the crate's private-mod convention):

```rust
pub(super) fn render(
```

- [ ] **Step 2: Typed `Ilk` + kind-parameterized head** (in `json.rs`). Add to the imports:

```rust
use crate::keri::Ilk;
use crate::serder::version::{Protocol, SerializationKind, VersionString};
```
(drop the old `use crate::serder::version::VersionString;` line). Change `write_head` (was direct.rs:67):

```rust
/// Write the shared `{"v":"<zero-size vstring>","t":"<ilk>","d":"<placeholder>`
/// head and return the size slot plus the `d` slot.
fn write_head(
    buf: &mut Vec<u8>,
    ilk: Ilk,
    placeholder: &str,
    kind: SerializationKind,
) -> Result<(Range<usize>, Range<usize>), SerderError> {
    let vs = VersionString::new(Protocol::Keri, 1, 0, kind, 0).to_str()?;
    buf.extend_from_slice(b"{\"v\":\"");
    let vs_start = buf.len();
    buf.extend_from_slice(vs.as_bytes());
    let size_start = vs_start
        .checked_add(10)
        .ok_or(SerderError::InvalidEventLayout("size slot offset overflow"))?;
    let size_end = size_start
        .checked_add(6)
        .ok_or(SerderError::InvalidEventLayout("size slot offset overflow"))?;

    buf.extend_from_slice(b"\",\"t\":");
    write_str(buf, ilk.code());
    buf.extend_from_slice(b",\"d\":\"");
    let d_start = buf.len();
    buf.extend_from_slice(placeholder.as_bytes());
    let d_end = buf.len();
    buf.push(b'"');
    Ok((size_start..size_end, d_start..d_end))
}
```

Change the renderer signatures and call sites — `render_icp(buf, e, placeholder, ilk: Ilk, delegator)`, `render_rot(buf, e, placeholder, ilk: Ilk)` — and the dispatch:

```rust
pub(super) fn render(
    event: EventRef<'_>,
    said_placeholder: &str,
    buf: &mut Vec<u8>,
) -> Result<EventLayout, SerderError> {
    match event {
        EventRef::Inception(e) => render_icp(buf, e, said_placeholder, Ilk::Icp, None),
        EventRef::Rotation(e) => render_rot(buf, e, said_placeholder, Ilk::Rot),
        EventRef::Interaction(e) => render_ixn(buf, e, said_placeholder),
        EventRef::DelegatedInception(e) => {
            let delegator = identifier_to_qb64_string(e.delegator());
            render_icp(buf, e.inception(), said_placeholder, Ilk::Dip, Some(&delegator))
        }
        EventRef::DelegatedRotation(e) => render_rot(buf, e.rotation(), said_placeholder, Ilk::Drt),
    }
}
```

Inside `render_icp`/`render_rot`: `write_head(buf, ilk, placeholder, SerializationKind::Json)?`; inside `render_ixn`: `write_head(buf, Ilk::Ixn, placeholder, SerializationKind::Json)?` (replacing the `"ixn"` literal).

- [ ] **Step 3: Doc sweep.** In `json.rs`: rewrite the module header (old lines 1-7) —

```rust
//! Canonical JSON body writer: the [`SerializationKind::Json`] codec.
//!
//! Emits the five fixed KERI event grammars straight into the caller's
//! buffer — no intermediate tree or `String` per render — recording the
//! backpatchable slot offsets by construction as it writes, never by
//! re-scanning the buffer. A future CBOR/MGPK codec is a sibling module
//! (`cbor.rs`) plus a match arm in [`SerializationKind::render`].
```

and delete the three "Mirror of [`super::...`]" doc sentences (old direct.rs:242, 254, 328) — the mirrored helpers no longer exist; keep the remaining behavioral text of each doc comment. In `serialize.rs`: update the `EventRef` doc (line 73-74, "hand an event to a serialization backend" → "hand an event to the writer without cloning it into a [`KeriEvent`]") and scrub any surviving `serialize_with`/`SerdeJson` doc mentions:

```bash
rg -n 'SerdeJson|DirectJson|serialize_with|EventSerializer|backend' cesr/src --glob '!target' -g '*.rs'
```
Expected: no matches (adjust any stragglers; "backend" prose should now say "writer").

- [ ] **Step 4: Full suite + doc build + commit**

```bash
nix develop --command cargo nextest run -p cesr-rs --all-features
nix develop --command cargo doc -p cesr-rs --all-features --no-deps 2>&1 | rg -i 'warning|error'; echo "exit: $?"
git add -A && git commit -m "refactor(serder): direct.rs becomes json.rs — typed Ilk, kind-parameterized head (#171)

The writer is named for the kind it emits, not by contrast to a deleted
counterpart. Ilk replaces stringly ilk params; write_head builds the
version string from the kind (the JSON literal now sits only in the
dispatch arm and this module).

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 8: Demote `serde`/`serde_json` to dev-dependencies

**Files:**
- Modify: `cesr/Cargo.toml`

- [ ] **Step 1: Verify zero production references first**

```bash
rg -n 'use serde|serde_json::|serde::' cesr/src --glob '!target' -g '*.rs' | rg -v '#\[cfg\(test\)\]' > /tmp/serde-audit.txt; cat /tmp/serde-audit.txt
```
Manually confirm every remaining hit is inside a `#[cfg(test)]` module or the `#[cfg(test)] ReferenceJson` variant. (The keripy_parity/keripy_diff modules are `#[cfg(test)]`-gated at `lib.rs:100-107`; `deserialize/reference.rs` at `deserialize.rs:36-37`.)

- [ ] **Step 2: Cargo.toml edits.**
  - In `[features]`: remove `"serde?/std"` and `"serde_json?/std"` from `std` (lines 28-29); remove `"serde?/alloc"` and `"serde_json?/alloc"` from `alloc` (lines 38-39); the `serder` feature (line 67) becomes:

```toml
serder = ["keri", "crypto", "stream", "internals"]
```

  - In `[dependencies]`: delete the `serde` and `serde_json` entries (lines 90-95).
  - In `[dev-dependencies]`: add (defaults on — tests build with std; the three serde_json features keep `RawValue`, insertion-order maps, and float round-tripping available to the test-only oracle and parity loaders):

```toml
serde = { version = "1.0.228", features = ["derive"] }
serde_json = { version = "1.0.149", features = [
    "float_roundtrip",
    "preserve_order",
    "raw_value",
] }
```

- [ ] **Step 3: Prove the demotion.** The production dependency graph must be serde-free:

```bash
nix develop --command bash -c "cargo tree -p cesr-rs -e normal --all-features | rg 'serde'"; echo "exit: $? (expect 1 — no matches)"
nix develop --command cargo build -p cesr-rs --all-features
nix develop --command cargo build -p cesr-rs --target wasm32-unknown-unknown --no-default-features --features "alloc,core,b64,keri,crypto,stream,serder,internals"
nix develop --command cargo nextest run -p cesr-rs --all-features
nix develop --command taplo fmt
```
Expected: `cargo tree` finds no serde in normal (non-dev) deps; all builds and tests green. (If the wasm invocation's feature set differs from the flake's `cesr-wasm` check, defer to the flake check in Task 9 — it is the authority.)

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "feat(serder)!: serde and serde_json leave the production dependency graph (#171)

Both demote to dev-dependencies (test-only oracle, parity corpus loaders,
structural-oracle tests). Production serder is dependency-free for
serialization: smaller no_std/wasm footprint, one less audit surface —
the #79 seam design's §3.5 end state.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 9: CHANGELOG, final gate, PR

**Files:**
- Modify: `cesr/CHANGELOG.md`

- [ ] **Step 1: CHANGELOG entry.** Match the existing entry style (read the top of `cesr/CHANGELOG.md` first); content to convey under the unreleased/next heading:

```markdown
### Breaking (rung 5 of #171 — single JSON writer, serde-free production path)

- Removed from the public API: `EventSerializer`, `SerdeJson`, `DirectJson`,
  `serialize_with`, `EventLayout` (now crate-internal), and the
  `SerderError::Json` error variant. Event serialization goes through the
  unchanged `serialize` / `serialize_*` / `KeriSerialize` entry points; the
  single canonical JSON writer produces byte-identical output (gated by the
  keripy byte-identity corpora).
- Renamed `serder::version::SerKind` → `SerializationKind`; it now carries
  the write-path dispatch (`render`), failing loud with the new
  `SerderError::UnsupportedSerializationKind` for kinds without a body codec
  (CBOR/MGPK/CESR), mirroring the strict reader.
- `serde`/`serde_json` are no longer production dependencies of the `serder`
  feature (dev-dependencies only). No wire bytes changed.
```

- [ ] **Step 2: Spec cross-check.** Re-read `docs/superpowers/specs/2026-07-16-171-rung-5-single-json-writer-design.md` §3-§5 against `git diff origin/main --stat`; confirm every listed deletion/move/rename landed. One known refinement to note in the PR: the spec's "write→read→write fixpoint" landed as the repointed `*_strict_equals_reference` proptests (they already asserted `strict_bytes == bytes`; one canonical location per invariant) rather than a duplicate suite.

- [ ] **Step 3: Commit, full gate on committed state**

```bash
git add -A && git commit -m "docs(changelog): rung 5 breaking changes (#171)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
nix flake check > /tmp/flake-check.log 2>&1; echo "exit: $?"
```
Expected: exit 0. If not, read `/tmp/flake-check.log`, fix, amend/commit, re-run.

- [ ] **Step 4: Push + PR** (account `joeldsouzax`; squash-merge convention like #172-#177)

```bash
git push -u origin 171-single-json-writer
gh pr create --title "feat(serder)!: rung 5 — single JSON writer, serde-free production path (#171)" --body "$(cat <<'EOF'
Rung 5 of #171 (spec: docs/superpowers/specs/2026-07-16-171-rung-5-single-json-writer-design.md).

## Breaking
- Public API removed: `EventSerializer`, `SerdeJson`, `DirectJson`, `serialize_with`, `EventLayout` (demoted), `SerderError::Json`.
- Renamed: `SerKind` → `SerializationKind` (+ new fail-loud `UnsupportedSerializationKind` variant).
- `serde`/`serde_json` demoted to dev-dependencies — production `serder` is serde-free (#79 §3.5 end state).

## Not breaking
- Zero wire bytes changed: keripy byte-identity corpora (26 vectors) + keri-rs fold differentials green throughout; the flip commit passed the cross-backend proptests before the reference backend was deleted.
- Coverage replaced, not dropped: write→read→write fixpoint continues via the repointed `*_strict_equals_reference` proptests; NEW structural-oracle proptests compare writer output against independently built serde_json Value trees per ilk; `patch_slot` gains direct unit tests replacing the HostileBackend stub suite; allocation guard becomes a pinned absolute count.

## CodSpeed note
Bench series `icp_serde_json`/`ixn16_serde_json` end (their backend is deleted); `icp_direct`/`ixn16_direct` continue unchanged.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 5: Post-merge follow-ups** (after review + squash-merge, not before): update the #171 epic progress comment (rung 5 done, rung 6 next); note in the epic that the rungs-4-6 handoff doc's `patch_slot`/`abs_range` deletion list was corrected by the spec.
