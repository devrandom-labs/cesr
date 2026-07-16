# Rung 5 — Single JSON Writer, serde-free Production Path (#171)

> **Status:** approved design, pre-plan.
> **Parent:** #171 serder domain redesign, rung 5 of 6. Handoff context in
> `docs/superpowers/plans/2026-07-14-171-rungs-4-6-handoff.md`; staged endgame in
> `docs/superpowers/specs/2026-07-10-79-serialization-backend-seam-design.md` (§3.5).
> **Baseline:** `main` @ `4dd8828` (rung 4 merged).

## 1 · Goal

Promote the buffer-direct JSON emitter (today `DirectJson` in
`cesr/src/serder/serialize/direct.rs`) to the **only** writer, delete the
`serde_json`-tree writer (`SerdeJson`) and its splice machinery, and complete the
seam design's §3.5 end state in the same rung: `serde_json` leaves the production
dependency graph entirely, demoting to `dev-dependencies`.

**Byte-identity is law.** Zero wire bytes change. The #145 keripy corpora
(`cesr/src/keripy_parity/{events,said_codes,seal_events}.rs`, `keri/tests/differential.rs`)
gate this: any diff there is a regression, full stop.

## 2 · Scope decisions (settled during brainstorming)

### 2.1 Full §3.5, not just the writer flip

The seam design staged four steps: (1) land the seam, (2) soak the direct backend,
(3) flip the default, (4) demote serde/serde_json to dev-dependencies. The rungs-4–6
handoff collapsed 3+4 into rung 5 but claimed `serde_json` must survive in production
for "OpaqueSeal handling on the read side". That claim is stale — verified at `4dd8828`:

- The tolerant reference reader is already `#[cfg(test)]`
  (`cesr/src/serder/deserialize.rs:36-37`).
- The strict production reader (`deserialize/canonical.rs`) is serde-free.
- `OpaqueSeal` validates with a hand-rolled scanner at construction
  (`cesr/src/keri/seal.rs`); `serde_json` appears only in its doc comments.
- After the writer dies, the sole production reference left is
  `SerderError::Json(#[from] serde_json::Error)` (`cesr/src/serder/error.rs:20`),
  whose one production use is `seal_to_json`'s defensive `RawValue` re-validation —
  itself deleted with the tree writer.

So both steps land in this rung: production `serder` becomes serde-free
(smaller no_std/wasm footprint, one less audit surface).

### 2.2 Dispatch: inherent method on the kind enum, no trait

`EventSerializer` is a 1-impl trait after `SerdeJson` dies, and its polymorphism sits
on the wrong axis: the genuine variation in this domain is the **serialization kind**
(JSON/CBOR/MGPK/CESR — a *closed*, spec-fixed set parsed from the version string at
`version.rs`), not "backends" emitting identical bytes. Rust's idiom for polymorphism
over a closed set is enum + exhaustive match, not an open trait:

```rust
// serialize.rs — inherent impl lives here, NOT in version.rs, so the
// version module stays free of event/render knowledge.
impl SerializationKind {
    pub(crate) fn render(
        self,
        event: EventRef<'_>,
        placeholder: &str,
        buf: &mut Vec<u8>,
    ) -> Result<EventLayout, SerderError> {
        match self {
            Self::Json => json::render(event, placeholder, buf),
            Self::Cbor | Self::Mgpk | Self::Cesr => {
                Err(SerderError::UnsupportedSerKind(self))
            }
        }
    }
}
```

Why this shape:

- **Exhaustiveness is a safety property.** A future `cbor::render` arm fails to
  compile until every dispatch site handles it. A trait gives no such signal.
- **The match cannot be avoided anyway.** The kind is runtime data (parsed from the
  version string); a trait would relocate the same match behind a vtable, not remove it.
- **Signature pinning is automatic.** All arms live in one function; kinds cannot
  drift apart the way sibling free fns could.
- **Fail-loud symmetry with the read path.** The strict reader already rejects
  non-JSON kinds (`canonical.rs:562-567`); the writer erroring on them enforces the
  same invariant the same way. `SerderError::UnsupportedSerKind(SerializationKind)`
  replaces the deleted `Json` variant.
- Today's callers pass `SerializationKind::Json` literally — no event can carry
  another kind because the reader rejects them. When a kind field arrives (CBOR card),
  the literal becomes data with no reshaping.

### 2.3 A future CBOR/MGPK kind composes by adding a module, not an abstraction

Per the seam design §3.4 the kind axis is explicitly out of scope; no open issue,
no strategy-doc mention, and `SerializationKind::{Cbor,Mgpk,Cesr}` appear only in
`version.rs`'s own tests. The settled composition story:

- Body-writing knowledge stays in `serder` — **never** on the `cesr::keri` event
  types. (A `write_body` method on events would bake one kind into the domain and
  grow an N-ilks × M-kinds impl matrix.)
- A CBOR card adds `serialize/cbor.rs` beside `serialize/json.rs` with the same
  free-fn shape and fills in the match arm. Shared-emitter abstraction is deferred
  to that card ("add at the second concrete use").
- Open assumption to probe *at the CBOR card, not now*: `EventLayout`'s byte-range
  backpatch contract holds across kinds only if the version string and SAID
  placeholder are fixed-width ASCII runs inside CBOR/MGPK payloads too. Believed
  true (KERI cold-start sniffing depends on it) but unverified against the spec and
  a real keripy CBOR vector.

### 2.4 Naming

- `SerKind` → **`SerializationKind`**. Not because it gains `render` — domain enums
  here carry behavior as the norm (`SigningThreshold::satisfy`, `Toad`, `Ilk`,
  `Role`, `ConfigTrait`) — but because the abbreviation is out of step with the
  rungs-1–4 de-jargonizing arc (`Tholder`→`SigningThreshold`, `Seqner`→`SequenceNumber`).
  `Toad` is the counter-precedent proving the rule: it stays because TOAD is the
  spec's own acronym; "Ser" is nobody's vocabulary. Breaking (type is publicly
  reachable via `pub mod version`), mechanical, three files.
- `serialize/direct.rs` → **`serialize/json.rs`**. "Direct" is defined only by
  contrast to the tree writer being deleted; once it is the sole writer the name
  means nothing. `json.rs` is `SerializationKind::Json` vocabulary; `cbor.rs` slots
  in beside it later.
- `DirectJson` (unit struct) is **deleted, not renamed** — it exists only to carry
  a vtable for the 1-impl trait. The ex-trait method becomes the module's free fn:
  `pub(crate) fn render(event, placeholder, buf) -> Result<EventLayout, SerderError>`.

### 2.5 The renderers keep their free-fn shape — no writer struct

Considered and rejected: an `EventWriter` struct owning the buffer and recording
slots via typestate. The existing emitters (`write_str`, `write_qb64_array`,
`write_seal`, …) are zero-state pure functions; the only slot-producing sites are
`write_head` (size + SAID) and the `icp`/`dip` prefix placeholder. Wrapping three
`Option<Range>` in a struct with a fallible `finish()` would *add* a runtime failure
mode ("finish with size unset") to replace code that is correct by construction.
Rejected likewise: a structure-enforcing object writer (closure-based `o.field(…)`) —
the grammar is five fixed layouts; malformed-JSON bugs are caught immediately by the
fixpoint property and corpora.

Two small correctness upgrades land while the files are open anyway:

- **Typed `Ilk`.** `write_head(buf, ilk: Ilk, …)` and the icp/rot renderers take
  `Ilk` (already a `cesr::keri` enum, already returned by `EventRef::ilk()`) instead
  of `"icp"`/`"dip"`/`"rot"`/`"drt"`/`"ixn"` string literals.
- **De-hardcode the version string.** `write_head` currently calls
  `VersionString::keri_json_v1()`; it takes the kind from its caller
  (`VersionString::new(…, kind, …)` already exists) so the JSON literal sits in
  exactly one place: the `Json` match arm.

## 3 · Deletions (verified present at `4dd8828`)

From `cesr/src/serder/serialize.rs`:

| Item | Line | Note |
|---|---|---|
| `trait EventSerializer` | 175 | public — breaking |
| `struct SerdeJson` + impl | 192 | public — breaking |
| `fn serialize_with<B>` | 230 | public — breaking; orchestration body survives as `pub(crate) fn serialize_event(event: EventRef<'_>)` |
| `fn extend_with_layout` + 4 framing consts | 278–343 | SerdeJson-only slot *search* |
| `fn abs_range` | 346 | only caller is `extend_with_layout` |
| `fn find_subslice` | 357 | the buffer-searching approach dies; slots come from the writer by construction |
| `enum AnchorJson`, `struct EventBody`, `fn seal_to_json`, `fn tholder_to_json`, `fn toad_json`, `fn matters_to_json_array` | 461–639 | the serde_json tree builders |

**`fn patch_slot` (366) STAYS** — the handoff doc wrongly listed it: it belongs to
the backend-agnostic orchestration (called at 248/256/262 for size/SAID/prefix
backpatch regardless of writer).

From `serialize/{icp,rot,ixn,dip,drt}.rs`: each file's `render_json` +
`build_*_json` (the SerdeJson render path). The five public `serialize_*` entry fns
**stay** with unchanged signatures — they erase concrete event types into `EventRef`
and now call `serialize_event`. `prefix_json_value` (icp.rs:85, shared with dip.rs)
dies with the tree path.

From `error.rs`: `SerderError::Json(#[from] serde_json::Error)` — replaced by
`UnsupportedSerKind(SerializationKind)` (different failure domain, not a rename).

Moves: `weight_to_string` (serialize.rs:621) into `json.rs` — it lived in the parent
only because two backends shared it. `EventLayout` drops from `pub` to `pub(crate)` —
it is meaningful only to a writer and there is no longer a public one.

`Cargo.toml`: `serde`/`serde_json` move from `[dependencies]` to
`[dev-dependencies]`; the `serder` feature drops `dep:serde`/`dep:serde_json`; the
`std`/`alloc` feature plumbing lines for them go. (`serde` usage audit is part of
the plan: if the strict reader genuinely uses no serde derive, both demote; if any
production `derive(Serialize)` survives outside the deleted code, only `serde_json`
demotes and the spec's claim is corrected in the PR.)

## 4 · Public API delta (breaking — MINOR bump under 0.x)

Removed: `EventSerializer`, `SerdeJson`, `DirectJson`, `serialize_with`,
`EventLayout` (demoted), `SerderError::Json`.
Renamed: `SerKind` → `SerializationKind` (reachable as `cesr::serder::version::SerKind`).
Added: `SerderError::UnsupportedSerKind(SerializationKind)`.
Unchanged: `serialize`, the five `serialize_*` fns, `KeriSerialize`/`KeriDeserialize`,
`EventRef`, `SerializedEvent`, all builders.

CHANGELOG entry required; PR description calls out each removal.

## 5 · Test & coverage plan

Deleting `SerdeJson` retires the cross-backend byte-identity proptests
(`{icp,rot,ixn,dip,drt}_backends_byte_identical`, direct.rs:433-461). Fixpoint alone
is self-consistency — a symmetric writer/reader bug keeps it green — so coverage is
replaced by **two complementary properties** over the same
`event_strategies.rs` space, landing in the same PR (coverage never dips):

1. **Write→read→write fixpoint (byte-level).** build → serialize → strict
   `deserialize_event` → re-serialize → assert byte equality. Covers canonical form:
   field order, framing, whitespace, escaping stability.
2. **serde_json structural oracle (content-level, test-only dep).** Parse the
   writer's output with `serde_json` into a `Value`; assert equality against a
   `Value` tree built *independently in test code from the domain fields* (via
   `json!`, never through production emitters). Covers value correctness through an
   implementation that shares no code with the writer — including classes the old
   differential was blind to (e.g. both backends shared `weight_to_string`, so a
   weight-rendering bug was invisible to it). The `v`/`d`/`i` backpatched fields get
   dedicated assertions (version-string shape + parsed size == byte length; SAID
   verifies through the existing read-path verify), since building them into the
   expected tree would be circular.

Test fallout, resolved:

- **`HostileBackend` tests** (serialize.rs:1008-1100) die with the trait. Every
  check they exercise lives in `patch_slot`; it gains direct unit tests with
  hand-forged `Range`s — testing the SUT instead of testing through a stub.
- **Escaper oracle proptests** (direct.rs:467-495, vs `serde_json::to_string`)
  survive unchanged — already test-only.
- **`tests/serder_allocation.rs`:** `direct_backend_allocates_strictly_less_than_serde_json`
  loses its baseline; converts to a pinned absolute allocation count for the single
  writer, mirroring `deserialize_allocation_count_is_pinned`.
- **`benches/serder.rs`:** comparative premise gone; reworks to bench the five
  public `serialize_*` fns (CodSpeed keeps a continuous series on the surviving path).
- **`deserialize.rs` tests** importing `SerdeJson`/`serialize_with` (:1656) repoint
  to the public `serialize_*` fns.
- **Broken intra-doc links to fix** (would fail `cargo doc`): direct.rs:6
  (`[SerdeJson]`), direct.rs:242/254/328 (`[super::matters_to_json_array]` etc.),
  serialize.rs:172/189/459-460.
- The ~60 `serde_json::from_slice` assertions across builder/serialize test modules
  keep working — `serde_json` remains a dev-dependency.

Gate: `nix flake check` on committed state, per house rule. The wasm/no_std checks
double as proof of the dependency demotion.

## 6 · Out of scope

- Any CBOR/MGPK/CESR body codec (the fail-loud match arms are the entire concession).
- Rung 6 zero-copy `KeriEvent` (#129).
- keri-rs `KeyState` vocabulary follow-on.
- No divergence-ledger entry: no wire behavior changes; non-JSON kinds were already
  rejected on read.

## 7 · Risks

| Risk | Mitigation |
|---|---|
| Writer flip changes production bytes | It cannot silently: #145 corpora assert byte-identical reserialization of 26 keripy vectors; cross-backend proptests are green at HEAD, proving the emitters agree *before* the flip |
| Fixpoint blind to symmetric writer/reader bugs | Structural oracle is an independent implementation over the full proptest space |
| Coverage dips between backend deletion and new properties | Both land in the same PR; corpora never leave |
| serde demotion breaks a hidden production use | wasm/no_std flake checks compile the crate without dev-deps; audit step in the plan |
