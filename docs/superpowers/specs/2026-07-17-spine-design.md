# The Spine — Design (stream → serder → keri as one pipeline)

**Status: awaiting approval. No implementation code lands until this document is approved.**

**Problem.** The workspace has no end-to-end path. `stream`, `serder`, and `keri-rs` are
three independently-rooted stacks that never call each other:

- `serder` imports nothing from `stream` — the only cross-import in the module is one
  digest call (`cesr/src/serder/said.rs:16`). No function anywhere takes wire bytes and
  returns a verified `KeyState`.
- `stream::parse_message` produces `CesrMessage::Event { payload, attachments }`
  (`cesr/src/stream/message.rs:270`); `serder::deserialize_event` wants a bare `&[u8]`
  (`cesr/src/serder/deserialize.rs:63`); `keri::Signed` must be hand-assembled from three
  separately-threaded slices under an unchecked provenance contract
  (`keri/src/state.rs:57-65`). Every in-tree `deserialize_event` caller is a test.
- The parsed signature groups (`ControllerIdxSigs::into_vec() -> Vec<Siger>`,
  `cesr/src/stream/group/types.rs:74`) have **no consumer** — nothing wires attachments
  into `Signed.sigs`/`wigs`. The keri-rs test harness re-signs with fresh keypairs
  instead (`keri/tests/common/mod.rs:64-71`).
- The write path stops at `SerializedEvent`. All 27 attachment-group constructors are
  `pub(crate)` (`types.rs:49,104,…`), so a consumer cannot construct an attachment group
  from their own signatures; `CesrMessage` has no write-side assembler. Signing and
  framing are not expressible through the public API.

Because no code crosses the seams, wire knowledge was re-derived on each side:

- Two full parsers for the same 17-byte version string: `stream/message.rs:62` vs
  `serder/version.rs:216` (different structs, `usize` vs `u32` sizes, different errors).
- Three representations of CESR version: dead `core::version::CesrVersion` (re-exported,
  zero consumers), a second duplicate `CesrVersion` enum at `stream/unwrap.rs:19`, and
  the phantom-type `V1`/`V2` at `stream/version.rs`. Plus a second serialization-kind
  table at `stream/encode.rs:598` shadowing `SerializationKind::as_str`
  (`serder/version.rs:53`).
- Validation asymmetry: signing-threshold well-formedness is enforced at build
  (`serder/builder/icp.rs:264`) and at fold (`keri/src/authority.rs:38`) but **never on
  deserialize** — a wire event with `kt` exceeding its key count parses successfully
  (documented in `keri/tests/transitions.rs:194-197`). `Signed.wigs` is stored and never
  read: witness receipts are never cryptographically verified anywhere.

**Non-negotiable gate.** The keripy differential suites (byte-identity event vectors,
parity families, fold KELs) stay green at every phase. Every phase is an
independently-green PR through `nix flake check`. Any behavioral drift on existing wire
bytes is a red build.

## Decisions

| Axis | Decision |
|------|----------|
| Spine home | `cesr::serder` (its feature already implies `stream` + `keri` + `crypto`) |
| Read entry | one function: wire bytes → `EventMessage` (event + sigs + wigs + body span) |
| keri-rs adapter | `Signed: From<&EventMessage>` behind a new opt-in `wire` feature, preserving the #128 sans-io boundary (serder stays out of keri-rs's default deps) |
| Version knowledge | single owner in `cesr::core::version`; both stream and serder consume it |
| Group `count` | derived from data at construction, never caller-supplied — invariant by construction |
| Acceptance tests | written verbatim in this spec, reviewed **before** implementation; land as the first (red) commit of their phase — an `#[ignore]`d test cannot land earlier because it must compile against the spine types |
| Sequencing | #181 (qb2 reader) and all other feature cards wait behind Phases 1–4 |

## 1. Target architecture

```
            READ                                        WRITE
wire bytes                                   InceptionBuilder … .build()
  │  stream::parse_message                       │  (unchanged, Phase 6 dedups internals)
  ▼                                              ▼
CesrMessage<'a>                              SerializedEvent
  │  serder::parse_event_message                 │  caller signs body with crypto::KeyPair
  ▼                                              ▼
EventMessage<'a>                             ControllerIdxSigs::from_sigers(&[Siger])
  │  keri::Signed::from(&msg)   [wire feat]      │  serder::frame_event_v1(…)
  ▼                                              ▼
KeyState::incept / ingest                    framed wire bytes (byte-identical to keripy)
```

One typed pipeline in each direction. Every seam is a type, not a convention.

## 2. New public surface

### 2.1 `cesr::serder::message` — the read spine (Phase 2)

```rust
/// A key event message as received from the wire: the parsed event, the exact
/// byte span its signatures sign, and its attached indexed signatures.
pub struct EventMessage<'a> {
    event: KeriEvent<'a>,
    body: &'a [u8],          // exact signed span, borrowed from input
    sigs: Vec<Siger<'a>>,     // -A controller indexed signatures
    wigs: Vec<Siger<'a>>,     // -B witness indexed signatures
}

impl<'a> EventMessage<'a> {
    pub fn event(&self) -> &KeriEvent<'a>;
    pub fn body(&self) -> &'a [u8];
    pub fn sigs(&self) -> &[Siger<'a>];
    pub fn wigs(&self) -> &[Siger<'a>];
}

/// Parse one framed key event message from the head of `input`.
/// Returns the message and the unconsumed remainder (stream-friendly).
pub fn parse_event_message(input: &[u8])
    -> Result<(EventMessage<'_>, &[u8]), EventMessageError>;
```

`EventMessageError` is a `thiserror` union per house convention — one `#[from]` variant
per source domain (`ParseError` from stream framing, `SerderError` from body
deserialization) plus message-level variants (`BareAttachment`, `UnexpectedGroup`).
This is the first error type that spans the seam, and the only place the conversion
lives.

Internals: `parse_message` → take `payload` as `body` → `deserialize_event(body)` →
walk `attachments` (`Groups`), routing `ControllerIdxSigs` → `sigs`,
`WitnessIdxSigs` → `wigs`, rejecting groups that cannot belong to a key event message.
This is the consumer the attachment groups have never had.

### 2.2 keri-rs `wire` feature — the adapter (Phase 2)

```rust
// keri-rs, #[cfg(feature = "wire")] — feature enables cesr/serder
impl<'e> From<&'e EventMessage<'e>> for Signed<'e> {
    fn from(msg: &'e EventMessage<'e>) -> Self {
        Signed {
            event: msg.event(),
            signed_bytes: msg.body(),   // provenance now held by construction
            sigs: msg.sigs().to_vec(),
            wigs: msg.wigs().to_vec(),
        }
    }
}
```

The #128 boundary holds: default keri-rs still takes parsed borrowed values and never
sees bytes; `wire` is the optional edge, exactly like the optional async edge decided
in #128. The `signed_bytes`-provenance contract (`state.rs:57-65`) stops being an honor
system for every consumer that comes through this door.

### 2.3 Write spine (Phase 4)

```rust
// stream: groups become constructible — count derived, not passed
impl ControllerIdxSigs {
    pub fn from_sigers(sigers: &[Siger<'_>]) -> Result<Self, ParseError>;
}
impl WitnessIdxSigs {
    pub fn from_sigers(sigers: &[Siger<'_>]) -> Result<Self, ParseError>;
}

// serder: the framing assembler (write mirror of parse_event_message)
pub fn frame_event_v1(
    event: &SerializedEvent,
    sigs: &ControllerIdxSigs,
    wigs: Option<&WitnessIdxSigs>,
) -> Vec<u8>;
```

`from_sigers` re-encodes through the existing validated `CesrEncode` path and sets
`count` from `sigers.len()` — the `count`-vs-`raw` invariant that is currently held by
convention (`types.rs:49` stores whatever the caller passes) becomes unconstructible-
if-wrong. The 27 `pub(crate)` constructors stay crate-private; construction is only
via parsing or `from_sigers`.

### 2.4 `cesr::core::version` — single owner of version knowledge (Phase 1)

Moves into `core::version` (both stream and serder already depend on `core`):

- `Protocol` (KERI/ACDC), `SerializationKind` (JSON/CBOR/MGPK/CESR) — one table.
- `VersionString` (V1, 17-byte) and `VersionStringV2` (19-byte): `parse` + `render`,
  used by **both** the stream framer and the serder canonical head.
- One `CesrVersion` enum (V1/V2). The phantom-typestate `stream::version::{V1,V2}`
  stays (it is the best-designed piece of the newer modules) and gains
  `const VERSION: CesrVersion` tying type-level to value-level.

Deleted: the dead `core::version::CesrVersion` (current form), the duplicate enum at
`stream/unwrap.rs:19`, the parallel parser + `b64_to_u8/16/32` wrappers in
`stream/message.rs:16-115`, all of `serder/version.rs` (moved), the second
`kind_to_bytes` table at `stream/encode.rs:598`.

## 3. Validation parity + witness receipts (Phase 3)

- `deserialize_*` gains the checks the builder already runs: `kt` well-formed against
  key count, `nt` against next-key count (`SigningThreshold::check_well_formed`, already
  shared code at `threshold.rs:176`). New `SerderError` variant; breaking, changelogged.
- keri-rs verifies `wigs`: each receipt verifies against the witness at its index in the
  governing witness set; the count of valid receipts must satisfy the `Toad`. New
  `Rejection` variant (`InsufficientWitnessReceipts`); breaking, changelogged. This makes
  `Signed.wigs` load-bearing for the first time.

## 4. Acceptance tests (reviewed here, land red-then-green in their phase)

Test names contain `keripy` so the nightly differential filter picks them up. Fixtures
are generated by a new `scripts/keripy_spine_gen.py` following the existing
`scripts/keripy_keystate_gen.py` pattern (pinned keripy env per `docs/keripy-parity/`),
committed together with the script that produced them. Assertion values below are
placeholders **in this spec only** — they are pinned to the generator's output in the
phase PR, and the PR must show the generator run that produced them.

**Test A — read spine (Phase 2, `keri/tests/spine.rs`, feature `wire`):**

```rust
use cesr::serder::parse_event_message;
use keri::{KeyState, Signed};

const KERIPY_ICP_SIGNED: &[u8] = include_bytes!("fixtures/keripy_icp_signed.cesr");

#[test]
fn keripy_signed_inception_stream_folds_to_key_state() {
    let (msg, rest) = parse_event_message(KERIPY_ICP_SIGNED).unwrap();
    assert!(rest.is_empty());
    let signed = Signed::from(&msg);
    let state = KeyState::incept(&signed).unwrap();
    assert_eq!(state.prefix().to_qb64(), /* pinned from generator */);
    assert_eq!(state.keys().len(), /* pinned */);
    assert_eq!(state.witness_threshold(), /* pinned */);
}

#[test]
fn keripy_signed_kel_stream_folds_through_ingest() {
    // icp + rot + ixn stream: fold all three through parse → Signed → ingest,
    // final state pinned against keripy's key state output for the same KEL.
}
```

**Test B — write spine (Phase 4, `cesr/tests/spine_write.rs`):**

```rust
#[test]
fn framed_inception_is_byte_identical_to_keripy() {
    // Build the event with InceptionBuilder from the generator's seeds,
    // sign the body with crypto::KeyPair, frame with frame_event_v1,
    // assert the full framed bytes equal the keripy stream fixture verbatim.
}

#[test]
fn write_then_read_round_trips_through_the_spine() {
    // frame_event_v1 output → parse_event_message → Signed → KeyState::incept
    // must reproduce the built event's state. Wire knowledge exists once when
    // this holds with zero re-encoding drift.
}
```

These tests are unwritable today. They fail if any seam disconnects again — that is the
regression guarantee this whole design exists to create.

## 5. Flatness cleanup (after the spine, because the spine makes it safer)

**Phase 5 — group unification.** One generic `Group` engine over an element-shape
descriptor replaces the 20 copy-pasted `{ raw: Bytes, count: u32 }` structs with their
17 hand-copied `count()/iter()/into_vec()` impls (`stream/group/types.rs`) and the 18
one-function parse files; the 2 genuinely irregular groups (nested counters,
`trans_idx_sig_groups`) keep custom impls. The 21 one-line `encode_*_v1/v2` wrappers
(`stream/encode.rs:142-224`) are deleted in favor of the `CesrEncode<V>` trait that
already exists. Types, parse, and encode for a group live in one place.

**Phase 6 — builder dedup.** The four establishment builders move from the flat
typestate (all fields present in every state, 15-field struct literals re-threaded at
every transition — `rot.rs:94-195` and its `drt.rs` twin) to core's per-state-struct
style (`core/matter/builder.rs:19-65`), and the four verbatim `build()` validation
prologues (`icp.rs:210-231`, `dip.rs:208-229`, `rot.rs:283-309`, drt) collapse into one
shared establishment-validation path. ~1,900 lines of plumbing deleted; public builder
API unchanged.

**Phase 7 — tripwires in the flake gate.**
- Version-grammar gate: version-string constants/parsers exist only under
  `core/version` (rg-based check in the flake, like the existing typos gate).
- Free-function ratchet: per-module `pub fn` counts recorded in a checked file; counts
  may only decrease. Current baseline: serder 70, stream 75, keri 1.

## 6. Phase ladder (each an independently-green PR, reviewed and merged by you)

| Phase | Content | Breaking |
|-------|---------|----------|
| 0 | this spec | — |
| 1 | version unification into `core::version` | yes — moved/renamed types, changelogged |
| 2 | read spine: `EventMessage`, `parse_event_message`, keri-rs `wire` feature, Test A red→green | additive |
| 3 | validation parity + wigs verification | yes — new error/rejection variants |
| 4 | write spine: `from_sigers`, `frame_event_v1`, Test B red→green | additive |
| 5 | group unification | internal (public group types preserved) |
| 6 | builder dedup | internal (builder API preserved) |
| 7 | tripwire gates in the flake | — |

Each phase gets its own bite-sized implementation plan
(`docs/superpowers/plans/`) written **after** this spec is approved, and its own issue
on the board (org Project #5) so the cards finally name the flow, not the pieces.
#181 (qb2 reader) is blocked behind Phase 4.
