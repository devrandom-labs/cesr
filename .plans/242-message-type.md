# #242 — Ilk → MessageType (clean-and-keep the wire tag)

## Context

Issue #242 (decision by Joel, 2026-07-26, design spec
`docs/superpowers/specs/2026-07-26-keri-events-role-newtypes-design.md` line 54):
keep a small `Copy` wire-tag type (it is held without the event body at the wire
edge and stored on `SerializedEvent`), but clean it so it stops reading as a
duplicate of `KeriEvent`. Three mandated steps:

1. Drop the 4 dead variants `Rct`/`Qry`/`Rpy`/`Exn`.
2. Write the variant→tag map once (today duplicated at
   `crates/keri-events/src/event/mod.rs:40` and
   `crates/keri-codec/src/serialize.rs:146` — identical arms).
3. Rename `Ilk` → `MessageType` (the KERI spec calls the `t` field the message
   type).

Invariants that must hold:

- **I1** Parsing an event body whose `t` is `"rct"`/`"qry"`/`"rpy"`/`"exn"`
  still fails with the SAME observable error as before:
  `DeserializeError` unknown-message-type variant carrying the code string,
  no panic, ever. The PRODUCTION rejection site is the `other` string-match
  arm at `crates/keri-codec/src/codec/event.rs:414` (it never consults the
  enum, so the variant drop does not change it). The `#[cfg(test)]` reference
  oracle (`deserialize/reference.rs`) rejects via the `_` arm at line 203
  today; after the drop it rejects via `MessageType::from_code` failing at
  lines 190-191 (the `map_err` there already produces the same error).
- **I2** The keripy-parity codex sweep
  (`crates/keri-codec/src/keripy_parity/codex.rs:91` `codex_tables_match_keripy`)
  must stay green. The 4 corpus rows for `rct`/`qry`/`rpy`/`exn` in
  `crates/keri-codec/tests/corpus/keripy/parity/codex.jsonl` currently have NO
  `divergence` marker, so after the variant drop the test would panic. Those
  rows get a divergence marker (step 6), and the generator script + ledger are
  updated in lockstep so a future regeneration reproduces the corpus.
- **I3** Naming: `ilk` is a keripy contraction and is banned outside the
  differential boundary (repo rule). The rename sweeps type, module, methods,
  fields, and error variants. EXCEPTION (differential boundary, keep as-is):
  the corpus `family` key string `"ilk"`, the `keripy_parity` module's match
  arm on that string, `scripts/keripy_parity_gen.py`'s internal vocabulary,
  and `docs/keripy-parity/ledger.md`'s references to keripy's `Ilks` codex
  (though ledger prose about what cesr implements changes — step 6).
- **I4** The variant→tag pairing is stated exactly once per event type: a
  `pub const MESSAGE_TYPE: MessageType` associated const on each of the 5
  event structs in keri-events. EVERY other site that pairs a variant with a
  tag references the consts: `KeriEvent::message_type`,
  `EventRef::message_type`, AND the render dispatch in
  `crates/keri-codec/src/codec/event.rs` (lines ~499-510 pass `Ilk::Icp` etc.
  into `Self::render_*` calls; line ~683 hardcodes `Ilk::Ixn` inside
  `render_ixn`; also lines ~521, 554, 626) — all become
  `InceptionEvent::MESSAGE_TYPE`-style const references. keri-events cannot
  see keri-codec's `EventRef`, so a single shared match is impossible; consts
  are the single source of truth.
- **I5** No lint relaxation, no new `#[allow]`. After the variant drop the `_`
  arm at `reference.rs:203` becomes unreachable and MUST be removed (clippy
  denies unreachable patterns). The `is_establishment` test's
  non-establishment list shrinks to `[Ixn]`.
- **I6** This is a breaking change to `keri-events`, `keri-codec`, and
  `keri-rs` public surfaces — expected, will be called out in PR/CHANGELOG by
  the controller. Do not add deprecation shims or re-export aliases.

## Steps

### Step 1 — keri-events: rename + drop variants + consts
`SEQUENTIAL — everything else depends on this`

Files: `crates/keri-events/src/ilk.rs` (rename to
`crates/keri-events/src/message_type.rs` via `git mv`),
`crates/keri-events/src/lib.rs`, `crates/keri-events/src/error.rs`,
`crates/keri-events/src/event/mod.rs`,
`crates/keri-events/src/event/inception.rs`,
`crates/keri-events/src/event/rotation.rs`,
`crates/keri-events/src/event/interaction.rs`,
`crates/keri-events/src/event/delegation.rs`.

1. `mv crates/keri-events/src/ilk.rs crates/keri-events/src/message_type.rs`
   (plain `mv`, NOT `git mv` — no git operations; git detects the rename at
   commit time).
   In it: enum `Ilk` → `MessageType`, keep derives and the 5 live variants
   `Icp/Rot/Ixn/Dip/Drt`; DELETE `Rct/Qry/Rpy/Exn` variants and their arms in
   `code()` / `from_code()`. Doc comment for the enum: it is the wire tag for
   the `t` field (the KERI spec's "message type"), a `Copy` tag held without
   the event body; note the receipt/query/reply/exchange codes are not yet
   supported and are rejected by `from_code`. Keep `code()`, `from_code()`,
   `is_establishment()` semantics unchanged for live variants.
2. `crates/keri-events/src/error.rs:13-14`: variant `UnknownIlk(String)` →
   `UnknownMessageType(String)`, display string
   `"unknown message type code: {0}"`. Update the doc comment.
3. `crates/keri-events/src/lib.rs:31-32,53`: `pub mod ilk;` → `pub mod
   message_type;`, `pub use ilk::Ilk;` → `pub use message_type::MessageType;`,
   and the doc line at 31 `/// Event type identifiers (ilks).` →
   `/// Event message-type tags.`.
4. Associated consts (I4): on each event struct add
   `pub const MESSAGE_TYPE: MessageType = MessageType::Icp;` (Rot/Ixn/Dip/Drt
   respectively) with a one-line doc `/// Wire tag for the `t` field.`.
   Structs: `InceptionEvent` (inception.rs), `RotationEvent` (rotation.rs),
   `InteractionEvent` (interaction.rs), `DelegatedInceptionEvent` and
   `DelegatedRotationEvent` (delegation.rs). Put the const at the top of each
   struct's existing inherent impl block; add the `MessageType` import at the
   top of the file (import style rule: no inline `use`, no qualified paths).
5. `crates/keri-events/src/event/mod.rs:38-47`: method `ilk()` →
   `message_type()`, return type `MessageType`, arms become
   `Self::Inception(_) => InceptionEvent::MESSAGE_TYPE` etc. (all 5). Update
   the doc comment.
6. Tests in `message_type.rs`: shrink `ALL_VARIANTS` to the 5 live pairs;
   `from_code` valid test uses `"icp"` and `"drt"`; invalid test keeps
   `"zzz"` AND adds a dead-code probe: each of `"rct"`, `"qry"`, `"rpy"`,
   `"exn"` returns `KeriError::UnknownMessageType` with the exact code string
   (loop over the 4, `assert!(matches!(...))` on the variant with the string
   bound and compared via `assert_eq!`). `establishment` test: establishment
   list unchanged, non-establishment list is `[MessageType::Ixn]`.
   Tests in `event/mod.rs:153,159`: `event.ilk()` → `event.message_type()`,
   `Ilk::` → `MessageType::`.

Expected outcome: `cargo nextest run -p keri-events` green; the string `Ilk`
and identifier `ilk` no longer appear in `crates/keri-events/src/` except the
word "ilk" MUST NOT appear at all (prose included — use "message type").

### Step 2 — keri-codec: rename sweep + dedup EventRef map
`SEQUENTIAL — depends on step 1` (then 2/3/4 are PARALLEL with each other)

Files: `crates/keri-codec/src/serialize.rs`, `crates/keri-codec/src/error.rs`,
`crates/keri-codec/src/codec/field.rs`, `crates/keri-codec/src/codec/event.rs`,
`crates/keri-codec/src/deserialize.rs`,
`crates/keri-codec/src/deserialize/reference.rs`,
`crates/keri-codec/src/said.rs`, `crates/keri-codec/src/traits.rs`,
`crates/keri-codec/src/keripy_parity/codex.rs`,
`crates/keri-codec/src/builder/{icp,rot,ixn,dip,drt}.rs`,
`crates/keri-codec/tests/transitions.rs`,
`crates/keri-codec/tests/frozen_surface.rs`.

1. `crates/keri-codec/src/error.rs:80-82`: `UnknownIlk(String)` →
   `UnknownMessageType(String)`, display `"unknown message type: {0}"`, doc
   comment "Unknown message type code in the `t` field.". Sweep every
   `DeserializeError::UnknownIlk` constructor site (`codec/field.rs:166`,
   `deserialize/reference.rs:191,844`, and any the compiler finds). At
   `codec/field.rs:161-162`, update the legacy-parity comment to name
   `UnknownMessageType` (the `ConfigTrait`-failure-onto-this-variant mapping
   is pre-existing deliberate parity; keep the behavior, just fix the
   comment's variant name).
   Also `crates/keri-codec/src/deserialize.rs`: the doc link
   ``[`DeserializeError::UnknownIlk`]`` at line 105 (rustdoc breaks if left),
   prose "ilk" hits (lines ~95, 135, 156, 177, 196, 217, 1160, 1855, 2286),
   and the test `error_unknown_ilk_at_public_dispatch` (line ~2525) →
   `error_unknown_message_type_at_public_dispatch` with its `UnknownIlk`
   match at ~2541 renamed.
2. `crates/keri-codec/src/serialize.rs`: import rename; `EventRef::ilk()`
   (line 146) → `message_type()`, arms reference the step-1 consts
   (`Self::Inception(_) => InceptionEvent::MESSAGE_TYPE` etc.);
   `SerializedEvent` private field `ilk` → `message_type`, accessor `ilk()`
   (line 382) → `message_type()`, doc "The event's message type (the `t`
   field's wire tag)."; update every internal use and the test at
   serialize.rs:923 plus the `ALL`-style test tables in the
   `mod tests` (lines ~810-930).
3. `crates/keri-codec/src/deserialize/reference.rs:190-205`: rename type +
   error variant; the match over the now-5-variant enum is exhaustive —
   DELETE the `_` arm at line 203 (I5). Keep the `map_err` at 190-191
   producing `DeserializeError::UnknownMessageType(ilk_str.to_owned())` —
   rename the local `ilk_str`/`ilk` bindings to `message_type_str`/
   `message_type`.
4. `crates/keri-codec/src/codec/event.rs` and `crates/keri-codec/src/said.rs`:
   rename imports/uses; sweep prose "ilk" → "message type" in doc comments
   (e.g. event.rs:193,214,245,380-381; said.rs:82). Local variable `ilk` at
   event.rs:245 → `message_type`. Per I4: the render dispatch arms at
   event.rs ~499-510 (and ~521, 554, 626) stop passing `Ilk::Icp`-style
   literals into `Self::render_*` — pass `InceptionEvent::MESSAGE_TYPE` etc.;
   the hardcoded `Ilk::Ixn` inside `render_ixn` at ~683 becomes
   `InteractionEvent::MESSAGE_TYPE`. After this, `MessageType::Icp`-style
   variant literals appear in keri-codec ONLY in tests and in
   `deserialize/reference.rs`'s dispatch match (which maps tag→variant, the
   inverse direction — not a copy of the variant→tag map).
5. `crates/keri-codec/src/keripy_parity/codex.rs:109-113`: `Ilk::from_code` →
   `MessageType::from_code` (+ import). KEEP the `"ilk"` family-string match
   arm and the panic/assert message strings mentioning "ilk" — differential
   boundary (I3).
6. Builder + integration tests: `result.ilk()` → `result.message_type()`,
   `keri_events::Ilk::X` → `keri_events::MessageType::X` in
   `builder/{icp,rot,ixn,dip,drt}.rs`, `traits.rs` tests,
   `tests/transitions.rs` (also `latest_ilk()` → `latest_message_type()`,
   matching step 3's keri crate rename). `tests/frozen_surface.rs:39,42,69`:
   `use keri_events::ilk::Ilk;` → `use keri_events::message_type::MessageType;`,
   `type_name::<Ilk>()` → `type_name::<MessageType>()`, comment update.
7. Add a defensive boundary test pinning I1 at the PUBLIC dispatch layer:
   beside `error_unknown_message_type_at_public_dispatch` (the renamed test
   at `deserialize.rs` ~2525, which probes `"xxx"`), add a case where a
   well-formed event body's `t` is `"rct"` and assert
   `DeserializeError::UnknownMessageType(s)` with `s == "rct"` (typed error,
   no panic). One case for `"rct"` is enough (the other three codes are
   covered by the keri-events unit probe). Existing adjacent probes to leave
   alone (rename-sweep only): `unknown_ilk_is_typed` (`codec/event.rs:974`,
   `"xxx"`) → `unknown_message_type_is_typed`, `oversized_ilk_is_rejected`
   (`codec/event.rs:1110`) → `oversized_message_type_is_rejected`.

Expected outcome: keri-codec compiles clean. NOTE the two test-gate
carve-outs: `codex_tables_match_keripy` stays red until step 5 lands, and
`tests/transitions.rs` cannot even build until step 3 lands (keri-codec
dev-depends on keri-rs, and transitions calls `latest_ilk()`). Steps 2+3+5
verify jointly via `cargo nextest run -p keri-codec -p keri-rs` after all
three are in.

### Step 3 — keri crate: state rename
`PARALLEL OK with steps 2 and 4 (disjoint files) — depends on step 1`
`Mechanical — sonic-suitable`

Files: `crates/keri/src/state.rs`, `crates/keri/src/error.rs`.

1. `state.rs`: import `Ilk` → `MessageType` (line 26); field `latest_ilk` →
   `latest_message_type` (line 87); accessor `latest_ilk()` →
   `latest_message_type()` (lines 116-118); constructor sites at 230, 298, 340
   (`MessageType::Icp/Rot/Ixn`); doc comments at 116 and 335 ("ilk" →
   "message type").
2. `crates/keri/src/error.rs:80`: doc prose "ilk placement" → "message type
   placement".

Expected outcome: `cargo nextest run -p keri-rs` green.

### Step 4 — grep sweep for stragglers
`PARALLEL OK with steps 2 and 3 — depends on step 1`

Blast-radius check across fuzz/, benches/, examples/, and all crates:

```bash
rg -n '\bIlk\b|UnknownIlk|\bilk\b' --type rust -g '!target' .
```

Fix any hit outside the I3 differential-boundary exceptions
(`keripy_parity/`, corpus files, `scripts/`, `docs/keripy-parity/`,
historical `docs/superpowers/` specs/plans which are frozen records — do NOT
edit those). Fuzz workspaces (`fuzz/`, `fuzz-common/`, `fuzz-afl/`) are
separate workspaces — if any hit appears there, fix it and run
`cargo check` in that workspace.

### Step 5 — parity corpus + generator + ledger
`SEQUENTIAL — after step 2 (same-crate test coupling); files disjoint from steps 3/4`

Files: `crates/keri-codec/tests/corpus/keripy/parity/codex.jsonl`,
`scripts/keripy_parity_gen.py`, `docs/keripy-parity/ledger.md`.

1. `codex.jsonl`: add to each of the 4 rows `rct`, `qry`, `rpy`, `exn` a
   divergence field (keep JSON key order consistent with other divergent rows):
   `"divergence": "KEL-core ilk without event support in cesr — MessageType variants dropped in #242 until receipt/query/reply/exchange land; see docs/keripy-parity/ledger.md"`.
2. `scripts/keripy_parity_gen.py`: line 61 `KEL_CORE_ILKS` currently holds all
   9 codes. Split: `SUPPORTED_ILKS = {"icp","rot","ixn","dip","drt"}` and give
   `rct/qry/rpy/exn` the same divergence string as step 5.1 via the existing
   divergence-map mechanism (mirror how `ILK_DIVERGENCE` is applied at line
   108), so regenerating reproduces the hand-edited corpus byte-for-byte.
   Keep the script's keripy vocabulary (I3).
3. `docs/keripy-parity/ledger.md` lines 20-21: rewrite to state cesr
   implements the 5 KEL event ilks (`icp` `rot` `ixn` `dip` `drt`); `rct`
   `qry` `rpy` `exn` are recognized by keripy but deliberately unsupported
   pending real receipt/query/reply/exchange support (#242 dropped the dead
   enum variants). Keep the rest of the ledger untouched.

Expected outcome: `cargo nextest run -p keri-codec codex` green — the 4 rows
now surface as DIVERGENCE lines, not assertions.

### Step 6 — full verification
`SEQUENTIAL — last`

```bash
cargo fmt --all
cargo nextest run
cargo test --doc --workspace
```

All green, quote the summary lines. Do NOT run `nix flake check` (controller
runs the gate via the push hook). Do NOT commit.

## Verification

- `cargo nextest run` — full workspace green (was 1683 tests; count may shift
  by the added/removed cases — report the new count).
- `cargo test --doc --workspace` — doc examples green.
- `rg -n '\bIlk\b|UnknownIlk' --type rust -g '!target' crates/` — zero hits.
- `rg -nwi 'ilk' --type rust crates/` — hits ONLY in
  `keripy_parity/codex.rs` (family string + messages),
  `keripy_parity/mod.rs` (the `pub ilk: String` field mirroring the
  `events.jsonl` corpus key — do NOT rename it, corpus deserialization
  depends on the key name), and `keripy_parity/events.rs` (corpus-field
  access + prose). Everything else says "message type".

## Out of scope

- NO event-model consolidation (rot/drt twins, InceptionEvent ⊂
  DelegatedInceptionEvent) — separate design thread per the spec.
- NO re-adding of receipt/query/reply/exchange support.
- NO changes to `free-fn-budget.toml`, `clippy.toml`, `[lints]`, or any lint
  levels; no new `#[allow]`.
- NO edits to `docs/superpowers/` (frozen records), CHANGELOGs (release-plz
  owns them), or `Cargo.toml` versions.
- NO commits, no git operations beyond reading.
