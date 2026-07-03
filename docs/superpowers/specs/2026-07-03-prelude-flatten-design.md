# P2.1 · Prelude + flattened re-exports — Design

- **Issue:** [#31](https://github.com/devrandom-labs/cesr/issues/31) (milestone: Phase 2 · DevX & API)
- **Date:** 2026-07-03
- **Status:** approved, pre-implementation
- **Breaking:** No — purely additive re-exports (still recorded in CHANGELOG per the 0.x convention).

## Problem

The 6-crate → 1-crate extraction preserved module paths verbatim, leaving import
warts. The README advertises `use cesr::core::matter::matter::Matter;` — the
double `matter::matter` inception. There is no `prelude`. Flagship types are only
reachable through long module paths (`cesr::core::matter::Matter` works, but
`cesr::Matter` and `cesr::core::Matter` do not). First impressions of an API are
its import ergonomics.

## Research findings (posted to issue #31 before implementation)

### Prelude conventions
- **`std::prelude`** is dominated by **traits** (`Clone`, `Iterator`, `From`/`Into`,
  `Drop`) plus a few core types (`Option`, `Vec`, `String`, `Box`). Traits are the
  point: they must be in scope for method resolution, and one-by-one imports are the
  real friction. (Rust std docs, `std::prelude`.)
- **`rayon::prelude`** is almost purely traits (`ParallelIterator`,
  `IntoParallelIterator`) — `.par_iter()` will not resolve without them. (rayon docs.)
- **`std::io::prelude`** — traits again (`Read`, `Write`, `BufRead`, `Seek`).
- **`tokio`** shipped a grab-bag `tokio::prelude` in 0.x and **deliberately removed
  it at 1.0**; a re-glob-everything prelude is now treated as an anti-pattern.
  **`bytes`** and **`serde`** ship **no prelude** — they expose `Bytes` / `Serialize`
  at the crate root directly.
- **Conclusion:** a prelude earns its keep for **traits** (needed implicitly), not
  for concrete types (named explicitly, therefore imported explicitly anyway).

### Re-export patterns / `no_std` / docs
- Crate-root `pub use` re-exports are the idiomatic flattening tool. Each must be
  `#[cfg(feature = "…")]`-gated so a lifted type exists only when its module compiles.
- `#![cfg_attr(docsrs, feature(doc_cfg))]` is already enabled → the feature gate is
  rendered on docs.rs automatically.
- `#[doc(inline)]` on a re-export pulls the type's real docs onto the root/prelude
  page instead of a bare "Re-export" stub.

### SemVer
- Adding re-exports and a prelude is **additive → non-breaking**. Recorded in
  CHANGELOG anyway (0.x → the entry documents the new public paths).
- Removing the `matter::matter::Matter` inception path would be the *only* breaking
  option and buys nothing → **keep it, stop advertising it.**

## Design decisions (locked with user)

1. **Aggressive crate-root flatten** — lift most public *types* to `cesr::`.
2. **Prefix the loser** for name collisions — canonical winner keeps the bare name;
   the other gets a module-prefixed alias; module paths keep working.
3. **Traits-focused prelude** — traits + a handful of headliner types.

## Specification

### 1. Crate-root flat namespace (`src/lib.rs`)

Feature-gated `pub use` re-exports lifting each module's flagship **types** to
`cesr::`. Representative (not exhaustive — final list assembled from module-root
re-exports during implementation):

- `core`: `Matter`, `Verfer`, `Diger`, `Signer`, `Cigar`, `Labeler`, `Noncer`,
  `Prefixer`, `Saider`, `Texter`, `Verser`, `Number`, `Seqner`, `Siger`, `Dater`,
  `Tholder`, `MatterBuilder`, `Indexer`, `IndexerBuilder`, the `*Code` enums,
  `CesrVersion`.
- `crypto`: `KeyPair`, `Ed25519`, `Secp256k1`, `Secp256r1`, the error enums.
- `stream`: `CesrGroup`, `CesrMessage`, `CesrCodec`, `ColdCode`, `Tritet`, `Groups`,
  `GroupsV2`, `V1`, `V2`, `VersionStringV2`, `ParseError`, and the group structs.
- `keri`: `KeriEvent`, `Identifier`, `Ilk`, `Role`, `Seal`, `KeyState`,
  `Inception/Rotation/Interaction/Delegated*` event structs, `KeriError`.
- `serder`: `InceptionBuilder`, `RotationBuilder`, `InteractionBuilder`,
  `Delegated*Builder`, `SerializedEvent`, `SerderError`.

**Not lifted:**
- Free **functions** stay module-qualified (`cesr::b64::encode_int`,
  `cesr::stream::parse_message`, `cesr::crypto::verify`). The naming convention
  makes the module the domain qualifier; `cesr::encode_int` would violate it.
- Type-state plumbing structs (`IStart`, `WithCode`, `NeedsKeys`, `Ready`, …) — not
  API surface.
- Sealing traits (`crypto::Sealed`, `stream::Sealed`) — internal.
- Generic error names that would be ambiguous at root (`b64::Error`) stay
  module-qualified (`cesr::b64::Error`).

### 2. Collision handling

The **only** bare-name collision among module-root flagship re-exports is
`CesrVersion` (`core` + `stream`), confirmed by inventory scan.

- `core::CesrVersion` → **`cesr::CesrVersion`** (keeps bare name; CESR-version
  selection is a core concept).
- `stream::CesrVersion` → **`cesr::StreamCesrVersion`** (module-prefixed alias).
- Both remain reachable via their module paths (`cesr::core::CesrVersion`,
  `cesr::stream::CesrVersion`) unchanged.

Any further collision surfacing when the full list is assembled follows the same
rule (core/keri/serder win bare names over stream by convention; document each in
the CHANGELOG entry).

### 3. `cesr::prelude`

New `pub mod prelude` with feature-gated contents, designed for `use cesr::prelude::*`:

- **Traits (the payload):** `CesrEncode`, `KeriSerialize`, `KeriDeserialize`,
  `Algorithm`, `ConfigTrait`. (`CesrCodec` is a **struct**, not a trait — excluded
  from the traits set; available at root as a type.)
- **Headliner types** (so the glob alone lets a newcomer write code): `Matter`,
  `Verfer`, `Diger`, `Signer`, `CesrGroup`, `CesrMessage`, `KeriEvent`,
  `Identifier`.
- `#[doc(inline)]` on re-exports.

### 4. Docs & examples

- Fix README (~line 43) and any examples: `use cesr::core::matter::matter::Matter;`
  → `use cesr::Matter;` (and show `use cesr::prelude::*;`).
- The `matter::matter::Matter` path stays compilable; simply no longer advertised.

### 5. Testing

1. **Round-trip / resolution tests** — a `tests/` integration file that
   `use cesr::{Matter, Verfer, CesrGroup, …};` and `use cesr::prelude::*;`, then
   constructs/uses one value per lifted path. Proves every path resolves and no
   collision slipped through. This is the re-export layer's analogue of a
   round-trip test.
2. **Cross-feature-combination** — the resolution test compiles under the feature
   combinations nextest already exercises; gated re-exports must not break any.
3. **no_std / WASM** — existing `cesr-nostd` and `cesr-wasm` flake checks must stay
   green with the gated re-exports present.
4. Full `nix flake check` green.

## Acceptance criteria (from issue #31)

- [ ] Research recommendation captured (this doc + issue comment).
- [ ] `cesr::prelude::*` exists; flagship types reachable without redundant path
      segments (`cesr::Matter`).
- [ ] Breaking changes recorded in CHANGELOG (here: additive paths documented);
      `nix flake check` green; no_std/WASM intact.

## Out of scope

- P2.2 runnable examples (#32) and P2.3 error ergonomics (#33) are separate cards.
- No renaming of source types (the "rename at source" collision option was not
  chosen).
