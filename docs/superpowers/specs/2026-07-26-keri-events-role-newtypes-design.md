# keri-events role newtypes + #193 close — design

**Date:** 2026-07-26
**Issue:** #193 (workspace split phase 2 — per-crate redesign). Closes the two remaining boxes: `keri-events` design pass, `cesr-stream` design pass.
**Branch base:** `refactor/193-p4-p5-ordinal-qb64-dedup` (P4/P5/P6 already landed).

## Naming law (Joel, 2026-07-26)

Names come from the **KERI/CESR spec**, never keripy. Each candidate is verified against the actual spec text (KERI IETF draft, CESR ToIP spec) before deciding — keep if it is spec vocabulary, rename if it is only a keripy Python class name. Confirmed keep: `Seal`, `Threshold`, `Identifier`, `Inception`, `Rotation`, `Interaction`, `Establishment`, `Receipt`, `Primitive`, `Group`. Confirmed rename: everything below.

## Problem

The keripy primitive names used throughout keri-events (`Verfer`, `Diger`, `Saider`, `Prefixer`) are **cesr type aliases** over `Matter<'a, C>`:

```rust
pub type Verfer<'a>   = Matter<'a, VerKeyCode>;   pub type Prefixer<'a> = Matter<'a, VerKeyCode>;
pub type Diger<'a>    = Matter<'a, DigestCode>;   pub type Saider<'a>   = Matter<'a, DigestCode>;
```

Aliases are transparent, so within a code family they collapse to **one** type: `Verfer ≡ Prefixer` (both `Matter<VerKeyCode>`), `Diger ≡ Saider` (both `Matter<DigestCode>`). The type system distinguishes by CESR code, not by semantic role — so a verification key (`k`) and a basic AID prefix (`i`) are interchangeable to the compiler, as are a next-key digest (`n`) and a SAID (`d`). Cross-family confusions are already compile errors; these **within-family** ones are not, and are caught only by runtime differential tests.

## Decision — Option A: distinct role newtypes in keri-events

Role is not on the wire (a parser reading a `VerKeyCode` cannot know key-vs-prefix; role comes from which field the value lands in). Therefore role is a **domain-layer** concept: the newtypes live in `keri-events`, wrapping cesr `Matter`. `cesr` stays pure substrate (`Matter<C>` + `*Code`); keri-events stops importing cesr's role aliases.

### New module `keri-events/src/primitive.rs`

```rust
pub struct VerifyingKey<'a>(Matter<'a, VerKeyCode>);   // was Verfer   — event keys `k`
pub struct Digest<'a>(Matter<'a, DigestCode>);         // was Diger    — next-key commitments `n`
pub struct Said<'a>(Matter<'a, DigestCode>);           // was Saider   — SAID `d`
pub struct BasicPrefix<'a>(Matter<'a, VerKeyCode>);    // was Prefixer — Identifier::Basic, seal `i`/`bi`
```

Each carries:
- `Deref<Target = Matter<'a, C>>` for read-through access (no method boilerplate).
- an explicit constructor `fn from_matter(Matter<'a, C>) -> Self` (naming the role is the safety checkpoint) — plus `From<Matter<..>>` for `?`/`.into()` ergonomics at construction sites.
- `into_static(self) -> Self<'static>`.
- derives: `Clone, Debug, PartialEq, Eq` (matching current alias usage).

Assigning a `VerifyingKey` into a `BasicPrefix` field is now a **compile error**. Gap closed at the exact locus of field-placement bugs.

### Domain retyping

- `Identifier` (identifier.rs): `Basic(BasicPrefix)` | `SelfAddressing(Said)` (was `Prefixer` / `Saider`). Reuses `Said` for the self-addressing prefix — a transferable prefix *is* a SAID.
- `Seal` (seal.rs): `i`/`bi` → `BasicPrefix`; `d`/`rd` → `Said`; `s` → `Number` (kept — substrate integer, not keripy lexicon); `t` → `Verser` (**open item**, see below).
- Event constructors (`InceptionEvent::new`, `RotationEvent::new`, delegated, interaction): `keys: Vec<VerifyingKey>`, `next: Vec<Digest>`, `said: Said`, `i: Identifier`.
- `Ilk` → `EventKind` (ilk.rs; `Ilk::Icp/Rot/Ixn/Dip/Drt` → `EventKind::…`; export in lib.rs).
- `Role::Indexer` variant — verify against KERI spec roles before touching; rename only if not a spec role.

## cesr-stream pass — confirm + tick, no code change

The design-review found it already tight (0 owned keripy names, 0 free `pub fn`, no frame-size duplication — killed in #199, `keripy_diff` correctly `#[cfg(test)]+std` gated). Action: verify the gate is green, note in the PR why no restructure, tick the box. No source edits.

## Scope / sequencing

- **keri-codec constructs keri-events structs** from parsed `Matter`. Retyping keri-events fields forces keri-codec's read path to wrap `Matter → newtype` at each construction site. The workspace cannot compile split across PRs → **keri-events + keri-codec land in one PR** (a controlled, called-out exception to #193's "one crate at a time"; unavoidable for a public data-type change).
- **cesr alias fate** becomes a small follow-on: once keri-events no longer imports them, only cesr-stream/keri-codec's codec layer references `Verfer`/`Diger`/etc. Rename-to-spec or remove later, lower stakes. Not in this PR.

## Open items

- **`Verser`** (Seal::Kind `t`, version/genus tag): keripy name, not spec vocabulary, but its spec replacement is unresolved (the CESR spec talks about "version string" / "genus-version", not a single primitive noun). Resolve the spec term before renaming; keep `Verser` this pass and track separately rather than invent a name.
- **`Role::Indexer`**: confirm whether "indexer" is a KERI spec role name before deciding keep/rename.

## Testing

- Round-trip: existing spine byte-identity + keripy differential corpus must stay green (wire behavior frozen — the law for every #193 pass). Newtypes are `Deref`-transparent and encode via the inner `Matter`, so wire bytes are unchanged by construction.
- Compile-time probes: add a `#[test]` (or trybuild-style doc) asserting a `VerifyingKey` cannot be assigned where a `BasicPrefix` is expected, i.e. the newtypes are genuinely distinct (a test that fails to compile if the distinction regresses).
- Covariance probes already in event/mod.rs, seal.rs must still pass (newtypes stay covariant in `'a`).
- Feature-combination + wasm + no_std builds green via `nix flake check`.

## Non-goals

- Renaming `Matter`/`Counter`/`Indexer` (cesr-core substrate, massive blast radius) — deferred, not opened.
- Making `Prefix` a single unified type — `Identifier` already models the family split correctly.
