# Workspace split phase 1 — carve `cesr-stream`, `keri-events`, `keri-codec`

**Issue:** [#192](https://github.com/devrandom-labs/cesr/issues/192)
**Status:** design — veto gate. Nothing moves before approval.
**Date:** 2026-07-17
**Related:** [#182](https://github.com/devrandom-labs/cesr/issues/182) (spine spec), [#193](https://github.com/devrandom-labs/cesr/issues/193) (phase 2 — blocked on this card)

## 1. Goal and non-goal

**Goal.** Mechanically carve three workspace crates out of the existing `stream`,
`keri`, and `serder` modules. Code moves, paths change.

**Non-goal — and this is the load-bearing constraint.** Zero redesign. No API is
improved, no name is fixed, no free function is collapsed, no error variant is
reshaped. The module APIs are known to be poor; repairing them is phase 2 (#193,
owner-driven). A change that is not "move a file or rewrite an import path" does
not belong in phase 1.

Every decision below was taken by asking which option is *mechanical*, not which
option is *better*.

## 2. Crate table

| Crate | Package | Lib name | Version | Contents | Depends on |
|---|---|---|---|---|---|
| cesr | `cesr-rs` | `cesr` | 0.9.0 → **0.12.0** (§2.1) | `b64` + `core` + `crypto` | — |
| cesr-stream | `cesr-stream` | `cesr_stream` | **0.1.0** | ex-module `stream` | `cesr` |
| keri-events | `keri-events` | `keri_events` | **0.1.0** | ex-module `keri` | `cesr` |
| keri-codec | `keri-codec` | `keri_codec` | **0.1.0** | ex-module `serder` | `cesr`, `cesr-stream`, `keri-events` |
| keri-rs | `keri-rs` | `keri` | 0.0.6 → **0.0.7** | unchanged | `cesr`, `keri-events`, `keri-codec` (behind `wire`) |

All three new names are **available on crates.io** (verified 2026-07-17), so
package name and lib name match — no `-rs` suffix dance. `cesr-rs` and `keri-rs`
remain the published names for the two existing crates for the reason recorded in
`cesr/Cargo.toml`: the bare `cesr` name is squatted (THCLab, v0.0.0).

**Naming is settled per #192 — do not relitigate.** `serder` dies as a name;
`cesr-stream` reclaims its spec-true original; the vocabulary crate is
`keri-events`; `crypto` and `b64` stay inside `cesr`.

### 2.1 Versions

New crates start at **0.1.0**. A version number is a claim about API stability,
not code maturity, and these three APIs are about to be redesigned in #193.
Starting them at `0.10.0` to match `cesr-rs` would fabricate nine minor releases
that never existed and assert a "ships as a set" coupling that the split exists
to dissolve — members version independently so `cesr` can sit still while
`keri-codec` churns. Maturity belongs in the README and the `description` field.

`cesr-rs` ends at **0.12.0**, reached in three steps rather than one. Each of the
three PRs (§6) strips a module from `cesr` and merges to `main` independently, so
each is its own breaking change and its own MINOR bump per the `0.x` SemVer
convention in CLAUDE.md:

| After PR | `cesr-rs` | Breaking change |
|---|---|---|
| 1 — keri-codec | 0.9.0 → **0.10.0** | `serder` leaves |
| 2 — cesr-stream | 0.10.0 → **0.11.0** | `stream` leaves; `async` moves |
| 3 — keri-events | 0.11.0 → **0.12.0** | `keri` leaves; `internals` moves |

Collapsing these into a single 0.10.0 would require holding the bump until PR 3,
which would publish two `main` states whose version does not describe their API —
the exact thing the version is for. Three bumps is the honest accounting of three
breaking merges.

Each new crate's `cesr` dependency requirement therefore pins whatever `cesr` is
current when that crate is born: `keri-codec` starts at `0.10`, `cesr-stream` at
`0.10`, `keri-events` at `0.11`, and PR 3 raises all of them to `0.12`.

`keri-rs` 0.0.6 → **0.0.7**: dependencies re-pointed.

## 3. Dependency DAG

```
cesr  (b64 + core + crypto)          CESR substrate: alphabet, code tables,
  │                                  version grammar, key math
  ├──► cesr-stream                   framing: counters, groups, cold-start,
  │                                  TextStream, CesrMessage
  ├──► keri-events                   vocabulary: events, seals, thresholds,
  │                                  Identifier, Toad
  └──► keri-codec  ◄── depends on all three
         ▲                           events <-> canonical JSON, SAID,
         │                           EventMessage::parse / frame_v1
      keri-rs                        unchanged (deps re-pointed; codec behind `wire`)
```

**The DAG is acyclic in production code.** Verified by enumerating cross-module
references:

```bash
cd cesr/src
for m in b64 core crypto keri serder stream; do
  echo "--- $m:"
  rg -o 'crate::(b64|core|crypto|keri|serder|stream)\b' "$m" -g '*.rs' --no-filename | sort | uniq -c | sort -rn
done
```

The one edge that would cycle — `crypto` → `keri` — is **test-only**: a single
import at `cesr/src/crypto/verify.rs:193` (`use crate::keri::SigningThreshold;`)
inside the `#[cfg(test)]` module opened at line 181, used at lines 643–644.
Handling in §5.

## 4. What moves where

### 4.1 Source

| From | To | Rewrite |
|---|---|---|
| `cesr/src/stream/` | `cesr-stream/src/` | `crate::stream::` → `crate::` |
| `cesr/src/keri/` | `keri-events/src/` | `crate::keri::` → `crate::` |
| `cesr/src/serder/` | `keri-codec/src/` | `crate::serder::` → `crate::` |

In every moved file, references to what stayed behind become external crate
paths:

- `crate::b64::` → `cesr::b64::`
- `crate::core::` → `cesr::core::`
- `crate::crypto::` → `cesr::crypto::`

And in `keri-codec`, references to its siblings:

- `crate::stream::` → `cesr_stream::`
- `crate::keri::` → `keri_events::`

Per the mandatory import style (CLAUDE.md), all rewritten imports stay at file
top; no inline `use`, no deep inline path qualification.

### 4.2 In-tree test modules

`keripy_diff` and `keripy_parity` are declared inside `cesr/src/lib.rs` (lines
128 and 132) as `#[cfg(test)] mod`s gated on `all(feature = "serder", feature =
"std")`. Both move to **`keri-codec`**, where their gate becomes unconditional
`#[cfg(test)]` — the `serder` feature that gated them no longer exists.

### 4.3 Tests

Single-crate integration tests follow their code:

| Test | Modules touched | Home |
|---|---|---|
| `allocation.rs` | b64, core, stream | `cesr-stream` |
| `prelude.rs` | core | `cesr` |
| `properties.rs` | keri | `keri-events` |

The remaining suites span the whole graph and go to **`keri-codec/tests/`**:

| Test | Modules touched |
|---|---|
| `frozen_surface.rs` | b64, core, crypto, keri, serder, stream |
| `spine.rs` | core, crypto, keri, serder, stream |
| `spine_write.rs` | core, crypto, keri, serder, stream |
| `kel_chain.rs` | core, keri, serder |
| `serder_allocation.rs` | core, keri, serder |
| `transitions.rs` | crypto, keri, serder |
| `differential.rs` | keri, serder |

**Why `keri-codec` and not a new conformance crate.** These suites genuinely test
the *system*, not a crate, and a non-published `cesr-conformance` member is the
better end state. But creating a crate and deciding what belongs in it is a
structural judgment call, and phase 1 does not make structural judgment calls it
can defer. `keri-codec` sits at the bottom of the DAG and already depends on
everything, so the move is files plus import paths and nothing else. Phase 2 can
lift them out in one commit.

Splitting these suites per-crate was rejected: a byte-identity test that sees
half the pipeline is not the same test, which violates the "pass unchanged"
requirement in §7.

### 4.4 The prelude fragments

`cesr/src/lib.rs:99-127` defines `pub mod prelude`, which re-exports from all
three departing modules:

| Prelude item | Module | Lands in |
|---|---|---|
| `Algorithm` | crypto | `cesr` |
| `Diger`, `Matter`, `Signer`, `Verfer` | core | `cesr` |
| `ConfigTrait`, `Identifier`, `KeriEvent` | keri | `keri-events` |
| `KeriDeserialize`, `KeriSerialize` | serder | `keri-codec` |
| `CesrEncode`, `CesrGroup`, `CesrMessage` | stream | `cesr-stream` |

Post-split `cesr` cannot name the departed crates, so **the prelude fragments**:
each crate gets a `prelude` carrying exactly the items that were in `cesr`'s
prelude from its own module — no more, no fewer. `cesr::prelude` retains the
crypto and core rows; the `#[cfg(feature = ...)]` attributes on every re-export
drop, since the features are gone.

This shrinks `cesr::prelude`, which is a breaking change — but it is a mechanical
consequence of the move rather than a design decision, and is covered by the
breaking bumps in §2.1. Whether each new crate *should* have a prelude, and
what belongs in it, is a #193 question. Phase 1 preserves what exists.

`cesr/tests/prelude.rs` references only `cesr::core` items and stays with `cesr`
unchanged.

### 4.5 The `crypto` → `keri` back-edge

`cesr` gains a **dev-dependency on `keri-events`**. Cargo permits
dev-dependency cycles (they are not build cycles), so `cesr` → dev → `keri-events`
→ `cesr` resolves. The test at `cesr/src/crypto/verify.rs` moves nowhere and
asserts the same thing.

The alternatives — relocating a crypto test into the vocabulary crate, or
dropping the threshold assertion — both change what is tested. A dev-dep changes
nothing.

### 4.6 Benches and examples

Split by their existing `required-features` in `cesr/Cargo.toml`:

| Item | `required-features` today | Home |
|---|---|---|
| bench `base64` | `core` | `cesr` |
| bench `matter`, `counter`, `stream` | `stream` | `cesr-stream` |
| bench `serder` | `serder` | `keri-codec` |
| example `encode_primitive` | `core` | `cesr` |
| example `keypair_sign_verify` | `crypto` | `cesr` |
| example `concurrent_parse`, `parse_stream` | `stream` | `cesr-stream` |
| example `incept_aid`, `multisig_threshold_icp`, `kel_chain`, `delegated_inception` | `serder` | `keri-codec` |

Placement is by what each item references, verified rather than assumed —
`matter` declares `required-features = ["stream"]` and genuinely needs framing
(it references `cesr::stream::qb`), so it lands in `cesr-stream` despite its name
suggesting `core`.

`required-features` entries naming dissolved module features are **dropped**, not
rewritten: once a bench lives in the crate that owns its code, the feature that
gated it is the crate itself.

### 4.7 Fuzz

Both fuzz workspaces stay isolated non-member workspaces (CLAUDE.md).

| Crate | Today | After |
|---|---|---|
| `fuzz` | `cesr = { package = "cesr-rs", features = ["stream"] }` | `cesr-stream` |
| `fuzz-common` | `cesr = { package = "cesr-rs", features = ["stream", "serder"] }` | `cesr-stream` + `keri-codec` |
| `fuzz-afl` | via `fuzz-common` | unchanged |

Target sources rewrite `cesr::stream::` → `cesr_stream::`, `cesr::serder::` →
`keri_codec::`, `cesr::keri::` → `keri_events::`; `cesr::core::` stays.

### 4.8 keripy differential harness

`scripts/keripy_*_gen.py` (five generators plus `KERIPY_PIN`) stay at the repo
root. Any path they emit into or read from moves with the tests in §4.3. Test
names must continue to contain `keripy` or the nightly filter never runs them.

## 5. Feature map

### 5.1 Before

`cesr-rs` today: `default = ["std", "core", "b64"]`; environment gates `std`,
`alloc`; module gates `b64`, `core`, `crypto`, `stream`, `keri`, `serder`; extras
`async`, `internals`, `test-utils`. `keri-rs`: `default = ["std"]`, plus `alloc`,
`wire`.

### 5.2 After

| Feature | Fate |
|---|---|
| `b64`, `core`, `crypto` | **dissolve** — always-on within `cesr` |
| `stream`, `keri`, `serder` | **dissolve** — become crate dependencies |
| `std`, `alloc` | **survive**, per crate |
| `async` | **survives** → `cesr-stream` (`tokio-util`, `futures-core`) |
| `test-utils` | **survives** → `cesr` |
| `wire` | **survives** → `keri-rs` (now enables `keri-codec`) |
| `internals` | **survives** → `keri-events` |

`cesr` default becomes `["std"]`; the module gates it named are gone.

### 5.3 `internals` — why it survives

`internals` gates exactly five all-field constructors:

| Item | Location |
|---|---|
| `InceptionEvent::new` | `cesr/src/keri/event/inception.rs:36` |
| `RotationEvent::new` | `cesr/src/keri/event/rotation.rs:36` |
| `InteractionEvent::new` | `cesr/src/keri/event/interaction.rs:24` |
| `DelegatedInceptionEvent::new` | `cesr/src/keri/event/delegation.rs:19` |
| `DelegatedRotationEvent::new` | `cesr/src/keri/event/delegation.rs:60` |

Today `serder` reaches them via the in-crate feature. Post-split `keri-codec` is
a different crate, and Cargo features cannot express "visible to that crate
only."

**Decision: keep `internals` as a feature on `keri-events`, enabled by
`keri-codec`.** #192's own feature map says only capability flags survive, and
this is a deliberate, scoped deviation from it.

The alternative — making the five constructors plain `pub` — is *not mechanical*.
It is a permanent public-API expansion performed under cover of a file move, and
it expands precisely the surface #193 exists to redesign. Carrying `internals`
across the boundary is a true no-op: Cargo's feature unification means the
feature behaves post-split exactly as it does today (additive, visible to anyone
who enables it), so the privacy story neither improves nor degrades. Phase 1
changes paths only. #193 deletes the feature as a deliberate surface decision
rather than inheriting five constructors it never chose to publish.

## 6. Landing order — sequential PRs off `main`

**Order: `keri-codec` → `cesr-stream` → `keri-events`.** Each PR branches off
fresh `main` after the previous merges. Each intermediate state compiles and
passes the full gate.

### 6.1 Why this order is forced

The intuitive staging — carve the leaf-most crate first — **does not compile**.
`cesr-stream` depends on `cesr`, but `serder` would still be inside `cesr` and
depends on `cesr-stream`. That is `cesr` → `cesr-stream` → `cesr`: a hard Cargo
build cycle, not the permitted dev-dependency kind. Carving `keri-events` first
hits the same wall.

The rule: **nothing can leave `cesr` while `serder` is still inside it and
depends on the thing leaving.** `serder`'s edges are production, not test —
`serder/error.rs:15`, `serder/serialize.rs:30-32`, `serder/message.rs:35-37` for
`stream`, and 89 references for `keri`. So `serder` leaves first.

| Step | PR | `cesr` retains | New crate depends on |
|---|---|---|---|
| 1 | `keri-codec` | b64, core, crypto, keri, stream | `cesr` w/ `stream`+`keri`+`internals` |
| 2 | `cesr-stream` | b64, core, crypto, keri | `cesr` |
| 3 | `keri-events` | b64, core, crypto | `cesr`; `cesr` gains dev-dep (§4.4) |

At step 1 `keri-codec` depends on `cesr` *with the module features still on* —
the features dissolve as their modules leave in steps 2 and 3.

### 6.2 Why sequential and not stacked

The ordering constraint in §6.1 is real but invisible in a diff — it depends on
today's edge structure, which a reviewer cannot see from the patch. Stacking puts
that fragility on top of a merge pattern that has already caused a mis-merge on
this repo (spine phase 1: #184 auto-merged into the phase-1 branch instead of
`main`, nuking the head branch and auto-closing #185). Sequential costs three
serialized gate runs — cheap against a mis-merge.

One atomic PR was rejected for the opposite reason: a ~40k-line diff cannot be
veto-reviewed, which defeats the gate this card exists to pass.

**Known weakness, stated plainly:** step 1 is the largest PR (`serder` is ~10,250
lines) and also carries the cross-crate suites from §4.3, so the "small
reviewable PRs" benefit of sequencing is weakest exactly where the risk is
highest. Steps 2 and 3 are comparatively clean. PR 1 is the veto-review that
matters.

### 6.3 Crate-name reservation

Reserve `cesr-stream`, `keri-events`, `keri-codec` on crates.io (reserve-crate
workflow) **before step 1**. All three verified available 2026-07-17.

## 7. Gates

The single gate remains `nix flake check` (CLAUDE.md). Per-crate clippy and
nextest; wasm and no_std builds where applicable. `[workspace.lints]` and
`[workspace.dependencies]` stay shared from the root virtual manifest.

### 7.1 Tripwires — mechanical remapping only

**`cesr-fn-ratchet`.** Budget keys in `free-fn-budget.toml` rename and their
directories become crate roots:

| Today | After | Budget |
|---|---|---|
| `stream` = 2 | `cesr-stream` | 2 |
| `keri` = 1 | `keri-events` | 1 |
| `serder` = 58 | `keri-codec` | 58 |
| `b64` = 6, `core` = 0, `crypto` = 6 | unchanged (still `cesr`) | 6 / 0 / 6 |
| `keri-rs` = 0 | unchanged | 0 |

**Counts do not change. A move is not a fix.** The ratchet's rule holds: budgets
may only go down, and lowering one requires the count to have actually dropped.
`serder`'s 58 free functions are the strongest argument for #193 and they must
survive phase 1 intact so #193 inherits an honest baseline.

**`cesr-version-owner`.** The file list extends from `${./cesr/src} ${./keri/src}`
to all five crate source roots. The owner is unchanged:
`cesr/src/core/version.rs`, which stays in `cesr`. The grammar tokens it trips on
are unchanged.

**`cesr-keri-boundary`.** Today it asserts `keri/Cargo.toml` names neither
`"internals"` nor `"test-utils"`. Post-split `internals` lives on `keri-events`
and `test-utils` on `cesr`, so the check's intent — keri-rs consumes public API
only — now requires guarding those feature names across *all* of keri-rs's
dependencies. The rg pattern already matches on the feature strings anywhere in
the file, so this is a comment update plus a re-verification, not new logic.

### 7.2 Frozen behavior

**Wire behavior is law.** The keripy differential suites and the spine
byte-identity suites must pass **unchanged** — not adapted, not re-baselined.
Their assertions are the definition of "mechanical": if a byte moves, the carve
is wrong.

### 7.3 Release plumbing

Per-crate `release-plz` config; a `CHANGELOG` per crate. CLAUDE.md's module table
becomes a crate table, and the `[workspace.metadata.crane] name = "cesr"` entry
needs review against a five-member workspace.

## 8. Acceptance

Phase 1 is done when:

1. Five crates exist per §2, with the DAG in §3 and no production cycle.
2. `nix flake check` is green, including the three remapped tripwires (§7.1).
3. keripy differential + spine byte-identity suites pass **unchanged** (§7.2).
4. `free-fn-budget.toml` counts are identical to today's, under renamed keys.
5. `keri-rs` builds with and without `wire`.
6. Fuzz workspaces build and `cesr-fuzz-replay` is green.
7. No API changed: no signature, name, error variant, or visibility differs from
   `main` except the mechanical consequences of the move — module paths becoming
   crate paths, `internals` moving crate, and the three boundary-forced `pub`
   promotions recorded in §10.1.

Point 7 is the veto criterion. Anything else is #193.

## 8a. Phase 1 (PR 1 — keri-codec) execution record

The carve surfaced five things the design did not anticipate. All are consequences
of the crate boundary making previously-invisible coupling legible, and each was
resolved without changing wire behavior (keripy differential + spine byte-identity
green throughout). Recorded here so #193 inherits the reasoning, not just the code.

### 8a.1 Three `pub(crate)` → `pub` promotions (owner decision: promote)

`serder` reached three `cesr` items through the (former) shared-crate privacy that
the boundary now forbids:

| Item | Location | Was | Now |
|---|---|---|---|
| `VERSION_SIZE_MAX` | `cesr/src/core/version.rs` | `pub(crate) const` | `pub const` |
| `scan_object` | `cesr/src/keri/seal.rs` | `pub(crate) fn` | `pub fn` |
| `ColdCode::detect` | `cesr/src/stream/cold.rs` | `pub(crate) fn` | `pub fn` |

**Decision: promote to plain `pub`.** This is *not* inconsistent with keeping
`internals` a feature (§5.3). Gating these behind `internals` would need
`#[cfg(feature)] pub` / `#[cfg(not)] pub(crate)` duplicate declarations — they are
used inside `cesr` too, unlike the five keri constructors — which is restructuring,
forbidden in phase 1. Promotion is the honest statement that `serder` genuinely
reached these; the split *revealed* pre-existing porousness rather than creating it.
All three land on #193's desk as candidates for a designed-away seam.

### 8a.2 The `render` orphan-rule break → local `pub(crate)` trait

`SerializationKind::render` was an *inherent impl on a `cesr`-owned type*, living in
`serder`'s file — legal only while they shared a crate. The boundary makes it an
orphan-rule violation that no `pub` can fix. Resolved with a `pub(crate)` trait
`RenderBody` local to `keri-codec`, implemented for the foreign `SerializationKind`.
Zero public surface (the method was already `pub(crate)`); call sites unchanged.
This is the first instance of the exact pattern #193 will generalize:
crate-local traits implemented for foreign types, replacing cross-module inherent
impls.

### 8a.3 `keripy_diff` belongs with the substrate, not the codec

The design's §4.3 move-list sent `keripy_diff` to `keri-codec`. It is actually a
CESR-substrate differential suite (matter/counter/indexer/stream vs keripy) with a
single incidental codec call (`to_qb64_string`, a pass-through to the core
`Matter::to_qb64()`). It stays in `cesr` as a `stream`-gated in-tree test and
travels with `stream` in PR 2; its substrate corpus (matter/counter/indexer/stream
`.jsonl`) moves with it, while the `parity/` corpus stays with `keripy_parity` in
`keri-codec`.

### 8a.4 `properties.rs` cannot live in keri-events (amends §4.3)

`keri/tests/common/mod.rs` builds genuine signed events using the codec, and every
keri integration suite — including `properties.rs` — depends on it. Because
`keri-events` has *no serialization of its own*, its property tests cannot construct
events without the codec. **§4.3 is amended:** `properties.rs` moves to `keri-codec`,
not `keri-events`. Consequently all four `keri/tests` suites (`differential`,
`transitions`, `spine`, `properties`) plus the shared `common`/`corpus`/`fixtures`
move to `keri-codec`, and `keri/tests` empties entirely — keri-rs has no integration
test that does not need the codec, which is the honest shape of a vocabulary crate
with no wire format.

### 8a.5 keri-events stays a separate crate (owner decision, PR 3)

Considered mid-execution: fold `keri-events` into `cesr` as a `types` module, since
its contents are pure data over core primitives. **Decision: keep it a separate
crate.** `cesr` is the CESR encoding substrate (a general spec used by KERI, ACDC,
and others); `keri-events` is KERI-specific protocol vocabulary. Folding KERI types
into `cesr` would erase the CESR/KERI layer boundary the split exists to draw, and
make every CESR-only consumer carry KERI vocabulary. No change to §2/§3.

## 9. Open items for #193 (explicitly NOT phase 1)

- The five `internals` constructors — publish deliberately or design them away.
- `keri-codec`'s 58 free functions.
- Lifting the cross-crate suites (§4.3) into a `cesr-conformance` member.
- keripy-lexicon type renames per the Rust-native naming rule.
