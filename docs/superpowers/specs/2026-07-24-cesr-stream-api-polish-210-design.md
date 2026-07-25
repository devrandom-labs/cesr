# cesr-stream API polish (#210) — design

Part of #193 (API redesign for `cesr-stream`). Addresses the medium-severity
findings from the API-surface review. Pre-1.0 active development: breaking
changes are allowed but must be intentional and recorded in each crate's
`CHANGELOG`.

## Decisions (locked)

| Finding | Decision |
|---------|----------|
| F1+F4 — `Groups`/`GroupsV2` duplication + read/write V-selection asymmetry | Collapse the iterator to `Groups<'a, V: Version = V1>`; keep `CesrGroup::parse` / `parse_v2` value-level (no turbofish). |
| F2 — `from_sigers` keripy-contraction name | Rename to `from_indexed_signatures`. |
| F3 — owned-`Bytes` read model vs zero-copy claim | Embrace copy-once: docs only, no signature change. |
| F5 — `qb2_to_qb64` module-name repetition + owned-`Vec` returns | Rename to `qb2::to_text` / `qb2::from_text`. Defer write-into-buffer variants to a separate perf issue. |

## Scope boundary

In scope: F1, F2, F4 fully; F3 as documentation; F5 as rename only.

Out of scope (deferred, note in the PR):

- F3 borrowing/lifetime-carrying read path — a future decision if truly
  zero-copy becomes a hard goal. Embracing copy-once now does **not** foreclose
  it.
- F5 write-into-buffer variants (`encode_count`/qb2 into `&mut BytesMut` to
  avoid per-call `Vec` alloc) — belongs in a perf issue where it can be
  benchmarked.
- The `Siger`/`Diger`/… element assoc-type contractions — originate in
  `cesr::core::primitives`, out of scope for `cesr-stream`.

## F1 + F4 — collapse the group iterator

`Groups<'a>` and `GroupsV2<'a>` (group/mod.rs) are near-verbatim: identical
struct shape, identical `Iterator` body, differing only in which parse core they
call (`CesrGroup::parse_bytes_at` vs `parse_bytes_v2_at`, which in turn select
`read_counter_v1`/`dispatch_v1` vs the `_v2` twins).

The sealed `Version` trait and its `V1`/`V2` markers (version.rs) already carry a
value-level `const VERSION: CesrVersion`. That is the selection lever.

### Shape

```rust
pub struct Groups<'a, V: Version = V1> {
    input: &'a [u8],
    buf: Option<Bytes>,
    cursor: usize,
    version: PhantomData<V>,
}

impl<'a, V: Version> Groups<'a, V> {
    #[must_use]
    pub const fn over(input: &'a [u8]) -> Self {
        Self { input, buf: None, cursor: 0, version: PhantomData }
    }
}

impl<V: Version> Iterator for Groups<'_, V> {
    type Item = Result<CesrGroup, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        let buf = self.buf.get_or_insert_with(|| Bytes::copy_from_slice(self.input));
        let buf_len = buf.len();
        if self.cursor >= buf_len {
            return None;
        }
        let parsed = match V::VERSION {
            CesrVersion::V1 => CesrGroup::parse_bytes_at(buf, self.cursor),
            CesrVersion::V2 => CesrGroup::parse_bytes_v2_at(buf, self.cursor),
        };
        match parsed {
            Ok((group, rest)) => {
                self.cursor = buf_len - rest.len();
                Some(Ok(group))
            }
            Err(e) => {
                self.cursor = buf_len;
                Some(Err(e))
            }
        }
    }
}
```

- `parse_bytes_at` / `parse_bytes_v2_at` are same-module `fn`s — callable from
  the generic `next`.
- Default `V = V1` keeps `Groups::over(x)` source-compatible for the common V1
  case. V2 call sites become `Groups::<V2>::over(x)`.
- `GroupsV2` struct + its impls are deleted.
- `Debug` prints `"Groups"` for both versions (no per-version struct name).

### Read/write symmetry (F4)

After the collapse, the read iterator selects its version by type parameter
(`Groups<V>`), matching the write side's `CesrEncode<V>`. The one-shot
`CesrGroup::parse` / `parse_v2` stay value-level deliberately — a type-level
`parse::<V>` would force turbofish at every call site for no ergonomic gain.

### Touch points

- `lib.rs:71` — `pub use group::{Groups, GroupsV2};` → `pub use group::Groups;`.
- group/mod.rs — delete `GroupsV2` struct + `impl`s; make `Groups` generic.
- group/mod.rs Debug test (~line 2267) — expected string `"GroupsV2 { … }"` →
  `"Groups { … }"`.
- group/mod.rs `GroupsV2::over` test call sites → `Groups::<V2>::over`.

**Breaking:** `GroupsV2` removed, `Groups` gains a (defaulted) type parameter.

## F2 — rename `from_sigers`

`Siger` is a keripy contraction; the naming convention bans keripy contractions
as names this crate mints. Rename the builder on both `ControllerIdxSigs` and
`WitnessIdxSigs` (kinds.rs:639, 657):

```
from_sigers  →  from_indexed_signatures
```

Chosen over `from_signatures` because the counter codes are
`ControllerIdxSigs` / `WitnessIdxSigs` — *indexed* signatures, and the name
should carry that distinction.

### Touch points

- kinds.rs:639, 657 — the two method definitions.
- Doc cross-references: mod.rs:150, kinds.rs:650.
- keri-codec `src/serialize.rs` test callers (528, 537, 553, 554, 572, 589,
  607).
- kinds.rs test module `mod from_sigers` and its test-fn names.

**Breaking:** public method rename.

## F3 — embrace copy-once (docs only)

`CesrGroup`/`Group`/`Frame` carry no input lifetime; `parse` does
`Bytes::copy_from_slice` once, then hands out O(1) slices. That is "copy-once,"
not zero-copy. The docs overpromise in places.

Action: sweep group/mod.rs docstrings and reword every "zero-copy" claim that
overpromises to the honest model — *one copy into a shared `Bytes` on the first
`next()`, O(1) refcounted slices thereafter*. No signature, type, or name
change.

Known spots: the "Zero-copy parsing core" doc on `parse_bytes` (~line 618), the
`CesrGroup::parse` doc (~588–589), and the two iterator docs (~763–766, and the
former GroupsV2 doc merged into the collapsed `Groups`). Grep `zero-copy` /
`zero copy` in group/mod.rs to find the full set.

## F5 — qb2 rename (rename only)

`qb2_to_qb64` repeats the module name (qb2.rs:56). Rename the pair to drop the
repetition:

```
qb2_to_qb64  →  qb2::to_text     (qb2 binary → qb64 text)
qb64_to_qb2  →  qb2::from_text   (qb64 text → qb2 binary)
```

### Touch points

- qb2.rs:24, 56 — the two fn definitions.
- `lib.rs:73` — `pub use qb2::{qb2_to_qb64, qb64_to_qb2};` →
  `pub use qb2::{from_text, to_text};`.
- keripy_diff/stream.rs:9, 35 — callers.
- qb2.rs test names referencing the old names.

Write-into-buffer variants deferred (see Scope boundary).

**Breaking:** public function renames.

## Testing

Categories-first (per CLAUDE.md):

1. **Round-trip / parity.** After the collapse, `Groups::<V1>::over` and
   `Groups::<V2>::over` reproduce, element-for-element, what the old
   `Groups`/`GroupsV2` produced over the same input (existing iterator tests,
   retargeted). qb2 round-trip (`to_text(from_text(x)) == x` and the inverse)
   under the new names.
2. **Defensive boundary.** Existing truncated/misaligned/oversize-count tests
   carry over unchanged in behavior; only names/paths update.
3. **Cross-feature.** `nix flake check` runs nextest across feature combos plus
   the wasm and no_std builds — no feature-specific code added, so this is
   coverage, not new surface.
4. **Bug-probe:** n/a — this is a rename + collapse, no new invariant.

No test may be a green test documenting a removed name; renamed tests assert the
same specific values as before.

## Gate

`nix flake check` only (clippy, fmt, taplo, audit, deny, nextest, doctest, wasm,
no_std, version-owner tripwire, fn-ratchet tripwire).

- fn-ratchet: qb2 stays 2 free `pub fn`s (net zero); the `Groups` collapse
  removes a *struct*, not a free fn; F2 renames *methods*. Ratchet budgets
  unaffected.
- version-owner: no version-string grammar tokens introduced outside
  version.rs.

## CHANGELOG

`crates/cesr-stream/CHANGELOG.md` unreleased section records, as breaking:

- `GroupsV2` removed; `Groups` is now `Groups<'a, V: Version = V1>` (use
  `Groups::<V2>` for V2 streams).
- `ControllerIdxSigs::from_sigers` / `WitnessIdxSigs::from_sigers` renamed to
  `from_indexed_signatures`.
- `qb2_to_qb64` / `qb64_to_qb2` renamed to `qb2::to_text` / `qb2::from_text`.

`crates/keri-codec/CHANGELOG.md`: no public change (only test-internal call-site
updates), so no entry required.
