# #160 — mixed-code SAID verify + per-field writer codes

## Context

keripy `incept(code=DigDex.X)` emits mixed-code inceptions: `makify` computes
**each said field under its own code** over one dummied render — `d` stays at
the Blake3-256 field default, `i` gets the override. So `i != d` for every
non-Blake3-256 override, and `i == d` exactly when the override IS Blake3-256.
keripy's dummy rule: dummy every said field whose code is **digestive**,
regardless of value equality.

cesr's read path dummies `i` iff `i == d` (string equality) —
`crates/keri-codec/src/said.rs:50` — so it rejects all 9 mixed-code corpus
rows (`TRACKED` in `crates/keri-codec/src/keripy_parity/said_codes.rs:33`).
cesr's write path drives both slots from ONE `said_code`
(`crates/keri-codec/src/serialize.rs:278-317`) and patches `i` with `d`'s
digest, so a parsed mixed event is not re-emittable byte-identically.

Facts already established (do not re-derive):

- `Identifier` decode is code-based (`crates/keri-codec/src/codec/field.rs:108-116`):
  a digestive `i` becomes `Identifier::SelfAddressing(Said)` carrying its own
  `DigestCode`. The event model needs NO changes.
- `ParsedIcp` has `said: Spanned` and `prefix: Spanned`
  (`crates/keri-codec/src/codec/event.rs:104-110`); spans address the qb64
  value bytes exactly, so dummying a span preserves the field's width — which
  equals its code's full size. Mixed widths (e.g. SHA3_512 `i` = 88 chars vs
  Blake3 `d` = 44) are handled by construction.
- Writer invariant after this change: BOTH digests are computed over the same
  size-patched, placeholder-filled buffer BEFORE either slot is spliced.
  keripy hashes the same dummied render for each field; splicing `d` before
  computing `i`'s digest would corrupt `i`.
- keripy also VERIFIES each said field under its own code — after this change
  a digestive `i` must be independently verified (not just dummied), else a
  forged digestive `i` would pass.

Invariants that must hold:

1. All 12 corpus rows in `said_codes.jsonl` round-trip byte-identically
   (read → write reproduces keripy's exact bytes, said, and pre).
2. Behavior is unchanged for `i == d` events and for non-digestive-`i`
   (basic derivation) events: same-code self-addressing events keep `i == d`
   (equal digests), basic prefixes serialize verbatim with a single-SAID `d`.
   ONE deliberate tightening: an event whose `i` is digestive but `i != d`
   under the SAME code currently passes read verify (only `d` dummied);
   after step 1 its `i` is also dummied and verified, so a non-matching
   digestive `i` flips accept → reject. This matches keripy (dummy every
   digestive said field) and is intended — cover it with the tamper probe.
3. Tampering the `i` of a mixed-code event fails verification with
   `SaidError::SaidMismatch` (reuse the existing variant — no new error
   variants; the expected/computed strings identify the field).
4. No panics on untrusted input; `Range` arithmetic stays checked via the
   existing `fill_span`/`patch_slot` guards.
5. `nix flake check` green: clippy god-level, fmt, wasm, no_std, ratchet
   (no new free `pub fn` — new helpers are methods or private fns).

## Steps

### 1. Read path — digestive-rule verify (`crates/keri-codec/src/said.rs`) — SEQUENTIAL (foundation)

- Restructure `verify_said_spans` (line 136) to verify N said fields over ONE
  scratch: take `raw` and a slice/array of `(&Spanned, DigestCode)` pairs
  (or an equivalent small internal shape — K3 owns the exact signature).
  Behavior: copy `raw` once, `fill_span` EVERY pair's span, then for each
  pair compute `Saider::digest(code, &scratch)` and compare `to_qb64()`
  against the pair's `value`; first mismatch returns
  `SaidError::SaidMismatch { expected, computed }`.
- `ParsedIcp::verify_said` (line 48): replace the
  `(self.said.value == self.prefix.value)` gate with the digestive rule:
  `infer_digest_code(self.prefix.value).ok()` — `Some(i_code)` means `i` is
  a said field: dummy AND verify it under `i_code`; `None` means basic
  derivation: leave `i` intact (a later `Field::decode::<Identifier>` still
  rejects genuinely unknown codes — unchanged).
- `ParsedRot::verify_said` / `ParsedIxn::verify_said`: single-pair call;
  behavior unchanged.
- Update module doc (lines 1-12), the `ParsedIcp::verify_said` doc, AND the
  `ParsedEvent::verify_said` doc (said.rs:84-85, "fill the `i` span when
  `d == i`"): the rule is "dummy every said field whose code is digestive",
  not `d == i`.
- Expected outcome: mixed-code corpus rows pass READ verification;
  `verify_said_spans_double_said_matches_reference` still passes (same code
  in both pairs degenerates to today's behavior).

Verification: `nix develop --command cargo nextest run -p keri-codec said`

### 2. Write path — per-field said codes (`crates/keri-codec/src/serialize.rs`, `crates/keri-codec/src/codec/event.rs`) — SEQUENTIAL, depends on step 1 (shares test helpers/semantics)

- `EventRef`: add `prefix_said_code(self) -> Option<DigestCode>` — for
  `Inception`/`DelegatedInception` whose `prefix()` is
  `Identifier::SelfAddressing(s)`, return `Some(*s.as_matter().code())`;
  `None` otherwise. Keep `is_double_said` (serialize.rs:182) delegating to
  `self.prefix_said_code().is_some()` so the two can never disagree; update
  its doc (it now means "`i` is self-addressing", NOT "`i == d`").
- `RenderBody::render` and `EventRef::render`
  (`codec/event.rs:496`) + `render_icp` (`codec/event.rs:560`): thread a
  second placeholder for the `i` slot (`Option<&str>`, present iff the
  prefix is self-addressing). The `Identifier::SelfAddressing` arm
  (`codec/event.rs:571-579`) writes the PREFIX placeholder, not `d`'s. A
  `None` prefix placeholder reaching that arm is a layout bug: return
  `InternalError::EventLayout`, never panic.
- `EventRef::serialize` (serialize.rs:278):
  1. `digest_code = self.said_code()`; `prefix_code = self.prefix_said_code()`.
  2. Build BOTH placeholders (`prefix_code.map(placeholder)` — propagate the
     existing `InternalError::PlaceholderPrimitive` on failure).
  3. Render, patch the size slot (unchanged).
  4. Compute `said = digest(digest_code, &buf)` AND
     `prefix_said = prefix_code -> digest(prefix_code, &buf)` — both BEFORE
     any splice (see Context invariant).
  5. `patch_slot` the `d` slot with `said`, then the `i` slot (when
     `layout.prefix` is `Some`) with `prefix_said`'s qb64. `layout.prefix`
     and `prefix_code` must be Some/None together — mismatch is
     `InternalError::EventLayout`.
  6. `SerializedEvent.prefix = prefix_said` (type unchanged,
     `Option<Said<'static>>`). Same-code events produce identical digests →
     `i == d` byte-identical to today.
- Update stale docs: `Serialize for InceptionEvent` (serialize.rs:52-61),
  `Serialize for DelegatedInceptionEvent` (serialize.rs:89-98),
  `EventRef::said_code` doc (serialize.rs:156-161), `SerializedEvent::prefix`
  doc (serialize.rs:356-359) — the `i` field serializes under the prefix's
  OWN digest code; `i == d` only when the codes coincide.
- Expected outcome: a parsed mixed-code event re-serializes byte-identically.

Verification: `nix develop --command cargo nextest run -p keri-codec serialize`

### 3. Tolerant oracle parity (`crates/keri-codec/src/deserialize/reference.rs`) — SEQUENTIAL, depends on step 1 (mirrors its rule)

- `deserialize_inception` (line 211-222) and `deserialize_delegated_inception`
  (line 347-360): replace the `d_str == i_str` gate with the digestive rule:
  `infer_digest_code(i_str).ok()`. When `Some(i_code)`:
  `verify_said_double(raw, digest_code, i_code)` — extend that helper to
  insert the `d` placeholder under `d`'s code and the `i` placeholder under
  `i_code`, then verify BOTH fields (each against its own digest of the same
  dummied render). When `None`: `verify_said_single` (unchanged).
- The oracle must stay behaviorally identical to the strict path — the
  differential tests (`strict vs oracle divergence` assertions in
  `deserialize.rs`) enforce this.

Verification: `nix develop --command cargo nextest run -p keri-codec deserialize`

### 4. Burn down TRACKED + tests (`crates/keri-codec/src/keripy_parity/said_codes.rs`, test additions) — SEQUENTIAL, depends on steps 1-3

- `said_codes.rs`: delete the `TRACKED` const, `tracked_issue`,
  `tracked_entries_are_not_stale`, and the `#[ignore]`d
  `mixed_code_vectors_round_trip_byte_identically` probe. The main sweep
  `representable_vectors_round_trip_byte_identically` now asserts EVERY row:
  drop the skip branch and change the final count assertion to
  `assert_eq!(asserted, 12)` (12 = corpus line count; keep the count exact so
  a silently-shrunk corpus fails). Keep
  `keripy_keeps_d_at_blake3_when_overriding_i` and
  `builder_said_code_output_verifies_per_field` unchanged. Rewrite the module
  doc (lines 1-14): the gap is closed; the sweep pins the digestive-rule
  semantics.
- New tests in `said.rs` (or the module K3 finds canonical — ONE location):
  - Mixed-code accept: build an `InceptionEvent::new` with
    `Identifier::SelfAddressing` under a non-Blake3 code (use a different
    WIDTH class too, e.g. SHA3_512/88-char, to exercise unequal spans),
    `said` under Blake3; serialize; `verify_said_raw` passes; `d` starts with
    `E`, `i` starts with the override code, `i != d`.
  - Independent-`i` tamper probe: take that serialized mixed event, corrupt
    one byte inside the `i` value, assert
    `Err(CodecError::Said(SaidError::SaidMismatch { .. }))`. This test FAILS
    if `i` is dummied but not verified — it is the probe for the new
    invariant.
- New test in `serialize.rs` tests (round-trip category): deserialize→
  serialize a mixed corpus row… already covered by the sweep in step 4's
  first bullet — do NOT duplicate; instead add the builder-independent unit:
  serialize the mixed `InceptionEvent` from the previous bullet, deserialize
  it back, re-serialize, assert byte identity (`decode(encode(x)) == x` and
  `encode(decode(bytes)) == bytes`).
- Fix ALL now-stale `d == i` doc/comment sites in `deserialize.rs`:
  strict-deserializer docs at lines 131-132 and 189-190 ("Verifies the
  double-SAID property when `d == i`"), Matrix B header at 2077 and bodies
  at 2080-2106 / 2144-2152 / 2167-2169 ("Write path is lossy … re-forces
  `i == d`"), and the `resaid_double` doc at 1182-1184. The write path no
  longer "ALWAYS forces `i == d`" — it emits `i` under the prefix's own
  code; `i == d` iff codes coincide. The spliced basic-prefix tests
  themselves stay valid (basic ⇒ verbatim `i`).

Verification: `nix develop --command cargo nextest run -p keri-codec`

## Verification (final gate)

```
nix develop --command cargo nextest run -p keri-codec
nix develop --command cargo fmt && nix develop --command taplo fmt
```

(Claude runs `nix flake check` after commit — it only sees committed state.)

## Out of scope

- NO builder `prefix_said_code` axis (issue #160 item 3 is optional; the
  existing `said_code` single-code projection is documented and pinned by
  `builder_said_code_output_verifies_per_field`). Do not touch
  `builder/icp.rs` beyond comments IF stale — its `i == d` claims remain
  true for builder output.
- NO new error variants, NO changes to `CodecError`/`SaidError`/
  `DeserializeError` shapes.
- NO changes to `crates/cesr`, `crates/cesr-stream`, `crates/keri-events`,
  `crates/keri`.
- NO corpus regeneration — `said_codes.jsonl` is pinned.
- NO lint-level changes, NO `#[allow]` without a `reason` on a specific item.
- `rotate()`/`interact()`/`deltate()` have no code override in keripy — rot/
  ixn/drt verify paths stay single-field.
