# 133 — D1: keripy signature-filtering semantics + issue cleanup

## Context

Issue #133's three written items are largely resolved by intervening work
(#132 `Digest::verify` bool fail-closed; fold API replaced by
`KeyState::incept`/`ingest`; fixtures consolidated onto `inception_full`).
The live substantive work re-anchored to #133 by the K2 design doc
(`docs/superpowers/specs/2026-07-29-88-k2-escrow-dispositions-design.md:117-121`)
and shipped code (`crates/keri/src/error.rs:69-70`) is **divergence D1**:

- keripy `verifySigs` (`src/keri/core/eventing.py:305-350`, pinned checkout at
  `~/Code/keripy`) **filters**: dedups sigers by full signature qb64
  (L324-329), *skips* a siger whose `index >= len(verfers)` (L334-337), *skips*
  a siger whose signature fails verification (L345-348), and returns the valid
  subset + its indices. The threshold is judged on that valid subset: satisfied
  → accept; zero valid → bare `ValidationError` drop (eventing.py:2821-2823);
  partial → `.pses` escrow (eventing.py:2861-2869).
- Our `Authority::verify` (`crates/keri/src/authority.rs:58-78`) **aborts** on
  the first bad signature (`collect::<Result<Vec<_>,_>>()?` →
  `Rejection::UnverifiedSignature`). An event carrying threshold-satisfying
  valid sigs plus one forged sig: keripy accepts, we reject. That is the D1
  divergence this plan closes.

Target semantics after this change (keripy parity):

- A signature that fails verification, or whose `index` addresses no key, is
  **skipped**, never an error. Only the final threshold check can fail.
- `Rejection::UnverifiedSignature(IndexedVerifyError)` becomes dead — **remove
  the variant** (breaking; pre-1.0 minor bump; CHANGELOG + PR call-out).
- `MissingSignatures { verified }` fires with `verified` = count of **distinct
  valid signature indices** (dedup by index; `SigningThreshold::satisfied_by`
  already dedups internally — `crates/keri-events/src/threshold.rs:123-126` —
  and strict Ed25519 verification makes two distinct valid sigs at one index
  impossible, so distinct-index count equals keripy's deduped `vindices` count).
  Disposition rule is unchanged: `verified == 0` Terminal, `>= 1`
  Awaiting(Signatures).
- `Verified` must carry **only the valid subset** — `Commitment::opened_by`
  (`authority.rs:158-181`) iterates `verified.sigs()` to count prior-next
  exposure, and a forged signature must not contribute an ondex.

Invariants that must hold:

- `cesr::crypto::verify_indexed` is NOT changed — it stays per-signature
  `Result` and the *caller* chooses abort vs filter (the witness path
  `Witnessing::receipted_by` at `authority.rs:249-253` already filters with
  `.filter_map(Result::ok)` + sort + dedup; the controller path now mirrors it).
- `Verified` remains unconstructible outside `Authority::verify` (proof type).
- No panics, no bare arithmetic, no lint relaxation. `usize::try_from` guards
  stay as-is where indices are converted.
- Import style: all `use` at top of file; no fully-qualified inline paths.

## Steps

### Step 1 — `Authority::verify` filters; `Verified` carries the valid subset
`SEQUENTIAL` — foundation for step 2. Files: `crates/keri/src/authority.rs`.

1. Rework `Authority::verify` (lines 58-78): pair each `verify_indexed` result
   with its source `Siger` (e.g. `verify_indexed(&keys, bytes, sigs).zip(sigs)`),
   keep only `Ok` pairs, collecting the valid `&'s Siger<'s>` refs and their
   `u32` indices. Sort + dedup the index list (mirror `receipted_by`,
   lines 249-253); `verified = indices.len()` (distinct count) feeds
   `MissingSignatures`. Threshold check stays `self.threshold.satisfied_by(indices)`.
   On success return `Verified` holding the valid subset.
2. Change `Verified<'s>` (lines 84-95): field becomes `sigs: Vec<&'s Siger<'s>>`;
   `sigs()` returns `&[&'s Siger<'s>]` (drop `const` if it cannot hold —
   `Vec` deref is not const-stable; a plain `#[must_use] pub fn` is fine).
   **Drop `Copy` from the derive** (`Vec` is not `Copy`); keep `Debug, Clone`.
3. Adapt `Commitment::opened_by` (lines 163-172): iteration now yields
   `&&Siger` — adjust patterns/derefs only; logic (ondex/index/digest skip
   semantics, sort+dedup of exposed) is UNCHANGED.
4. Doc sweep in this file:
   - `verify` doc (lines 45-57): describe filter semantics with the keripy
     anchor `verifySigs` `eventing.py:305-350` (dedup by sig, skip
     out-of-range index, skip failed verification, judge valid subset);
     `# Errors` now lists only `Rejection::MissingSignatures`. State that
     `verified` counts distinct valid indices.
   - `Verified` doc (lines 81-95): "every provided signature verified" becomes
     "the valid subset of the provided signatures — each verified against the
     key its index selects; invalid or out-of-range signatures were filtered".
5. Rework/extend the inline tests (`#[cfg(test)]` from line 285). Existing
   `verify_rejects_a_forged_signature` (~line 331): a single forged sig at
   threshold 1 now yields `Rejection::MissingSignatures { verified: 0 }` —
   rename to `forged_only_signature_set_is_missing_signatures_zero` and assert
   that exact variant/value. Add (each asserts exact variants/values, no
   stringify):
   - `forged_extra_signature_is_filtered_not_fatal`: 2 keys, threshold 2, both
     valid sigs + 1 forged third sig → `Ok`; `Verified::sigs().len() == 2`.
   - `out_of_range_index_is_skipped`: valid sig at index 0 (threshold 1) + sig
     with index 5 over 1 key → `Ok`, `sigs().len() == 1`.
   - `forged_below_threshold_reports_valid_count`: 2 keys, threshold 2, one
     valid + one forged → `Err(MissingSignatures { verified: 1 })`.
   - `duplicate_signature_counts_once`: same valid sig attached twice,
     threshold 2 over 2 keys → `Err(MissingSignatures { verified: 1 })`.
   - `opened_by_ignores_filtered_signatures`: rotation-shaped check at the
     authority level — commitment over one next key; verify with one valid
     exposing sig (correct ondex) plus one forged sig carrying an ondex; the
     forged sig is filtered so exposure comes only from the valid sig →
     `opened_by` returns `Ok`. Reuse the existing test key/siger helpers in
     this module (`keyed`, `sign_indexed`, `IndexMode::Both`). NOTE: no digest
     helper exists in this test module — build the committed `Digest` yourself
     (e.g. `cesr::crypto` Blake3-256 digest over the revealed key's
     `to_qb64b()`, wrapped in the `keri_events::Digest` role newtype; follow
     however `Digest` values are constructed in existing keri crate tests).

Verification (this step): from repo root,
`cargo check -p keri-rs --all-features` — compile only; full clippy/tests come
after step 2 (removing the dead variant) and the final gate. DO NOT run
`cargo test`/`cargo nextest` (sandboxed shell stalls on test binaries).

### Step 2 — remove `Rejection::UnverifiedSignature`
`SEQUENTIAL — depends on step 1`. Files: `crates/keri/src/error.rs`.

1. Delete the `UnverifiedSignature(#[from] IndexedVerifyError)` variant
   (lines 63-72) including its D1 doc comment, and the now-unused
   `use cesr::crypto::IndexedVerifyError;` import (line 2).
2. Remove its arm from `disposition()` (line 249).
3. Update `MissingSignatures` doc (lines 42-61): `verified` is the number of
   **distinct valid signature indices** after filtering (keripy `verifySigs`
   semantics); `verified == 0` now means *no verifiable controller signature*
   (attached set empty, all forged, or all out-of-range) — spec MUST-drop
   wording stays; the "abort-on-bad-signature semantics" sentence goes away.
4. Delete tests that exercised the removed variant:
   `index_out_of_range_maps_to_unverified_signature` (~line 353),
   `verification_failure_maps_to_unverified_signature` (~line 365),
   `unverified_signature_is_terminal` (~line 509). Prune the now-unused
   `cesr::crypto::{SignatureError, VerificationError}` /
   `IndexedVerifyError` test imports.

Verification: `cargo check -p keri-rs --all-features --tests && cargo clippy -p keri-rs --all-features --tests -- -D warnings` (clippy via the workspace lint table; no test runs). NOTE: keri-codec's test target is broken at this
point until step 5 lands — that is expected; step 5 owns it.

### Step 3 — K2 design-doc sweep
`PARALLEL OK` (disjoint files; sonic-suitable). Files:
`docs/superpowers/specs/2026-07-29-88-k2-escrow-dispositions-design.md`.

1. Line ~85: replace "Under our abort-on-bad-sig semantics (see divergences),
   all provided sigs verified when this variant fires, so `verified == 0` ⇔
   empty attached sig set." with the filtered reading: `verified` = distinct
   valid indices after keripy-parity filtering (#133); `verified == 0` ⇔ no
   verifiable controller signature.
2. Per-variant table (~line 102): delete the `UnverifiedSignature(_)` row.
3. D1 divergence bullet (~lines 117-121): mark **Resolved by #133** — describe
   the new filter semantics in one sentence and drop the "K9 differential must
   account for it" sentence for D1 (the dedup-divergence note in
   `authority.rs:149-152` is separate and stays).

### Step 4 — CHANGELOG
`PARALLEL OK` (disjoint). Files: `crates/keri/CHANGELOG.md`.

Add under `## [Unreleased]` / `### Changed`, matching existing entry style:

```markdown
- [**breaking**] #133 D1 — `Authority::verify` now filters invalid signatures
  (keripy `verifySigs` parity): a signature that fails verification or whose
  index addresses no key is skipped, never fatal; the threshold is judged on
  the valid subset and `Verified` carries only that subset (`Verified` loses
  `Copy`; `Verified::sigs` now returns the filtered `&[&Siger]`).
  `Rejection::UnverifiedSignature` is removed;
  `MissingSignatures { verified }` counts distinct valid signature indices.
```

### Step 5 — keri-codec test fallout + fixture residue
`SEQUENTIAL — depends on steps 1-2` (transitions.rs edits here follow from the
variant removal). Files: `crates/keri-codec/tests/common/mod.rs`,
`crates/keri-codec/tests/transitions.rs`, `crates/keri-codec/tests/snapshot.rs`.

1. Rewrite the three transitions.rs tests that matched the removed variant —
   each attaches a single forged / wrong-key / out-of-range signature, which
   under filter semantics is skipped leaving zero valid, so the expected
   rejection becomes `Rejection::MissingSignatures { verified: 0 }` (same
   Terminal disposition):
   - `genesis_with_a_bad_signature_is_invalid_signature` (L179-192) — rename
     to reflect the new verdict (e.g. `genesis_with_only_a_bad_signature_is_missing_signatures`).
   - `a_signature_from_the_wrong_key_is_rejected` (L920-933) — assertion
     becomes `MissingSignatures { verified: 0 }`.
   - `a_signer_index_out_of_range_is_invalid` (L1175-1188) — same; rename to
     say the out-of-range signature is skipped.
   Remove the now-unused `use cesr::crypto::IndexedVerifyError;`
   (transitions.rs:14). Assert exact variants (`matches!` / `let ... else`),
   never stringified messages.
2. Extend `inception_full` (mod.rs:280-298) with a trailing
   `config: Vec<ConfigTrait>` parameter, passed to the builder via
   `.config(config)` alongside the existing chain (order irrelevant; builder is
   fluent; `.config(vec![])` is a no-op vs the default — verified against
   icp.rs:157,197-201). The `#[allow(clippy::too_many_arguments)]` already
   present covers it.
3. `genesis_config` (mod.rs:313-322) becomes a thin delegation to
   `inception_full` (single key, `Simple(1)` thresholds, no witnesses, toad 0,
   the given config) — delete its hand-rolled builder chain.
4. Update EVERY existing `inception_full` caller to pass `vec![]` for config.
   Sweep with `rg -n 'inception_full\(' crates/keri-codec/tests` — call sites
   exist in mod.rs (`genesis`, `inception_multi`), transitions.rs (~17 sites:
   L105, 233, 249, 269, 331, 490, 524, 558, 625, 699, 758, 794, 946, 966,
   996, 1024, 1057), and **snapshot.rs (L74, L111, L173)**. The grep is
   authoritative, not the line list.

Verification: `cargo check -p keri-codec --all-features --tests` (no test runs).

## Verification (final, whole plan)

- `cargo check --workspace --all-features --tests` and
  `cargo clippy --workspace --all-features --tests -- -D warnings` must pass
  (`--tests` is required — without it broken test targets slip through).
- DO NOT run `cargo test` / `cargo nextest` — test binaries stall in this
  sandbox. The full test suite runs in `nix flake check` via the commit hook,
  which the controller (Claude) drives after review.

## Out of scope

- `cesr::crypto::verify_indexed` and everything under `crates/cesr` — unchanged.
- The witness path `Witnessing::receipted_by` — already filter-based; untouched.
- The ondex dedup divergence (`authority.rs:149-152` doc note) — stays a K9
  differential carve-out; do not "fix" it.
- `Commitment::opened_by` logic (skip semantics, threshold call) — only the
  mechanical iteration adaptation from step 1.3.
- No new `Rejection` variants; no `clippy.toml`/`[lints]` changes; no
  `#[allow]` additions beyond what already exists.
- Do not commit; the controller commits after review.
