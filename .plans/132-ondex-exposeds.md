# #132 — Rotation next-key commitment: ondex-based exposure (partial rotation)

## Context

K1 shipped the rotation next-key commitment as a strict positional full-rotation
check (`Commitment::opened_by`, `crates/keri/src/authority.rs:97`): the revealed
key list must equal the committed digest list in length, each revealed key must
hash to the positionally corresponding digest, and `0..n` must satisfy the prior
next threshold. That form over-rejects three shapes the KERI spec explicitly
permits.

**Spec is the authority** (ToIP KERI spec; local copy
`/private/tmp/claude-501/-Users-joel-Code-devrandom-cesr/0ad106ef-f1f0-467a-9c68-659c8b938919/scratchpad/keri-spec-body.md`).
keripy is the semantics oracle for corner behavior only, never architecture.
Normative properties:

- **S1 (spec L174, L1387)**: a rotation MUST be signed by private keys from the
  newly exposed pre-rotated keypairs satisfying the *prior next threshold*; the
  new current key list MUST include the threshold-satisficing subset of the
  prior next key list.
- **S2 (spec L1488)**: the exposed pre-rotated keys must be verified against
  their pre-committed digests from the prior establishment event.
- **S3 (spec L1470, L1496-1498)**: *Partial* rotation (some pre-rotated keys
  held in reserve, unexposed) and *Augmented* rotation (current list contains
  new keys never pre-rotated) are both legal. Therefore: no
  `revealed.len() == committed.len()` rule, no positional mapping, and unsigned
  or uncommitted current keys are NOT checked against digests.
- **S4 (spec L1256)**: dual-index verification: `ondex` selects the prior next
  *digest*, `index` selects the exposed public key in the current signing list,
  the digest is recomputed over the exposed key's qb64 **under the committed
  digest's own code** (crypto agility), compared, and only then does the
  signature verify/count.
- **S5 (spec L1537, L1543 reserve examples)**: prior-next-threshold
  satisfaction is measured over *signatures* from exposed keys, not mere key
  presence.

keripy corner semantics (`keripy/src/keri/core/eventing.py`, `Kever.exposeds`
L2962-3007, call site L2875):

- `exposeds` runs over **verified** sigers only (docstring assumption:
  "the signature has been verified").
- Per siger: `ondex is None` → skip; `ondex` out of range → skip (raise is
  commented out); digest mismatch → skip. Skipping never errors; only the final
  threshold check can fail.
- Failure disposition is **escrow partially-signed** (`escrowPSEvent` +
  `MissingSignatureError`, L2877-2885) — curable by more signatures, NOT
  terminal. This closes divergence D2 from the K2 design doc.

Known, documented divergences that REMAIN (not this card's scope):

- **D1 (#133)**: our `Authority::verify` aborts on the first bad signature;
  keripy filters and judges the valid subset. Unchanged here. Consequence used
  by this card: after `verify` succeeds, every provided signature is verified,
  so the exposure scan may run over the full signature set.
- **Dedup**: `SigningThreshold::satisfied_by`
  (`crates/keri-events/src/threshold.rs:123`) dedups indices; keripy's numeric
  `_satisfy_numeric` (coring.py L4873) counts duplicates. A duplicate ondex is
  only producible via a duplicated key in the current list; ours is
  conservative (over-rejects, never over-accepts). Document in `opened_by` docs
  and probe with a test.

**Approach (Joel-approved, option B)**: typed proof of verification.
`Authority::verify` returns a `Verified<'s>` newtype wrapping the verified
signature slice; `Commitment::opened_by` takes `&Verified` — unverified
signatures cannot reach the commitment check at compile time. This encodes
keripy's docstring assumption in the type system (cesr aesthetic: invalid
states unrepresentable).

Invariants that must hold after this change:

1. A signature can only contribute an ondex if it verified against the revealed
   current key at its `index` (type-enforced via `Verified`).
2. An admitted ondex requires `Digest::verify` of the revealed key's qb64 under
   the committed digest's own code (S4; `Digest::verify` already does this).
3. Skip semantics: `ondex` None / ondex out of committed range / `index` out of
   revealed range / digest mismatch → the signature contributes nothing and
   causes no error.
4. Prior-next-threshold failure is `Awaiting(Signatures)`, not terminal.
5. Existing full-rotation vectors still pass: test sigs use code `A`
   (`IndexedSigCode::Ed25519`, `IndexMode::Both`), whose implicit
   `ondex == index` (`indexer/builder.rs:342`, matching keripy) makes a full
   in-order reveal satisfy the new check.
6. No panics, no bare arithmetic: index conversions via `usize::try_from`,
   lookups via `.get()`.

## Steps

All steps are SEQUENTIAL (single crate pair, shared types) except step 6
(changelog) which is PARALLEL OK with step 5.

### 1. `crates/keri/src/error.rs` — replace the terminal variant with a curable one

- Delete `Rejection::NextKeyCommitmentMismatch` (variant, L81-90).
- Add in its place:

  ```rust
  /// The verified signatures do not expose enough prior next keys to satisfy
  /// the prior next threshold.
  #[error("prior next threshold not satisfied: {exposed} exposed prior-next key(s)")]
  PriorNextThresholdUnsatisfied {
      /// Distinct prior-next indices exposed by verified signatures.
      exposed: usize,
  },
  ```

  Doc comment must state: disposition `Awaiting(Signatures)` (keripy `.pses`
  via `escrowPSEvent` + `MissingSignatureError`, eventing.py:2877-2885); D2
  divergence from the K2 design doc is closed by #132; more controller
  signatures for the same event version are the re-drive trigger.
- `disposition()` (L235): move the variant out of the `Terminal` arm; add
  `Self::PriorNextThresholdUnsatisfied { .. } => Disposition::Awaiting(EvidenceKind::Signatures)`.
- Update the disposition test at L512
  (`next_key_commitment_mismatch_is_terminal`): rename to
  `prior_next_threshold_unsatisfied_awaits_signatures`, assert
  `Disposition::Awaiting(EvidenceKind::Signatures)`.
- Sweep `error.rs` doc references: the D1 note at L69 mentions "#132/#133" —
  reduce to #133 (this card lands). Expected outcome: `rg NextKeyCommitmentMismatch crates/keri/src` empty.

### 2. `crates/keri/src/authority.rs` — `Verified` proof + ondex-based `opened_by`

- New type after `Authority`:

  ```rust
  /// Proof that a signature set verified against an [`Authority`]: the only
  /// way to obtain one is [`Authority::verify`], so APIs taking `&Verified`
  /// cannot receive unverified signatures.
  #[derive(Debug, Clone, Copy)]
  pub struct Verified<'s> {
      sigs: &'s [Siger<'s>],
  }
  ```

  Private field, NO public constructor, no `new_unchecked`. Accessor
  `pub fn sigs(&self) -> &'s [Siger<'s>]`.
- `Authority::verify` signature becomes:

  ```rust
  pub fn verify<'s>(
      &self,
      bytes: &[u8],
      sigs: &'s [Siger<'s>],
  ) -> Result<Verified<'s>, Rejection> {
  ```

  Body unchanged except the `Ok(())` becomes `Ok(Verified { sigs })`. Update
  the doc comment: on success every provided signature verified against the
  key its index selects (abort-on-bad-sig, D1/#133), and the returned
  `Verified` witnesses that fact. BREAKING — callers within the workspace:
  `state.rs` (3 sites) and the `authority.rs` tests.
- Rewrite `Commitment::opened_by`:

  ```rust
  pub fn opened_by(
      &self,
      revealed: &Authority<'_>,
      verified: &Verified<'_>,
  ) -> Result<(), Rejection> {
  ```

  Body (functional style, no bare arithmetic, no panic):

  ```rust
  let mut exposed: Vec<u32> = verified
      .sigs()
      .iter()
      .filter_map(|sig| {
          let ondex = sig.ondex()?;
          let digest = self.next_digests.get(usize::try_from(ondex).ok()?)?;
          let key = revealed.keys.get(usize::try_from(sig.index()).ok()?)?;
          digest.verify(&key.to_qb64b()).then_some(ondex)
      })
      .collect();
  exposed.sort_unstable();
  exposed.dedup();
  let count = exposed.len();
  if self.next_threshold.satisfied_by(exposed) {
      Ok(())
  } else {
      Err(Rejection::PriorNextThresholdUnsatisfied { exposed: count })
  }
  ```

  (The local sort/dedup exists to report a truthful `exposed` count;
  `satisfied_by` dedups again internally — cheap, bounded.)
- Doc comment for `opened_by` must carry: the S1-S5 spec anchors (partial +
  augmented rotation legality, dual-index procedure, crypto agility via the
  committed digest's own code), the skip semantics list, the keripy anchor
  (`Kever.exposeds` eventing.py:2962-3007, threshold call 2875), and the dedup
  divergence note (keripy `_satisfy_numeric` counts duplicate ondices from
  duplicated current keys; we dedup — conservative; K9 differential must
  account).
- `Siger` already exposes `ondex()` (`cesr/src/core/primitives/siger.rs:105`).
  `Digest::verify` already hashes under its own code. Do NOT add parallel
  helpers (reuse-core rule).

### 3. `crates/keri/src/state.rs` — reorder `rotate`, thread `Verified`

- `rotate` (L278): new order — chain check, well-formedness, signature
  verification, then commitment opening with the proof:

  ```rust
  self.check_chains_onto(rot.sn().value(), rot.prior_event_said())?;
  rot.authority().well_formed()?;
  let verified = rot.authority().verify(signed.signed_bytes, &signed.sigs)?;
  self.commitment().opened_by(&rot.authority(), &verified)?;
  ```

  Update the surrounding comments: a rotation is self-certifying against its
  revealed authority; the verified signatures then open the prior next-key
  commitment by exposure (spec partial-rotation form).
- `incept` (L211) and `interact` (L336): `verify` now returns `Verified`;
  both discard it — the existing `...verify(...)?;` statement form already
  drops the value, keep as is.
- Doc sweep in `state.rs`: L275-277 ("the revealed keys must satisfy the prior
  next-key commitment") stays true but reword to exposure form ("verified
  signatures must expose a prior-next-threshold-satisfying subset of the
  committed next keys").

### 4. `crates/keri-codec/tests/common/mod.rs` — dual-index sign helper

- Add alongside `Key::sign` (L77):

  ```rust
  /// A real dual-indexed Ed25519 signature over `bytes`: `index` into the
  /// current key list, `ondex` into the prior next-key digest list. Uses the
  /// big dual code (`2A`) so the ondex is explicit on the wire.
  pub fn sign_dual(&self, bytes: &[u8], index: u32, ondex: u32) -> Fallible<Siger<'static>> {
      let cigar = self.kp.sign(bytes)?;
      let indexer = IndexerBuilder::new()
          .with_code(IndexedSigCode::Ed25519Big)
          .with_indices(index, ondex)?
          .with_raw(cigar.raw().to_vec())?;
      Ok(Siger::new(indexer).with_verfer(self.verfer.as_matter().clone()))
  }
  ```

- Add a current-only variant if step 5's tests need it:
  `sign_current_only` with `IndexedSigCode::Ed25519Crt` and `.with_index`.
- If the existing genesis/rotation builders cannot express multi-key next
  commitments with a chosen next threshold, extend them minimally (e.g. a
  `genesis_with`/`RotationKeys` widening) — follow the existing builder
  patterns in the file; forged events must re-seal SAIDs the way the existing
  helpers do.

### 5. `crates/keri-codec/tests/transitions.rs` — rewrite + new vectors

Update the two stale tests:

- `rotation_revealing_the_wrong_key_breaks_the_commitment` (L406): same
  fixture; expectation becomes
  `Rejection::PriorNextThresholdUnsatisfied { exposed: 0 }` (k2's sig has
  implicit ondex 0, but k2 does not hash to the committed digest of k1 →
  skipped, nothing exposed).
- `rotation_revealing_the_wrong_key_arity_breaks_the_commitment` (L418): this
  shape is now a LEGAL augmented rotation (spec L1470/L1496). Rewrite as an
  acceptance test (e.g. `augmented_rotation_with_uncommitted_extra_key_is_accepted`):
  reveal `[k1, kx]` against the single committed `k1`, sign with `k1` at
  index 0 (implicit ondex 0 matches), assert the fold accepts and the new
  state's keys are `[k1, kx]`.

New vectors (each: build KEL via existing helpers, exact `assert!`/`matches!`
on variant and state fields — no stringly asserts):

- `partial_rotation_reveals_satisfying_subset_is_accepted`: icp commits next
  `[k1, k2, k3]` with next threshold `Simple(2)`; rot reveals `[k1, k3]`
  (holds `k2` in reserve), sigs `k1.sign_dual(bytes, 0, 0)` and
  `k3.sign_dual(bytes, 1, 2)`; accepted; state keys `[k1, k3]`.
- `reordered_reveal_maps_by_ondex_is_accepted`: icp commits `[k1, k2]`,
  next threshold `Simple(2)`; rot reveals `[k2, k1]` (reverse order), sigs
  `k2.sign_dual(bytes, 0, 1)` and `k1.sign_dual(bytes, 1, 0)`; accepted.
- `partial_rotation_below_prior_next_threshold_awaits_signatures`: icp commits
  `[k1, k2, k3]` next threshold `Simple(2)`; rot reveals `[k1]` with only
  `k1.sign_dual(bytes, 0, 0)`; current threshold satisfied but exposure is 1
  → `PriorNextThresholdUnsatisfied { exposed: 1 }`; additionally assert
  `r.disposition() == Disposition::Awaiting(EvidenceKind::Signatures)`.
- `current_only_signature_exposes_nothing`: rot correctly reveals the
  committed key but signs with `sign_current_only` → current threshold OK,
  exposure 0 → `PriorNextThresholdUnsatisfied { exposed: 0 }`.
- `ondex_out_of_range_is_skipped_not_fatal`: sig with `ondex` beyond the
  committed list (e.g. `sign_dual(bytes, 0, 7)` against a 1-digest
  commitment) → skipped → `PriorNextThresholdUnsatisfied { exposed: 0 }`
  (no panic, no index error).
- `duplicate_ondex_counts_once`: current list `[k1, k1]` (same key twice),
  committed `[k1, k2]` with next threshold `Simple(2)`; sigs
  `k1.sign_dual(bytes, 0, 0)` and `k1.sign_dual(bytes, 1, 0)` → both admit
  ondex 0, dedup → exposed 1 → rejected. Doc comment on the test: documents
  the conservative divergence from keripy's numeric duplicate counting.
- Full-rotation regression: existing happy-path rotation tests must pass
  unmodified (code `A` implicit `ondex == index`).

### 6. `crates/keri/CHANGELOG.md` — breaking-change entry (PARALLEL OK with 5)

Under Unreleased/next: `feat(keri)!: #132` — rotation commitment now
ondex-exposure based (spec partial/augmented rotation);
`Rejection::NextKeyCommitmentMismatch` removed in favor of curable
`Rejection::PriorNextThresholdUnsatisfied`; `Authority::verify` returns
`Verified` proof; `Commitment::opened_by` takes the revealed authority plus
that proof. If the changelog file lives elsewhere (release-plz layout), put
the entry where the previous `feat(keri)!` entries live.

## Verification

Sandbox rule: NO `cargo test`/`cargo nextest` in this session (binaries hang
in the sandbox). Use only:

```bash
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets
```

Both must be clean (clippy is deny-all/pedantic/nursery — fix code, never
`#[allow]`). Tests run unsandboxed in the commit hook's `nix flake check`,
which the controller drives after review.

## Out of scope

- D1 signature-filtering semantics (`Authority::verify` abort-on-bad-sig) — #133.
- Delegation (K4), witness receipt evidence (K5), duplicity (K3).
- K9 differential corpus harness — this card only leaves the divergence notes
  it needs (dedup note in `opened_by` docs).
- Any change to `SigningThreshold::satisfied_by`, `Siger`, `Indexer`, or
  `Digest` — the cesr substrate already provides everything.
- `KeyStateSnapshot` trusted fold — crypto-free, unaffected.
