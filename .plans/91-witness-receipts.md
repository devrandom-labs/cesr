# K5 · #91 — Witness receipts + TOAD accounting (pure judgment)

## Context

Issue #91: out-of-band receipt validation as pure functions in `keri-rs`.
K1 already verifies *inline* receipts during the fold
(`Witnessing::receipted_by`, `crates/keri/src/authority.rs:257`). K5 adds
judgment for receipts arriving *after* acceptance as their own messages
(#82's `ReceiptMessage`), judged one at a time. Accumulation is host stream
state — no counters, no tables in the core.

keripy conformance oracle (checkout `~/Code/keripy`, main `9161a705`):
`Kevery.processReceipt` `src/keri/core/eventing.py:4481`. Semantics to port:

- **Stale check** (eventing.py:4526-4530): receipt is only accepted for the
  last-seen event at `(pre, sn)`; body `d` must equal that event's SAID,
  else `ValidationError` (drop). No event at that sn → escrow
  (eventing.py:4705-4718, `UnverifiedReceiptError`) — in the pure model the
  host simply has no accepted event to judge against, and the *evidence*
  classification below covers the transferable case.
- **Couples** (eventing.py:4534-4559): transferable verfer → skip; verify
  cigar over the RECEIPTED EVENT's raw bytes with the prefix as key; if the
  receiptor prefix is in the governing witness set, promote to an indexed
  witness signature at that position (eventing.py:4553-4557); otherwise it
  is a non-witness endorsement (watcher etc. — trust is host policy).
- **Wigs** (eventing.py:4562-4587): index ≥ witness count → skip; verify
  over event raw bytes against the witness the index selects.
- **Transferable groups** (eventing.py:4589-4652): look up receiptor's
  establishment event at the claimed sn; missing → escrow
  (`escrowTReceipts` + `UnverifiedTransferableReceiptError`,
  eventing.py:4604-4610); found but SAID differs → `ValidationError`
  (eventing.py:4613-4616); est event with no keys → `ValidationError`
  (eventing.py:4620-4624); sig index ≥ key count → `ValidationError`
  (eventing.py:4638-4640, NOT a skip — differs from controller verify);
  each remaining sig verified over the event's raw bytes against the key
  its index selects; only verifying sigs are stored. keripy applies **no
  threshold** to transferable receipt sigs.
- **TOAD accounting**: the distinct-witness set is host state; the core
  judges satisfaction of `Toad` over distinct valid indices
  (`len(windices) < toader.num`, K1 parity at eventing.py:2788).

### Invariants that must hold

- Sans-io: no lookups, no storage; every cross-KEL fact is a typed argument
  (K4 `DelegationEvidence` precedent, `crates/keri/src/delegation.rs`).
- `keri-rs` free-`pub fn` budget is **0** (`free-fn-budget.toml:29`) — every
  new entry point is a method on a domain type. No free functions.
- Parsing/verifying untrusted input never panics; no bare arithmetic in
  count/size paths; `usize::try_from` guarded comparisons like
  `receipted_by`.
- One error enum per module domain: new `ReceiptError` lives in the new
  `receipt` module; `Rejection` (fold verdict) is NOT extended.
- Adding `EvidenceKind::ReceiptorEstablishment` is a **deliberate breaking
  change** (exhaustive enum, promised in `crates/keri/src/error.rs:204`) —
  CHANGELOG entry required.
- Zero-copy: all new types borrow (`'e` lifetimes), no `into_static` piles,
  no allocation beyond the `Vec<u32>` index collection already idiomatic in
  `authority.rs`.
- Rust-native naming — no keripy lexicon (no "tsg", "cigar", "wiger" in
  public names).

## Steps

### Step 1 — `EvidenceKind::ReceiptorEstablishment` (SEQUENTIAL, foundation)

File: `crates/keri/src/error.rs`

- Add to `EvidenceKind` (payload-free variant; the host holds the
  endorsement, so it already knows the `(receiptor, sn)` coordinate to
  fetch):

  ```rust
  /// The transferable receiptor's establishment event at the coordinate
  /// the endorsement names. keripy's unverified transferable-receipt
  /// escrow (`escrowTReceipts` + `UnverifiedTransferableReceiptError`,
  /// eventing.py:4604-4610). Re-drive
  /// [`ReceiptedEvent::endorsed_by`](crate::ReceiptedEvent::endorsed_by)
  /// with the evidence once the host's stream/query produces it.
  ReceiptorEstablishment,
  ```

- Update the `EvidenceKind` doc comment: remove the "will be added as a
  deliberate breaking change" sentence (it lands here).
- No change to `Rejection` or its `disposition()` — receipts are judged
  outside the fold.

Verification: `cargo check -p keri-rs`.

### Step 2 — `receipt` module: types + judgments + unit tests (SEQUENTIAL — depends on step 1)

New file: `crates/keri/src/receipt.rs`; wire into
`crates/keri/src/lib.rs` in the same change (module + re-exports —
dead_code=deny means module and callers land together).

Module doc: the three receipt shapes, accumulation-is-host-state, keripy
anchors as above.

2a. **`ReceiptedEvent<'e>`** — the accepted event a receipt is judged
against, host-constructed with pub fields (precedent: `Signed`,
`crates/keri/src/state.rs:71`):

```rust
pub struct ReceiptedEvent<'e> {
    /// Identifier prefix of the KEL holding the accepted event.
    pub prefix: &'e Identifier<'e>,
    /// Sequence number of the accepted event.
    pub sn: Number,
    /// SAID of the accepted event.
    pub said: &'e Said<'e>,
    /// The exact serialized bytes of the accepted event — what every
    /// receipt signature signs (same provenance contract as
    /// `Signed::signed_bytes`).
    pub signed_bytes: &'e [u8],
}
```

Methods:

- `pub fn named_by(&self, receipt: &Receipt<'_>) -> Result<(), ReceiptError>`
  — the stale check: receipt `(prefix, sn, said)` must all equal this
  event's coordinate; mismatch → `ReceiptError::Stale` (keripy
  eventing.py:4526-4530). Compare via existing `PartialEq` on
  `Identifier`/`Said` and `Number::value()`.
- `pub fn endorsed_by(&self, endorsement: &TransferableEndorsement<'_>, receiptor: Option<&ReceiptorEstablishment<'_>>) -> Result<(), ReceiptError>`
  — the transferable judgment, keripy's order:
  1. `receiptor` is `None` → `ReceiptError::EvidenceRequired` (the escrow
     arm — host re-drives with evidence).
  2. `receiptor.said != endorsement.said` →
     `ReceiptError::EstablishmentMismatch` (eventing.py:4613-4616).
  3. `receiptor.keys.is_empty()` → `ReceiptError::NoAuthorityKeys`
     (eventing.py:4620-4624).
  4. Any sig with `usize::try_from(sig.index())` out of range of
     `receiptor.keys` → `ReceiptError::EndorsementIndexOutOfRange { index, count }`
     (eventing.py:4638-4640 — an ERROR here, unlike wig skipping).
  5. Verify every sig over `self.signed_bytes` against the key its index
     selects (`cesr::crypto::verify_indexed`, unwrap role newtype via
     `as_matter()` at the crypto boundary exactly like
     `authority.rs:262-269`); zero verifying sigs →
     `ReceiptError::NoVerifiedSignatures`. No threshold (keripy applies
     none). Success: `Ok(())`.

2b. **Evidence + endorsement types** (parsed borrowed values, K4 pattern):

```rust
pub struct TransferableEndorsement<'e> {
    /// The endorser's identifier.
    pub receiptor: &'e Identifier<'e>,
    /// Sequence number of the endorser's establishment event.
    pub sn: Number,
    /// SAID of the endorser's establishment event.
    pub said: &'e Said<'e>,
    /// Indexed signatures over the receipted event's bytes, indexed into
    /// that establishment event's key list.
    pub sigs: &'e [Siger<'e>],
}

pub struct ReceiptorEstablishment<'e> {
    /// SAID of the receiptor's establishment event at the endorsement's
    /// claimed sn — host-asserted as ACCEPTED in the receiptor's KEL.
    pub said: &'e Said<'e>,
    /// That establishment event's signing keys.
    pub keys: &'e [VerifyingKey<'e>],
}
```

2c. **`WitnessIndex`** — proof-carrying newtype (issue #91 sketch): a
witness position that verified. Private field, no public constructor;
produced only by the judgments below. `pub const fn value(self) -> u32`.
Derives: `Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord`.

2d. **`impl Witnessing<'_>`** (in `receipt.rs`, same crate — keep
`authority.rs` untouched):

- `pub fn receipt(&self, bytes: &[u8], wig: &Siger<'_>) -> Result<WitnessIndex, ReceiptError>`
  — judge ONE late witness receipt: run `verify_indexed` over the witness
  set with the single sig (`core::slice::from_ref`), map the single item's
  `IndexedVerifyError` into `ReceiptError::Signature` via `#[from]`; on
  success wrap the index. (Where the inline fold *skips* bad wigs in a
  batch, single-receipt judgment reports the failure — the host asked
  about THIS receipt.)
- `pub fn witness_index(&self, prefix: &BasicPrefix<'_>) -> Option<WitnessIndex>`
  — couple promotion (eventing.py:4553-4557): position of `prefix` in the
  governing set. Couple *verification* itself is already
  `cesr::crypto::verify` (prefix IS the key) — no new wrapper; document
  the two-call recipe on this method.
- `pub fn accounted_by<I>(&self, indices: I) -> Result<(), ReceiptError>
  where I: IntoIterator<Item = WitnessIndex>`
  — TOAD accounting over the host-accumulated distinct set: dedup
  (sort_unstable + dedup on values), drop out-of-range defensively
  (validate at own boundary even though `WitnessIndex` is proof-carrying —
  the proof binds to *a* witness set, not necessarily this one), compare
  count ≥ `self.toad.value()` with the same `usize::try_from` guard as
  `receipted_by` (authority.rs:276). Toad 0 → vacuously `Ok`. Failure:
  `ReceiptError::InsufficientReceipts { valid, required }`.

2e. **`ReceiptError`** — module-domain enum, `thiserror`,
`#[non_exhaustive]`, plus total `disposition()` (no wildcard arm, K2
pattern from `Rejection::disposition`):

| Variant | Payload | Disposition |
|---|---|---|
| `Stale` | `named_sn: u128, accepted_sn: u128` | `Terminal` (keripy drop) |
| `Signature` | `#[from] IndexedVerifyError` (covers index-out-of-range AND crypto failure — reuse, don't duplicate) | `Terminal` |
| `EvidenceRequired` | — | `Awaiting(ReceiptorEstablishment)` |
| `EstablishmentMismatch` | — | `Terminal` (keripy `ValidationError`) |
| `NoAuthorityKeys` | — | `Terminal` |
| `EndorsementIndexOutOfRange` | `index: u32, count: usize` | `Terminal` |
| `NoVerifiedSignatures` | — | `Terminal` |
| `InsufficientReceipts` | `valid: usize, required: u32` | `Awaiting(WitnessReceipts { valid, required })` |

Every disposition documented on the variant with its keripy anchor, same
style as `Rejection`.

2f. **lib.rs**: `pub mod receipt;` (doc line), re-export
`ReceiptedEvent, TransferableEndorsement, ReceiptorEstablishment, WitnessIndex, ReceiptError`;
add a crate-doc paragraph "**Receipts are judged one at a time;
accumulation is host state**" following the existing delegation/escrow
paragraphs (`lib.rs:39-54`).

2g. **Unit tests** in `receipt.rs` (fixtures like `authority.rs` tests —
`KeyPair<Ed25519>`, `sign_indexed`, `IndexMode::CurrentOnly` for wigs):

- Round-trip/judgment happy paths: wig at each index verifies and
  `accounted_by` over the collected `WitnessIndex`es satisfies an exact
  toad; couple promotion finds the right index; transferable endorsement
  with matching evidence passes.
- Negatives (issue acceptance list): wrong wig index (out of range →
  `Signature(IndexOutOfRange)`), forged wig sig, forged transferable sig
  (`NoVerifiedSignatures`), receiptor-authority coordinate mismatch
  (`EstablishmentMismatch`), missing evidence (`EvidenceRequired`), empty
  key list (`NoAuthorityKeys`), transferable sig index out of range
  (`EndorsementIndexOutOfRange`), stale receipt (wrong said / wrong sn /
  wrong prefix → `Stale`).
- Disposition tests: every variant's `disposition()` asserted exactly
  (`assert_eq!` on `Disposition`).
- Duplicate-index accounting: same witness twice counts once.
- Proptest (module `properties`, `ProptestConfig::with_cases(64)`): TOAD
  accounting over witness-count `n in 1..=8usize`, toad drawn from
  `{0, 1, n, n+1}` via `Toad::from_wire`, and a subset of valid indices:
  `accounted_by` is `Ok` iff distinct in-range count ≥ toad. Boundaries 0,
  1, count, count+1 explicitly covered (issue acceptance).

Verification: `cargo check -p keri-rs` and
`cargo clippy -p keri-rs --all-targets --all-features`. Do NOT run tests
(sandbox — tests run in the commit-hook `nix flake check`, driven by
Claude).

### Step 3 — wire adapter (SEQUENTIAL — depends on step 2)

File: `crates/keri/src/wire.rs` (feature `wire`)

```rust
impl<'e> From<&'e TransferableReceipt<'e>> for TransferableEndorsement<'e> {
    fn from(receipt: &'e TransferableReceipt<'e>) -> Self {
        Self {
            receiptor: receipt.receiptor(),
            sn: receipt.sn(),
            said: receipt.said(),
            sigs: receipt.signatures(),
        }
    }
}
```

(`keri_codec::TransferableReceipt` getters:
`crates/keri-codec/src/message.rs:256-281`.) Extend the wire.rs module doc
one sentence. No `ReceiptMessage → Signed` adapter — a receipt message is
not a fold input.

Verification: `cargo check -p keri-rs --features wire` +
`cargo clippy -p keri-rs --features wire --all-targets`.

### Step 4 — keripy differential (SEQUENTIAL — depends on step 2; PARALLEL OK with step 3, disjoint files)

New file: `crates/keri-codec/tests/keripy_receipts.rs` (name MUST contain
"keripy" — nightly filter). keri-rs is already a dev-dependency of
keri-codec (see `crates/keri-codec/tests/differential.rs:30`); corpus is
`crates/keri-codec/tests/corpus/keripy/parity/receipts.jsonl` (10 rows, 5
framed), loaded the `include_str!` way (differential.rs precedent). Reuse
the vector shape from `crates/keri-codec/src/keripy_parity/mod.rs`
(`ReceiptVector`) — if it is not exported to integration tests, define a
local serde mirror struct in the test file (it is test-only).

For every `kind == "framed"` vector:

1. `ReceiptMessage::parse(stream)`.
2. Build `ReceiptedEvent` from the vector's `pre`/`sn`/`said` (+
   `event_raw` as `signed_bytes`); assert
   `event.named_by(message.receipt())` is `Ok`.
3. Wigs: `Witnessing::new(&witnesses, Toad::from_wire(n))` from the
   vector's witness list (n = wig count); judge each wig via
   `Witnessing::receipt`, assert the recovered `WitnessIndex` values equal
   keripy's `0..n`, and `accounted_by` over them is `Ok`; with
   `Toad::from_wire(n + 1)` assert
   `ReceiptError::InsufficientReceipts { valid: n, required: n + 1 }`.
4. Couples: `cesr::crypto::verify` over `event_raw` (already covered by
   the #82 parity suite — assert again here as the K5 recipe) and
   `witness_index` promotion is `None` (corpus endorsers are not
   witnesses).
5. Transferable groups: build `TransferableEndorsement` via the step-3
   `From` impl (enable feature `wire` for this test — add
   `required-features` or use the dev-dependency's feature; if keri-codec's
   dev-dep on keri-rs lacks `wire`, construct the struct literally
   instead — prefer the literal construction to avoid feature plumbing in
   dev-deps), evidence `ReceiptorEstablishment` from the vector's
   `endorser_said`/`endorser_key`; assert `endorsed_by` is `Ok`; assert
   `endorsed_by` with `None` evidence is `EvidenceRequired` and its
   disposition is `Awaiting(ReceiptorEstablishment)`; assert wrong-said
   evidence (use the receipted event's said) is `EstablishmentMismatch`.

Body rows (`kind == "body"`): assert `named_by` catches a coordinate
mismatch — parse the body, judge against a `ReceiptedEvent` with a
different sn, expect `Stale`.

Verification: `cargo check -p keri-codec --tests`.

### Step 5 — CHANGELOG (PARALLEL OK with steps 3-4 — disjoint file)

File: `crates/keri/CHANGELOG.md`, under `## [Unreleased]` → `### Added`:

- K5 #91: `receipt` module — `ReceiptedEvent` (stale check +
  transferable-endorsement judgment), `Witnessing::{receipt,
  witness_index, accounted_by}`, `WitnessIndex`, `ReceiptError` with
  escrow dispositions. **[breaking]** `EvidenceKind` gains
  `ReceiptorEstablishment` (exhaustive-enum addition).

## Verification (final, K3 runs)

```bash
cargo check --workspace --all-features
cargo clippy --workspace --all-targets --all-features
cargo fmt --check
```

Tests, taplo, audit, wasm/no_std run in `nix flake check` via the push
hook — Claude drives that, NOT K3 (sandbox: cargo test hangs).

## Out of scope

- Receipt generation, collection/mailboxes, KAACE (#26-29).
- Witness rotation semantics (K1 cut/add — untouched).
- `Rejection`/fold changes beyond none at all; `authority.rs`,
  `state.rs`, `duplicity.rs`, `delegation.rs` untouched.
- `qry`/`rpy`/`exn`, `rsgs` (last-est receipt groups), keripy own-event
  policy (`lax`/`local` — host policy, not validation).
- No new corpus generation; existing `receipts.jsonl` only.
- No lint relaxation; no `free-fn-budget.toml` change (methods only).
