# K2 Escrow Dispositions Implementation Plan (#88)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `Rejection::disposition()` — a total, pure classification of every fold rejection as Terminal or Awaiting(EvidenceKind), so hosts know whether to drop or park-and-re-drive.

**Architecture:** Two new exhaustive enums (`Disposition`, `EvidenceKind`) plus one `const fn` method in `crates/keri/src/error.rs`. One breaking payload change: `MissingSignatures` gains `{ verified: usize }` (the KERI spec's DDoS rule splits on that count — zero verifiable sigs MUST drop, ≥1 below threshold SHOULD escrow). No tables, no timers, no storage.

**Tech Stack:** Rust edition 2024, thiserror, nextest. Design doc: `docs/superpowers/specs/2026-07-29-88-k2-escrow-dispositions-design.md` (evidence anchors for every classification live there — keripy `eventing.py` line numbers + spec quotes).

**Branch:** `88-k2-escrow-dispositions` (already exists, design doc committed).

**Verification:** `nix flake check` is the single gate; the controller (Claude) drives it via the pre-push hook. Executor inner loop is `cargo check` + `cargo clippy` ONLY (see executor constraints).

## Executor constraints (K3 — read first)

- **NEVER run tests** (`cargo test`, `cargo nextest run`) — they hang
  uninterruptibly in this sandbox. Tests are executed by the controller via
  the unsandboxed `nix flake check` gate after your run. Where a step below
  says "run tests", substitute:
  `cargo check -p keri-rs -p keri-codec --all-targets` then
  `cargo clippy -p keri-rs -p keri-codec --all-targets`.
  Clippy must be CLEAN — the workspace denies `all` + `pedantic` + `nursery` +
  restriction suite; never add an `#[allow]`.
- **NEVER run `git commit`/`git add`/`git checkout`** — the controller
  commits per task after review. Leave edits on disk.
- **Steps are SEQUENTIAL** — Tasks 1, 2, 3 all touch
  `crates/keri/src/error.rs`; Task 4 is controller-only. No fan-out.
- Import style: all `use` at top of file, no inline `use`, no
  fully-qualified construction paths (commit hooks enforce).
- Task 4 (CHANGELOG, push, PR) is CONTROLLER-ONLY — skip it entirely.

---

### Task 1: `MissingSignatures` carries the verified-signature count (breaking)

**Files:**
- Modify: `crates/keri/src/error.rs:27-29` (variant)
- Modify: `crates/keri/src/authority.rs:53-68` (raise site), `crates/keri/src/authority.rs:250-259` (unit test)
- Modify: `crates/keri-codec/tests/transitions.rs:168,195,443,618`
- Modify: `crates/keri-codec/tests/properties.rs:133`

- [ ] **Step 1: Update the six test assertions to expect the payload (failing first)**

`crates/keri-codec/tests/transitions.rs` — four `matches!` sites get exact counts:

Line 168 (`genesis_without_signatures_is_missing_signatures` — empty sig list):
```rust
    assert!(matches!(r, Rejection::MissingSignatures { verified: 0 }));
```

Line 195 (`multisig_inception_below_threshold_is_missing_signatures` — 1 valid sig, 2-of-3):
```rust
    assert!(matches!(r, Rejection::MissingSignatures { verified: 1 }));
```

Line 443 (below-threshold rotation — 1 valid sig of 2 required):
```rust
    assert!(matches!(r, Rejection::MissingSignatures { verified: 1 }));
```

Line 618 (`interaction_below_threshold_is_missing_signatures` — 1 valid sig, 2-of-3):
```rust
    assert!(matches!(r, Rejection::MissingSignatures { verified: 1 }));
```

`crates/keri-codec/tests/properties.rs:133` (`inception_threshold_boundary` — `t - 1` signers):
```rust
        prop_assert!(
            matches!(below, Err(Rejection::MissingSignatures { verified }) if verified == t - 1)
        );
```

`crates/keri/src/authority.rs` unit test (`verify_under_threshold_is_missing_signatures`, ~line 251 — 1 of 2 sigs):
```rust
        assert!(matches!(
            Authority::new(&keys, &th).verify(msg, &sigs[..1]),
            Err(Rejection::MissingSignatures { verified: 1 })
        ));
```

- [ ] **Step 2: Verify the build fails (tests now name a payload the variant lacks)**

Run: `cargo check -p keri-rs -p keri-codec --all-targets 2>&1 | tail -20`
Expected: compile error `variant Rejection::MissingSignatures does not have a field named verified` (or similar E0026/E0559).

- [ ] **Step 3: Change the variant and the raise site**

`crates/keri/src/error.rs` — replace lines 27-29:
```rust
    /// The verified signatures do not satisfy the signing threshold.
    ///
    /// `verified` is the number of signatures that verified against a current
    /// key. Under [`Authority::verify`](crate::Authority::verify)'s
    /// abort-on-bad-signature semantics every *provided* signature verified
    /// when this fires, so `verified == 0` means the attached signature set
    /// was empty.
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) when `verified == 0`
    /// (KERI spec: a message without at least one verifiable controller
    /// signature MUST be dropped, not escrowed — DDoS guard);
    /// [`Awaiting(Signatures)`](EvidenceKind::Signatures) when `verified >= 1`
    /// (spec SHOULD-escrow; keripy `.pses` via `escrowPSEvent` +
    /// `MissingSignatureError`). Re-drive trigger: more controller signatures
    /// for the same event version arrive.
    #[error("signing threshold not satisfied: {verified} verified signature(s)")]
    MissingSignatures {
        /// How many signatures verified against a current key.
        verified: usize,
    },
```

`crates/keri/src/authority.rs` — in `verify` (lines 62-67), capture the count before
`satisfied_by` consumes the Vec:
```rust
        let indices = verify_indexed(&keys, bytes, sigs).collect::<Result<Vec<_>, _>>()?;
        let verified = indices.len();
        if self.threshold.satisfied_by(indices) {
            Ok(())
        } else {
            Err(Rejection::MissingSignatures { verified })
        }
```

Also update the doc comment on `verify` (lines 50-52) to name the payload:
```rust
    /// Returns [`Rejection::UnverifiedSignature`] if a signature fails to verify or
    /// its index addresses no key, or [`Rejection::MissingSignatures`] (carrying the
    /// verified-signature count) if the verified set does not satisfy the threshold.
```

- [ ] **Step 4: Run the affected crates' tests**

Run: `cargo check -p keri-rs -p keri-codec --all-targets && cargo clippy -p keri-rs -p keri-codec --all-targets 2>&1 | tail -5`
Expected: clean check and clean clippy (no warnings — workspace lints deny). Tests run in the controller's gate.

- [ ] **Step 5: Commit**

```bash
git add crates/keri/src/error.rs crates/keri/src/authority.rs crates/keri-codec/tests/transitions.rs crates/keri-codec/tests/properties.rs
git commit -m "refactor(keri)!: #88 MissingSignatures carries verified-signature count

Breaking: Rejection::MissingSignatures is now a struct variant
{ verified: usize }. The KERI spec's DDoS rule (spec-body.md:1266)
splits on this count — zero verifiable signatures MUST drop, one or
more below threshold SHOULD escrow — so K2's disposition() needs it.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: `Disposition`, `EvidenceKind`, `Rejection::disposition()`

**Files:**
- Modify: `crates/keri/src/error.rs` (new enums + method + tests; rustdoc pass on every variant)
- Modify: `crates/keri/src/lib.rs:60` (re-export)

- [ ] **Step 1: Write the failing tests**

Append to the existing `#[cfg(test)] mod tests` in `crates/keri/src/error.rs`:

```rust
    #[test]
    fn out_of_order_gap_awaits_prior_events() {
        let r = Rejection::OutOfOrder {
            expected: 3,
            actual: 7,
        };
        assert_eq!(
            r.disposition(),
            Disposition::Awaiting(EvidenceKind::PriorEvents { expected_sn: 3 })
        );
    }

    #[test]
    fn out_of_order_stale_is_terminal() {
        let r = Rejection::OutOfOrder {
            expected: 3,
            actual: 2,
        };
        assert_eq!(r.disposition(), Disposition::Terminal);
    }

    #[test]
    fn out_of_order_stale_at_u128_boundary_is_terminal() {
        let r = Rejection::OutOfOrder {
            expected: u128::MAX,
            actual: 0,
        };
        assert_eq!(r.disposition(), Disposition::Terminal);
    }

    #[test]
    fn out_of_order_minimal_gap_awaits_prior_events() {
        let r = Rejection::OutOfOrder {
            expected: 3,
            actual: 4,
        };
        assert_eq!(
            r.disposition(),
            Disposition::Awaiting(EvidenceKind::PriorEvents { expected_sn: 3 })
        );
    }

    #[test]
    fn zero_verified_signatures_is_terminal() {
        let r = Rejection::MissingSignatures { verified: 0 };
        assert_eq!(r.disposition(), Disposition::Terminal);
    }

    #[test]
    fn one_verified_signature_below_threshold_awaits_signatures() {
        let r = Rejection::MissingSignatures { verified: 1 };
        assert_eq!(
            r.disposition(),
            Disposition::Awaiting(EvidenceKind::Signatures)
        );
    }

    #[test]
    fn insufficient_witness_receipts_awaits_receipts() {
        let r = Rejection::InsufficientWitnessReceipts {
            valid: 1,
            required: 3,
        };
        assert_eq!(
            r.disposition(),
            Disposition::Awaiting(EvidenceKind::WitnessReceipts {
                valid: 1,
                required: 3
            })
        );
    }

    #[test]
    fn delegation_unsupported_awaits_delegation_evidence() {
        let r = Rejection::DelegationUnsupported;
        assert_eq!(
            r.disposition(),
            Disposition::Awaiting(EvidenceKind::DelegationEvidence)
        );
    }

    #[test]
    fn prior_digest_mismatch_is_terminal() {
        assert_eq!(Rejection::PriorDigestMismatch.disposition(), Disposition::Terminal);
    }

    #[test]
    fn unverified_signature_is_terminal() {
        let r = Rejection::from(IndexedVerifyError::IndexOutOfRange {
            index: 5,
            key_count: 2,
        });
        assert_eq!(r.disposition(), Disposition::Terminal);
    }

    #[test]
    fn malformed_threshold_is_terminal() {
        let r = Rejection::from(SigningThresholdError::BelowMinimum);
        assert_eq!(r.disposition(), Disposition::Terminal);
    }

    #[test]
    fn prior_next_threshold_unsatisfied_awaits_signatures() {
        assert_eq!(
            Rejection::PriorNextThresholdUnsatisfied { exposed: 0 }.disposition(),
            Disposition::Awaiting(EvidenceKind::Signatures)
        );
    }

    #[test]
    fn witness_set_error_is_terminal() {
        let r = Rejection::from(WitnessSetError::RemovalNotCurrent);
        assert_eq!(r.disposition(), Disposition::Terminal);
    }

    #[test]
    fn witness_threshold_exceeded_is_terminal() {
        let r = Rejection::WitnessThresholdExceeded { toad: 3, count: 2 };
        assert_eq!(r.disposition(), Disposition::Terminal);
    }

    #[test]
    fn transferability_error_is_terminal() {
        let r = Rejection::from(TransferabilityError::NonTransferableCommitsNextKeys);
        assert_eq!(r.disposition(), Disposition::Terminal);
    }

    #[test]
    fn structural_error_is_terminal() {
        let r = Rejection::from(StructuralError::DuplicateInception);
        assert_eq!(r.disposition(), Disposition::Terminal);
    }
```

- [ ] **Step 2: Verify they fail to compile (types don't exist yet)**

Run: `cargo check -p keri-rs --all-targets 2>&1 | tail -10`
Expected: compile error `cannot find type Disposition in this scope` / `no method named disposition`.

- [ ] **Step 3: Implement the enums and the method**

Add to `crates/keri/src/error.rs`, after the `Rejection` enum (before `WitnessSetError`):

```rust
/// What a host should do with a rejected event.
///
/// Escrow as a pure classification: `keri-rs` owes only the verdict on the
/// fold's [`Rejection`] — parking, retry scheduling, timeouts, and storage
/// are entirely the host's (an event-sourced host records "awaiting X" as its
/// own state and re-drives the event when X arrives). Both enums here are
/// deliberately exhaustive: a new evidence kind (K4 delegation, K5 receipt
/// evidence) must be a compile error in hosts, not a silently-parked event
/// that never re-drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Never acceptable — drop or report. (Duplicity routing detail is K3.)
    Terminal,
    /// Acceptable the moment this evidence arrives — park and re-drive.
    Awaiting(EvidenceKind),
}

/// The specific evidence whose arrival makes a parked event acceptable.
///
/// Each variant names the keripy escrow whose *outcome* it reproduces
/// (semantics, not tables — see the K2 design doc for line-anchored
/// evidence). Receipt evidence for transferable receiptors is K5 and will be
/// added as a deliberate breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceKind {
    /// The KEL events between the accepted head and `expected_sn`.
    /// keripy `.ooes` (out-of-order escrow). Re-drive when the prior
    /// event(s) arrive and fold in order.
    PriorEvents {
        /// The sequence number the fold expected next.
        expected_sn: u128,
    },
    /// More controller signatures for the same event version.
    /// keripy `.pses` (partially-signed escrow). Re-drive when new
    /// signatures arrive, attached to the event or to a receipt of it.
    Signatures,
    /// More witness receipts over the event. keripy `.pwes` (partially
    /// witnessed escrow). Re-drive when further receipts arrive.
    WitnessReceipts {
        /// Distinct witnesses whose receipt verified.
        valid: usize,
        /// The governing threshold of accountable duplicity (TOAD).
        required: u32,
    },
    /// The delegator's authorizing evidence for a delegated event.
    /// keripy `.pdes`/`.udes` (partially/unverified delegated escrow).
    /// K4 builds the verification path; re-drive when it lands and the
    /// delegator's seal is available.
    DelegationEvidence,
}

impl Rejection {
    /// Classify this rejection: [`Terminal`](Disposition::Terminal) or
    /// [`Awaiting`](Disposition::Awaiting) specific evidence.
    ///
    /// Total over every variant with no wildcard arm, so a new [`Rejection`]
    /// variant forces a decision here at compile time. The rule: **awaiting**
    /// iff more host-supplied evidence (prior events, signatures, receipts,
    /// delegator approval) can change the verdict on re-drive; **terminal**
    /// iff the verdict is a function of the event's own content plus accepted
    /// state alone, so re-driving the same event can never succeed.
    #[must_use]
    pub const fn disposition(&self) -> Disposition {
        match self {
            Self::OutOfOrder { expected, actual } => {
                if *actual > *expected {
                    Disposition::Awaiting(EvidenceKind::PriorEvents {
                        expected_sn: *expected,
                    })
                } else {
                    // Stale: the "missing prior" already exists, so no
                    // evidence arrival can cure it. keripy routes sn <= sno
                    // to the duplicity / superseding-recovery path — K3.
                    Disposition::Terminal
                }
            }
            Self::MissingSignatures { verified: 0 } => Disposition::Terminal,
            Self::MissingSignatures { .. } => {
                Disposition::Awaiting(EvidenceKind::Signatures)
            }
            Self::InsufficientWitnessReceipts { valid, required } => {
                Disposition::Awaiting(EvidenceKind::WitnessReceipts {
                    valid: *valid,
                    required: *required,
                })
            }
            Self::DelegationUnsupported => {
                Disposition::Awaiting(EvidenceKind::DelegationEvidence)
            }
            Self::PriorDigestMismatch
            | Self::UnverifiedSignature(_)
            | Self::MalformedThreshold(_)
            | Self::WitnessSet(_)
            | Self::WitnessThresholdExceeded { .. }
            | Self::Transferability(_)
            | Self::Structural(_) => Disposition::Terminal,
            Self::PriorNextThresholdUnsatisfied { .. } => {
                Disposition::Awaiting(EvidenceKind::Signatures)
            }
        }
    }
}
```

`crates/keri/src/lib.rs:60` — extend the re-export:
```rust
pub use error::{
    Disposition, EvidenceKind, Rejection, StructuralError, TransferabilityError, WitnessSetError,
};
```

- [ ] **Step 4: Run the tests**

Run: `cargo check -p keri-rs --all-targets && cargo clippy -p keri-rs --all-targets 2>&1 | tail -5`
Expected: PASS, including the 16 new disposition tests.

- [ ] **Step 5: Commit**

```bash
git add crates/keri/src/error.rs crates/keri/src/lib.rs
git commit -m "feat(keri): #88 K2 Rejection::disposition — terminal vs awaiting-evidence

Escrow as a pure classification on the fold's verdict: Disposition
{Terminal, Awaiting(EvidenceKind)} with a total, wildcard-free const
match. Both enums exhaustive by design — K4/K5 evidence kinds must be
compile errors in hosts, not silently-parked events.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Rustdoc pass — every `Rejection` variant names its disposition, keripy equivalent, re-drive trigger

**Files:**
- Modify: `crates/keri/src/error.rs` (doc comments only; `MissingSignatures` already done in Task 1)
- Modify: `crates/keri/src/lib.rs:39-43` (crate-doc pointer to `disposition`)

- [ ] **Step 1: Rewrite the variant docs**

Replace each variant's doc comment in `crates/keri/src/error.rs` (code and
`#[error]` strings unchanged). Evidence anchors are in the design doc; docs
carry the semantic mapping only:

`OutOfOrder`:
```rust
    /// Sequence number is not the expected next sn.
    ///
    /// Disposition: gap (`actual > expected`) is
    /// [`Awaiting(PriorEvents)`](EvidenceKind::PriorEvents) — keripy's
    /// out-of-order escrow (`.ooes`, `OutOfOrderError`); re-drive when the
    /// missing prior events arrive. Stale (`actual < expected`) is
    /// [`Terminal`](Disposition::Terminal): the prior event already exists,
    /// keripy routes it to duplicity / superseding recovery — K3.
```

`PriorDigestMismatch`:
```rust
    /// Prior-event digest does not match the current state's latest SAID.
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal). Fires at the
    /// in-order sn, where keripy raises a bare `ValidationError` (drop).
    /// keripy's likely-duplicitous escrow (`.ldes`) concerns a *different*
    /// situation — a second event at an already-accepted sn — which is K3's
    /// duplicity verdict, not this rejection.
```

`UnverifiedSignature`:
```rust
    /// A controller signature did not verify, or its index addressed no key.
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) — re-driving the
    /// same event re-checks the same signatures. Divergence (D1, see the K2
    /// design doc): keripy *filters* unverifiable signatures and judges the
    /// valid subset, so it never rejects solely for a bad attached signature;
    /// this fold aborts on the first one. Tracked with #132/#133; K9
    /// differential must account for it.
```

`MalformedThreshold`:
```rust
    /// The event's signing threshold is not well-formed for its key set.
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) — keripy raises a
    /// bare `ValidationError` (drop) for an invalid sith.
```

`PriorNextThresholdUnsatisfied`:
```rust
    /// The verified signatures do not expose enough prior next keys to
    /// satisfy the prior next threshold.
    ///
    /// Disposition:
    /// [`Awaiting(Signatures)`](EvidenceKind::Signatures) — keripy's
    /// partially-signed escrow (`.pses` via `escrowPSEvent` +
    /// `MissingSignatureError`, `src/keri/core/eventing.py:2877-2885`).
    /// Divergence D2 from the K2 design doc is closed by #132.
    #[error("prior next threshold not satisfied: {exposed} exposed prior-next key(s)")]
    PriorNextThresholdUnsatisfied {
        /// Distinct prior-next indices exposed by verified signatures.
        exposed: usize,
    },
```

`WitnessSet`:
```rust
    /// A rotation's witness cut/add deltas are inconsistent.
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) — keripy's backer
    /// derivation raises a bare `ValidationError` (drop) for every cut/add
    /// algebra violation.
```

`WitnessThresholdExceeded`:
```rust
    /// The witness threshold (TOAD) is out of bounds for the witness set.
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) — keripy drops
    /// out-of-bounds toads with a bare `ValidationError`.
```

`InsufficientWitnessReceipts` (replaces the stale "terminal rejection" prose):
```rust
    /// Fewer distinct witnesses than the TOAD requires have a valid receipt
    /// over the event.
    ///
    /// Disposition:
    /// [`Awaiting(WitnessReceipts)`](EvidenceKind::WitnessReceipts) —
    /// keripy's partially-witnessed escrow (`.pwes`, `escrowPWEvent` +
    /// `MissingWitnessSignatureError`). Re-drive when further witness
    /// receipts arrive.
```

`Transferability`:
```rust
    /// The inception violates a transferability / next-key commitment rule.
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) — inception content
    /// is self-contradictory. keripy drops a non-transferable inception that
    /// commits next keys; the self-addressing-without-next-keys rule is
    /// deliberately stricter than keripy, which accepts such an inception as
    /// an abandoned identifier (divergence D3, see the K2 design doc).
```

`DelegationUnsupported`:
```rust
    /// A delegated inception/rotation (`dip`/`drt`). Delegated-event folding —
    /// which requires verifying the delegator's authorizing seal — is deferred
    /// to K4 (delegation); K1 rejects these rather than accept them unverified.
    ///
    /// Disposition:
    /// [`Awaiting(DelegationEvidence)`](EvidenceKind::DelegationEvidence) —
    /// keripy's delegated escrows (`.pdes`/`.udes`). Re-drive once K4's
    /// verification path lands and the delegator's evidence is available.
```

`Structural`:
```rust
    /// The event violates a structural rule (shape, arity, message type
    /// placement, ranges).
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) — the KERI spec
    /// requires config-trait violations to be invalidated ("MUST … drop"),
    /// and the remaining shape/arity/range violations are functions of the
    /// event's own content.
```

Also update the `Rejection` enum-level doc line 9 — the taxonomy note is now
stale:
```rust
/// Why an event was not accepted by the fold.
///
/// The fold's single verdict type. Variants that wrap a cesr or keri sub-error
/// carry it directly, so the precise cause survives (`?` lifts each source in via
/// [`From`]). [`disposition`](Self::disposition) classifies every variant as
/// [`Terminal`](Disposition::Terminal) or [`Awaiting`](Disposition::Awaiting)
/// specific evidence — the K2 escrow verdict.
/// `#[non_exhaustive]` keeps additions non-breaking for external matchers.
```

`crates/keri/src/lib.rs` — extend the K4 paragraph (lines 39-43) with the host
guidance sentence:
```rust
//! **Delegation authorization is deferred to K4.** Verifying a delegated event's
//! authorizing seal requires the delegator's KEL, which this crate does not have,
//! so delegated inceptions/rotations (`dip`/`drt`) are rejected
//! ([`DelegationUnsupported`](Rejection::DelegationUnsupported)) rather than
//! accepted unverified.
//!
//! **Escrow is a classification, not a subsystem.** For every [`Rejection`]
//! the fold owes exactly one extra bit of judgment:
//! [`Rejection::disposition`] says whether the event is
//! [`Terminal`](Disposition::Terminal) (never acceptable — drop) or
//! [`Awaiting`](Disposition::Awaiting) specific
//! [`EvidenceKind`] (park and re-drive when it arrives). Storage, timers,
//! and retry scheduling are the host's.
```

- [ ] **Step 2: Doc build + tests**

Run: `cargo doc -p keri-rs --no-deps 2>&1 | tail -5 && cargo clippy -p keri-rs --all-targets 2>&1 | tail -3`
Expected: doc build with ZERO warnings — inspect the output for `broken intra-doc link` warnings and fix any (they may be warnings here but fail the flake gate); clippy clean.

- [ ] **Step 3: Commit**

```bash
git add crates/keri/src/error.rs crates/keri/src/lib.rs
git commit -m "docs(keri): #88 disposition, keripy escrow equivalent, re-drive trigger on every Rejection variant

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: CHANGELOG, gate, PR

**Files:**
- Modify: `crates/keri/CHANGELOG.md` (Unreleased section)

- [ ] **Step 1: CHANGELOG entries**

Add under `## [Unreleased]` in `crates/keri/CHANGELOG.md` — a new `### Added`
block before the existing `### Changed`, and one entry at the top of
`### Changed`:

```markdown
### Added

- `Rejection::disposition()` with `Disposition` / `EvidenceKind` — K2 escrow
  as a pure classification: every fold rejection is `Terminal` (drop) or
  `Awaiting` specific evidence (park and re-drive). Both enums are
  deliberately exhaustive so new evidence kinds (K4/K5) are compile errors
  in hosts. (#88)
```

```markdown
- [**breaking**] `Rejection::MissingSignatures` is now a struct variant
  carrying `verified: usize` (the count of signatures that verified). The
  KERI spec's DDoS rule splits on this count: zero verifiable signatures
  MUST be dropped, one or more below threshold SHOULD be escrowed. (#88)
```

- [ ] **Step 2: Commit, push (gate runs via pre-push hook)**

```bash
git add crates/keri/CHANGELOG.md
git commit -m "docs(keri): #88 CHANGELOG — disposition API + MissingSignatures payload

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
git push -u origin 88-k2-escrow-dispositions
```

Expected: pre-push hook runs `nix flake check` on committed state; push
succeeds only if green. Do NOT foreground-poll a separate `nix flake check`.

- [ ] **Step 3: PR**

```bash
gh pr create --title "feat(keri): #88 K2 escrow dispositions — Rejection::disposition, terminal vs awaiting-evidence" --body "$(cat <<'EOF'
Closes #88.

Escrow as a pure classification on the fold's verdict — no tables, no
timers, no storage. `Rejection::disposition()` is a total, wildcard-free
`const fn`: **Terminal** (re-driving the same event can never succeed) or
**Awaiting(EvidenceKind)** (park; re-drive when the named evidence arrives).

Design doc with line-anchored evidence (keripy `eventing.py` + ToIP spec):
`docs/superpowers/specs/2026-07-29-88-k2-escrow-dispositions-design.md`.

**Breaking** (0.x minor): `Rejection::MissingSignatures` →
`MissingSignatures { verified: usize }`. Spec rule (spec-body.md:1266):
zero verifiable signatures MUST drop (DDoS guard), ≥1 below threshold
SHOULD escrow — the disposition needs the count.

Classification highlights (full table in the design doc):
- `OutOfOrder` gap → `Awaiting(PriorEvents)` (keripy `.ooes`); stale →
  `Terminal` (keripy routes to duplicity/superseding recovery — K3).
- `InsufficientWitnessReceipts` → `Awaiting(WitnessReceipts)` (`.pwes`).
- `DelegationUnsupported` → `Awaiting(DelegationEvidence)` (`.pdes`/`.udes`).
- Everything content-determined → `Terminal`.

Recorded keripy divergences: D1 signature filtering (#133); D2 next-key
commitment ondex semantics resolved by #132; D3 abandoned-identifier
inceptions resolved by #250. Each noted on the variant rustdoc for K9.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)" --base main
gh pr merge --auto --squash
```

Expected: PR opens against main, auto-merge armed pending CI.

---

## Self-review notes

- Spec coverage: surface (Task 2), breaking payload (Task 1), rustdoc duty
  (Task 3 + `MissingSignatures` in Task 1), tests per variant/branch with
  boundaries (Task 2 Step 1), CHANGELOG/PR callout (Task 4). K9 vectors are
  out of scope per design doc.
- `disposition()` is a method, not a free fn — `free-fn-budget.toml`
  (`keri-rs = 0`) unaffected.
- `Rejection` stays `#[non_exhaustive]`; the exhaustive match lives inside
  the defining crate, so the acceptance criterion (no wildcard arm) holds.
- Const fn: match + nested `if` on `Copy` scalars is const-stable; clippy
  nursery `missing_const_for_fn` would demand it anyway.
