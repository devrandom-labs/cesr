# 250 — D3: accept abandoned-at-birth inceptions, gate events on non-transferable state

## Context

Spec: `docs/superpowers/specs/2026-07-29-250-d3-abandoned-inceptions-design.md` (read it first).

- KERI spec (ToIP, "Next key digest list field"): inception with empty `n` —
  "the associated AID MUST be deemed non-transferable, and no more key events
  MUST be allowed in that KEL"; rotation with empty `n` — "deemed abandoned,
  and no more key events MUST be allowed".
- keripy (`eventing.py`, 9161a705): inception accepts empty `n` on a
  transferable prefix (only inception check: 2374-2378 non-trans prefix must
  have empty `n`); `Kever.transferable` = ndigers non-empty AND prefix code
  transferable (2166); `Kever.update` rejects ALL further events on a
  non-transferable state (2477).
- Our fold rejects the inception (`SelfAddressingWithoutNextKeys`,
  `crates/keri/src/state.rs:650`) — spec nonconformance. Two latent gaps share
  the root cause: `ingest` has no transferability gate (interaction on a basic
  non-transferable AID is accepted today), and rotation-to-empty-`n` leaves a
  state that still accepts interactions.

Invariants that must hold:

- State transferability = prefix code transferable AND `next_keys` non-empty,
  recomputed at every establishment (validating fold AND trusted snapshot fold).
- A non-transferable state rejects EVERY event, first in precedence (before
  duplicate-inception / delegation checks), with the new
  `Rejection::NonTransferableState`, disposition `Terminal`.
- Trusted snapshot fold stays total, deterministic, crypto-free — computation
  only, no new checks.
- Breaking changes (variant removed from `TransferabilityError`, variant added
  to `Rejection`, fold behavior) go in `crates/keri/CHANGELOG.md` under
  `[Unreleased]`.
- All snippets below are rustfmt-clean; keep them so.
- Engineering rules apply: no inline `use`, exact-variant `matches!` in tests,
  comments only for the why.

## Steps

### Step 1 — error.rs: variant swap + disposition (SEQUENTIAL — first)

File: `crates/keri/src/error.rs`

1a. Delete `TransferabilityError::SelfAddressingWithoutNextKeys` (lines
277-279). `TransferabilityError` keeps its one remaining variant.

1b. Rewrite the `Rejection::Transferability` rustdoc (lines 128-136) — the D3
divergence prose is now wrong. Replace the doc comment with:

```rust
    /// The inception violates the transferability / next-key agreement rule:
    /// a non-transferable prefix must not commit to next keys.
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) — inception content
    /// is self-contradictory; keripy drops it with a bare `ValidationError`
    /// (eventing.py:2374-2378). The former self-addressing-without-next-keys
    /// rejection was removed by #250: the spec requires such an inception to
    /// be accepted and deemed non-transferable (see
    /// [`NonTransferableState`](Self::NonTransferableState)).
```

1c. Add a new `Rejection` variant after `DelegationUnsupported` (before
`Structural`):

```rust
    /// Any event on a non-transferable or abandoned key state: the state
    /// commits to no next keys (empty-`n` inception, or abandonment via an
    /// empty-`n` rotation), so its KEL admits no more key events (spec MUST).
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) — keripy drops with a
    /// bare `ValidationError` ("Unexpected event … is nontransferable or
    /// abandoned state", eventing.py:2477). No evidence can re-open a closed
    /// KEL, so there is no re-drive trigger.
    #[error("no more key events: key state is non-transferable or abandoned")]
    NonTransferableState,
```

1d. In `disposition()` add `Self::NonTransferableState` to the `Terminal`
arm (the big `|` chain). The match has no wildcard — the compiler enforces
this.

1e. Tests in the same file's `#[cfg(test)]` module: the test at ~line 372
constructs `TransferabilityError::SelfAddressingWithoutNextKeys` — rewrite it
against `NonTransferableCommitsNextKeys`. Add a disposition test:

```rust
    #[test]
    fn non_transferable_state_is_terminal() {
        assert_eq!(
            Rejection::NonTransferableState.disposition(),
            Disposition::Terminal
        );
    }
```

Verification: `cargo check -p keri-rs` (expect state.rs to now fail — fixed in
Step 2; run the check after Step 2 for a green signal, or check both together).

### Step 2 — state.rs: derived transferability + inert gate (SEQUENTIAL — depends on Step 1)

File: `crates/keri/src/state.rs`

2a. `Transferability` rustdoc (lines 33-39) is wrong once derivation changes.
Replace with:

```rust
/// Whether an identifier's controlling keys can be rotated.
///
/// Derived state, not a prefix-code echo (keripy `Kever.transferable`,
/// eventing.py:2166): `Transferable` iff the prefix code is transferable AND
/// the current next-key commitment is non-empty. Recomputed at every
/// establishment event — an empty-`n` inception is non-transferable at birth,
/// and an empty-`n` rotation abandons the identifier. A non-transferable
/// state admits no further events (spec: "no more key events").
```

2b. `decide_transferability` (lines 640-657) — drop the self-addressing check,
derive from both facts:

```rust
/// Transferability must agree with the pre-rotation commitment: a
/// non-transferable prefix commits to no next keys. A transferable prefix
/// with an empty next-key list is accepted and deemed non-transferable at
/// birth (spec; keripy eventing.py:2166).
fn decide_transferability(icp: &InceptionEvent) -> Result<Transferability, TransferabilityError> {
    let transferable = icp.prefix().is_transferable();
    let next_empty = icp.next_keys().is_empty();
    if !transferable && !next_empty {
        return Err(TransferabilityError::NonTransferableCommitsNextKeys);
    }
    Ok(if transferable && !next_empty {
        Transferability::Transferable
    } else {
        Transferability::NonTransferable
    })
}
```

2c. `ingest` — inert-state gate first, before the event-kind match (keripy's
2477 gate precedes everything; error precedence now matches keripy):

```rust
    pub fn ingest(self, signed: &Signed<'e>) -> Result<Self, Rejection> {
        if !self.is_transferable() {
            return Err(Rejection::NonTransferableState);
        }
        match signed.event {
```

Also extend the `ingest` rustdoc `# Errors` sentence to mention the gate:
events on a non-transferable or abandoned state are rejected first.

2d. `rotated()` — abandonment: recompute transferability before `..self`:

```rust
            transferability: if rot.next_keys().is_empty() {
                Transferability::NonTransferable
            } else {
                self.transferability
            },
```

(`self.transferability` is necessarily `Transferable` here — the gate ran —
but the carry form keeps the expression total; do not add an assert.)

2e. `KeyStateSnapshot::genesis` (lines ~434-439) — mirror the derived rule:

```rust
        let transferability = if icp.prefix().is_transferable() && !icp.next_keys().is_empty() {
            Transferability::Transferable
        } else {
            Transferability::NonTransferable
        };
```

Update the `genesis` rustdoc line "Transferability is derived from the prefix
alone" — now "derived from the prefix code and the next-key commitment".

2f. `rolled()` — same recompute as 2d (field before `..self`):

```rust
            transferability: if rot.next_keys().is_empty() {
                Transferability::NonTransferable
            } else {
                self.transferability
            },
```

Trusted fold stays total and crypto-free: these are computations, not checks.

Verification: `cargo check -p keri-rs && cargo clippy -p keri-rs --all-features`

### Step 3 — transition tests (PARALLEL OK after Step 2; files disjoint from Steps 4-5)

Files: `crates/keri-codec/tests/transitions.rs`,
`crates/keri-codec/tests/common/mod.rs`

3a. Helper in `common/mod.rs` next to `plain_rotation`: an abandoning
rotation. Mirror `inception_full`'s conditional — only set `next_threshold`
when the next set is non-empty; if `RotationBuilder::build` rejects the
default threshold against an empty next list, that is the how to solve here
(read `crates/keri-codec/src/builder/rot.rs:336` first):

```rust
/// A single-signer rotation committing to no next keys (abandonment).
pub fn abandoning_rotation(prior: &Event, sn: u128, reveal: &Key) -> Fallible<Event> {
    let ser = RotationBuilder::new()
        .prefix(prior.prefix.clone())
        .prior_event_said(prior.said.clone())
        .keys(verfers(&[reveal]))
        .prior_witnesses(vec![])
        .sn(sn)
        .threshold(SigningThreshold::Simple(1))
        .next_keys(vec![])
        .build()?;
    finish_chained(&ser, prior.prefix.clone())
}
```

3b. In `transitions.rs`, REPLACE
`inception_committing_to_no_next_keys_is_invalid` (~line 222, asserts the
deleted variant) with acceptance + closed-KEL probes:

```rust
#[test]
fn inception_without_next_keys_is_accepted_like_keripy() -> Fallible<()> {
    // Spec: an empty-`n` inception MUST be deemed non-transferable and its
    // KEL closed (keripy eventing.py:2166 accepts; 2477 closes).
    let k0 = Key::new()?;
    let icp = inception_full(&[&k0], &[], SigningThreshold::Simple(1), &[], 0)?;
    let state = KeyState::incept(&icp.signed(vec![k0.sign(&icp.bytes, 0)?]))?;
    assert!(!state.is_transferable());
    Ok(())
}

#[test]
fn rotation_on_an_abandoned_at_birth_identifier_is_rejected() -> Fallible<()> {
    let (k0, k1, k2) = (Key::new()?, Key::new()?, Key::new()?);
    let icp = inception_full(&[&k0], &[], SigningThreshold::Simple(1), &[], 0)?;
    let state = KeyState::incept(&icp.signed(vec![k0.sign(&icp.bytes, 0)?]))?;
    let rot = plain_rotation(&icp, 1, &k1, &k2)?;
    let Err(r) = state.ingest(&rot.signed(vec![k1.sign(&rot.bytes, 0)?])) else {
        return Err("a rotation on an abandoned-at-birth identifier was accepted".into());
    };
    assert!(matches!(r, Rejection::NonTransferableState));
    Ok(())
}

#[test]
fn interaction_on_an_abandoned_at_birth_identifier_is_rejected() -> Fallible<()> {
    let k0 = Key::new()?;
    let icp = inception_full(&[&k0], &[], SigningThreshold::Simple(1), &[], 0)?;
    let state = KeyState::incept(&icp.signed(vec![k0.sign(&icp.bytes, 0)?]))?;
    let ixn = interaction(&icp, 1)?;
    let Err(r) = state.ingest(&ixn.signed(vec![k0.sign(&ixn.bytes, 0)?])) else {
        return Err("an interaction on an abandoned-at-birth identifier was accepted".into());
    };
    assert!(matches!(r, Rejection::NonTransferableState));
    Ok(())
}
```

3c. Abandonment-by-rotation test:

```rust
#[test]
fn abandonment_rotation_closes_the_kel() -> Fallible<()> {
    // Spec: an empty-`n` rotation abandons the identifier; no more key events.
    let (k0, k1) = (Key::new()?, Key::new()?);
    let icp = genesis(&k0, &k1)?;
    let rot = abandoning_rotation(&icp, 1, &k1)?;
    let state = seed(&icp, &k0)?.ingest(&rot.signed(vec![k1.sign(&rot.bytes, 0)?]))?;
    assert!(!state.is_transferable());
    let ixn = interaction(&rot, 2)?;
    let Err(r) = state.ingest(&ixn.signed(vec![k1.sign(&ixn.bytes, 0)?])) else {
        return Err("an interaction after an abandonment rotation was accepted".into());
    };
    assert!(matches!(r, Rejection::NonTransferableState));
    Ok(())
}
```

3d. Latent-gap probe — interaction on a basic non-transferable AID (fails on
pre-#250 code, proving the gap). The serder builders only mint self-addressing
prefixes, so forge the event with the `keri-events` internals constructor
(`InceptionEvent::new` — the pattern in
`crates/keri-codec/tests/serder_allocation.rs:116` builds an
`Identifier::Basic` inception): non-transferable Ed25519N prefix wrapping
`k0`'s raw key, `keys = [k0]`, empty `next_keys`, serialize via the
`keri_codec` `Serialize` trait, re-seal only `d` (the `reseal` helper in
`common/mod.rs` is the `d`-only span rewriter), sign with `k0`, `incept`, then
build an interaction on it (via `InteractionBuilder`, prefix =
`Identifier::Basic`) and assert `ingest` rejects with
`Rejection::NonTransferableState` via exact `matches!`. Name the test
`interaction_on_a_basic_non_transferable_identifier_is_rejected`. If a helper
is needed, add it to `common/mod.rs` beside `inception_full`.

3e. Update the imports in `transitions.rs` (drop nothing —
`TransferabilityError` is still used by the `NonTransferableCommitsNextKeys`
path only if a test asserts it; if no test uses it after 3b, remove it from
the `use keri::{...}` list).

Verification: `cargo check -p keri-codec --tests && cargo clippy -p keri-codec --tests`

### Step 4 — snapshot equivalence over abandonment (SEQUENTIAL — depends on Step 3's `abandoning_rotation` helper)

Files: `crates/keri-codec/tests/snapshot.rs` and/or
`crates/keri-codec/tests/properties.rs` — read both first; extend whichever
holds the validating-fold ↔ trusted-fold equivalence tests (follow the
existing pattern in that file).

Two additions:

- Empty-`n` genesis: `KeyStateSnapshot::genesis(icp)` must produce
  `transferability` equal to the validating fold's (`NonTransferable`), and
  `snapshot.view()` must equal the fold's `KeyState` field-for-field, per the
  existing equivalence assertion style.
- Abandonment rotation: fold `icp(genesis) → abandoning rotation` through the
  validating fold; `advance` the snapshot over the same events; assert the
  views stay equal and both report `is_transferable() == false`.

Reuse `abandoning_rotation` from `common` (Step 3a) — do not duplicate it.

Verification: `cargo check -p keri-codec --tests`

### Step 5 — docs (PARALLEL OK after Step 2; files disjoint from Steps 3-4)

5a. `crates/keri/CHANGELOG.md` under `## [Unreleased]`:

```markdown
### Changed

- [**breaking**] #250 D3 — an empty-`n` inception is now accepted and deemed
  non-transferable (spec MUST; keripy parity) instead of rejected;
  `TransferabilityError::SelfAddressingWithoutNextKeys` is removed. A new
  first-in-precedence `ingest` gate rejects every event on a non-transferable
  or abandoned key state with the new `Rejection::NonTransferableState`
  (disposition `Terminal`); an empty-`n` rotation now abandons the identifier
  in both the validating fold and `KeyStateSnapshot`.
```

5b. `docs/superpowers/specs/2026-07-29-88-k2-escrow-dispositions-design.md`:
append one line to the D3 bullet (~line 128): `Resolved by #250 — the
rejection is dropped; see 2026-07-29-250-d3-abandoned-inceptions-design.md.`
Also fix the disposition-table row (~line 107) that says
"`SelfAddressingWithoutNextKeys`: no keripy analog …" — mark it removed by
#250.

Verification: none beyond rendering — markdown only.

## Verification (whole plan)

- `cargo check --workspace --all-features`
- `cargo clippy --workspace --all-features`
- Do NOT run `cargo test`/`cargo nextest` (sandboxed dispatch hangs on test
  binaries). Tests run in `nix flake check`, driven by the controller at
  commit time.

## Out of scope

- K9 differential vectors (#95) — they now need NO D3 carve-out.
- D1/D2 (#132/#133), delegation (K4), escrow storage/timeouts (host runtime).
- No lint-level changes, no `clippy.toml`, no new `#[allow]`.
- Do not touch `free-fn-budget.toml` — no free `pub fn` may be added to
  production modules (the new test helper lives in `tests/common`, exempt).
