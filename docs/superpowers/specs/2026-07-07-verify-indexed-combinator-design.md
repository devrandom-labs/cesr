# Design — `cesr::crypto::verify_indexed` lazy indexed-signature combinator

**Date:** 2026-07-07
**Type:** Additive `cesr` public surface + `keri` refactor onto it. Not breaking (new fn + new error enum; keri internals only).

## Problem

`keri::state::verify_controller_sigs` is the inner loop of the KEL fold — it runs once per
event on every `ingest`. It currently hand-rolls, in `keri`, an operation defined entirely
over **cesr types**:

```rust
for sig in sigs {
    let signer = signer_at(signers, sig.index())?;   // u32 → usize, slice .get()
    verify(signer, signed_bytes, sig).map_err(...)?;
}
if threshold.satisfy(sigs.iter().map(Siger::index)) { ... }
```

Three smells:

1. **CESR-type logic in keri.** Resolving `siger.index() → keys[index]` is the *meaning* of an
   indexed signature — a `Siger`/`Verfer` operation. `signer_at` (the `u32→usize` conversion + bounds
   check) lives in keri only because no cesr combinator offers it.
2. **Two consumers of one pattern.** `Signed` carries both `sigs` (controller) and `wigs` (witness
   receipts), both `Vec<Siger>`, both requiring identical index-resolve-then-verify. `wigs` is not
   consumed yet (future scope) but will duplicate `signer_at` when it is.
3. **cesr already declares this as its intent.** `crypto::verify`'s docstring: *"composing into lazy
   iterator chains over `stream`-parsed signature groups: `sigers.try_for_each(|s| verify(verfer, msg, s))`."*
   The combinator is the missing piece that doc describes — the resolve step `verify` can't do alone
   (it takes an already-resolved `verfer`).

## Design decisions (confirmed with user)

- **Home: `cesr::crypto`**, next to `verify`. Index→key resolution is a CESR-level operation on CESR
  types; keri (state logic) should not own it. Consistent with the sans-io split.
- **Lazy, zero-alloc, borrowing.** Returns `impl Iterator`, no intermediate `Vec`, borrows `keys`/`data`/
  `sigs` throughout — matches cesr's borrow-before-own / lazy-over-eager aesthetic. The only allocation on
  the path stays inside `Tholder::satisfy` (its existing dedup `Vec`), unchanged.
- **Yields the verified key-index**, so threshold satisfaction composes directly on the output.

## Changes

### 1. New error enum — `src/crypto/error.rs`

```rust
/// Failure verifying an indexed signature against a key list: the index addressed no
/// key, or the signature did not verify.
#[derive(Debug, thiserror::Error)]
pub enum IndexedVerifyError {
    #[error("signature index {index} out of range for {key_count} keys")]
    IndexOutOfRange { index: u32, key_count: usize },
    #[error(transparent)]
    Verification(#[from] VerificationError),
}
```

Two distinct domains kept distinct (Mandatory Rule 3): an out-of-range index is malformed framing;
a verification failure is a bad signature. keri maps each to a different `RejectionReason` (below),
so they must not be merged.

### 2. New combinator — `src/crypto/verify.rs`

```rust
/// Verifies each indexed signature in `sigs` against the key it addresses in `keys`,
/// lazily. Each item is the signature's key-index on success, or the first failure
/// (index out of range, or the cryptographic check failed).
///
/// Zero-alloc and borrowing: resolution is `keys[siger.index()]`; verification defers
/// to [`verify`]. The index is CESR framing metadata and is not part of the signed
/// payload. Composes with `Tholder::satisfy` over the yielded indices.
pub fn verify_indexed<'a>(
    keys: &'a [Verfer<'a>],
    data: &'a [u8],
    sigs: impl IntoIterator<Item = &'a Siger<'a>> + 'a,
) -> impl Iterator<Item = Result<u32, IndexedVerifyError>> + 'a {
    sigs.into_iter().map(move |sig| {
        let index = sig.index();
        let pos = usize::try_from(index)
            .map_err(|_| IndexedVerifyError::IndexOutOfRange { index, key_count: keys.len() })?;
        let key = keys.get(pos)
            .ok_or(IndexedVerifyError::IndexOutOfRange { index, key_count: keys.len() })?;
        verify(key, data, sig)?;
        Ok(index)
    })
}
```

Re-export `verify_indexed` and `IndexedVerifyError` from `crypto/mod.rs` alongside `verify`.

### 3. keri refactor — `keri/src/state.rs`

`verify_controller_sigs` collapses to one traversal; `signer_at` is **deleted** (its logic moved
into the combinator):

```rust
fn verify_controller_sigs(
    signers: &[Verfer<'_>],
    signed_bytes: &[u8],
    threshold: &Tholder,
    sigs: &[Siger<'_>],
) -> Result<(), Rejection> {
    let indices = verify_indexed(signers, signed_bytes, sigs)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| match e {
            IndexedVerifyError::IndexOutOfRange { .. } => Rejection::new(RejectionReason::InvalidEvent),
            IndexedVerifyError::Verification(_) => Rejection::new(RejectionReason::InvalidSignature),
        })?;
    if threshold.satisfy(indices) {
        Ok(())
    } else {
        Err(Rejection::new(RejectionReason::MissingSignatures))
    }
}
```

Behavior-preserving: out-of-range index → `InvalidEvent` (was `signer_at`'s error), verify failure →
`InvalidSignature`, threshold miss → `MissingSignatures` — identical to today. `collect` fails fast on
the first bad signature, matching the current early-`?` return. The `wigs` path, when implemented, calls
the same `verify_indexed`.

## Testing (cesr, TDD — categories first)

In `crypto/verify.rs` tests:

1. **Happy round-trip:** N keys, N valid sigers at distinct indices → yields `Ok(index)` for each, in order.
2. **Out-of-range index:** a siger with `index == keys.len()` (and one with a large index) → first item is
   `Err(IndexOutOfRange { .. })`; assert the exact variant + fields.
3. **Bad signature:** a siger whose bytes don't match the resolved key → `Err(Verification(_))`; assert variant.
4. **Fail-fast / laziness:** a valid sig followed by a bad one → collecting stops at the error; a bad sig
   followed by a valid one → first item is the error (iterator not fully driven).
5. **Composition:** `verify_indexed(...).collect::<Result<Vec<_>,_>>()` then `Tholder::satisfy` returns the
   same accept/reject as the pre-refactor two-pass form on the same inputs.

keri side: the existing 30 `state.rs` tests (invalid-signature, missing-signature, out-of-range) must stay
green with no changes — they are the behavior-preservation guard.

## Boundary note

This moves index→key resolution across the seam **into cesr** (new `verify_indexed` + `IndexedVerifyError`).
Additive on cesr's public surface; keri strictly shrinks (`signer_at` deleted, one fewer hand-rolled loop).
Aligns with the sans-io split (cesr = crypto/codec primitives, keri = state logic) and with
`verify`'s documented composition intent.
