//! Shared test fixtures for the fold integration tests.
//!
//! These build **real** CESR/serder artifacts (via `InceptionBuilder` +
//! `deserialize_event`) so the fold is exercised against genuine wire-format
//! events rather than hand-rolled structs. Signatures carry placeholder raw
//! bytes: the fold never verifies them, it reads only `Siger::index`.
#![allow(
    dead_code,
    reason = "shared fixtures included by multiple test binaries; not every binary uses every helper"
)]
#![allow(
    unreachable_pub,
    reason = "helpers are `pub` for cross-test-file use; the module is private per test binary"
)]
#![allow(
    clippy::unwrap_used,
    reason = "test fixtures: a build failure here is a test-setup bug that should abort loudly"
)]
#![allow(
    clippy::too_many_arguments,
    reason = "witnessed-rotation fixture threads every rotation field explicitly for test clarity"
)]

use std::borrow::Cow;

use cesr::core::indexer::IndexerBuilder;
use cesr::core::indexer::code::IndexedSigCode;
use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::{DigestCode, VerKeyCode};
use cesr::core::primitives::{Diger, Prefixer, Saider, Siger, Tholder, Verfer};
use cesr::crypto::digest;
use cesr::keri::{ConfigTrait, KeriEvent};
use cesr::serder::{
    DelegatedInceptionBuilder, DelegatedRotationBuilder, InceptionBuilder, InteractionBuilder,
    RotationBuilder, deserialize_event,
};

use keri::KeyState;

/// An Ed25519 (transferable) verification key whose 32 raw bytes are all `fill`.
#[must_use]
pub fn verfer(fill: u8) -> Verfer<'static> {
    MatterBuilder::new()
        .with_code(VerKeyCode::Ed25519)
        .with_raw(Cow::<[u8]>::Owned(vec![fill; 32]))
        .unwrap()
        .build()
        .unwrap()
}

/// The Blake3-256 digest committing to `v`'s qualified-base64 form — the
/// pre-rotation commitment placed in an inception's `next_keys`.
#[must_use]
pub fn commit(v: &Verfer<'static>) -> Diger<'static> {
    digest(DigestCode::Blake3_256, &v.to_qb64b()).unwrap()
}

/// A single-signer, single-next-key inception event, round-tripped through
/// serder so it is a genuine parsed [`KeriEvent`].
#[must_use]
pub fn inception(k0: &Verfer<'static>, k1: &Verfer<'static>) -> KeriEvent {
    inception_with_config(k0, k1, vec![])
}

/// Like [`inception`] but with explicit configuration traits — for exercising
/// `estOnly` and other config-gated validation paths.
#[must_use]
pub fn inception_with_config(
    k0: &Verfer<'static>,
    k1: &Verfer<'static>,
    config: Vec<ConfigTrait>,
) -> KeriEvent {
    let serialized = InceptionBuilder::new()
        .keys(vec![k0.clone()])
        .threshold(Tholder::Simple(1))
        .next_keys(vec![commit(k1)])
        .next_threshold(Tholder::Simple(1))
        .config(config)
        .build()
        .unwrap();
    deserialize_event(serialized.as_bytes()).unwrap()
}

/// An interaction event at `sn` that chains onto `prior`: it carries `prior`'s
/// prefix and points its `prior_event_said` at `prior`'s latest SAID.
#[must_use]
pub fn interaction_after(prior: &KeyState, sn: u128) -> KeriEvent {
    let serialized = InteractionBuilder::new()
        .prefix(prior.prefix().clone().into_static())
        .prior_event_said(prior.latest_said().clone().into_static())
        .sn(sn)
        .build()
        .unwrap();
    deserialize_event(serialized.as_bytes()).unwrap()
}

/// A rotation event at `sn` that chains onto `prior`: it reveals `reveal` as the
/// new current key and commits to `next_commit` for the following rotation.
#[must_use]
pub fn rotation_after(
    prior: &KeyState,
    sn: u128,
    reveal: &Verfer<'static>,
    next_commit: &Verfer<'static>,
) -> KeriEvent {
    let serialized = RotationBuilder::new()
        .prefix(prior.prefix().clone().into_static())
        .prior_event_said(prior.latest_said().clone().into_static())
        .keys(vec![reveal.clone()])
        .sn(sn)
        .threshold(Tholder::Simple(1))
        .next_keys(vec![commit(next_commit)])
        .next_threshold(Tholder::Simple(1))
        .build()
        .unwrap();
    deserialize_event(serialized.as_bytes()).unwrap()
}

/// A rotation event at `sn` chaining onto `prior` that reveals `reveal`, commits
/// to `next_commit`, and applies witness cuts (`removals`) then adds
/// (`additions`) with a new TOAD (`toad`). Exercises the `resolve_witnesses`
/// cut/add path. `Prefixer` and `Verfer` are the same type, so [`verfer`] doubles
/// as a witness-prefix constructor.
#[must_use]
pub fn rotation_with_witnesses(
    prior: &KeyState,
    sn: u128,
    reveal: &Verfer<'static>,
    next_commit: &Verfer<'static>,
    removals: Vec<Prefixer<'static>>,
    additions: Vec<Prefixer<'static>>,
    toad: u32,
) -> KeriEvent {
    let serialized = RotationBuilder::new()
        .prefix(prior.prefix().clone().into_static())
        .prior_event_said(prior.latest_said().clone().into_static())
        .keys(vec![reveal.clone()])
        .sn(sn)
        .threshold(Tholder::Simple(1))
        .next_keys(vec![commit(next_commit)])
        .next_threshold(Tholder::Simple(1))
        .witness_removals(removals)
        .witness_additions(additions)
        .witness_threshold(toad)
        .build()
        .unwrap();
    deserialize_event(serialized.as_bytes()).unwrap()
}

/// Like [`inception`] but with an explicit signing threshold — for exercising
/// weighted and malformed-threshold validation paths.
#[must_use]
pub fn inception_with_threshold(
    k0: &Verfer<'static>,
    k1: &Verfer<'static>,
    threshold: Tholder,
) -> KeriEvent {
    let serialized = InceptionBuilder::new()
        .keys(vec![k0.clone()])
        .threshold(threshold)
        .next_keys(vec![commit(k1)])
        .next_threshold(Tholder::Simple(1))
        .build()
        .unwrap();
    deserialize_event(serialized.as_bytes()).unwrap()
}

/// Like [`inception`] but with an explicit witness set and witness threshold
/// (TOAD) — for exercising the `toad > witness-count` boundary. The builder does
/// not validate the TOAD against the witness count; the fold's `check_witnesses`
/// does, so a `witness_threshold` exceeding `witnesses.len()` builds fine and is
/// rejected at validation. `Prefixer` and `Verfer` are the same type
/// (`Matter<VerKeyCode>`), so [`verfer`] doubles as a witness-prefix constructor.
#[must_use]
pub fn inception_with_witnesses(
    k0: &Verfer<'static>,
    k1: &Verfer<'static>,
    witnesses: Vec<Prefixer<'static>>,
    witness_threshold: u32,
) -> KeriEvent {
    let serialized = InceptionBuilder::new()
        .keys(vec![k0.clone()])
        .threshold(Tholder::Simple(1))
        .next_keys(vec![commit(k1)])
        .next_threshold(Tholder::Simple(1))
        .witnesses(witnesses)
        .witness_threshold(witness_threshold)
        .build()
        .unwrap();
    deserialize_event(serialized.as_bytes()).unwrap()
}

/// An inception with an explicit key list and signing threshold, round-tripped
/// through serder — for exercising the threshold boundary with `k` keys. Commits
/// to a single `next` pre-rotation key.
#[must_use]
pub fn inception_multi(
    keys: &[Verfer<'static>],
    next: &Verfer<'static>,
    threshold: Tholder,
) -> KeriEvent {
    let serialized = InceptionBuilder::new()
        .keys(keys.to_vec())
        .threshold(threshold)
        .next_keys(vec![commit(next)])
        .next_threshold(Tholder::Simple(1))
        .build()
        .unwrap();
    deserialize_event(serialized.as_bytes()).unwrap()
}

/// A delegated inception (`dip`) event: single signing key `k0` under the
/// authority of `delegator`, round-tripped through serder so it is a genuine
/// parsed `KeriEvent::DelegatedInception`. K1's fold rejects these (K4 scope).
#[must_use]
pub fn delegated_inception(k0: &Verfer<'_>, delegator: &Prefixer<'_>) -> KeriEvent {
    let serialized = DelegatedInceptionBuilder::new()
        .keys(vec![k0.clone().into_static()])
        .delegator(delegator.clone().into_static())
        .build()
        .unwrap();
    deserialize_event(serialized.as_bytes()).unwrap()
}

/// A delegated rotation (`drt`) event at `sn` chaining onto `prior_said` under
/// `prefix`, revealing `reveal` as the new key, round-tripped through serder so
/// it is a genuine parsed `KeriEvent::DelegatedRotation`. K1's fold rejects these
/// (K4 scope). A Blake3-256 digest (`commit`) doubles as a `Saider` prior-SAID.
#[must_use]
pub fn delegated_rotation(
    prefix: &Prefixer<'_>,
    prior_said: &Saider<'_>,
    sn: u128,
    reveal: &Verfer<'_>,
) -> KeriEvent {
    let serialized = DelegatedRotationBuilder::new()
        .prefix(prefix.clone().into_static())
        .prior_event_said(prior_said.clone().into_static())
        .keys(vec![reveal.clone().into_static()])
        .sn(sn)
        .build()
        .unwrap();
    deserialize_event(serialized.as_bytes()).unwrap()
}

/// An indexed Ed25519 signature at `index` with placeholder raw bytes and
/// `signer` attached. The fold reads only the index; the raw bytes are inert.
#[must_use]
pub fn sig_for(index: u32, signer: &Verfer<'static>) -> Siger<'static> {
    let indexer = IndexerBuilder::new()
        .with_code(IndexedSigCode::Ed25519)
        .with_index(index)
        .unwrap()
        .with_raw(Cow::<[u8]>::Owned(vec![0u8; 64]))
        .unwrap();
    Siger::new(indexer).with_verfer(signer.clone())
}
