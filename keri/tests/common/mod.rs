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

use std::borrow::Cow;

use cesr::core::indexer::IndexerBuilder;
use cesr::core::indexer::code::IndexedSigCode;
use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::{DigestCode, VerKeyCode};
use cesr::core::primitives::{Diger, Siger, Tholder, Verfer};
use cesr::crypto::digest;
use cesr::keri::{ConfigTrait, KeriEvent};
use cesr::serder::{InceptionBuilder, InteractionBuilder, deserialize_event};

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
