//! Shared fixtures for the key-state transition tests.
//!
//! Every event here is a **genuine** CESR/serder artifact (built via the public
//! `serder` builders and round-tripped through `deserialize_event`) signed by
//! **real** Ed25519 keypairs. The transition verifies signatures cryptographically
//! inside the fold, so a fixture with placeholder signatures would be rejected —
//! the fold is exercised against the same wire bytes and signatures a real KEL
//! carries. Setup is fallible and flows through `?`; there is no `unwrap`/`expect`.
//!
//! keri-rs consumes only cesr's **public** API (`internals`/`test-utils` are
//! forbidden by `keri/Cargo.toml`), so these fixtures cannot fabricate a malformed
//! parsed event directly — they build valid events and let the fold reject the
//! ones that violate a state-level invariant. The one exception is
//! [`overlap_rotation`], which forges a wire-only event shape (a cut/add
//! overlap no builder emits) by patching a built event's bytes and re-sealing
//! its SAID — still entirely via the public API.
#![allow(
    dead_code,
    reason = "one shared harness feeds three test binaries; no single binary uses every fixture"
)]
#![allow(
    unreachable_pub,
    reason = "fixtures are `pub` for cross-binary reuse; the module itself is private per test binary"
)]

use std::error::Error;
use std::ops::Range;

use cesr::core::indexer::IndexerBuilder;
use cesr::core::indexer::code::IndexedSigCode;
use cesr::core::matter::code::{CesrCode, DigestCode, VerKeyCode};
use cesr::core::primitives::{Diger, Prefixer, Saider, Siger, Tholder, Verfer};
use cesr::crypto::{Ed25519, KeyPair, digest};
use cesr::keri::{ConfigTrait, Identifier, KeriEvent};
use cesr::serder::said::{compute_digest, said_placeholder};
use cesr::serder::{
    DelegatedInceptionBuilder, DelegatedRotationBuilder, InceptionBuilder, InteractionBuilder,
    RotationBuilder, SerializedEvent, deserialize_event,
};

use keri::{KeyState, Signed};

/// A boxed-error result: fixture setup failures abort the test loudly via `?`.
pub type Fallible<T> = Result<T, Box<dyn Error>>;

/// An Ed25519 controller: a keypair plus its transferable verification key.
pub struct Key {
    kp: KeyPair<Ed25519>,
    /// The controller's transferable Ed25519 verification key.
    pub verfer: Verfer<'static>,
}

impl Key {
    /// A fresh random controller.
    pub fn new() -> Fallible<Self> {
        let kp = KeyPair::<Ed25519>::generate()?;
        let verfer = kp.verfer(VerKeyCode::Ed25519)?.into_static();
        Ok(Self { kp, verfer })
    }

    /// A real indexed Ed25519 signature over `bytes` at `index`, carrying this
    /// key's verfer.
    pub fn sign(&self, bytes: &[u8], index: u32) -> Fallible<Siger<'static>> {
        let cigar = self.kp.sign(bytes)?;
        let indexer = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519)
            .with_index(index)?
            .with_raw(cigar.raw().to_vec())?;
        Ok(Siger::new(indexer).with_verfer(self.verfer.clone()))
    }
}

/// The Blake3-256 pre-rotation commitment to `v`'s qualified-base64 form.
pub fn commit(v: &Verfer<'static>) -> Fallible<Diger<'static>> {
    Ok(digest(DigestCode::Blake3_256, &v.to_qb64b())?)
}

/// The commitments to a set of next keys, in order.
fn commitments(next: &[&Key]) -> Fallible<Vec<Diger<'static>>> {
    next.iter().map(|k| commit(&k.verfer)).collect()
}

/// The verfers of a set of keys, in order — doubles as witness prefixes since a
/// `Prefixer` and a `Verfer` are the same `Matter<VerKeyCode>` type.
fn verfers(keys: &[&Key]) -> Vec<Verfer<'static>> {
    keys.iter().map(|k| k.verfer.clone()).collect()
}

/// An owned parsed event, the bytes it was signed over, its SAID, and the
/// identifier prefix it belongs to.
pub struct Event {
    /// The parsed event handed to the transition.
    pub parsed: KeriEvent,
    /// The serialized bytes the signatures are computed over.
    pub bytes: Vec<u8>,
    /// The event's self-addressing identifier / digest.
    pub said: Saider<'static>,
    /// The identifier prefix the event belongs to.
    pub prefix: Identifier<'static>,
}

impl Event {
    fn build(bytes: Vec<u8>, said: Saider<'static>, prefix: Identifier<'static>) -> Fallible<Self> {
        let parsed = deserialize_event(&bytes)?;
        Ok(Self {
            parsed,
            bytes,
            said,
            prefix,
        })
    }

    /// Borrow this event and its signatures into a transition input (no receipts).
    pub fn signed<'a>(&'a self, sigs: Vec<Siger<'a>>) -> Signed<'a> {
        Signed {
            event: &self.parsed,
            signed_bytes: &self.bytes,
            sigs,
            wigs: vec![],
        }
    }

    /// Sign this event with `keys`, placing each signature at its list position.
    pub fn sign_all<'a>(&'a self, keys: &[&Key]) -> Fallible<Vec<Siger<'a>>> {
        keys.iter()
            .enumerate()
            .map(|(i, k)| k.sign(&self.bytes, u32::try_from(i)?))
            .collect()
    }
}

/// A rotation's witness delta: the claimed prior set, prefixes to cut,
/// prefixes to add, and the new TOAD.
pub struct WitnessChange {
    /// The prior witness set the delta claims to rotate. The builder
    /// validates cut/add relations against this claim; the fold checks the
    /// true key state, so a false claim yields a builder-valid event the
    /// fold rejects — exactly the shape the rejection tests need.
    pub prior: Vec<Prefixer<'static>>,
    /// Current witnesses to remove.
    pub removals: Vec<Prefixer<'static>>,
    /// New witnesses to add.
    pub additions: Vec<Prefixer<'static>>,
    /// The post-rotation witness threshold (TOAD).
    pub toad: u32,
}

impl WitnessChange {
    /// No witness change and a zero TOAD.
    pub const fn none() -> Self {
        Self {
            prior: Vec::new(),
            removals: Vec::new(),
            additions: Vec::new(),
            toad: 0,
        }
    }
}

/// The key material a rotation reveals: the new current keys, the keys committed
/// to next, and the signing threshold over the revealed set.
pub struct RotationKeys<'k> {
    /// The keys revealed as the new current signing set.
    pub reveal: &'k [&'k Key],
    /// The keys committed to for the following rotation.
    pub next: &'k [&'k Key],
    /// The signing threshold over `reveal`.
    pub threshold: Tholder,
}

/// A parsed [`Event`] from a serialized event whose prefix comes from its own
/// self-addressing identifier (inception).
fn finish_inception(ser: &SerializedEvent) -> Fallible<Event> {
    let prefix = ser.identifier().ok_or("inception must yield a prefix")?;
    Event::build(
        ser.as_bytes().to_vec(),
        ser.said().clone().into_static(),
        prefix,
    )
}

/// A parsed [`Event`] carrying an explicit `prefix` (interaction / rotation, which
/// inherit the establishing identifier).
fn finish_chained(ser: &SerializedEvent, prefix: Identifier<'static>) -> Fallible<Event> {
    Event::build(
        ser.as_bytes().to_vec(),
        ser.said().clone().into_static(),
        prefix,
    )
}

// ── Inception fixtures ──────────────────────────────────────────────────────

/// The general inception fixture: an explicit signing key set and threshold, a set
/// of committed next keys (empty for a non-committing genesis), and a witness set
/// with an explicit TOAD. Always yields a self-addressing prefix (the only prefix
/// form the public builder produces).
pub fn inception_full(
    keys: &[&Key],
    next: &[&Key],
    threshold: Tholder,
    witnesses: &[&Key],
    toad: u32,
) -> Fallible<Event> {
    let mut builder = InceptionBuilder::new()
        .keys(verfers(keys))
        .threshold(threshold)
        .next_keys(commitments(next)?)
        .witnesses(verfers(witnesses))
        .witness_threshold(toad);
    if !next.is_empty() {
        builder = builder.next_threshold(Tholder::Simple(1));
    }
    finish_inception(&builder.build()?)
}

/// A single-signer genesis committing to `next`.
pub fn genesis(k0: &Key, next: &Key) -> Fallible<Event> {
    inception_full(&[k0], &[next], Tholder::Simple(1), &[], 0)
}

/// A single-signer genesis committing to `next`, with explicit config traits.
pub fn genesis_config(k0: &Key, next: &Key, config: Vec<ConfigTrait>) -> Fallible<Event> {
    let ser = InceptionBuilder::new()
        .keys(vec![k0.verfer.clone()])
        .threshold(Tholder::Simple(1))
        .next_keys(vec![commit(&next.verfer)?])
        .next_threshold(Tholder::Simple(1))
        .config(config)
        .build()?;
    finish_inception(&ser)
}

/// A multi-signer genesis with an explicit signing threshold, committing to `next`.
pub fn inception_multi(keys: &[&Key], next: &Key, threshold: Tholder) -> Fallible<Event> {
    inception_full(keys, &[next], threshold, &[], 0)
}

/// A wire-forged inception whose TOAD exceeds its witness count — the
/// builder rejects this shape at construction (`validate_toad`), but it can
/// still arrive over the wire from another implementation, and the fold's
/// own witness-threshold check must stay covered. Forged by building a
/// valid witness-less genesis (`"bt":"0"`), patching the TOAD to 1 (same
/// length, offsets survive), and re-sealing the double SAID: `d` and `i`
/// carry the same digest, so both spans are re-derived and the prefix is
/// the fresh SAID.
pub fn excess_toad_inception(k0: &Key, next: &Key) -> Fallible<Event> {
    let ser = InceptionBuilder::new()
        .keys(vec![k0.verfer.clone()])
        .threshold(Tholder::Simple(1))
        .next_keys(vec![commit(&next.verfer)?])
        .next_threshold(Tholder::Simple(1))
        .build()?;
    let body = String::from_utf8(ser.as_bytes().to_vec())?;
    (body.matches("\"bt\":\"0\"").count() == 1)
        .then_some(())
        .ok_or("forge failed: expected exactly one \"bt\":\"0\" to patch")?;
    let patched = body.replace("\"bt\":\"0\"", "\"bt\":\"1\"");
    let (forged, said) = reseal_icp(patched.into_bytes())?;
    Event::build(forged, said.clone(), said.into())
}

// ── Interaction / rotation fixtures ─────────────────────────────────────────

/// An interaction at `sn` chaining onto `prior`.
pub fn interaction(prior: &Event, sn: u128) -> Fallible<Event> {
    let ser = InteractionBuilder::new()
        .prefix(prior.prefix.clone())
        .prior_event_said(prior.said.clone())
        .sn(sn)
        .build()?;
    finish_chained(&ser, prior.prefix.clone())
}

/// A rotation at `sn` chaining onto `prior`, with explicit key material and a
/// witness change.
pub fn rotation(
    prior: &Event,
    sn: u128,
    keys: RotationKeys<'_>,
    witnesses: WitnessChange,
) -> Fallible<Event> {
    let ser = RotationBuilder::new()
        .prefix(prior.prefix.clone())
        .prior_event_said(prior.said.clone())
        .keys(verfers(keys.reveal))
        .prior_witnesses(witnesses.prior)
        .sn(sn)
        .threshold(keys.threshold)
        .next_keys(commitments(keys.next)?)
        .next_threshold(Tholder::Simple(1))
        .witness_removals(witnesses.removals)
        .witness_additions(witnesses.additions)
        .witness_threshold(witnesses.toad)
        .build()?;
    finish_chained(&ser, prior.prefix.clone())
}

/// A single-signer rotation with no witness change.
pub fn plain_rotation(prior: &Event, sn: u128, reveal: &Key, next: &Key) -> Fallible<Event> {
    rotation(
        prior,
        sn,
        RotationKeys {
            reveal: &[reveal],
            next: &[next],
            threshold: Tholder::Simple(1),
        },
        WitnessChange::none(),
    )
}

/// A single-signer rotation applying a witness change.
pub fn rotation_witnessed(
    prior: &Event,
    sn: u128,
    reveal: &Key,
    next: &Key,
    witnesses: WitnessChange,
) -> Fallible<Event> {
    rotation(
        prior,
        sn,
        RotationKeys {
            reveal: &[reveal],
            next: &[next],
            threshold: Tholder::Simple(1),
        },
        witnesses,
    )
}

/// A rotation whose `br` and `ba` both contain `wit` — an event-level
/// contradiction no factory (ours or keripy's) will emit, but which can
/// arrive over the wire. Forged by building a valid swap (`cut wit, add
/// decoy`) and rewriting the decoy's qb64 to `wit`'s (same code, same
/// length, so offsets survive). `deserialize_event` recomputes and checks
/// the SAID on every read, so the `d` field is re-derived over the patched
/// body — only the witness delta is forged, not the digest.
pub fn overlap_rotation(
    prior: &Event,
    sn: u128,
    keys: RotationKeys<'_>,
    wit: &Key,
    decoy: &Key,
) -> Fallible<Event> {
    let ser = RotationBuilder::new()
        .prefix(prior.prefix.clone())
        .prior_event_said(prior.said.clone())
        .keys(verfers(keys.reveal))
        .prior_witnesses(vec![wit.verfer.clone()])
        .sn(sn)
        .threshold(keys.threshold)
        .next_keys(commitments(keys.next)?)
        .next_threshold(Tholder::Simple(1))
        .witness_removals(vec![wit.verfer.clone()])
        .witness_additions(vec![decoy.verfer.clone()])
        .witness_threshold(1)
        .build()?;
    let wit_qb64 = wit.verfer.to_qb64();
    let swapped =
        String::from_utf8(ser.as_bytes().to_vec())?.replace(&decoy.verfer.to_qb64(), &wit_qb64);
    (swapped.matches(&wit_qb64).count() == 2)
        .then_some(())
        .ok_or("forge failed: wit must appear in both br and ba")?;
    let (forged, said) = reseal(swapped.into_bytes())?;
    Event::build(forged, said, prior.prefix.clone())
}

/// Recompute a SAID-bearing event's `d` field over its current bytes: fill
/// the existing `d` value with placeholders, hash, and splice the fresh
/// digest back in. Used to re-derive a valid SAID after a fixture patches
/// an already-built event's body (the digest code and qb64 length are
/// fixed, so the field's byte span never moves).
fn reseal(raw: Vec<u8>) -> Fallible<(Vec<u8>, Saider<'static>)> {
    reseal_spans(raw, &[b"\"d\":\""])
}

/// [`reseal`] for the double-SAID inception shape: a self-addressing `icp`
/// carries the same digest in `d` and `i`, and both the write path and
/// `deserialize_event` hash with BOTH value spans dummied, so both must be
/// re-derived together.
fn reseal_icp(raw: Vec<u8>) -> Fallible<(Vec<u8>, Saider<'static>)> {
    let d_span = said_span(&raw, b"\"d\":\"")?;
    let i_span = said_span(&raw, b"\"i\":\"")?;
    (raw.get(d_span) == raw.get(i_span))
        .then_some(())
        .ok_or("reseal_icp expects a self-addressing inception (d == i)")?;
    reseal_spans(raw, &[b"\"d\":\"", b"\"i\":\""])
}

/// Fill every listed SAID field with placeholders, hash once, and splice the
/// fresh digest into each — the span-fill mirror of the write path's
/// placeholder render.
fn reseal_spans(mut raw: Vec<u8>, keys: &[&[u8]]) -> Fallible<(Vec<u8>, Saider<'static>)> {
    let placeholder = said_placeholder(DigestCode::Blake3_256)?;
    let spans = keys
        .iter()
        .map(|key| said_span(&raw, key))
        .collect::<Fallible<Vec<_>>>()?;
    for span in &spans {
        raw.get_mut(span.clone())
            .ok_or("SAID field span out of bounds")?
            .copy_from_slice(placeholder.as_bytes());
    }
    let digest = compute_digest(&raw, DigestCode::Blake3_256)?;
    for span in spans {
        raw.get_mut(span)
            .ok_or("SAID field span out of bounds")?
            .copy_from_slice(digest.to_qb64().as_bytes());
    }
    Ok((raw, digest))
}

/// The byte span of the qb64 value following `key` (e.g. `b"\"d\":\""`),
/// guarded on the value carrying the Blake3-256 code character — resealing
/// under a different code would silently override the event's declared
/// digest algorithm.
fn said_span(raw: &[u8], key: &[u8]) -> Fallible<Range<usize>> {
    let start = raw
        .windows(key.len())
        .position(|w| w == key)
        .ok_or("event is missing an expected SAID field")?
        + key.len();
    let code = DigestCode::Blake3_256.as_str().as_bytes();
    if raw.get(start..start + code.len()) != Some(code) {
        return Err("reseal supports only Blake3-256 SAIDs".into());
    }
    Ok(start..start + said_placeholder(DigestCode::Blake3_256)?.len())
}

// ── Delegated fixtures (rejected by the K1 fold) ────────────────────────────

/// A delegated inception (`dip`) under `delegator` — the fold rejects these (K4).
pub fn delegated_inception(k0: &Key, next: &Key, delegator: &Prefixer<'static>) -> Fallible<Event> {
    let ser = DelegatedInceptionBuilder::new()
        .keys(vec![k0.verfer.clone()])
        .delegator(delegator.clone())
        .next_keys(vec![commit(&next.verfer)?])
        .next_threshold(Tholder::Simple(1))
        .build()?;
    let prefix = ser
        .identifier()
        .ok_or("delegated inception must yield a prefix")?;
    Event::build(
        ser.as_bytes().to_vec(),
        ser.said().clone().into_static(),
        prefix,
    )
}

/// A delegated rotation (`drt`) at `sn` chaining onto `prior` — rejected (K4).
pub fn delegated_rotation(prior: &Event, sn: u128, reveal: &Key) -> Fallible<Event> {
    let ser = DelegatedRotationBuilder::new()
        .prefix(prior.prefix.clone())
        .prior_event_said(prior.said.clone())
        .keys(vec![reveal.verfer.clone()])
        .prior_witnesses(vec![])
        .sn(sn)
        .build()?;
    Event::build(
        ser.as_bytes().to_vec(),
        ser.said().clone().into_static(),
        prior.prefix.clone(),
    )
}

// ── Driving the transition ──────────────────────────────────────────────────

/// Seed the fold from a single-signer genesis, keeping `icp` alive in the caller.
pub fn seed<'e>(icp: &'e Event, k0: &Key) -> Fallible<KeyState<'e>> {
    Ok(KeyState::incept(
        &icp.signed(vec![k0.sign(&icp.bytes, 0)?]),
    )?)
}

/// Reconstruct an indexed signature from its qualified-base64 form (for replaying
/// externally-produced signatures, e.g. a keripy differential corpus).
pub fn siger_from_qb64(qb64: &str) -> Fallible<Siger<'static>> {
    let (indexer, _) = IndexerBuilder::new().from_qb64(qb64.as_bytes())?;
    Ok(Siger::new(indexer))
}
