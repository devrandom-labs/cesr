//! Manual release measurements of the public signed KEL read and fold path.
//! The first A15 workload pins keripy's three-message icp/rot/ixn stream.
#![cfg(feature = "std")]
#![allow(
    clippy::expect_used,
    clippy::print_stdout,
    reason = "explicitly invoked release benchmark reports fallible fixture and measurement data"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::error::Error;
use std::hint::black_box;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use cesr::core::counter::CounterCodeV1;
use cesr::core::indexer::code::IndexMode;
use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::{DigestCode, NoncerCode, NumberCode, VerKeyCode};
use cesr::core::primitives::{Noncer, Number, Siger};
use cesr::crypto::salt::{Salt, Tier};
use cesr::crypto::{Ed25519, KeyPair, SignatureError, VerificationError, digest, verify};
use cesr_stream::encode::EncodeCount;
use cesr_stream::group::{ControllerIdxSigs, WitnessIdxSigs};
use cesr_stream::version::{CesrEncode, V1};
use cesr_stream::{FrameLimits, MessageFramer};
use keri::{
    CredentialState, CredentialStatus, Custodian, KeySpec, KeyState, KeyStateSnapshot,
    PathConvention, RegistryRejection, RegistryState, Rejection, SaltyCustodian, SameSnVerdict,
    Signed, SignedTel, TelEvidence,
};
use keri_codec::{
    CodecError, Deserialize, EventMessage, InceptionBuilder, InteractionBuilder, IssueBuilder,
    JsonLimits, MessageLimits, RegistryInceptionBuilder, RevokeBuilder, RotationBuilder, SadCodes,
    SerializedEvent, TelMessage,
};
use keri_events::{
    Acdc, BasicPrefix, ConfigTrait, Digest, Identifier, KeriEvent, Said, Seal, SigningThreshold,
    VerifyingKey,
};

const KEL: &[u8] = include_bytes!("fixtures/keripy_kel_signed.cesr");
const WITNESSED_ICP: &[u8] = include_bytes!("fixtures/keripy_icp_witnessed.cesr");
const SAMPLES: usize = 101;
const WARMUPS: usize = 100;

thread_local! {
    static TRACKING: Cell<bool> = const { Cell::new(false) };
    static ALLOCS: Cell<usize> = const { Cell::new(0) };
    static REQUESTED: Cell<usize> = const { Cell::new(0) };
    static LIVE: Cell<usize> = const { Cell::new(0) };
    static PEAK: Cell<usize> = const { Cell::new(0) };
}

struct Counting;

#[allow(
    unsafe_code,
    reason = "test-binary-only allocator to measure the actual public workload"
)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() && TRACKING.try_with(Cell::get).unwrap_or(false) {
            let _ = ALLOCS.try_with(|cell| cell.set(cell.get() + 1));
            let _ = REQUESTED.try_with(|cell| cell.set(cell.get() + layout.size()));
            let _ = LIVE.try_with(|cell| {
                let live = cell.get() + layout.size();
                cell.set(live);
                let _ = PEAK.try_with(|peak| peak.set(peak.get().max(live)));
            });
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if TRACKING.try_with(Cell::get).unwrap_or(false) {
            let _ = LIVE.try_with(|cell| cell.set(cell.get().saturating_sub(layout.size())));
        }
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if !new_ptr.is_null() && TRACKING.try_with(Cell::get).unwrap_or(false) {
            let _ = ALLOCS.try_with(|cell| cell.set(cell.get() + 1));
            let _ = REQUESTED.try_with(|cell| cell.set(cell.get() + new_size));
            let _ = LIVE.try_with(|cell| {
                let live = cell
                    .get()
                    .saturating_sub(layout.size())
                    .saturating_add(new_size);
                cell.set(live);
                let _ = PEAK.try_with(|peak| peak.set(peak.get().max(live)));
            });
        }
        new_ptr
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

#[derive(Clone, Copy)]
struct Sample {
    nanos: u128,
    allocs: usize,
    requested: usize,
    retained: usize,
    peak: usize,
}

fn measure<T>(f: impl FnOnce() -> T) -> (T, Sample) {
    ALLOCS.with(|cell| cell.set(0));
    REQUESTED.with(|cell| cell.set(0));
    LIVE.with(|cell| cell.set(0));
    PEAK.with(|cell| cell.set(0));
    TRACKING.with(|cell| cell.set(true));
    let started = Instant::now();
    let result = f();
    let elapsed: Duration = started.elapsed();
    TRACKING.with(|cell| cell.set(false));
    (
        result,
        Sample {
            nanos: elapsed.as_nanos(),
            allocs: ALLOCS.with(Cell::get),
            requested: REQUESTED.with(Cell::get),
            retained: LIVE.with(Cell::get),
            peak: PEAK.with(Cell::get),
        },
    )
}

const fn limits() -> MessageLimits {
    MessageLimits::new(
        FrameLimits {
            max_body_bytes: 8 * 1024 * 1024,
            max_attachment_bytes: 8 * 1024 * 1024,
            max_attachment_groups: 8192,
            max_group_elements: 8192,
            max_signatures: 8192,
            max_nested_groups: 8192,
            max_nesting_depth: 64,
        },
        JsonLimits::new(8192, 64),
    )
}

fn accepted_kel_snapshot() -> Result<KeyStateSnapshot, Box<dyn Error>> {
    let mut remaining = KEL;
    let mut messages = Vec::new();
    while !remaining.is_empty() {
        let (message, rest) = EventMessage::parse(remaining, limits())?;
        messages.push(message);
        remaining = rest;
    }
    snapshot_from_messages(&messages)
}

fn snapshot_from_messages(
    messages: &[EventMessage<'_>],
) -> Result<KeyStateSnapshot, Box<dyn Error>> {
    let signed: Vec<Signed<'_>> = messages.iter().map(Signed::from).collect();
    let (genesis, later) = signed.split_first().ok_or("empty pinned KEL")?;
    let state = later
        .iter()
        .try_fold(KeyState::incept(genesis)?, KeyState::ingest)?;
    Ok(KeyStateSnapshot::from(&state))
}

fn accepted_kel_chunked_snapshot(chunk_size: usize) -> Result<KeyStateSnapshot, Box<dyn Error>> {
    let mut framer = MessageFramer::new(limits().frame);
    let mut buffer = BytesMut::new();
    let mut wire_frames = Vec::new();
    for chunk in KEL.chunks(chunk_size) {
        buffer.extend_from_slice(chunk);
        while let Some(span) = framer.advance(&buffer, false)? {
            wire_frames.push(buffer.split_to(span.total_len).freeze());
        }
    }
    while let Some(span) = framer.advance(&buffer, true)? {
        wire_frames.push(buffer.split_to(span.total_len).freeze());
    }
    if !buffer.is_empty() {
        return Err("chunked KEL left trailing bytes".into());
    }
    let mut messages = Vec::new();
    for frame in &wire_frames {
        let (message, rest) = EventMessage::parse(frame, limits())?;
        if !rest.is_empty() {
            return Err("chunked frame had a remainder".into());
        }
        messages.push(message);
    }
    snapshot_from_messages(&messages)
}

fn accepted_kel_batch(count: usize) -> Result<Vec<KeyStateSnapshot>, Box<dyn Error>> {
    (0..count).map(|_| accepted_kel_snapshot()).collect()
}

fn accepted_witnessed_snapshot() -> Result<KeyStateSnapshot, Box<dyn Error>> {
    let (message, rest) = EventMessage::parse(WITNESSED_ICP, limits())?;
    if !rest.is_empty() {
        return Err("witnessed fixture has trailing bytes".into());
    }
    let signed = Signed::from(&message);
    Ok(KeyStateSnapshot::from(&KeyState::incept(&signed)?))
}

fn rejected_missing_witness_receipts() -> Result<(), Box<dyn Error>> {
    let (message, rest) = EventMessage::parse(WITNESSED_ICP, limits())?;
    if !rest.is_empty() {
        return Err("witnessed fixture has trailing bytes".into());
    }
    let signed = Signed::from_host_asserted_parts(
        message.event(),
        message.body(),
        message.sigs().to_vec(),
        vec![],
    );
    match KeyState::incept(&signed) {
        Err(Rejection::InsufficientWitnessReceipts {
            valid: 0,
            required: 2,
        }) => Ok(()),
        _ => Err("missing receipts did not produce the pinned rejection".into()),
    }
}

struct RecoveryWire {
    inception: Vec<u8>,
    first_interaction: Vec<u8>,
    second_interaction: Vec<u8>,
    recovery_rotation: Vec<u8>,
}

impl RecoveryWire {
    const fn len(&self) -> usize {
        self.inception.len()
            + self.first_interaction.len()
            + self.second_interaction.len()
            + self.recovery_rotation.len()
    }
}

fn frame_signed(
    event: &SerializedEvent,
    key: &KeyPair<Ed25519>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let signature = key.sign_indexed(event.as_bytes(), 0, IndexMode::Both)?;
    let group = ControllerIdxSigs::from_indexed_signatures(&[signature])?;
    Ok(event.frame_v1(&group, None)?)
}

fn recovery_wire() -> Result<RecoveryWire, Box<dyn Error>> {
    let current = KeyPair::<Ed25519>::from_seed_bytes(&[1; 32]);
    let revealed = KeyPair::<Ed25519>::from_seed_bytes(&[2; 32]);
    let next = KeyPair::<Ed25519>::from_seed_bytes(&[3; 32]);
    let current_verfer =
        VerifyingKey::from_matter(current.verfer(VerKeyCode::Ed25519)?.into_static());
    let revealed_verfer =
        VerifyingKey::from_matter(revealed.verfer(VerKeyCode::Ed25519)?.into_static());
    let next_verfer = VerifyingKey::from_matter(next.verfer(VerKeyCode::Ed25519)?.into_static());
    let revealed_commitment =
        Digest::from_matter(digest(DigestCode::Blake3_256, &revealed_verfer.to_qb64b())?);
    let next_commitment =
        Digest::from_matter(digest(DigestCode::Blake3_256, &next_verfer.to_qb64b())?);
    let inception = InceptionBuilder::new()
        .keys(vec![current_verfer])
        .threshold(SigningThreshold::Simple(1))
        .next_keys(vec![revealed_commitment])
        .next_threshold(SigningThreshold::Simple(1))
        .build()?;
    let prefix = inception
        .identifier()
        .ok_or("recovery inception has no prefix")?;
    let first_interaction = InteractionBuilder::new()
        .prefix(prefix.clone())
        .prior_event_said(inception.said().clone().into_static())
        .sn(1)
        .build()?;
    let second_interaction = InteractionBuilder::new()
        .prefix(prefix.clone())
        .prior_event_said(first_interaction.said().clone().into_static())
        .sn(2)
        .build()?;
    let recovery_rotation = RotationBuilder::new()
        .prefix(prefix)
        .prior_event_said(inception.said().clone().into_static())
        .keys(vec![revealed_verfer])
        .prior_witnesses(vec![])
        .sn(1)
        .threshold(SigningThreshold::Simple(1))
        .next_keys(vec![next_commitment])
        .next_threshold(SigningThreshold::Simple(1))
        .build()?;
    Ok(RecoveryWire {
        inception: frame_signed(&inception, &current)?,
        first_interaction: frame_signed(&first_interaction, &current)?,
        second_interaction: frame_signed(&second_interaction, &current)?,
        recovery_rotation: frame_signed(&recovery_rotation, &revealed)?,
    })
}

fn recovered_snapshot(wire: &RecoveryWire) -> Result<KeyStateSnapshot, Box<dyn Error>> {
    let parse = |raw| -> Result<EventMessage<'_>, Box<dyn Error>> {
        let (message, rest) = EventMessage::parse(raw, limits())?;
        if !rest.is_empty() {
            return Err("recovery frame has a remainder".into());
        }
        Ok(message)
    };
    let inception = parse(&wire.inception)?;
    let first_interaction = parse(&wire.first_interaction)?;
    let second_interaction = parse(&wire.second_interaction)?;
    let recovery_rotation = parse(&wire.recovery_rotation)?;
    let initial = Signed::from(&inception);
    let first = Signed::from(&first_interaction);
    let second = Signed::from(&second_interaction);
    let recovery = Signed::from(&recovery_rotation);
    let head = KeyState::incept(&initial)?
        .ingest(&first)?
        .ingest(&second)?;
    if head.judge_same_sn(recovery_rotation.event(), first_interaction.event(), &[])?
        != SameSnVerdict::Supersedes
    {
        return Err("signed recovery did not supersede the recorded interaction".into());
    }
    let recovered = KeyState::incept(&initial)?.ingest(&recovery)?;
    if recovered.sn().value() != 1 || recovered.last_establishment().sn.value() != 1 {
        return Err("signed recovery did not rewind and establish at sequence one".into());
    }
    Ok(KeyStateSnapshot::from(&recovered))
}

#[derive(Clone, Copy)]
struct InceptionDimensions {
    keys: usize,
    signatures: usize,
    witnesses: usize,
    receipts: usize,
    duplicates: usize,
    groups: usize,
}

fn scaled_inception_wire(dimensions: InceptionDimensions) -> Result<Vec<u8>, Box<dyn Error>> {
    let InceptionDimensions {
        keys: key_count,
        signatures: controller_signature_count,
        witnesses: witness_count,
        receipts: witness_signature_count,
        duplicates: duplicate_controller_signatures,
        groups: controller_groups,
    } = dimensions;
    if key_count == 0
        || controller_signature_count == 0
        || controller_signature_count > key_count
        || witness_signature_count > witness_count
        || controller_groups == 0
        || !(controller_signature_count + duplicate_controller_signatures)
            .is_multiple_of(controller_groups)
    {
        return Err("invalid inception scaling dimensions".into());
    }
    let controllers: Vec<_> = (0..u8::try_from(key_count)?)
        .map(|index| KeyPair::<Ed25519>::from_seed_bytes(&[index + 10; 32]))
        .collect();
    let witnesses: Vec<_> = (0..u8::try_from(witness_count)?)
        .map(|index| KeyPair::<Ed25519>::from_seed_bytes(&[index + 100; 32]))
        .collect();
    let keys = controllers
        .iter()
        .map(|key| {
            Ok(VerifyingKey::from_matter(
                key.verfer(VerKeyCode::Ed25519)?.into_static(),
            ))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let witness_prefixes = witnesses
        .iter()
        .map(|key| {
            Ok(BasicPrefix::from_matter(
                key.verfer(VerKeyCode::Ed25519N)?.into_static(),
            ))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let next = KeyPair::<Ed25519>::from_seed_bytes(&[250; 32]);
    let next_verfer = VerifyingKey::from_matter(next.verfer(VerKeyCode::Ed25519)?.into_static());
    let next_commitment =
        Digest::from_matter(digest(DigestCode::Blake3_256, &next_verfer.to_qb64b())?);
    let event = InceptionBuilder::new()
        .keys(keys)
        .threshold(SigningThreshold::Simple(1))
        .next_keys(vec![next_commitment])
        .next_threshold(SigningThreshold::Simple(1))
        .witnesses(witness_prefixes)
        .witness_threshold(u32::from(witness_count != 0))
        .build()?;
    let mut signatures = controllers
        .iter()
        .take(controller_signature_count)
        .enumerate()
        .map(|(index, key)| {
            Ok(key.sign_indexed(event.as_bytes(), u32::try_from(index)?, IndexMode::Both)?)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let first = signatures[0].clone();
    signatures.extend((0..duplicate_controller_signatures).map(|_| first.clone()));
    let witness_signatures = witnesses
        .iter()
        .take(witness_signature_count)
        .enumerate()
        .map(|(index, key)| {
            Ok(key.sign_indexed(event.as_bytes(), u32::try_from(index)?, IndexMode::Both)?)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    frame_grouped_inception(&event, &signatures, &witness_signatures, controller_groups)
}

fn frame_grouped_inception(
    event: &SerializedEvent,
    signatures: &[Siger<'_>],
    witness_signatures: &[Siger<'_>],
    controller_groups: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let witness_group = WitnessIdxSigs::from_indexed_signatures(witness_signatures)?;
    if controller_groups == 1 {
        let controller_group = ControllerIdxSigs::from_indexed_signatures(signatures)?;
        return Ok(event.frame_v1(&controller_group, Some(&witness_group))?);
    }
    let mut attachment = BytesMut::new();
    for chunk in signatures.chunks(signatures.len() / controller_groups) {
        let group = ControllerIdxSigs::from_indexed_signatures(chunk)?;
        CesrEncode::<V1>::encode_cesr(&group, &mut attachment)?;
    }
    if witness_group.count() != 0 {
        CesrEncode::<V1>::encode_cesr(&witness_group, &mut attachment)?;
    }
    let quadlets = u32::try_from(attachment.len() / 4)?;
    let mut wire = event.as_bytes().to_vec();
    wire.extend_from_slice(&CounterCodeV1::AttachmentGroup.encode_count_auto(quadlets)?);
    wire.extend_from_slice(&attachment);
    Ok(wire)
}

fn scaled_inception_snapshot(wire: &[u8]) -> Result<KeyStateSnapshot, Box<dyn Error>> {
    let (message, rest) = EventMessage::parse(wire, limits())?;
    if !rest.is_empty() {
        return Err("scaled inception has trailing bytes".into());
    }
    Ok(KeyStateSnapshot::from(&KeyState::incept(&Signed::from(
        &message,
    ))?))
}

fn anchored_kel_wire(anchor_count: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let current = KeyPair::<Ed25519>::from_seed_bytes(&[1; 32]);
    let next = KeyPair::<Ed25519>::from_seed_bytes(&[2; 32]);
    let current_verfer =
        VerifyingKey::from_matter(current.verfer(VerKeyCode::Ed25519)?.into_static());
    let next_verfer = VerifyingKey::from_matter(next.verfer(VerKeyCode::Ed25519)?.into_static());
    let next_commitment =
        Digest::from_matter(digest(DigestCode::Blake3_256, &next_verfer.to_qb64b())?);
    let inception = InceptionBuilder::new()
        .keys(vec![current_verfer])
        .next_keys(vec![next_commitment])
        .build()?;
    let anchors = (0..anchor_count)
        .map(|index| {
            Ok(Seal::Digest {
                d: Said::from_matter(digest(DigestCode::Blake3_256, &index.to_be_bytes())?),
            })
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let interaction = InteractionBuilder::new()
        .prefix(
            inception
                .identifier()
                .ok_or("anchor inception has no prefix")?,
        )
        .prior_event_said(inception.said().clone().into_static())
        .anchors(anchors)
        .build()?;
    let mut wire = frame_signed(&inception, &current)?;
    wire.extend_from_slice(&frame_signed(&interaction, &current)?);
    Ok(wire)
}

fn anchored_kel_snapshot(wire: &[u8]) -> Result<KeyStateSnapshot, Box<dyn Error>> {
    let (inception, remaining) = EventMessage::parse(wire, limits())?;
    let (interaction, rest) = EventMessage::parse(remaining, limits())?;
    if !rest.is_empty() {
        return Err("anchored KEL has trailing bytes".into());
    }
    let state = KeyState::incept(&Signed::from(&inception))?.ingest(&Signed::from(&interaction))?;
    Ok(KeyStateSnapshot::from(&state))
}

struct CredentialWire {
    raw: Vec<u8>,
    tampered: Vec<u8>,
    signature: Siger<'static>,
    invalid_signature: Siger<'static>,
    issuer: VerifyingKey<'static>,
}

fn credential_wire(payload_bytes: usize, index: usize) -> Result<CredentialWire, Box<dyn Error>> {
    let issuer_key = KeyPair::<Ed25519>::from_seed_bytes(&[17; 32]);
    let invalid_key = KeyPair::<Ed25519>::from_seed_bytes(&[18; 32]);
    let issuer = VerifyingKey::from_matter(issuer_key.verfer(VerKeyCode::Ed25519)?.into_static());
    let schema = Said::from_matter(digest(DigestCode::Blake3_256, b"a15-schema")?);
    let placeholder = "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let payload = format!("{index:08x}{}", "x".repeat(payload_bytes));
    let mut attributes = format!(r#"{{"d":"{placeholder}","payload":"{payload}"}}"#).into_bytes();
    let codes = SadCodes::from_pairs(&[("d", DigestCode::Blake3_256)])?;
    codes.saidify(&mut attributes)?;
    let attributes_json = String::from_utf8(attributes)?;
    let mut raw = format!(
        r#"{{"v":"ACDC10JSON000000_","d":"{placeholder}","i":"{}","s":"{}","a":{attributes_json}}}"#,
        issuer.to_qb64(),
        schema.to_qb64(),
    )
    .into_bytes();
    codes.saidify(&mut raw)?;
    let signature = issuer_key.sign_indexed(&raw, 0, IndexMode::Both)?;
    let invalid_signature = invalid_key.sign_indexed(&raw, 0, IndexMode::Both)?;
    let mut tampered = raw.clone();
    let payload_end = tampered
        .iter()
        .rposition(|byte| *byte == b'x')
        .ok_or("credential has no payload byte")?;
    tampered[payload_end] = b'y';
    Ok(CredentialWire {
        raw,
        tampered,
        signature,
        invalid_signature,
        issuer,
    })
}

fn verified_credential(wire: &CredentialWire) -> Result<Acdc<'static>, Box<dyn Error>> {
    let credential = Acdc::deserialize(&wire.raw, limits().json)?;
    if credential
        .issuer()
        .as_prefixer()
        .map(|prefix| prefix.to_qb64())
        != Some(wire.issuer.to_qb64())
    {
        return Err("credential issuer differs from signing key".into());
    }
    verify(wire.issuer.as_matter(), &wire.raw, &wire.signature)?;
    Ok(credential.into_static())
}

fn rejected_credential_said(wire: &CredentialWire) -> Result<(), Box<dyn Error>> {
    match Acdc::deserialize(&wire.tampered, limits().json) {
        Err(CodecError::Said(_)) => Ok(()),
        _ => Err("tampered credential did not fail SAID verification".into()),
    }
}

fn rejected_credential_signature(wire: &CredentialWire) -> Result<(), Box<dyn Error>> {
    let _credential = Acdc::deserialize(&wire.raw, limits().json)?;
    match verify(wire.issuer.as_matter(), &wire.raw, &wire.invalid_signature) {
        Err(VerificationError::Signature(SignatureError::Invalid)) => Ok(()),
        _ => Err("credential with wrong signer did not fail signature verification".into()),
    }
}

struct TelScenario {
    issuer: KeyStateSnapshot,
    registry_wire: Vec<u8>,
    issue_wire: Vec<u8>,
    revoke_wire: Vec<u8>,
    registry_anchor: KeriEvent<'static>,
    issue_anchor: KeriEvent<'static>,
    revoke_anchor: KeriEvent<'static>,
}

impl TelScenario {
    const fn len(&self) -> usize {
        self.registry_wire.len() + self.issue_wire.len() + self.revoke_wire.len()
    }
}

fn tel_source_frame(
    event: &SerializedEvent,
    anchor_sn: u16,
    anchor_said: &Said<'_>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let seqner = MatterBuilder::new()
        .with_code(NumberCode::Short)
        .with_raw(anchor_sn.to_be_bytes().to_vec())?
        .build()?;
    let mut source = CounterCodeV1::SealSourceCouples.encode_count_auto(1)?;
    source.extend_from_slice(&seqner.to_qb64b());
    source.extend_from_slice(&anchor_said.to_qb64b());
    let mut wire = event.as_bytes().to_vec();
    wire.extend_from_slice(
        &CounterCodeV1::AttachmentGroup.encode_count_auto(u32::try_from(source.len() / 4)?)?,
    );
    wire.extend_from_slice(&source);
    Ok(wire)
}

fn tel_anchor(
    issuer: &Identifier<'static>,
    prior: &SerializedEvent,
    anchor_sn: u128,
    tel_coordinate: (&Said<'static>, u128),
    tel: &SerializedEvent,
) -> Result<SerializedEvent, Box<dyn Error>> {
    Ok(InteractionBuilder::new()
        .prefix(issuer.clone())
        .prior_event_said(prior.said().clone().into_static())
        .sn(anchor_sn)
        .anchors(vec![Seal::Event {
            i: Identifier::SelfAddressing(tel_coordinate.0.clone()),
            s: Number::new(tel_coordinate.1),
            d: tel.said().clone().into_static(),
        }])
        .build()?)
}

fn parse_event_frame(raw: &[u8]) -> Result<EventMessage<'_>, Box<dyn Error>> {
    let (message, rest) = EventMessage::parse(raw, limits())?;
    if !rest.is_empty() {
        return Err("KEL anchor frame has trailing bytes".into());
    }
    Ok(message)
}

fn parse_tel_frame(raw: &[u8]) -> Result<TelMessage<'_>, Box<dyn Error>> {
    let (message, rest) = TelMessage::parse(raw, limits())?;
    if !rest.is_empty() {
        return Err("TEL frame has trailing bytes".into());
    }
    Ok(message)
}

fn accepted_issuer_snapshot(kel_wires: &[Vec<u8>]) -> Result<KeyStateSnapshot, Box<dyn Error>> {
    let kel = kel_wires
        .iter()
        .map(|raw| parse_event_frame(raw))
        .collect::<Result<Vec<_>, _>>()?;
    let signed: Vec<_> = kel.iter().map(Signed::from).collect();
    let (first, later) = signed.split_first().ok_or("empty TEL issuer KEL")?;
    let state = later
        .iter()
        .try_fold(KeyState::incept(first)?, KeyState::ingest)?;
    Ok(KeyStateSnapshot::from(&state))
}

fn tel_scenario() -> Result<TelScenario, Box<dyn Error>> {
    let controller = KeyPair::<Ed25519>::from_seed_bytes(&[31; 32]);
    let next = KeyPair::<Ed25519>::from_seed_bytes(&[32; 32]);
    let controller_verfer =
        VerifyingKey::from_matter(controller.verfer(VerKeyCode::Ed25519)?.into_static());
    let next_verfer = VerifyingKey::from_matter(next.verfer(VerKeyCode::Ed25519)?.into_static());
    let next_commitment =
        Digest::from_matter(digest(DigestCode::Blake3_256, &next_verfer.to_qb64b())?);
    let inception = InceptionBuilder::new()
        .keys(vec![controller_verfer])
        .next_keys(vec![next_commitment])
        .build()?;
    let issuer = inception.identifier().ok_or("TEL issuer has no prefix")?;
    let nonce: Noncer<'static> = MatterBuilder::new()
        .with_code(NoncerCode::Salt128)
        .with_raw(vec![0x11; 16])?
        .build()?;
    let registry = RegistryInceptionBuilder::new(issuer.clone(), nonce)
        .config(vec![ConfigTrait::NoBackers])
        .build()?;
    let registry_id = registry.said().clone().into_static();
    let credential_id = Said::from_matter(digest(DigestCode::Blake3_256, b"a15-tel-credential")?);
    let issue = IssueBuilder::new(
        credential_id.clone(),
        registry_id.clone(),
        "2026-09-30T00:00:00+00:00",
    )
    .build()?;
    let revoke = RevokeBuilder::new(
        credential_id.clone(),
        registry_id.clone(),
        issue.said().clone().into_static(),
        "2026-09-30T00:00:01+00:00",
    )
    .build()?;
    let anchor1 = tel_anchor(&issuer, &inception, 1, (&registry_id, 0), &registry)?;
    let anchor2 = tel_anchor(&issuer, &anchor1, 2, (&credential_id, 0), &issue)?;
    let anchor3 = tel_anchor(&issuer, &anchor2, 3, (&credential_id, 1), &revoke)?;
    let kel_wires = [
        frame_signed(&inception, &controller)?,
        frame_signed(&anchor1, &controller)?,
        frame_signed(&anchor2, &controller)?,
        frame_signed(&anchor3, &controller)?,
    ];
    let issuer_snapshot = accepted_issuer_snapshot(&kel_wires)?;
    if issuer_snapshot.view().sn().value() != 3 {
        return Err("TEL anchor KEL did not validate to sequence three".into());
    }
    Ok(TelScenario {
        issuer: issuer_snapshot,
        registry_wire: tel_source_frame(&registry, 1, anchor1.said())?,
        issue_wire: tel_source_frame(&issue, 2, anchor2.said())?,
        revoke_wire: tel_source_frame(&revoke, 3, anchor3.said())?,
        registry_anchor: KeriEvent::deserialize(anchor1.as_bytes(), limits().json)?.into_static(),
        issue_anchor: KeriEvent::deserialize(anchor2.as_bytes(), limits().json)?.into_static(),
        revoke_anchor: KeriEvent::deserialize(anchor3.as_bytes(), limits().json)?.into_static(),
    })
}

struct TelCountScenario {
    issuer: KeyStateSnapshot,
    registry_wire: Vec<u8>,
    registry_anchor: KeriEvent<'static>,
    issues: Vec<(Vec<u8>, KeriEvent<'static>)>,
}

impl TelCountScenario {
    fn len(&self) -> usize {
        self.registry_wire.len()
            + self
                .issues
                .iter()
                .map(|(wire, _)| wire.len())
                .sum::<usize>()
    }
}

fn tel_count_scenario(count: usize) -> Result<TelCountScenario, Box<dyn Error>> {
    let controller = KeyPair::<Ed25519>::from_seed_bytes(&[41; 32]);
    let next = KeyPair::<Ed25519>::from_seed_bytes(&[42; 32]);
    let controller_verfer =
        VerifyingKey::from_matter(controller.verfer(VerKeyCode::Ed25519)?.into_static());
    let next_verfer = VerifyingKey::from_matter(next.verfer(VerKeyCode::Ed25519)?.into_static());
    let next_commitment =
        Digest::from_matter(digest(DigestCode::Blake3_256, &next_verfer.to_qb64b())?);
    let inception = InceptionBuilder::new()
        .keys(vec![controller_verfer])
        .next_keys(vec![next_commitment])
        .build()?;
    let issuer = inception.identifier().ok_or("TEL issuer has no prefix")?;
    let nonce: Noncer<'static> = MatterBuilder::new()
        .with_code(NoncerCode::Salt128)
        .with_raw(vec![0x22; 16])?
        .build()?;
    let registry = RegistryInceptionBuilder::new(issuer.clone(), nonce)
        .config(vec![ConfigTrait::NoBackers])
        .build()?;
    let registry_id = registry.said().clone().into_static();
    let first_anchor = tel_anchor(&issuer, &inception, 1, (&registry_id, 0), &registry)?;
    let registry_wire = tel_source_frame(&registry, 1, first_anchor.said())?;
    let registry_anchor =
        KeriEvent::deserialize(first_anchor.as_bytes(), limits().json)?.into_static();
    let mut kel_wires = vec![
        frame_signed(&inception, &controller)?,
        frame_signed(&first_anchor, &controller)?,
    ];
    let mut prior = first_anchor;
    let mut credential_events = Vec::with_capacity(count);
    for index in 0..count {
        let credential_id =
            Said::from_matter(digest(DigestCode::Blake3_256, &index.to_be_bytes())?);
        let issue = IssueBuilder::new(
            credential_id.clone(),
            registry_id.clone(),
            "2026-09-30T00:00:00+00:00",
        )
        .build()?;
        let anchor_sn = u128::try_from(index)?
            .checked_add(2)
            .ok_or("TEL sequence overflow")?;
        let anchor = tel_anchor(&issuer, &prior, anchor_sn, (&credential_id, 0), &issue)?;
        let wire = tel_source_frame(&issue, u16::try_from(anchor_sn)?, anchor.said())?;
        let accepted = KeriEvent::deserialize(anchor.as_bytes(), limits().json)?.into_static();
        kel_wires.push(frame_signed(&anchor, &controller)?);
        credential_events.push((wire, accepted));
        prior = anchor;
    }
    let issuer_snapshot = accepted_issuer_snapshot(&kel_wires)?;
    if issuer_snapshot.view().sn().value() != u128::try_from(count)? + 1 {
        return Err("TEL count KEL did not validate all issue anchors".into());
    }
    Ok(TelCountScenario {
        issuer: issuer_snapshot,
        registry_wire,
        registry_anchor,
        issues: credential_events,
    })
}

fn tel_issue_count(
    scenario: &TelCountScenario,
) -> Result<(RegistryState, Vec<CredentialState>), Box<dyn Error>> {
    let issuer = scenario.issuer.view();
    let registry_message = parse_tel_frame(&scenario.registry_wire)?;
    let registry = RegistryState::incept(
        &SignedTel::from(&registry_message).with_host_accepted_anchor(&scenario.registry_anchor),
        &issuer,
    )?;
    let evidence = TelEvidence::Issuer {
        state: &issuer,
        anchor: None,
    };
    let mut heads = Vec::with_capacity(scenario.issues.len());
    for (wire, anchor) in &scenario.issues {
        let message = parse_tel_frame(wire)?;
        let head = CredentialState::incept(
            &registry,
            &SignedTel::from(&message).with_host_accepted_anchor(anchor),
            &evidence,
        )?;
        if head.status() != CredentialStatus::Issued {
            return Err("TEL issue did not produce an issued head".into());
        }
        heads.push(head);
    }
    Ok((registry, heads))
}

fn tel_issue_revoke(
    scenario: &TelScenario,
) -> Result<(RegistryState, CredentialState), Box<dyn Error>> {
    let issuer = scenario.issuer.view();
    let registry_message = parse_tel_frame(&scenario.registry_wire)?;
    let registry = RegistryState::incept(
        &SignedTel::from(&registry_message).with_host_accepted_anchor(&scenario.registry_anchor),
        &issuer,
    )?;
    let evidence = TelEvidence::Issuer {
        state: &issuer,
        anchor: None,
    };
    let issue_message = parse_tel_frame(&scenario.issue_wire)?;
    let mut credential = CredentialState::incept(
        &registry,
        &SignedTel::from(&issue_message).with_host_accepted_anchor(&scenario.issue_anchor),
        &evidence,
    )?;
    let revoke_message = parse_tel_frame(&scenario.revoke_wire)?;
    credential.ingest_mut(
        &registry,
        &SignedTel::from(&revoke_message).with_host_accepted_anchor(&scenario.revoke_anchor),
        &evidence,
    )?;
    if credential.status() != CredentialStatus::Revoked {
        return Err("accepted TEL did not revoke the credential".into());
    }
    Ok((registry, credential))
}

fn tel_reject_missing_issue_anchor(scenario: &TelScenario) -> Result<(), Box<dyn Error>> {
    let issuer = scenario.issuer.view();
    let registry_message = parse_tel_frame(&scenario.registry_wire)?;
    let registry = RegistryState::incept(
        &SignedTel::from(&registry_message).with_host_accepted_anchor(&scenario.registry_anchor),
        &issuer,
    )?;
    let issue_message = parse_tel_frame(&scenario.issue_wire)?;
    match CredentialState::incept(
        &registry,
        &SignedTel::from(&issue_message),
        &TelEvidence::Issuer {
            state: &issuer,
            anchor: None,
        },
    ) {
        Err(RegistryRejection::MissingAnchor) => Ok(()),
        _ => Err("missing accepted TEL issue anchor did not reject".into()),
    }
}

fn tel_reject_missing_revoke_anchor(scenario: &TelScenario) -> Result<(), Box<dyn Error>> {
    let issuer = scenario.issuer.view();
    let registry_message = parse_tel_frame(&scenario.registry_wire)?;
    let registry = RegistryState::incept(
        &SignedTel::from(&registry_message).with_host_accepted_anchor(&scenario.registry_anchor),
        &issuer,
    )?;
    let evidence = TelEvidence::Issuer {
        state: &issuer,
        anchor: None,
    };
    let issue_message = parse_tel_frame(&scenario.issue_wire)?;
    let mut credential = CredentialState::incept(
        &registry,
        &SignedTel::from(&issue_message).with_host_accepted_anchor(&scenario.issue_anchor),
        &evidence,
    )?;
    let revoke_message = parse_tel_frame(&scenario.revoke_wire)?;
    if !matches!(
        credential.ingest_mut(&registry, &SignedTel::from(&revoke_message), &evidence),
        Err(RegistryRejection::MissingAnchor)
    ) || credential.status() != CredentialStatus::Issued
    {
        return Err("missing revoke anchor did not preserve issued state".into());
    }
    Ok(())
}

fn percentile(values: &mut [u128], index: usize) -> u128 {
    values.sort_unstable();
    values[index]
}

fn report_case_with_protocol<T>(
    name: &str,
    input_bytes: usize,
    warmups: usize,
    sample_count: usize,
    mut f: impl FnMut() -> T,
) {
    for _ in 0..warmups {
        black_box(f());
    }
    let mut samples = Vec::with_capacity(sample_count);
    for _ in 0..sample_count {
        let (result, sample) = measure(&mut f);
        black_box(&result);
        samples.push(sample);
    }
    let mut nanos: Vec<_> = samples.iter().map(|sample| sample.nanos).collect();
    let mut allocs: Vec<_> = samples
        .iter()
        .map(|sample| u128::try_from(sample.allocs).expect("small count"))
        .collect();
    let mut requested: Vec<_> = samples
        .iter()
        .map(|sample| u128::try_from(sample.requested).expect("small count"))
        .collect();
    let mut retained: Vec<_> = samples
        .iter()
        .map(|sample| u128::try_from(sample.retained).expect("small count"))
        .collect();
    let mut peak: Vec<_> = samples
        .iter()
        .map(|sample| u128::try_from(sample.peak).expect("small count"))
        .collect();
    let p10 = percentile(&mut nanos, sample_count / 10);
    let median = percentile(&mut nanos, sample_count / 2);
    let p90 = percentile(&mut nanos, sample_count * 9 / 10);
    let throughput = u128::try_from(input_bytes).expect("small fixture") * 1_000_000_000 / median;
    println!(
        "{{\"case\":\"{name}\",\"input_bytes\":{input_bytes},\"warmups\":{warmups},\"samples\":{sample_count},\"p10_ns\":{p10},\"median_ns\":{median},\"p90_ns\":{p90},\"throughput_bytes_per_s\":{throughput},\"median_allocs\":{},\"median_requested_bytes\":{},\"median_retained_bytes\":{},\"median_peak_bytes\":{}}}",
        percentile(&mut allocs, sample_count / 2),
        percentile(&mut requested, sample_count / 2),
        percentile(&mut retained, sample_count / 2),
        percentile(&mut peak, sample_count / 2),
    );
}

fn report_case<T>(name: &str, input_bytes: usize, f: impl FnMut() -> T) {
    report_case_with_protocol(name, input_bytes, WARMUPS, SAMPLES, f);
}

#[test]
#[ignore = "manual release performance baseline; run with --ignored --nocapture"]
fn pinned_kel_parse_bind_verify_fold_owned_snapshot() {
    report_case(
        "pinned_kel_parse_bind_verify_fold_owned_snapshot",
        KEL.len(),
        || accepted_kel_snapshot().expect("pinned KEL must fold"),
    );
}

#[test]
#[ignore = "manual release performance baseline; run with --ignored --nocapture"]
fn witnessed_inception_with_receipt_accumulation() {
    report_case(
        "witnessed_inception_with_receipt_accumulation",
        WITNESSED_ICP.len(),
        || accepted_witnessed_snapshot().expect("pinned witnessed inception must fold"),
    );
}

#[test]
#[ignore = "manual release performance baseline; run with --ignored --nocapture"]
fn witnessed_inception_rejects_missing_receipts() {
    report_case(
        "witnessed_inception_rejects_missing_receipts",
        WITNESSED_ICP.len(),
        || rejected_missing_witness_receipts().expect("pinned missing-receipt rejection"),
    );
}

#[test]
#[ignore = "manual release performance baseline; run with --ignored --nocapture"]
fn sixteen_independent_kel_folds_held_as_a_batch() {
    report_case(
        "sixteen_independent_kel_folds_held_as_a_batch",
        KEL.len() * 16,
        || accepted_kel_batch(16).expect("all pinned KEL folds must succeed"),
    );
}

#[test]
#[ignore = "manual release performance baseline; run with --ignored --nocapture"]
fn kel_bytewise_chunking_and_owned_snapshot() {
    report_case(
        "kel_bytewise_chunking_and_owned_snapshot",
        KEL.len(),
        || accepted_kel_chunked_snapshot(1).expect("bytewise KEL must fold"),
    );
}

#[test]
#[ignore = "manual release performance baseline; run with --ignored --nocapture"]
fn kel_sixty_four_byte_chunks_and_owned_snapshot() {
    report_case(
        "kel_sixty_four_byte_chunks_and_owned_snapshot",
        KEL.len(),
        || accepted_kel_chunked_snapshot(64).expect("chunked KEL must fold"),
    );
}

#[test]
#[ignore = "manual release performance baseline; run with --ignored --nocapture"]
fn signed_rotation_supersedes_interactions_and_refolds() {
    let wire = recovery_wire().expect("deterministic signed recovery fixture");
    report_case(
        "signed_rotation_supersedes_interactions_and_refolds",
        wire.len(),
        || recovered_snapshot(&wire).expect("signed recovery must supersede and refold"),
    );
}

#[test]
#[ignore = "manual release performance baseline; run with --ignored --nocapture"]
fn scaled_key_witness_signature_and_duplicate_inceptions() {
    let dimensions = [
        (1, 1, 0, 0, 0),
        (4, 1, 0, 0, 0),
        (8, 1, 0, 0, 0),
        (8, 4, 0, 0, 0),
        (8, 8, 0, 0, 0),
        (1, 1, 4, 1, 0),
        (1, 1, 8, 1, 0),
        (1, 1, 8, 4, 0),
        (1, 1, 8, 8, 0),
        (1, 1, 0, 0, 8),
        (1, 1, 0, 0, 64),
    ];
    for (keys, signatures, witnesses, receipts, duplicates) in dimensions {
        let wire = scaled_inception_wire(InceptionDimensions {
            keys,
            signatures,
            witnesses,
            receipts,
            duplicates,
            groups: 1,
        })
        .expect("deterministic scaled inception fixture");
        let name = format!(
            "scaled_inception_keys_{keys}_signatures_{signatures}_witnesses_{witnesses}_receipts_{receipts}_duplicates_{duplicates}"
        );
        report_case(&name, wire.len(), || {
            scaled_inception_snapshot(&wire).expect("scaled signed inception must fold")
        });
    }
}

#[test]
#[ignore = "manual release performance baseline; run with --ignored --nocapture"]
fn scaled_attachment_groups_with_eight_real_signatures() {
    for groups in [1, 2, 4, 8] {
        let wire = scaled_inception_wire(InceptionDimensions {
            keys: 8,
            signatures: 8,
            witnesses: 0,
            receipts: 0,
            duplicates: 0,
            groups,
        })
        .expect("deterministic grouped signed inception fixture");
        let name = format!("scaled_inception_eight_signatures_{groups}_controller_groups");
        report_case(&name, wire.len(), || {
            scaled_inception_snapshot(&wire).expect("grouped signed inception must fold")
        });
    }
}

#[test]
#[ignore = "manual release performance baseline; run with --ignored --nocapture"]
fn anchored_kel_body_byte_scaling_with_fixed_two_signatures() {
    for anchors in [0, 32, 512, 2048] {
        let wire = anchored_kel_wire(anchors).expect("deterministic anchored KEL fixture");
        let name = format!("anchored_kel_{anchors}_digest_seals_two_signatures");
        report_case(&name, wire.len(), || {
            anchored_kel_snapshot(&wire).expect("anchored signed KEL must fold")
        });
    }
}

#[test]
#[ignore = "manual release performance baseline; run with --ignored --nocapture"]
fn acdc_payload_size_and_cryptographic_rejection() {
    for payload_bytes in [1024, 65_536, 524_288] {
        let wire = credential_wire(payload_bytes, 0).expect("deterministic signed ACDC fixture");
        let name = format!("acdc_{payload_bytes}_payload_bytes_verified_owned");
        report_case(&name, wire.raw.len(), || {
            verified_credential(&wire).expect("signed credential must verify")
        });
    }
    let wire = credential_wire(65_536, 0).expect("deterministic rejected ACDC fixture");
    report_case(
        "acdc_65536_payload_bytes_rejected_said",
        wire.tampered.len(),
        || {
            rejected_credential_said(&wire).expect("tampered SAID must reject");
        },
    );
    report_case(
        "acdc_65536_payload_bytes_rejected_signature",
        wire.raw.len(),
        || {
            rejected_credential_signature(&wire).expect("wrong signer must reject");
        },
    );
}

#[test]
#[ignore = "manual release performance baseline; run with --ignored --nocapture"]
fn acdc_credential_count_with_owned_results() {
    for count in [1, 16, 64] {
        let credentials = (0..count)
            .map(|index| credential_wire(1024, index))
            .collect::<Result<Vec<_>, _>>()
            .expect("deterministic signed ACDC batch");
        let input_bytes = credentials.iter().map(|wire| wire.raw.len()).sum();
        let name = format!("acdc_{count}_distinct_credentials_verified_owned");
        report_case(&name, input_bytes, || {
            credentials
                .iter()
                .map(|wire| verified_credential(wire))
                .collect::<Result<Vec<_>, _>>()
                .expect("all distinct credentials must verify")
        });
    }
}

#[test]
#[ignore = "manual release performance baseline; run with --ignored --nocapture"]
fn tel_issuance_revocation_and_missing_anchor() {
    let scenario = tel_scenario().expect("deterministic signed TEL/KEL fixture");
    report_case("tel_registry_issue_revoke_owned", scenario.len(), || {
        tel_issue_revoke(&scenario).expect("anchored TEL lifecycle must fold")
    });
    report_case(
        "tel_issue_rejects_missing_accepted_kel_anchor",
        scenario.registry_wire.len() + scenario.issue_wire.len(),
        || tel_reject_missing_issue_anchor(&scenario).expect("missing TEL anchor must reject"),
    );
    report_case(
        "tel_revoke_rejects_missing_anchor_preserves_issue",
        scenario.len(),
        || {
            tel_reject_missing_revoke_anchor(&scenario)
                .expect("missing revocation anchor must reject");
        },
    );
}

#[test]
#[ignore = "manual release performance baseline; run with --ignored --nocapture"]
fn tel_distinct_credential_count_with_owned_heads() {
    for count in [1, 16, 64] {
        let scenario = tel_count_scenario(count).expect("signed TEL count fixture");
        let name = format!("tel_{count}_distinct_issued_credential_heads");
        report_case(&name, scenario.len(), || {
            tel_issue_count(&scenario).expect("all anchored TEL issues must fold")
        });
    }
}

#[test]
#[ignore = "manual release performance baseline; run with --ignored --nocapture"]
fn salty_custody_argon2_and_signing_separated() {
    let salt = Salt::from_raw(&[0x44; 16]).expect("fixed benchmark salt");
    let mut custodian = SaltyCustodian::new(
        Salt::from_raw(&[0x44; 16]).expect("fixed custodian salt"),
        Tier::Low,
        PathConvention::Keripy,
    );
    let path = custodian.derivation_path(0, 0);
    custodian
        .incept(KeySpec {
            count: 1,
            ncount: 1,
            transferable: true,
        })
        .expect("low-tier single-key custodian inception");
    let prederived = salt
        .key_pair(&path, Tier::Low)
        .expect("benchmark signing-only control key");
    let message = b"a15 custody exact bytes signed at low Argon2id tier";
    let custody_signature = custodian.sign(message, None).expect("custodian signature");
    let signing_only_signature = prederived
        .sign_indexed(message, 0, IndexMode::Both)
        .expect("signing-only signature");
    assert_eq!(custody_signature.as_slice(), &[signing_only_signature]);

    report_case_with_protocol(
        "salty_custodian_low_incept_one_current_one_next",
        16,
        3,
        21,
        || {
            let mut fresh = SaltyCustodian::new(
                Salt::from_raw(&[0x44; 16]).expect("fixed benchmark salt"),
                Tier::Low,
                PathConvention::Keripy,
            );
            fresh
                .incept(KeySpec {
                    count: 1,
                    ncount: 1,
                    transferable: true,
                })
                .expect("low-tier current and next derivation")
        },
    );
    report_case_with_protocol("salt_argon2id_low_stretch", path.len(), 3, 21, || {
        salt.stretch(&path, Tier::Low)
            .expect("low-tier Argon2id derivation")
    });
    report_case_with_protocol(
        "salty_custodian_low_sign_rederiving",
        message.len(),
        3,
        21,
        || {
            custodian
                .sign(message, None)
                .expect("low-tier custodian signature")
        },
    );
    report_case(
        "ed25519_indexed_sign_with_prederived_key",
        message.len(),
        || {
            prederived
                .sign_indexed(message, 0, IndexMode::Both)
                .expect("Ed25519 signing-only control")
        },
    );
}
