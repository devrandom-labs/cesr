//! Audit observations, not regression expectations: these tests assert the
//! observed defects. Copy temporarily into crates/keri-codec/tests/audit_probe.rs.
//! Run: cargo test -p keri-codec --test audit_probe -- --nocapture
//! Remove the temporary copy afterwards. See the companion audit report.
#![allow(clippy::print_stdout, reason = "audit measurement output")]

mod common;

use cesr::core::primitives::Number;
use common::{Fallible, Key, delegated_inception, genesis, interaction, plain_rotation, seed};
use keri::{Authority, DelegationEvidence, KeyState, Signed};
use keri_codec::{
    CodecError, Deserialize, DeserializeError, EventMessage, Exn, InteractionBuilder, Serialize,
};
use keri_events::{Identifier, InceptionEvent, KeriEvent, SigningThreshold, ThresholdForm, Toad};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::hint::black_box;
use std::time::Instant;

thread_local! {
    static COUNT: Cell<usize> = const { Cell::new(0) };
    static BYTES: Cell<usize> = const { Cell::new(0) };
}
struct Counting;
#[allow(unsafe_code, reason = "audit-only allocator instrumentation")]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = COUNT.try_with(|v| v.set(v.get() + 1));
        let _ = BYTES.try_with(|v| v.set(v.get() + layout.size()));
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let _ = COUNT.try_with(|v| v.set(v.get() + 1));
        let _ = BYTES.try_with(|v| v.set(v.get() + size));
        unsafe { System.realloc(ptr, layout, size) }
    }
}
#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn measure<T>(f: impl FnOnce() -> T) -> (T, usize, usize) {
    let count = COUNT.with(Cell::get);
    let bytes = BYTES.with(Cell::get);
    let result = f();
    (
        result,
        COUNT.with(Cell::get) - count,
        BYTES.with(Cell::get) - bytes,
    )
}

#[test]
fn audit_wrong_identifier_advances_state() -> Fallible<()> {
    let (key, next, other_key, other_next) = (Key::new()?, Key::new()?, Key::new()?, Key::new()?);
    let icp = genesis(&key, &next)?;
    let other = genesis(&other_key, &other_next)?;
    let serialized = InteractionBuilder::new()
        .prefix(other.prefix.clone())
        .prior_event_said(icp.said.clone())
        .sn(1)
        .build()?;
    let mut wire = serialized.as_bytes().to_vec();
    wire.extend_from_slice(b"-AAB");
    wire.extend_from_slice(key.sign(serialized.as_bytes(), 0)?.to_qb64().as_bytes());
    let (message, rest) = EventMessage::parse(&wire)?;
    assert!(rest.is_empty());
    assert_ne!(message.event().prefix(), &icp.prefix);
    let state = seed(&icp, &key)?.ingest(&Signed::from(&message))?;
    assert_eq!(state.sn().value(), 1);
    assert_eq!(state.prefix(), &icp.prefix);
    assert_eq!(state.latest_said(), message.event().said());
    Ok(())
}

#[test]
fn audit_plain_rotation_bypasses_delegation_evidence() -> Fallible<()> {
    let (dk, dn, key, next, later) = (
        Key::new()?,
        Key::new()?,
        Key::new()?,
        Key::new()?,
        Key::new()?,
    );
    let delegator = genesis(&dk, &dn)?;
    let dip = delegated_inception(&key, &next, delegator.prefix.clone())?;
    let state = KeyState::incept_delegated(
        &dip.signed(vec![key.sign(&dip.bytes, 0)?]),
        &DelegationEvidence::HostAccepted,
    )?;
    let rot = plain_rotation(&dip, 1, &next, &later)?;
    let mut wire = rot.bytes.clone();
    wire.extend_from_slice(b"-AAB");
    wire.extend_from_slice(next.sign(&rot.bytes, 0)?.to_qb64().as_bytes());
    let (message, _) = EventMessage::parse(&wire)?;
    let advanced = state.ingest(&Signed::from(&message))?;
    assert_eq!(advanced.sn().value(), 1);
    assert!(advanced.delegator().is_some());
    assert!(matches!(message.event(), KeriEvent::Rotation(_)));
    Ok(())
}

#[test]
fn audit_signed_event_and_bytes_can_disagree() -> Fallible<()> {
    let (key, next) = (Key::new()?, Key::new()?);
    let icp = genesis(&key, &next)?;
    let ixn = interaction(&icp, 1)?;
    let unrelated = b"not a KERI event";
    let supplied = Signed {
        event: &ixn.parsed,
        signed_bytes: unrelated,
        sigs: vec![key.sign(unrelated, 0)?],
        wigs: vec![],
    };
    let advanced = seed(&icp, &key)?.ingest(&supplied)?;
    assert_eq!(advanced.latest_said(), &ixn.said);
    Ok(())
}

#[test]
fn audit_basic_identifier_accepts_an_unrelated_controlling_key() -> Fallible<()> {
    let (victim, attacker, next) = (Key::new()?, Key::new()?, Key::new()?);
    let template = genesis(&attacker, &next)?;
    let victim_prefix = common::nontransferable_prefix_of(&victim)?;
    let event = InceptionEvent::new(
        Identifier::Basic(victim_prefix.clone()),
        Number::new(0),
        template.said,
        vec![attacker.verfer.clone()],
        SigningThreshold::Simple(1),
        vec![],
        SigningThreshold::Simple(0),
        vec![],
        Toad::exact(0, 0)?,
        vec![],
        vec![],
        ThresholdForm::HexString,
    );
    let serialized = event.serialize()?;
    let mut wire = serialized.as_bytes().to_vec();
    wire.extend_from_slice(b"-AAB");
    wire.extend_from_slice(
        attacker
            .sign(serialized.as_bytes(), 0)?
            .to_qb64()
            .as_bytes(),
    );
    let (message, _) = EventMessage::parse(&wire)?;
    let state = KeyState::incept(&Signed::from(&message))?;
    assert_eq!(state.prefix(), &Identifier::Basic(victim_prefix));
    assert_eq!(state.keys(), &[attacker.verfer]);
    Ok(())
}

#[test]
fn audit_duplicate_witness_counts_as_two_witnesses() -> Fallible<()> {
    let (key, next, witness) = (Key::new()?, Key::new()?, Key::witness()?);
    let template = genesis(&key, &next)?;
    let event = InceptionEvent::new(
        template.prefix.clone(),
        Number::new(0),
        template.said,
        vec![key.verfer.clone()],
        SigningThreshold::Simple(1),
        vec![common::commit(&next.verfer)?],
        SigningThreshold::Simple(1),
        vec![common::prefix_of(&witness), common::prefix_of(&witness)],
        Toad::exact(2, 2)?,
        vec![],
        vec![],
        ThresholdForm::HexString,
    );
    let serialized = event.serialize()?;
    let mut wire = serialized.as_bytes().to_vec();
    wire.extend_from_slice(b"-AAB");
    wire.extend_from_slice(key.sign(serialized.as_bytes(), 0)?.to_qb64().as_bytes());
    wire.extend_from_slice(b"-BAC");
    wire.extend_from_slice(witness.sign(serialized.as_bytes(), 0)?.to_qb64().as_bytes());
    wire.extend_from_slice(witness.sign(serialized.as_bytes(), 1)?.to_qb64().as_bytes());
    let (message, _) = EventMessage::parse(&wire)?;
    let state = KeyState::incept(&Signed::from(&message))?;
    assert_eq!(state.witness_threshold().value(), 2);
    assert_eq!(state.witnesses()[0], state.witnesses()[1]);
    Ok(())
}

#[test]
fn audit_attachment_copy_scaling_and_verification_allocations() -> Fallible<()> {
    let (key, next) = (Key::new()?, Key::new()?);
    let icp = genesis(&key, &next)?;
    let sig = key.sign(&icp.bytes, 0)?;
    let signature = sig.to_qb64();
    for count in [1, 16, 64, 256, 1024] {
        let mut wire = icp.bytes.clone();
        for _ in 0..count {
            wire.extend_from_slice(b"-AAB");
            wire.extend_from_slice(signature.as_bytes());
        }
        let (result, allocations, bytes) = measure(|| EventMessage::parse(&wire));
        let (message, remainder) = result?;
        assert!(remainder.is_empty());
        assert_eq!(message.sigs().len(), count);
        println!(
            "bare groups={count} input={} allocations={allocations} allocated_bytes={bytes}",
            wire.len()
        );
    }
    let mut framed = icp.bytes.clone();
    // One signature group is 92 bytes = 23 quadlets; -VAX is its V1 frame.
    framed.extend_from_slice(b"-VAX-AAB");
    framed.extend_from_slice(signature.as_bytes());
    for count in [1, 16, 64, 256] {
        let batch = framed.repeat(count);
        let (result, allocations, bytes) = measure(|| -> Fallible<usize> {
            let mut rest = batch.as_slice();
            let mut parsed = 0;
            while !rest.is_empty() {
                let (_, remainder) = EventMessage::parse(rest)?;
                rest = remainder;
                parsed += 1;
            }
            Ok(parsed)
        });
        assert_eq!(result?, count);
        println!(
            "framed messages={count} input={} allocations={allocations} allocated_bytes={bytes}",
            batch.len()
        );
    }
    let (message, _) = EventMessage::parse(&framed)?;
    let (_, allocations, bytes) = measure(|| Signed::from(&message));
    println!("wire to Signed allocations={allocations} allocated_bytes={bytes}");
    let keys = [key.verfer.clone()];
    let threshold = SigningThreshold::Simple(1);
    let authority = Authority::new(&keys, &threshold);
    for count in [1, 16, 64, 256] {
        let sigs = vec![sig.clone(); count];
        let started = Instant::now();
        let (result, allocations, bytes) =
            measure(|| authority.verify(black_box(&icp.bytes), &sigs));
        assert_eq!(result?.sigs().len(), count);
        println!(
            "duplicate signatures={count} allocations={allocations} allocated_bytes={bytes} elapsed_us={}",
            started.elapsed().as_micros()
        );
    }
    // Ensure the public body codec agrees with the fixture as a control.
    assert_eq!(
        KeriEvent::deserialize(&icp.bytes)?.said(),
        icp.parsed.said()
    );
    Ok(())
}

#[test]
fn audit_ipex_builder_attempts_to_decode_a_hash_placeholder() -> Fallible<()> {
    let (key, next) = (Key::new()?, Key::new()?);
    let icp = genesis(&key, &next)?;
    let timestamp = "2026-09-29T12:00:00+00:00";
    assert!(matches!(
        Exn::ipex_agree(&icp.prefix, timestamp, "hello", Some(&icp.said)),
        Err(CodecError::Deserialize(
            DeserializeError::UnparseablePrimitive { field: "d", .. }
        ))
    ));
    Ok(())
}

#[test]
fn audit_ipex_parser_rejects_ordinary_escaped_text() -> Fallible<()> {
    let line = include_str!("corpus/ipex/happy.jsonl")
        .lines()
        .nth(2)
        .ok_or("missing agree fixture")?;
    let fixture: serde_json::Value = serde_json::from_str(line)?;
    let raw = fixture["raw"].as_str().ok_or("missing raw")?;
    Exn::deserialize(raw.as_bytes())?;
    let mut body: serde_json::Value = serde_json::from_str(raw)?;
    body["a"]["m"] = serde_json::Value::String("say \"hello\"".into());
    let size = serde_json::to_vec(&body)?.len();
    body["v"] = serde_json::Value::String(format!("KERI10JSON{size:06x}_"));
    let (sealed, _) = common::reseal_spans(serde_json::to_vec(&body)?, &[b"\"d\":\""])?;
    assert!(matches!(
        Exn::deserialize(&sealed),
        Err(CodecError::Deserialize(
            DeserializeError::NonCanonical { .. }
        ))
    ));
    Ok(())
}

#[test]
fn audit_binary_group_and_short_json_are_not_incrementally_parsed() -> Fallible<()> {
    let (key, next) = (Key::new()?, Key::new()?);
    let icp = genesis(&key, &next)?;
    let mut text = b"-AAB".to_vec();
    text.extend_from_slice(key.sign(&icp.bytes, 0)?.to_qb64().as_bytes());
    assert!(cesr_stream::CesrGroup::parse(&text).is_ok());
    let binary = cesr::b64::Qb64(&text).decode()?;
    assert!(cesr_stream::CesrMessage::parse(&binary).is_err());
    assert!(matches!(
        cesr_stream::CesrMessage::parse(b"{\"v\":\"KER"),
        Err(cesr_stream::ParseError::MissingVersionString)
    ));
    Ok(())
}
