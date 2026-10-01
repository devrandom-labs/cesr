//! A10 authentication and A11 retained-state release-only measurements.
//! Setup is outside each sample; run explicitly with `--release --ignored`.
#![cfg(feature = "std")]
#![allow(clippy::print_stdout, reason = "explicit release benchmark output")]

mod common;

use core::cell::Cell;
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::time::Instant;

use cesr::core::indexer::IndexerBuilder;
use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::{DigestCode, NoncerCode};
use cesr::core::primitives::{Noncer, Number, Siger};
use cesr::crypto::digest;
use keri::{
    Authority, Commitment, KeyStateSnapshot, ReceiptedEvent, ReceiptorEstablishment, RegistryState,
    Signed, SignedTel, TelAnchorCoordinate, TelEvidence, TransferableEndorsement, Witnessing,
};
use keri_codec::{Deserialize, EventMessage, IssueBuilder, RegistryInceptionBuilder};
use keri_events::{
    ConfigTrait, Digest, Identifier, KeriEvent, Said, Seal, SigningThreshold, TelEvent, Toad,
};

use common::{
    Fallible, Key, commit, genesis, interaction, interaction_anchoring, nontransferable_prefix_of,
    prefix_of, seed,
};

#[test]
fn wire_carrier_borrows_parsed_signatures_and_host_carrier_retains_owned() -> Fallible<()> {
    let (controller, next, witness) = (Key::new()?, Key::new()?, Key::witness()?);
    let event = genesis(&controller, &next)?;
    let signature = controller.sign(&event.bytes, 0)?;
    let mut wire = event.bytes.clone();
    wire.extend_from_slice(b"-AAB");
    wire.extend_from_slice(signature.to_qb64().as_bytes());
    wire.extend_from_slice(b"-BAB");
    wire.extend_from_slice(witness.sign(&event.bytes, 0)?.to_qb64().as_bytes());
    let (message, rest) = EventMessage::parse(&wire, common::message_limits())?;
    assert!(rest.is_empty());
    let transient = Signed::from(&message);
    assert_eq!(transient.sigs().as_ptr(), message.sigs().as_ptr());
    assert_eq!(transient.wigs().as_ptr(), message.wigs().as_ptr());
    assert_eq!(transient.signed_bytes().as_ptr(), message.body().as_ptr());

    let owned = vec![signature];
    let original_storage = owned.as_ptr();
    let retained = Signed::from_host_asserted_parts(&event.parsed, &event.bytes, owned, vec![]);
    assert_eq!(retained.sigs().as_ptr(), original_storage);
    Ok(())
}

#[test]
fn duplicate_wire_material_is_compacted_before_authentication() -> Fallible<()> {
    let signer = Key::new()?;
    let bytes = b"a10 duplicate signature work";
    let keys = [signer.verfer.clone()];
    let threshold = SigningThreshold::Simple(1);
    let signature = signer.sign(bytes, 0)?;
    let bare = Siger::new(
        IndexerBuilder::new()
            .with_code(signature.code())
            .with_index(signature.index())?
            .with_raw(signature.raw().to_vec())?,
    );
    assert_ne!(
        bare, signature,
        "attached verfer affects local Siger equality"
    );
    let equivalent_wire = [bare, signature.clone()];
    assert_eq!(
        Authority::new(&keys, &threshold)
            .verify(bytes, &equivalent_wire)?
            .sigs()
            .len(),
        1,
        "attached verifier metadata is not part of signed wire material"
    );
    let repeated = vec![signature; 256];
    let (result, allocations, allocated_bytes, _) =
        measure(|| Authority::new(&keys, &threshold).verify(bytes, black_box(&repeated)));
    let verified = result?;
    assert_eq!(verified.sigs().len(), 1, "one unique wire signature");
    assert!(
        allocations <= 8,
        "{allocations} allocations for one unique signature"
    );
    assert!(
        allocated_bytes <= 1024,
        "{allocated_bytes} bytes for one unique signature"
    );
    Ok(())
}

#[test]
fn invalid_first_and_distinct_ondex_are_preserved() -> Fallible<()> {
    let (signer, impostor) = (Key::new()?, Key::new()?);
    let bytes = b"a10 indexed signature alternatives";
    let keys = [signer.verfer.clone()];
    let threshold = SigningThreshold::Simple(1);
    let valid = signer.sign_dual(bytes, 0, 1)?;
    let forged = impostor.sign_dual(bytes, 0, 1)?;
    let candidates = [forged, valid.clone()];
    let verified = Authority::new(&keys, &threshold).verify(bytes, &candidates)?;
    assert_eq!(verified.sigs().len(), 1);
    assert_eq!(verified.sigs()[0].raw(), valid.raw());

    let prior: Digest<'static> = commit(&signer.verfer)?;
    let commitments = [prior.clone(), prior];
    let prior_threshold = SigningThreshold::Simple(2);
    let commitment = Commitment::new(&commitments, &prior_threshold);
    let current_only = signer.sign_current_only(bytes, 0)?;
    let other_ondex = signer.sign_dual(bytes, 0, 0)?;
    let alternatives = [current_only, valid, other_ondex];
    assert_eq!(
        Authority::new(&keys, &threshold)
            .verify(bytes, &alternatives)?
            .sigs()
            .len(),
        3,
        "distinct wire signatures at the same index remain available"
    );
    commitment.verify_opening(&Authority::new(&keys, &threshold), bytes, &alternatives)?;
    Ok(())
}

#[test]
fn duplicate_witness_and_transferable_receipt_paths() -> Fallible<()> {
    let (controller, next, witness, impostor, receiptor) = (
        Key::new()?,
        Key::new()?,
        Key::witness()?,
        Key::witness()?,
        Key::new()?,
    );
    let event = genesis(&controller, &next)?;
    let witnesses = [nontransferable_prefix_of(&witness)?];
    let witnessing = Witnessing::new(&witnesses, Toad::exact(1, 1)?);
    let forged_witness = impostor.sign(&event.bytes, 0)?;
    let valid_witness = witness.sign(&event.bytes, 0)?;
    witnessing.receipted_by(&event.bytes, &[forged_witness, valid_witness.clone()])?;
    let repeats = vec![valid_witness; 256];
    let (result, allocations, allocated_bytes, _) =
        measure(|| witnessing.receipted_by(&event.bytes, black_box(&repeats)));
    result?;
    assert!(allocations <= 6, "{allocations} witness allocations");
    assert!(allocated_bytes <= 1024, "{allocated_bytes} witness bytes");

    let keys = [receiptor.verfer.clone()];
    let establishment = ReceiptorEstablishment {
        said: &event.said,
        keys: &keys,
    };
    let accepted = ReceiptedEvent {
        prefix: &event.prefix,
        sn: event.parsed.sn(),
        said: &event.said,
        signed_bytes: &event.bytes,
    };
    let forged_receipt = impostor.sign(&event.bytes, 0)?;
    let valid_receipt = receiptor.sign(&event.bytes, 0)?;
    let in_range_receipt = TransferableEndorsement {
        receiptor: &event.prefix,
        sn: event.parsed.sn(),
        said: &event.said,
        sigs: &[forged_receipt, valid_receipt],
    };
    accepted.endorsed_by(&in_range_receipt, Some(&establishment))?;
    let out_of_range = receiptor.sign(&event.bytes, 9)?;
    let out_of_range_receipt = TransferableEndorsement {
        sigs: &[receiptor.sign(&event.bytes, 0)?, out_of_range],
        ..in_range_receipt
    };
    assert!(matches!(
        accepted.endorsed_by(&out_of_range_receipt, Some(&establishment)),
        Err(keri::ReceiptError::EndorsementIndexOutOfRange { index: 9, count: 1 })
    ));
    Ok(())
}

#[test]
fn duplicate_backer_receipts_have_bounded_allocations() -> Fallible<()> {
    let (controller, next, backer, impostor) = (Key::new()?, Key::new()?, Key::new()?, Key::new()?);
    let event = genesis(&controller, &next)?;
    let issuer_state = seed(&event, &controller)?;
    let nonce: Noncer<'static> = MatterBuilder::new()
        .with_code(NoncerCode::Salt128)
        .with_raw(std::borrow::Cow::Owned(vec![0x23; 16]))?
        .build()?;
    let serialized = RegistryInceptionBuilder::new(event.prefix.clone(), nonce)
        .backers(vec![prefix_of(&backer)], 1)
        .build()?;
    let bytes = serialized.as_bytes().to_vec();
    let vcp = TelEvent::deserialize(&bytes, keri_codec::JsonLimits::new(4096, 64))?.into_static();
    let anchor = interaction_anchoring(
        &event,
        1,
        vec![Seal::Event {
            i: Identifier::SelfAddressing(serialized.said().clone().into_static()),
            s: vcp.sn(),
            d: serialized.said().clone().into_static(),
        }],
    )?;
    let base = SignedTel::from_host_asserted_parts(&vcp, &bytes, vec![])
        .with_source(TelAnchorCoordinate::new(
            Number::new(1),
            anchor.said.clone(),
        ))
        .with_host_accepted_anchor(&anchor.parsed);
    let forged = impostor.sign(&bytes, 0)?;
    let valid = backer.sign(&bytes, 0)?;
    RegistryState::incept(
        &base.clone().with_backer_sigs(vec![forged, valid.clone()]),
        &issuer_state,
    )?;
    let owned_backers = vec![valid; 256];
    let original_storage = owned_backers.as_ptr();
    let repeated = base.with_backer_sigs(owned_backers);
    assert_eq!(repeated.backer_sigs().as_ptr(), original_storage);
    let (result, allocations, allocated_bytes, _) =
        measure(|| RegistryState::incept(black_box(&repeated), black_box(&issuer_state)));
    result?;
    assert!(allocations <= 10, "{allocations} backer allocations");
    assert!(allocated_bytes <= 1024, "{allocated_bytes} backer bytes");
    Ok(())
}

thread_local! {
    static ALLOCS: Cell<usize> = const { Cell::new(0) };
    static BYTES: Cell<usize> = const { Cell::new(0) };
    static LIVE_BYTES: Cell<usize> = const { Cell::new(0) };
}

struct Counting;

#[allow(unsafe_code, reason = "test-only allocation instrumentation")]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCS.try_with(|cell| cell.set(cell.get() + 1));
        let _ = BYTES.try_with(|cell| cell.set(cell.get() + layout.size()));
        let _ = LIVE_BYTES.try_with(|cell| cell.set(cell.get() + layout.size()));
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let _ = LIVE_BYTES.try_with(|cell| cell.set(cell.get().saturating_sub(layout.size())));
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let _ = ALLOCS.try_with(|cell| cell.set(cell.get() + 1));
        let _ = BYTES.try_with(|cell| cell.set(cell.get() + size));
        let _ =
            LIVE_BYTES.try_with(|cell| cell.set(cell.get().saturating_sub(layout.size()) + size));
        unsafe { System.realloc(ptr, layout, size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn measure<T>(f: impl FnOnce() -> T) -> (T, usize, usize, u128) {
    let allocs = ALLOCS.with(Cell::get);
    let bytes = BYTES.with(Cell::get);
    let start = Instant::now();
    let result = f();
    (
        result,
        ALLOCS.with(Cell::get) - allocs,
        BYTES.with(Cell::get) - bytes,
        start.elapsed().as_micros(),
    )
}

fn measure_ns<T>(f: impl FnOnce() -> T) -> (T, usize, usize, u128) {
    let allocs = ALLOCS.with(Cell::get);
    let bytes = BYTES.with(Cell::get);
    let start = Instant::now();
    let result = f();
    (
        result,
        ALLOCS.with(Cell::get) - allocs,
        BYTES.with(Cell::get) - bytes,
        start.elapsed().as_nanos(),
    )
}

#[test]
#[ignore = "run explicitly in release mode for A10 before/after measurements"]
#[allow(
    clippy::too_many_lines,
    clippy::shadow_unrelated,
    clippy::shadow_reuse,
    reason = "release-only matrix repeats the same measurement shape across four public judgments"
)]
fn authentication_paths() -> Fallible<()> {
    let (controller, next, witness, receiptor) =
        (Key::new()?, Key::new()?, Key::witness()?, Key::new()?);
    let event = genesis(&controller, &next)?;
    let body = event.bytes.as_slice();
    let controller_key = [controller.verfer.clone()];
    let receipt_key = [receiptor.verfer.clone()];
    let witnesses = [nontransferable_prefix_of(&witness)?];
    let threshold = SigningThreshold::Simple(1);
    let authority = Authority::new(&controller_key, &threshold);
    let witnessing = Witnessing::new(&witnesses, Toad::exact(1, 1)?);
    let receipted = ReceiptedEvent {
        prefix: &event.prefix,
        sn: event.parsed.sn(),
        said: &event.said,
        signed_bytes: body,
    };
    let receiptor_establishment = ReceiptorEstablishment {
        said: &event.said,
        keys: &receipt_key,
    };
    let controller_sig = controller.sign(body, 0)?;
    let witness_sig = witness.sign(body, 0)?;
    let receipt_sig = receiptor.sign(body, 0)?;

    let backer = Key::new()?;
    let issuer_state = seed(&event, &controller)?;
    let nonce: Noncer<'static> = MatterBuilder::new()
        .with_code(NoncerCode::Salt128)
        .with_raw(std::borrow::Cow::Owned(vec![0x22; 16]))?
        .build()?;
    let serialized_vcp = RegistryInceptionBuilder::new(event.prefix.clone(), nonce)
        .backers(vec![prefix_of(&backer)], 1)
        .build()?;
    let vcp_bytes = serialized_vcp.as_bytes().to_vec();
    let vcp =
        TelEvent::deserialize(&vcp_bytes, keri_codec::JsonLimits::new(4096, 64))?.into_static();
    let anchor = interaction_anchoring(
        &event,
        1,
        vec![Seal::Event {
            i: Identifier::SelfAddressing(serialized_vcp.said().clone().into_static()),
            s: vcp.sn(),
            d: serialized_vcp.said().clone().into_static(),
        }],
    )?;
    let backer_sig = backer.sign(&vcp_bytes, 0)?;

    let mut wire = body.to_vec();
    wire.extend_from_slice(b"-AAB");
    wire.extend_from_slice(controller_sig.to_qb64().as_bytes());
    let (message, rest) = EventMessage::parse(&wire, common::message_limits())?;
    assert!(rest.is_empty());
    let (signed, allocs, bytes, elapsed) = measure(|| Signed::from(black_box(&message)));
    assert_eq!(signed.sigs().len(), 1);
    println!("path=wire count=1 allocations={allocs} allocated_bytes={bytes} elapsed_us={elapsed}");

    for count in [1, 16, 64, 256] {
        let controllers = vec![controller_sig.clone(); count];
        let witness_sigs = vec![witness_sig.clone(); count];
        let receipt_sigs = vec![receipt_sig.clone(); count];
        let backer_sigs = vec![backer_sig.clone(); count];
        let endorsement = TransferableEndorsement {
            receiptor: &event.prefix,
            sn: event.parsed.sn(),
            said: &event.said,
            sigs: &receipt_sigs,
        };

        let (result, allocs, bytes, elapsed) =
            measure(|| authority.verify(black_box(body), black_box(&controllers)));
        assert_eq!(result?.sigs().len(), 1);
        println!(
            "path=controller count={count} allocations={allocs} allocated_bytes={bytes} elapsed_us={elapsed}"
        );

        let (result, allocs, bytes, elapsed) =
            measure(|| witnessing.receipted_by(black_box(body), black_box(&witness_sigs)));
        result?;
        println!(
            "path=witness count={count} allocations={allocs} allocated_bytes={bytes} elapsed_us={elapsed}"
        );

        let (result, allocs, bytes, elapsed) = measure(|| {
            receipted.endorsed_by(black_box(&endorsement), Some(&receiptor_establishment))
        });
        result?;
        println!(
            "path=receipt count={count} allocations={allocs} allocated_bytes={bytes} elapsed_us={elapsed}"
        );

        let signed_tel = SignedTel::from_host_asserted_parts(&vcp, &vcp_bytes, Vec::new())
            .with_source(TelAnchorCoordinate::new(
                Number::new(1),
                anchor.said.clone(),
            ))
            .with_host_accepted_anchor(&anchor.parsed)
            .with_backer_sigs(backer_sigs);
        let (result, allocs, bytes, elapsed) =
            measure(|| RegistryState::incept(black_box(&signed_tel), black_box(&issuer_state)));
        result?;
        println!(
            "path=backer count={count} allocations={allocs} allocated_bytes={bytes} elapsed_us={elapsed}"
        );
    }
    Ok(())
}

fn issue_fixture(
    prior: &common::Event,
    anchor_sn: u128,
    registry: &Said<'static>,
    credential: &Said<'static>,
) -> Fallible<(TelEvent<'static>, Vec<u8>, common::Event)> {
    let serialized = IssueBuilder::new(
        credential.clone(),
        registry.clone(),
        "2026-09-29T00:00:00+00:00",
    )
    .build()?;
    let bytes = serialized.as_bytes().to_vec();
    let event = TelEvent::deserialize(&bytes, keri_codec::JsonLimits::new(4096, 64))?.into_static();
    let anchor = interaction_anchoring(
        prior,
        anchor_sn,
        vec![Seal::Event {
            i: Identifier::SelfAddressing(credential.clone()),
            s: event.sn(),
            d: serialized.said().clone().into_static(),
        }],
    )?;
    Ok((event, bytes, anchor))
}

#[test]
#[ignore = "run explicitly in release mode for A11 KEL snapshot retry allocations"]
fn kel_snapshot_retry_allocations() -> Fallible<()> {
    let (issuer, next) = (Key::new()?, Key::new()?);
    let icp = genesis(&issuer, &next)?;
    let KeriEvent::Inception(inception) = &icp.parsed else {
        return Err("genesis fixture was not an inception".into());
    };
    let snapshot = KeyStateSnapshot::genesis(inception);
    let ixn = interaction(&icp, 1)?;
    let (view, view_allocs, view_bytes, view_elapsed) = measure(|| snapshot.view());
    assert_eq!(view.sn().value(), 0);
    println!(
        "path=a11_snapshot_view allocations={view_allocs} allocated_bytes={view_bytes} elapsed_us={view_elapsed}"
    );
    let (result, reject_allocs, reject_bytes, reject_elapsed) =
        measure(|| view.ingest(&ixn.signed(vec![])));
    assert!(result.is_err());
    println!(
        "path=a11_snapshot_reject allocations={reject_allocs} allocated_bytes={reject_bytes} elapsed_us={reject_elapsed}"
    );
    let mut working = snapshot.view();
    let signed_ixn = ixn.signed(vec![issuer.sign(&ixn.bytes, 0)?]);
    let (accepted, accept_allocs, accept_bytes, accept_elapsed) =
        measure(|| working.ingest_mut(&signed_ixn));
    accepted?;
    assert_eq!(working.sn().value(), 1);
    println!(
        "path=a11_snapshot_accept allocations={accept_allocs} allocated_bytes={accept_bytes} elapsed_us={accept_elapsed}"
    );
    Ok(())
}

#[test]
#[ignore = "run explicitly in release mode for A12 registry cardinality measurements"]
#[allow(
    clippy::too_many_lines,
    reason = "release-only cardinality experiment with bounded fixture indexes"
)]
fn registry_cardinality_after() -> Fallible<()> {
    use std::collections::HashMap;

    let (issuer, next) = (Key::new()?, Key::new()?);
    let icp = genesis(&issuer, &next)?;
    let issuer_state = seed(&icp, &issuer)?;
    let nonce: Noncer<'static> = MatterBuilder::new()
        .with_code(NoncerCode::Salt128)
        .with_raw(std::borrow::Cow::Owned(vec![0x55; 16]))?
        .build()?;
    let serialized_vcp = RegistryInceptionBuilder::new(icp.prefix.clone(), nonce)
        .config(vec![ConfigTrait::NoBackers])
        .build()?;
    let vcp_bytes = serialized_vcp.as_bytes().to_vec();
    let vcp =
        TelEvent::deserialize(&vcp_bytes, keri_codec::JsonLimits::new(4096, 64))?.into_static();
    let vcp_anchor = interaction_anchoring(
        &icp,
        1,
        vec![Seal::Event {
            i: Identifier::SelfAddressing(serialized_vcp.said().clone().into_static()),
            s: vcp.sn(),
            d: serialized_vcp.said().clone().into_static(),
        }],
    )?;
    let signed_vcp = SignedTel::from_host_asserted_parts(&vcp, &vcp_bytes, Vec::new())
        .with_source(TelAnchorCoordinate::new(
            Number::new(1),
            vcp_anchor.said.clone(),
        ))
        .with_host_accepted_anchor(&vcp_anchor.parsed);
    let registry_said = serialized_vcp.said().clone().into_static();

    let mut prepared = Vec::with_capacity(1025);
    for index in 0..1025_u128 {
        let credential = Said::from_matter(digest(DigestCode::Blake3_256, &index.to_be_bytes())?);
        let prior_anchor = prepared.last().map_or(
            &vcp_anchor,
            |(_, _, _, anchor, _): &(_, _, _, common::Event, _)| anchor,
        );
        let (event, bytes, anchor) =
            issue_fixture(prior_anchor, index + 2, &registry_said, &credential)?;
        let key = credential.to_qb64();
        prepared.push((credential, event, bytes, anchor, key));
    }
    let evidence = TelEvidence::Issuer {
        state: &issuer_state,
        anchor: None,
    };
    let registry = RegistryState::incept(&signed_vcp, &issuer_state)?;
    let mut stored: HashMap<String, keri::CredentialState> = HashMap::new();
    let baseline_live = LIVE_BYTES.with(Cell::get);
    let mut issue_core_ns = 0_u128;
    let mut issue_host_ns = 0_u128;
    let mut issue_core_allocs = 0_usize;
    let mut issue_core_bytes = 0_usize;
    let mut issue_host_allocs = 0_usize;
    let mut issue_host_bytes = 0_usize;
    for (index, (credential, event, bytes, anchor, key)) in prepared.iter().take(1024).enumerate() {
        let signed = SignedTel::from_host_asserted_parts(event, bytes, Vec::new())
            .with_source(TelAnchorCoordinate::new(
                Number::new(u128::try_from(index)? + 2),
                anchor.said.clone(),
            ))
            .with_host_accepted_anchor(&anchor.parsed);
        let (candidate, core_allocs, core_bytes, core_elapsed) = measure_ns(|| {
            keri::CredentialState::incept(
                black_box(&registry),
                black_box(&signed),
                black_box(&evidence),
            )
        });
        let head = candidate?;
        issue_core_ns += core_elapsed;
        issue_core_allocs += core_allocs;
        issue_core_bytes += core_bytes;
        let (prior, host_allocs, host_bytes, host_elapsed) =
            measure_ns(|| stored.insert(key.clone(), head));
        assert!(prior.is_none());
        issue_host_ns += host_elapsed;
        issue_host_allocs += host_allocs;
        issue_host_bytes += host_bytes;
        let count = index + 1;
        if [16, 64, 256, 1024].contains(&count) {
            let ((), lookup_allocs, lookup_bytes, lookup_ns) = measure_ns(|| {
                for probe in 0..10_000_usize {
                    let selected = (probe * 7919) % count;
                    let stored_head = stored.get(black_box(&prepared[selected].4));
                    assert_eq!(
                        stored_head.map(keri::CredentialState::status),
                        Some(keri::CredentialStatus::Issued)
                    );
                }
            });
            let (replayed, replay_allocs, replay_bytes, replay_ns) =
                measure_ns(|| stored.contains_key(black_box(key)));
            assert!(replayed);
            let (_, next_event, next_bytes, next_anchor, _) = &prepared[count];
            let missing = SignedTel::from_host_asserted_parts(next_event, next_bytes, Vec::new())
                .with_source(TelAnchorCoordinate::new(
                    Number::new(u128::try_from(count)? + 2),
                    next_anchor.said.clone(),
                ));
            let (rejected, reject_allocs, reject_bytes, reject_ns) =
                measure_ns(|| keri::CredentialState::incept(&registry, &missing, &evidence));
            assert!(matches!(
                rejected,
                Err(keri::RegistryRejection::MissingAnchor)
            ));
            assert_eq!(
                stored.get(key).map(keri::CredentialState::credential),
                Some(credential)
            );
            let retained_delta = LIVE_BYTES.with(Cell::get).saturating_sub(baseline_live);
            println!(
                "path=a12_after count={count} issue_core_ns={issue_core_ns} issue_host_ns={issue_host_ns} issue_core_allocs={issue_core_allocs} issue_core_bytes={issue_core_bytes} issue_host_allocs={issue_host_allocs} issue_host_bytes={issue_host_bytes} retained_delta={retained_delta} lookup_10000_ns={lookup_ns} lookup_allocs={lookup_allocs} lookup_bytes={lookup_bytes} replay_ns={replay_ns} replay_allocs={replay_allocs} replay_bytes={replay_bytes} reject_ns={reject_ns} reject_allocs={reject_allocs} reject_bytes={reject_bytes}"
            );
        }
    }
    Ok(())
}
