//! #82 receipt (`rct`) differential: keripy-generated receipt bodies and
//! framed receipt messages replay through the typed pipeline.
//!
//! Body rows must (1) parse into keripy's exact `(pre, sn, said)` coordinate
//! and (2) re-serialize byte-identically. Framed rows (keripy `messagize`,
//! V1 with the `-V` counter) must parse, route every endorsement family to
//! keripy's counts, verify every signature over the receipted event's raw
//! bytes, and — for couple/wiger shapes, whose wire forms the domain types
//! retain — re-frame byte-identically. Transferable-group rows are not
//! re-framed: [`TransferableReceipt`](crate::TransferableReceipt) lifts the
//! seqner to an ordinal value and deliberately drops its wire code, so the
//! write mirror for `-F` is covered by the unit suite instead.

use std::string::String;
use std::vec::Vec;

use crate::message::ReceiptMessage;
use crate::traits::{Deserialize, Serialize};
use cesr::core::matter::Matter;
use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::{MatterCode, VerKeyCode};
use cesr::crypto::{verify, verify_indexed};
use cesr_stream::group::{NonTransReceiptCouples, WitnessIdxSigs};
use keri_events::{Identifier, Receipt};

use super::{ReceiptVector, load_receipts};

fn matter_from_qb64(qb64: &str) -> Matter<'static, MatterCode> {
    MatterBuilder::new()
        .from_qualified_base64(qb64.as_bytes())
        .unwrap_or_else(|e| panic!("corpus qb64 {qb64} must parse: {e}"))
        .into_static()
}

fn verfer_from_qb64(qb64: &str) -> Matter<'static, VerKeyCode> {
    matter_from_qb64(qb64)
        .narrow::<VerKeyCode>()
        .unwrap_or_else(|e| panic!("corpus prefix {qb64} must be a verkey: {e}"))
}

fn identifier_qb64(identifier: &Identifier<'_>) -> String {
    match identifier {
        Identifier::Basic(p) => p.to_qb64(),
        Identifier::SelfAddressing(s) => s.to_qb64(),
    }
}

fn sn_value(hex: &str) -> u128 {
    u128::from_str_radix(hex, 16).unwrap_or_else(|e| panic!("corpus sn {hex} must be hex: {e}"))
}

/// Body differential: every keripy `receipt()` body parses to the same
/// coordinate and re-serializes byte-for-byte.
#[test]
#[allow(
    clippy::panic,
    reason = "test-only sweep: an unreadable vector panics with case context"
)]
fn receipt_corpus_bodies_round_trip_byte_identically() {
    let vectors: Vec<ReceiptVector> = load_receipts()
        .into_iter()
        .filter(|v| v.kind == "body")
        .collect();
    assert_eq!(vectors.len(), 5, "body corpus shrank or grew unexpectedly");
    for v in &vectors {
        let raw = v.raw.as_ref().expect("body rows carry raw").as_bytes();
        let receipt = Receipt::deserialize(raw)
            .unwrap_or_else(|e| panic!("case {}: read failed: {e}", v.case));
        assert_eq!(identifier_qb64(receipt.prefix()), v.pre, "case {}", v.case);
        assert_eq!(receipt.sn().value(), sn_value(&v.sn), "case {}", v.case);
        assert_eq!(receipt.said().to_qb64(), v.said, "case {}", v.case);
        let reserialized = receipt
            .serialize()
            .unwrap_or_else(|e| panic!("case {}: write failed: {e}", v.case));
        assert_eq!(
            reserialized.as_bytes(),
            raw,
            "case {}: re-serialized bytes differ",
            v.case
        );
    }
}

/// Stream differential: every keripy `messagize` receipt stream parses,
/// routes to keripy's endorsement counts, and every signature verifies over
/// the receipted event's raw bytes.
#[test]
#[allow(
    clippy::panic,
    reason = "test-only sweep: an unreadable vector panics with case context"
)]
fn receipt_corpus_streams_parse_route_and_verify() {
    let vectors: Vec<ReceiptVector> = load_receipts()
        .into_iter()
        .filter(|v| v.kind == "framed")
        .collect();
    assert_eq!(
        vectors.len(),
        5,
        "framed corpus shrank or grew unexpectedly"
    );
    for v in &vectors {
        let stream = v.stream.as_ref().expect("framed rows carry stream");
        let event_raw = v
            .event_raw
            .as_ref()
            .expect("framed rows carry event_raw")
            .as_bytes();
        let counts = v.counts.as_ref().expect("framed rows carry counts");

        let (message, rest) = ReceiptMessage::parse(stream.as_bytes())
            .unwrap_or_else(|e| panic!("case {}: parse failed: {e}", v.case));
        assert!(rest.is_empty(), "case {}: unconsumed remainder", v.case);

        assert_eq!(
            identifier_qb64(message.receipt().prefix()),
            v.pre,
            "case {}",
            v.case
        );
        assert_eq!(
            message.receipt().sn().value(),
            sn_value(&v.sn),
            "case {}",
            v.case
        );
        assert_eq!(
            message.receipt().said().to_qb64(),
            v.said,
            "case {}",
            v.case
        );
        assert_eq!(message.couples().len(), counts.couples, "case {}", v.case);
        assert_eq!(message.wigs().len(), counts.wigs, "case {}", v.case);
        assert_eq!(
            message.trans_receipts().len(),
            counts.trans,
            "case {}",
            v.case
        );

        // The body span re-serializes byte-identically from the parsed data.
        let reserialized = message.receipt().serialize().unwrap();
        assert_eq!(reserialized.as_bytes(), message.body(), "case {}", v.case);

        // Couples verify over the receipted EVENT's bytes with the couple's
        // own prefix as the key (keripy processReceipt, eventing.py:4531).
        for couple in message.couples() {
            verify(
                couple.receiptor().as_matter(),
                event_raw,
                couple.signature(),
            )
            .unwrap_or_else(|e| panic!("case {}: couple failed to verify: {e}", v.case));
        }

        // Wigers verify indexed against the witness list keripy signed with.
        if !message.wigs().is_empty() {
            let witness_verfers: Vec<Matter<'static, VerKeyCode>> =
                v.witnesses.iter().map(|w| verfer_from_qb64(w)).collect();
            let indices: Vec<u32> = verify_indexed(&witness_verfers, event_raw, message.wigs())
                .collect::<Result<Vec<_>, _>>()
                .unwrap_or_else(|e| panic!("case {}: wig failed to verify: {e}", v.case));
            assert_eq!(indices.len(), counts.wigs, "case {}", v.case);
        }

        // Transferable groups carry keripy's establishment coordinate and
        // their nested sigs verify against the endorser's key.
        for endorsement in message.trans_receipts() {
            assert_eq!(
                identifier_qb64(endorsement.receiptor()),
                *v.endorser_pre
                    .as_ref()
                    .expect("trans rows carry endorser_pre"),
                "case {}",
                v.case
            );
            assert_eq!(
                endorsement.sn().value(),
                sn_value(
                    v.endorser_sn
                        .as_ref()
                        .expect("trans rows carry endorser_sn")
                ),
                "case {}",
                v.case
            );
            assert_eq!(
                endorsement.said().to_qb64(),
                *v.endorser_said
                    .as_ref()
                    .expect("trans rows carry endorser_said"),
                "case {}",
                v.case
            );
            let endorser_verfer = verfer_from_qb64(
                v.endorser_key
                    .as_ref()
                    .expect("trans rows carry endorser_key"),
            );
            let indices: Vec<u32> = verify_indexed(
                core::slice::from_ref(&endorser_verfer),
                event_raw,
                endorsement.signatures(),
            )
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|e| panic!("case {}: endorsement failed to verify: {e}", v.case));
            assert_eq!(indices, alloc::vec![0], "case {}", v.case);
        }
    }
}

/// Write-mirror differential: couple/wiger streams re-frame byte-identically
/// from the parsed domain data (the wire forms those types retain in full).
#[test]
#[allow(
    clippy::panic,
    reason = "test-only sweep: an unreadable vector panics with case context"
)]
fn receipt_corpus_couple_and_wiger_streams_reframe_byte_identically() {
    let vectors: Vec<ReceiptVector> = load_receipts()
        .into_iter()
        .filter(|v| v.kind == "framed" && v.counts.as_ref().is_some_and(|c| c.trans == 0))
        .collect();
    assert_eq!(
        vectors.len(),
        3,
        "couple/wiger corpus shrank or grew unexpectedly"
    );
    for v in &vectors {
        let stream = v.stream.as_ref().expect("framed rows carry stream");
        let (message, _) = ReceiptMessage::parse(stream.as_bytes()).unwrap();

        let couple_elements: Vec<_> = message
            .couples()
            .iter()
            .map(|c| (c.receiptor().as_matter().clone(), c.signature().clone()))
            .collect();
        let couples = NonTransReceiptCouples::from_couples(&couple_elements).unwrap();
        let wigs = WitnessIdxSigs::from_indexed_signatures(message.wigs()).unwrap();

        let reframed = message
            .receipt()
            .serialize()
            .unwrap()
            .frame_v1(
                None,
                Some(&wigs).filter(|w| w.count() > 0),
                Some(&couples).filter(|c| c.count() > 0),
            )
            .unwrap_or_else(|e| panic!("case {}: reframe failed: {e}", v.case));
        assert_eq!(
            reframed,
            stream.as_bytes(),
            "case {}: re-framed stream differs from keripy's",
            v.case
        );
    }
}
