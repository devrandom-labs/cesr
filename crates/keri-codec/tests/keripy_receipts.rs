//! keripy differential vectors for the K5 (#91) receipt judgments.
//!
//! Replays the checked-in, **keripy-generated** receipt corpus
//! (`corpus/keripy/parity/receipts.jsonl` — see `scripts/keripy_receipts_gen.py`;
//! oracle main `9161a705`, `Kevery.processReceipt` eventing.py:4481) through
//! the `keri` receipt judgments: every framed vector's receipts are judged
//! against the accepted event they endorse, every wig verifies against the
//! witness its index selects, every couple verifies and promotes into the
//! governing witness set (the corpus couple receiptor IS `witnesses[0]`,
//! keripy's couple-to-wig promotion at eventing.py:4553-4557), and every
//! transferable group verifies against its endorser's establishment
//! evidence. Body rows exercise the stale check against a mismatched
//! coordinate.
//!
//! The corpus is embedded via `include_str!` because the nix gate builds and
//! runs tests in separate hermetic phases, so a runtime `CARGO_MANIFEST_DIR`
//! path is unreliable. `ReceiptVector` is a local mirror of the parity
//! harness's private loader type (`src/keripy_parity/mod.rs`) — deliberately
//! test-only, per the K5 plan.
#![allow(
    clippy::expect_used,
    reason = "test-only corpus harness: a malformed vector fails the test with context"
)]

use keri::{
    Disposition, EvidenceKind, ReceiptError, ReceiptedEvent, ReceiptorEstablishment,
    TransferableEndorsement, WitnessIndex, Witnessing,
};
use keri_codec::{Deserialize as _, ReceiptMessage, TransferableReceipt};
use keri_events::{BasicPrefix, Identifier, Receipt, Said, Toad, VerifyingKey};

use cesr::core::matter::Matter;
use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::{DigestCode, MatterCode, VerKeyCode};
use cesr::core::primitives::Number;
use cesr::crypto::verify;

const CORPUS: &str = include_str!("corpus/keripy/parity/receipts.jsonl");

#[derive(Debug, serde::Deserialize)]
struct ReceiptCounts {
    couples: usize,
    wigs: usize,
    trans: usize,
}

#[derive(Debug, serde::Deserialize)]
struct ReceiptVector {
    kind: String,
    case: String,
    pre: String,
    sn: String,
    said: String,
    #[serde(default)]
    raw: Option<String>,
    #[serde(default)]
    event_raw: Option<String>,
    #[serde(default)]
    witnesses: Vec<String>,
    #[serde(default)]
    endorser_pre: Option<String>,
    #[serde(default)]
    endorser_sn: Option<String>,
    #[serde(default)]
    endorser_said: Option<String>,
    #[serde(default)]
    endorser_key: Option<String>,
    #[serde(default)]
    counts: Option<ReceiptCounts>,
    #[serde(default)]
    stream: Option<String>,
}

fn load_receipts() -> Vec<ReceiptVector> {
    CORPUS
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("corpus line must parse"))
        .collect()
}

fn matter_from_qb64(qb64: &str) -> Matter<'static, MatterCode> {
    MatterBuilder::new()
        .from_qualified_base64(qb64.as_bytes())
        .expect("corpus qb64 must parse")
        .into_static()
}

fn identifier_from_qb64(qb64: &str) -> Identifier<'static> {
    let matter = matter_from_qb64(qb64);
    if let Ok(key) = matter.clone().narrow::<VerKeyCode>() {
        return Identifier::Basic(BasicPrefix::from_matter(key));
    }
    matter
        .narrow::<DigestCode>()
        .map(|digest| Identifier::SelfAddressing(Said::from_matter(digest)))
        .expect("corpus prefix must be a verkey or digest")
}

fn said_from_qb64(qb64: &str) -> Said<'static> {
    Said::from_matter(
        matter_from_qb64(qb64)
            .narrow::<DigestCode>()
            .expect("corpus said must be a digest"),
    )
}

fn verkey_from_qb64(qb64: &str) -> Matter<'static, VerKeyCode> {
    matter_from_qb64(qb64)
        .narrow::<VerKeyCode>()
        .expect("corpus key must be a verkey")
}

fn identifier_qb64(identifier: &Identifier<'_>) -> String {
    match identifier {
        Identifier::Basic(p) => p.to_qb64(),
        Identifier::SelfAddressing(s) => s.to_qb64(),
    }
}

fn sn_value(hex: &str) -> u128 {
    u128::from_str_radix(hex, 16).expect("corpus sn must be hex")
}

/// Framed rows: every endorsement family judged against the accepted event.
#[test]
fn framed_receipts_judge_against_the_accepted_event() {
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
        check_framed_vector(v);
    }
}

fn check_framed_vector(v: &ReceiptVector) {
    let stream = v.stream.as_ref().expect("framed rows carry stream");
    let event_raw = v
        .event_raw
        .as_ref()
        .expect("framed rows carry event_raw")
        .as_bytes();
    let counts = v.counts.as_ref().expect("framed rows carry counts");

    let (message, rest) =
        ReceiptMessage::parse(stream.as_bytes()).expect("corpus stream must parse");
    assert!(rest.is_empty(), "case {}: unconsumed remainder", v.case);
    assert_eq!(message.couples().len(), counts.couples, "case {}", v.case);
    assert_eq!(message.wigs().len(), counts.wigs, "case {}", v.case);
    assert_eq!(
        message.trans_receipts().len(),
        counts.trans,
        "case {}",
        v.case
    );

    // The accepted event every receipt in this stream endorses.
    let prefix = identifier_from_qb64(&v.pre);
    let said = said_from_qb64(&v.said);
    let event = ReceiptedEvent {
        prefix: &prefix,
        sn: Number::new(sn_value(&v.sn)),
        said: &said,
        signed_bytes: event_raw,
    };
    event
        .named_by(message.receipt())
        .expect("corpus receipt names its event");

    // The governing witness set keripy signed the receipts under.
    let witnesses: Vec<BasicPrefix<'static>> = v
        .witnesses
        .iter()
        .map(|w| BasicPrefix::from_matter(verkey_from_qb64(w)))
        .collect();
    check_wigs(v, &message, event_raw, &witnesses);
    check_couples(v, &message, event_raw, &witnesses);
    for trans in message.trans_receipts() {
        check_trans_endorsement(v, trans, &event, &said);
    }
}

/// Wigs: each verifies, the recovered positions are keripy's 0..n, and an
/// exact toad is satisfied while n+1 reports the shortfall.
fn check_wigs(
    v: &ReceiptVector,
    message: &ReceiptMessage<'_>,
    event_raw: &[u8],
    witnesses: &[BasicPrefix<'static>],
) {
    let counts = v.counts.as_ref().expect("framed rows carry counts");
    let wig_count = u32::try_from(message.wigs().len()).expect("wig count fits u32");
    let witnessing = Witnessing::new(witnesses, Toad::from_wire(wig_count));
    let indices: Vec<WitnessIndex> = message
        .wigs()
        .iter()
        .map(|wig| {
            witnessing
                .receipt(event_raw, wig)
                .expect("corpus wig must verify")
        })
        .collect();
    let recovered: Vec<u32> = indices.iter().map(|i| i.value()).collect();
    let expected: Vec<u32> = (0..wig_count).collect();
    assert_eq!(recovered, expected, "case {}", v.case);
    witnessing
        .accounted_by(indices.iter().copied())
        .expect("exact toad must be satisfied");
    let over = Witnessing::new(witnesses, Toad::from_wire(wig_count + 1));
    assert!(
        matches!(
            over.accounted_by(indices.iter().copied()),
            Err(ReceiptError::InsufficientReceipts { valid, required })
                if valid == counts.wigs && required == wig_count + 1
        ),
        "case {}",
        v.case
    );
}

/// Couples: the endorsement verifies with the prefix as key, and the
/// corpus couple receiptor IS witnesses[0], so it promotes at index 0
/// (keripy eventing.py:4553-4557).
fn check_couples(
    v: &ReceiptVector,
    message: &ReceiptMessage<'_>,
    event_raw: &[u8],
    witnesses: &[BasicPrefix<'static>],
) {
    let witnessing = Witnessing::new(witnesses, Toad::from_wire(0));
    for couple in message.couples() {
        verify(
            couple.receiptor().as_matter(),
            event_raw,
            couple.signature(),
        )
        .expect("corpus couple must verify");
        assert_eq!(
            witnessing
                .witness_index(couple.receiptor())
                .map(WitnessIndex::value),
            Some(0),
            "case {}",
            v.case
        );
    }
}

/// One transferable endorsement: keripy's establishment coordinate,
/// verified against the endorser's key; escrow and mismatch arms included.
fn check_trans_endorsement(
    v: &ReceiptVector,
    trans: &TransferableReceipt<'_>,
    event: &ReceiptedEvent<'_>,
    said: &Said<'_>,
) {
    assert_eq!(
        identifier_qb64(trans.receiptor()),
        *v.endorser_pre
            .as_ref()
            .expect("trans rows carry endorser_pre"),
        "case {}",
        v.case
    );
    assert_eq!(
        trans.sn().value(),
        sn_value(
            v.endorser_sn
                .as_ref()
                .expect("trans rows carry endorser_sn")
        ),
        "case {}",
        v.case
    );
    let endorser_said = said_from_qb64(
        v.endorser_said
            .as_ref()
            .expect("trans rows carry endorser_said"),
    );
    assert_eq!(
        trans.said().to_qb64(),
        endorser_said.to_qb64(),
        "case {}",
        v.case
    );
    let endorser_key = VerifyingKey::from_matter(verkey_from_qb64(
        v.endorser_key
            .as_ref()
            .expect("trans rows carry endorser_key"),
    ));
    let endorsement = TransferableEndorsement::from(trans);
    let evidence = ReceiptorEstablishment {
        said: &endorser_said,
        keys: core::slice::from_ref(&endorser_key),
    };
    event
        .endorsed_by(&endorsement, Some(&evidence))
        .expect("corpus endorsement must verify");

    let err = event
        .endorsed_by(&endorsement, None)
        .expect_err("missing evidence must not verify");
    assert!(
        matches!(err, ReceiptError::EvidenceRequired),
        "case {}",
        v.case
    );
    assert_eq!(
        err.disposition(),
        Disposition::Awaiting(EvidenceKind::ReceiptorEstablishment),
        "case {}",
        v.case
    );

    // Wrong-said evidence (the receipted event's SAID, not the
    // establishment's) is a keripy ValidationError — terminal.
    let wrong = ReceiptorEstablishment {
        said,
        keys: core::slice::from_ref(&endorser_key),
    };
    assert!(
        matches!(
            event.endorsed_by(&endorsement, Some(&wrong)),
            Err(ReceiptError::EstablishmentMismatch)
        ),
        "case {}",
        v.case
    );
}

/// Body rows: the stale check catches a coordinate mismatch.
#[test]
fn body_receipts_fail_the_stale_check_against_a_different_sn() {
    let vectors: Vec<ReceiptVector> = load_receipts()
        .into_iter()
        .filter(|v| v.kind == "body")
        .collect();
    assert_eq!(vectors.len(), 5, "body corpus shrank or grew unexpectedly");
    for v in &vectors {
        let raw = v.raw.as_ref().expect("body rows carry raw");
        let receipt = Receipt::deserialize(raw.as_bytes()).expect("corpus body must parse");
        assert_eq!(identifier_qb64(receipt.prefix()), v.pre, "case {}", v.case);
        let prefix = identifier_from_qb64(&v.pre);
        let said = said_from_qb64(&v.said);
        let event = ReceiptedEvent {
            prefix: &prefix,
            sn: Number::new(sn_value(&v.sn) + 1),
            said: &said,
            signed_bytes: b"body rows carry no event bytes",
        };
        assert!(
            matches!(event.named_by(&receipt), Err(ReceiptError::Stale { .. })),
            "case {}",
            v.case
        );
    }
}
