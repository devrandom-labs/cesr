//! A14: pinned keripy `messagize` bytes through the sans-I/O framer and
//! the public typed read path, preserving exact signed body spans.
#![cfg(feature = "std")]

use std::error::Error;

use cesr_stream::{FrameLimits, MessageFramer};
use keri_codec::{
    CodecError, Deserialize, DeserializeError, EventMessage, EventMessageError, Exn, JsonLimits,
    Message, MessageError, MessageLimits,
};
use keri_events::{Acdc, KeriEvent, Receipt, TelEvent};

const KEL: &[u8] = include_bytes!("fixtures/keripy_kel_signed.cesr");
// Pinned V1 keripy fixture: icp, rot, ixn, each followed by a complete -V
// attachment envelope. These lengths are derived from the independent fixture
// generator's version-string sizes and -V quadlet counters.
const FRAME_LENGTHS: [usize; 3] = [577, 630, 387];
const BODY_LENGTHS: [usize; 3] = [393, 446, 203];

type Fallible<T> = Result<T, Box<dyn Error>>;

const fn limits() -> FrameLimits {
    FrameLimits {
        max_body_bytes: 1024,
        max_attachment_bytes: 1024,
        max_attachment_groups: 8,
        max_group_elements: 8,
        max_signatures: 8,
        max_nested_groups: 8,
        max_nesting_depth: 2,
    }
}

const fn message_limits() -> MessageLimits {
    MessageLimits::new(limits(), JsonLimits::new(64, 16))
}

fn drain_ready(
    framer: &mut MessageFramer,
    buffer: &mut Vec<u8>,
    lengths: &mut Vec<usize>,
    eof: bool,
) -> Fallible<()> {
    while let Some(span) = framer.advance(buffer, eof)? {
        assert!(span.total_len > 0, "every emitted frame makes progress");
        assert!(span.total_len <= buffer.len());
        let frame: Vec<u8> = buffer.drain(..span.total_len).collect();
        let (message, rest) = EventMessage::parse(&frame, message_limits())?;
        assert!(rest.is_empty(), "framer must not include the next message");
        assert_eq!(message.body(), &frame[..span.body_len.unwrap_or(0)]);
        lengths.push(frame.len());
    }
    Ok(())
}

#[test]
fn keripy_v1_kel_matches_at_every_two_chunk_split() -> Fallible<()> {
    assert_eq!(FRAME_LENGTHS.iter().sum::<usize>(), KEL.len());
    for split in 0..=KEL.len() {
        let mut framer = MessageFramer::new(limits());
        let mut buffer = KEL[..split].to_vec();
        let mut lengths = Vec::new();
        drain_ready(&mut framer, &mut buffer, &mut lengths, false)?;
        buffer.extend_from_slice(&KEL[split..]);
        drain_ready(&mut framer, &mut buffer, &mut lengths, true)?;
        assert!(buffer.is_empty(), "unconsumed bytes at split {split}");
        assert_eq!(lengths, FRAME_LENGTHS, "frame boundaries at split {split}");
    }
    Ok(())
}

#[test]
fn keripy_v1_kel_matches_under_bytewise_delivery() -> Fallible<()> {
    let mut framer = MessageFramer::new(limits());
    let mut buffer = Vec::new();
    let mut lengths = Vec::new();
    let mut bodies = Vec::new();
    for byte in KEL {
        buffer.push(*byte);
        if let Some(span) = framer.advance(&buffer, false)? {
            bodies.push(span.body_len.unwrap_or(0));
            let frame: Vec<u8> = buffer.drain(..span.total_len).collect();
            let (message, rest) = EventMessage::parse(&frame, message_limits())?;
            assert!(rest.is_empty());
            assert_eq!(message.body(), &frame[..span.body_len.unwrap_or(0)]);
            lengths.push(frame.len());
        }
    }
    drain_ready(&mut framer, &mut buffer, &mut lengths, true)?;
    assert!(buffer.is_empty());
    assert_eq!(lengths, FRAME_LENGTHS);
    assert_eq!(bodies, BODY_LENGTHS);
    Ok(())
}

#[test]
fn public_typed_kel_reader_rejects_field_and_depth_excess() {
    let body = &KEL[..BODY_LENGTHS[0]];
    let fields = KeriEvent::deserialize(body, JsonLimits::new(1, 64));
    assert!(matches!(
        fields,
        Err(CodecError::Deserialize(DeserializeError::JsonFieldLimit {
            limit: 1,
            ..
        }))
    ));
    let depth = KeriEvent::deserialize(body, JsonLimits::new(64, 1));
    assert!(matches!(
        depth,
        Err(CodecError::Deserialize(DeserializeError::JsonDepthLimit {
            limit: 1,
            ..
        }))
    ));
}

#[test]
fn public_message_reader_applies_both_frame_and_json_policy() {
    let frame = &KEL[..FRAME_LENGTHS[0]];
    let json_tight = MessageLimits::new(limits(), JsonLimits::new(1, 64));
    assert!(matches!(
        EventMessage::parse(frame, json_tight),
        Err(EventMessageError::Body(CodecError::Deserialize(
            DeserializeError::JsonFieldLimit { limit: 1, .. }
        )))
    ));
    assert!(matches!(
        Message::parse(frame, json_tight),
        Err(MessageError::Body(CodecError::Deserialize(
            DeserializeError::JsonFieldLimit { limit: 1, .. }
        )))
    ));
    let mut frame_policy = limits();
    frame_policy.max_body_bytes = BODY_LENGTHS[0] - 1;
    let tight_limits = MessageLimits::new(frame_policy, JsonLimits::new(64, 16));
    assert!(matches!(
        EventMessage::parse(frame, tight_limits),
        Err(EventMessageError::Frame(
            cesr_stream::ParseError::LimitExceeded {
                kind: cesr_stream::LimitKind::BodyBytes,
                ..
            }
        ))
    ));
}

fn first_corpus_body(corpus: &str) -> Fallible<Vec<u8>> {
    let line = corpus.lines().next().ok_or("empty pinned corpus")?;
    let row: serde_json::Value = serde_json::from_str(line)?;
    Ok(row["raw"]
        .as_str()
        .ok_or("missing raw body")?
        .as_bytes()
        .to_vec())
}

fn corpus_field(corpus: &str, case: &str, field: &str) -> Fallible<Vec<u8>> {
    for line in corpus.lines() {
        let row: serde_json::Value = serde_json::from_str(line)?;
        if row["case"] == case {
            return Ok(row[field]
                .as_str()
                .ok_or("missing pinned corpus field")?
                .as_bytes()
                .to_vec());
        }
    }
    Err(format!("missing pinned corpus case {case}").into())
}

fn spans_at_split(wire: &[u8], split: usize) -> Fallible<Vec<(usize, Option<usize>)>> {
    let mut framer = MessageFramer::new(limits());
    let mut buffer = wire[..split].to_vec();
    let mut spans = Vec::new();
    for (fragment, eof) in [(&[][..], false), (&wire[split..], true)] {
        buffer.extend_from_slice(fragment);
        while let Some(span) = framer.advance(&buffer, eof)? {
            spans.push((span.total_len, span.body_len));
            buffer.drain(..span.total_len);
        }
    }
    assert!(buffer.is_empty(), "unconsumed bytes at split {split}");
    Ok(spans)
}

fn assert_one_frame_at_every_split(wire: &[u8], body_len: usize) -> Fallible<()> {
    for split in 0..=wire.len() {
        let spans = spans_at_split(wire, split)?;
        assert_eq!(spans, [(wire.len(), Some(body_len))], "split {split}");
    }
    Ok(())
}

#[test]
fn pinned_tel_receipt_exn_acdc_frames_match_at_every_split() -> Fallible<()> {
    let tel = first_corpus_body(include_str!("corpus/tel/happy.jsonl"))?;
    let exn = first_corpus_body(include_str!("corpus/ipex/happy.jsonl"))?;
    let acdc = first_corpus_body(include_str!("corpus/json_payload/acdc.jsonl"))?;
    let receipt = corpus_field(
        include_str!("corpus/keripy/parity/receipts.jsonl"),
        "framed_couples",
        "stream",
    )?;
    let receipt_body = first_corpus_body(include_str!("corpus/keripy/parity/receipts.jsonl"))?;
    for (wire, body_len) in [
        (&tel[..], tel.len()),
        (&exn[..], exn.len()),
        (&acdc[..], acdc.len()),
        (&receipt[..], receipt_body.len()),
    ] {
        assert_one_frame_at_every_split(wire, body_len)?;
    }
    let typed_limits = MessageLimits::new(limits(), JsonLimits::new(4096, 64));
    assert!(matches!(
        Message::parse(&tel, typed_limits)?,
        (Message::Tel(_), [])
    ));
    assert!(matches!(
        Message::parse(&exn, typed_limits)?,
        (Message::Exn(_), [])
    ));
    assert!(matches!(
        Message::parse(&receipt, typed_limits)?,
        (Message::Receipt(_), [])
    ));
    Acdc::deserialize(&acdc, typed_limits.json)?;
    Ok(())
}

#[test]
fn bare_kel_attachment_run_ends_at_next_body_for_every_split() -> Fallible<()> {
    let first_body = &KEL[..BODY_LENGTHS[0]];
    let envelope_start = BODY_LENGTHS[0];
    assert_eq!(&KEL[envelope_start..envelope_start + 2], b"-V");
    let bare_attachments = &KEL[envelope_start + 4..FRAME_LENGTHS[0]];
    let second_start = FRAME_LENGTHS[0];
    let second_body = &KEL[second_start..second_start + BODY_LENGTHS[1]];
    let bare_len = first_body.len() + bare_attachments.len();
    let mut wire = Vec::new();
    wire.extend_from_slice(first_body);
    wire.extend_from_slice(bare_attachments);
    wire.extend_from_slice(second_body);

    for split in 0..=wire.len() {
        let spans = spans_at_split(&wire, split)?;
        assert_eq!(
            spans,
            [
                (bare_len, Some(BODY_LENGTHS[0])),
                (BODY_LENGTHS[1], Some(BODY_LENGTHS[1]))
            ],
            "split {split}"
        );
    }

    let (first, rest) = EventMessage::parse(&wire, message_limits())?;
    assert_eq!(first.body(), first_body);
    assert_eq!(rest, second_body);
    let (second, final_remainder) = EventMessage::parse(rest, message_limits())?;
    assert_eq!(second.body(), second_body);
    assert!(final_remainder.is_empty());
    Ok(())
}

fn assert_field_limit<T: Deserialize>(body: &[u8]) {
    assert!(matches!(
        T::deserialize(body, JsonLimits::new(1, 64)),
        Err(CodecError::Deserialize(DeserializeError::JsonFieldLimit {
            limit: 1,
            ..
        }))
    ));
}

fn assert_depth_limit<T: Deserialize>(body: &[u8]) {
    assert!(matches!(
        T::deserialize(body, JsonLimits::new(4096, 1)),
        Err(CodecError::Deserialize(DeserializeError::JsonDepthLimit {
            limit: 1,
            ..
        }))
    ));
}

#[test]
fn pinned_tel_receipt_exn_acdc_bodies_obey_public_json_limits() -> Fallible<()> {
    let tel = first_corpus_body(include_str!("corpus/tel/happy.jsonl"))?;
    let receipt = first_corpus_body(include_str!("corpus/keripy/parity/receipts.jsonl"))?;
    let exn = first_corpus_body(include_str!("corpus/json_payload/happy.jsonl"))?;
    let acdc = first_corpus_body(include_str!("corpus/json_payload/acdc.jsonl"))?;
    let generous = JsonLimits::new(4096, 64);
    TelEvent::deserialize(&tel, generous)?;
    Receipt::deserialize(&receipt, generous)?;
    Exn::deserialize(&exn, generous)?;
    Acdc::deserialize(&acdc, generous)?;
    assert_field_limit::<TelEvent<'static>>(&tel);
    assert_field_limit::<Receipt<'static>>(&receipt);
    assert_field_limit::<Exn<'static>>(&exn);
    assert_field_limit::<Acdc<'static>>(&acdc);
    assert_depth_limit::<TelEvent<'static>>(&tel);
    assert_depth_limit::<Exn<'static>>(&exn);
    assert_depth_limit::<Acdc<'static>>(&acdc);
    Ok(())
}

#[test]
fn public_kel_reader_counts_opaque_anchor_members_and_nesting() -> Fallible<()> {
    let original = std::str::from_utf8(&KEL[..BODY_LENGTHS[0]])?;
    let mut body = original.replace("\"a\":[]", "\"a\":[{\"x\":0,\"y\":1,\"z\":2}]");
    assert_ne!(body, original);
    body.replace_range(16..22, &format!("{:06x}", body.len()));
    assert!(matches!(
        KeriEvent::deserialize(body.as_bytes(), JsonLimits::new(4096, 64)),
        Err(CodecError::Said(_))
    ));
    assert!(matches!(
        KeriEvent::deserialize(body.as_bytes(), JsonLimits::new(15, 64)),
        Err(CodecError::Deserialize(DeserializeError::InvalidAnchor {
            source: keri_codec::OpaqueScanError::FieldLimit { limit: 15, .. },
            ..
        }))
    ));

    let mut deep = original.replace("\"a\":[]", "\"a\":[{\"x\":[[0]]}]");
    assert_ne!(deep, original);
    deep.replace_range(16..22, &format!("{:06x}", deep.len()));
    assert!(matches!(
        KeriEvent::deserialize(deep.as_bytes(), JsonLimits::new(4096, 4)),
        Err(CodecError::Deserialize(DeserializeError::InvalidAnchor {
            source: keri_codec::OpaqueScanError::DepthLimit { limit: 4, .. },
            ..
        }))
    ));
    Ok(())
}
