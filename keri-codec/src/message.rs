//! The read spine: one framed key event message off the wire.
//!
//! [`EventMessage::parse`] is the crate's front door for wire bytes. It
//! composes the modules end to end — `stream` finds the frame
//! ([`CesrMessage::parse`](cesr_stream::CesrMessage::parse): cold-start detection +
//! version-string size), `serder` decodes the body
//! ([`KeriDeserialize`] for [`KeriEvent`]: strict
//! canonical JSON + SAID verification), and the attachment groups are
//! routed into typed indexed
//! signatures — returning the parsed event, the exact byte span its
//! signatures sign, and the unconsumed remainder so multi-message streams
//! parse in a loop. The write mirror is
//! [`SerializedEvent::frame_v1`](crate::SerializedEvent::frame_v1),
//! whose output round-trips through this parser byte-exactly.
//!
//! Attachment layouts (KERI/CESR V1, as keripy emits them):
//!
//! - **Framed** (`messagize` default): one `-V` attachment group whose
//!   quadlet count delimits the attachment region; the remainder starts
//!   exactly after it.
//! - **Bare**: top-level groups follow the body until the next cold-start
//!   transition (the next body byte, or end of input).
//!
//! A nested `-V` inside an attachment frame is rejected
//! ([`EventMessageError::UnexpectedGroup`]): keripy V1 never nests
//! attachment frames (nesting is a CESR v2 genus feature), and refusing it
//! keeps the walk iterative — no recursion over untrusted input.

use core::fmt;

use crate::error::{EventMessageError, SerderError};
use crate::traits::KeriDeserialize;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{vec, vec::Vec};
use cesr::core::primitives::Siger;
use cesr::keri::KeriEvent;
use cesr_stream::cold::ColdCode;
use cesr_stream::group::CesrGroup;
use cesr_stream::message::CesrMessage;

/// A key event message as received from the wire: the parsed event, the
/// exact byte span its signatures sign, and its attached indexed signatures.
///
/// Constructed only by [`EventMessage::parse`], so `body` is by construction
/// the span `event` was deserialized from — the provenance the downstream
/// fold (`keri_rs::Signed`) otherwise has to take on faith.
pub struct EventMessage<'a> {
    event: KeriEvent<'a>,
    body: &'a [u8],
    sigs: Vec<Siger<'a>>,
    wigs: Vec<Siger<'a>>,
}

impl fmt::Debug for EventMessage<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventMessage")
            .field("body_len", &self.body.len())
            .field("sigs", &self.sigs.len())
            .field("wigs", &self.wigs.len())
            .finish_non_exhaustive()
    }
}

impl<'a> EventMessage<'a> {
    /// Parse one framed key event message from the head of `input`,
    /// returning the message and the unconsumed remainder.
    ///
    /// The remainder is exactly the bytes after this message's attachments,
    /// so a concatenated stream parses by looping until the remainder is
    /// empty.
    ///
    /// # Errors
    ///
    /// Returns [`EventMessageError::Frame`] if the CESR framing or an
    /// attachment group is malformed or truncated,
    /// [`EventMessageError::Body`] if the body fails strict canonical
    /// deserialization or SAID verification,
    /// [`EventMessageError::BareAttachment`] if the input starts with a
    /// CESR group instead of an event body, or
    /// [`EventMessageError::UnexpectedGroup`] for an attachment group that
    /// cannot belong to a key event message.
    pub fn parse(input: &'a [u8]) -> Result<(Self, &'a [u8]), EventMessageError> {
        let CesrMessage::Event { payload, .. } = CesrMessage::parse(input)? else {
            return Err(EventMessageError::BareAttachment);
        };
        let event = KeriEvent::deserialize(payload)?;
        // `payload` is the head of `input` (`input[..size]` by the framer's
        // construction), so the attachment region starts at its length. The
        // `get` cannot miss; surfacing the impossible as a typed layout error
        // keeps this arithmetic-free and panic-free.
        let after_body = input.get(payload.len()..).ok_or(EventMessageError::Body(
            SerderError::InvalidEventLayout("event payload exceeds its own input"),
        ))?;
        let mut sigs = Vec::new();
        let mut wigs = Vec::new();
        let rest = consume_attachments(after_body, &mut sigs, &mut wigs)?;
        Ok((
            Self {
                event,
                body: payload,
                sigs,
                wigs,
            },
            rest,
        ))
    }

    /// The parsed key event.
    #[must_use]
    pub const fn event(&self) -> &KeriEvent<'a> {
        &self.event
    }

    /// The exact serialized span the attached signatures sign, borrowed from
    /// the input.
    #[must_use]
    pub const fn body(&self) -> &'a [u8] {
        self.body
    }

    /// Controller indexed signatures (`-A` `ControllerIdxSigs`).
    #[must_use]
    pub fn sigs(&self) -> &[Siger<'a>] {
        &self.sigs
    }

    /// Witness indexed signatures (`-B` `WitnessIdxSigs`).
    #[must_use]
    pub fn wigs(&self) -> &[Siger<'a>] {
        &self.wigs
    }
}

/// Route the attachment region following an event body into controller and
/// witness indexed signatures, returning the unconsumed remainder.
///
/// Consumes consecutive top-level CESR groups until the input ends or the
/// next byte is not a CESR cold start (i.e. the next message's body begins).
/// A top-level `-V` attachment frame delimits its own contents by quadlet
/// count; its inner groups are routed one level deep, keeping the walk
/// iterative.
fn consume_attachments<'i>(
    input: &'i [u8],
    sigs: &mut Vec<Siger<'static>>,
    wigs: &mut Vec<Siger<'static>>,
) -> Result<&'i [u8], EventMessageError> {
    let mut rest = input;
    while let Some(&first) = rest.first() {
        if !matches!(
            ColdCode::detect(first),
            Ok(ColdCode::CesrBase64 | ColdCode::CesrBinary)
        ) {
            break;
        }
        let (group, remainder) = CesrGroup::parse(rest)?;
        match group {
            CesrGroup::AttachmentGroup(frame) => {
                for inner in frame {
                    route_signature_group(inner?, sigs, wigs)?;
                }
            }
            other => route_signature_group(other, sigs, wigs)?,
        }
        rest = remainder;
    }
    Ok(rest)
}

/// Route one signature-bearing group; anything else cannot belong to a key
/// event message.
fn route_signature_group(
    group: CesrGroup,
    sigs: &mut Vec<Siger<'static>>,
    wigs: &mut Vec<Siger<'static>>,
) -> Result<(), EventMessageError> {
    match group {
        CesrGroup::ControllerIdxSigs(g) => {
            sigs.extend(g.into_vec().map_err(EventMessageError::Frame)?);
            Ok(())
        }
        CesrGroup::WitnessIdxSigs(g) => {
            wigs.extend(g.into_vec().map_err(EventMessageError::Frame)?);
            Ok(())
        }
        other => Err(EventMessageError::UnexpectedGroup {
            group: group_name(&other),
        }),
    }
}

/// The [`CesrGroup`] variant name, for [`EventMessageError::UnexpectedGroup`].
const fn group_name(group: &CesrGroup) -> &'static str {
    match group {
        CesrGroup::ControllerIdxSigs(_) => "ControllerIdxSigs",
        CesrGroup::WitnessIdxSigs(_) => "WitnessIdxSigs",
        CesrGroup::NonTransReceiptCouples(_) => "NonTransReceiptCouples",
        CesrGroup::TransReceiptQuadruples(_) => "TransReceiptQuadruples",
        CesrGroup::FirstSeenReplayCouples(_) => "FirstSeenReplayCouples",
        CesrGroup::TransIdxSigGroups(_) => "TransIdxSigGroups",
        CesrGroup::SealSourceCouples(_) => "SealSourceCouples",
        CesrGroup::TransLastIdxSigGroups(_) => "TransLastIdxSigGroups",
        CesrGroup::SealSourceTriples(_) => "SealSourceTriples",
        CesrGroup::PathedMaterialCouples(_) => "PathedMaterialCouples",
        CesrGroup::AttachmentGroup(_) => "AttachmentGroup",
        CesrGroup::GenericGroup(_) => "GenericGroup",
        CesrGroup::BodyWithAttachmentGroup(_) => "BodyWithAttachmentGroup",
        CesrGroup::NonNativeBodyGroup(_) => "NonNativeBodyGroup",
        CesrGroup::ESSRPayloadGroup(_) => "ESSRPayloadGroup",
        CesrGroup::DatagramSegmentGroup(_) => "DatagramSegmentGroup",
        CesrGroup::ESSRWrapperGroup(_) => "ESSRWrapperGroup",
        CesrGroup::FixBodyGroup(_) => "FixBodyGroup",
        CesrGroup::MapBodyGroup(_) => "MapBodyGroup",
        CesrGroup::GenericMapGroup(_) => "GenericMapGroup",
        CesrGroup::GenericListGroup(_) => "GenericListGroup",
        CesrGroup::DigestSealSingles(_) => "DigestSealSingles",
        CesrGroup::MerkleRootSealSingles(_) => "MerkleRootSealSingles",
        CesrGroup::SealSourceLastSingles(_) => "SealSourceLastSingles",
        CesrGroup::BackerRegistrarSealCouples(_) => "BackerRegistrarSealCouples",
        CesrGroup::TypedDigestSealCouples(_) => "TypedDigestSealCouples",
        CesrGroup::BlindedStateQuadruples(_) => "BlindedStateQuadruples",
        CesrGroup::BoundStateSextuples(_) => "BoundStateSextuples",
        CesrGroup::TypedMediaQuadruples(_) => "TypedMediaQuadruples",
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panics acceptable"
)]
mod tests {
    use core::num::NonZeroUsize;

    use super::*;
    use crate::builder::icp::InceptionBuilder;
    use crate::builder::ixn::InteractionBuilder;
    use crate::serialize::SerializedEvent;
    use alloc::string::String;
    use alloc::vec::Vec;
    use cesr::core::counter::CounterCodeV1;
    use cesr::core::indexer::IndexerBuilder;
    use cesr::core::indexer::code::IndexedSigCode;
    use cesr::core::matter::code::{DigestCode, VerKeyCode};
    use cesr::crypto::{Ed25519, KeyPair, digest};
    use cesr::keri::SigningThreshold;
    use cesr_stream::error::ParseError;

    fn build_siger_qb64(index: u32) -> Vec<u8> {
        IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519)
            .with_index(index)
            .unwrap()
            .with_raw(&[0u8; 64])
            .unwrap()
            .to_qb64()
            .into_bytes()
    }

    fn build_counter_qb64(code: CounterCodeV1, count: u32) -> Vec<u8> {
        let hard = code.as_str();
        let soft = cesr::b64::encode_int(count, NonZeroUsize::new(code.soft_size()).unwrap());
        let mut out = String::from(hard);
        out.push_str(&soft);
        out.into_bytes()
    }

    /// A genuine serder-built inception body (valid SAID) to frame under test.
    fn build_icp_body() -> SerializedEvent {
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let verfer = kp.verfer(VerKeyCode::Ed25519).unwrap().into_static();
        let next = digest(DigestCode::Blake3_256, &verfer.to_qb64b()).unwrap();
        InceptionBuilder::new()
            .keys(vec![verfer])
            .threshold(SigningThreshold::Simple(1))
            .next_keys(vec![next])
            .next_threshold(SigningThreshold::Simple(1))
            .build()
            .unwrap()
    }

    /// One controller-sig group (`-A` counter + `count` sigers), bare.
    fn controller_sigs_group(count: u32) -> Vec<u8> {
        let mut out = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, count);
        for i in 0..count {
            out.extend_from_slice(&build_siger_qb64(i));
        }
        out
    }

    /// Wrap an attachment payload in a `-V` frame (count in quadlets).
    fn framed(payload: &[u8]) -> Vec<u8> {
        assert_eq!(payload.len() % 4, 0, "attachments are whole quadlets");
        let quadlets = u32::try_from(payload.len() / 4).unwrap();
        let mut out = build_counter_qb64(CounterCodeV1::AttachmentGroup, quadlets);
        out.extend_from_slice(payload);
        out
    }

    /// keripy `messagize` shape: body + framed controller sigs.
    fn framed_message(body: &[u8], sig_count: u32) -> Vec<u8> {
        let mut msg = body.to_vec();
        msg.extend_from_slice(&framed(&controller_sigs_group(sig_count)));
        msg
    }

    // ── Round-trip / sequence ────────────────────────────────────────────

    #[test]
    fn parses_framed_message_and_routes_controller_sigs() {
        let body = build_icp_body();
        let msg = framed_message(body.as_bytes(), 2);

        let (parsed, rest) = EventMessage::parse(&msg).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.body(), body.as_bytes());
        assert_eq!(parsed.sigs().len(), 2);
        assert!(parsed.wigs().is_empty());
        assert!(matches!(parsed.event(), KeriEvent::Inception(_)));
    }

    #[test]
    fn parses_bare_layout_and_routes_witness_sigs() {
        let body = build_icp_body();
        let mut msg = body.as_bytes().to_vec();
        msg.extend_from_slice(&controller_sigs_group(1));
        msg.extend_from_slice(&build_counter_qb64(CounterCodeV1::WitnessIdxSigs, 1));
        msg.extend_from_slice(&build_siger_qb64(0));

        let (parsed, rest) = EventMessage::parse(&msg).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.sigs().len(), 1);
        assert_eq!(parsed.wigs().len(), 1);
    }

    #[test]
    fn framed_witness_sigs_route_to_wigs() {
        let body = build_icp_body();
        let mut attachment = controller_sigs_group(1);
        attachment.extend_from_slice(&build_counter_qb64(CounterCodeV1::WitnessIdxSigs, 2));
        attachment.extend_from_slice(&build_siger_qb64(0));
        attachment.extend_from_slice(&build_siger_qb64(1));
        let mut msg = body.as_bytes().to_vec();
        msg.extend_from_slice(&framed(&attachment));

        let (parsed, rest) = EventMessage::parse(&msg).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.sigs().len(), 1);
        assert_eq!(parsed.wigs().len(), 2);
    }

    #[test]
    fn multi_message_stream_parses_in_a_loop_with_exact_remainders() {
        let icp = build_icp_body();
        let prefix = icp.identifier().unwrap();
        let ixn = InteractionBuilder::new()
            .prefix(prefix.clone())
            .prior_event_said(icp.said().clone().into_static())
            .sn(1)
            .build()
            .unwrap();

        let first = framed_message(icp.as_bytes(), 1);
        let second = framed_message(ixn.as_bytes(), 1);
        let mut stream = first;
        stream.extend_from_slice(&second);

        let (msg1, rest1) = EventMessage::parse(&stream).unwrap();
        assert_eq!(msg1.body(), icp.as_bytes());
        assert_eq!(rest1, second.as_slice(), "remainder is exactly message 2");
        let (msg2, rest2) = EventMessage::parse(rest1).unwrap();
        assert_eq!(msg2.body(), ixn.as_bytes());
        assert!(matches!(msg2.event(), KeriEvent::Interaction(_)));
        assert!(rest2.is_empty());
    }

    #[test]
    fn body_borrows_the_input_buffer() {
        let body = build_icp_body();
        let msg = framed_message(body.as_bytes(), 1);
        let (parsed, _) = EventMessage::parse(&msg).unwrap();
        assert_eq!(
            parsed.body().as_ptr(),
            msg.as_ptr(),
            "body must be the zero-copy head of the input"
        );
    }

    #[test]
    fn event_with_no_attachments_parses_with_empty_sigs() {
        let body = build_icp_body();
        let (parsed, rest) = EventMessage::parse(body.as_bytes()).unwrap();
        assert!(rest.is_empty());
        assert!(parsed.sigs().is_empty());
        assert!(parsed.wigs().is_empty());
    }

    // ── Defensive boundaries ─────────────────────────────────────────────

    #[test]
    fn bare_attachment_input_is_rejected() {
        let input = controller_sigs_group(1);
        let err = EventMessage::parse(&input).unwrap_err();
        assert!(matches!(err, EventMessageError::BareAttachment));
    }

    #[test]
    fn unexpected_group_is_rejected_with_its_name() {
        // A seal-source couple cannot belong to a key event message.
        let body = build_icp_body();
        let mut attachment = build_counter_qb64(CounterCodeV1::SealSourceCouples, 1);
        attachment.extend_from_slice(b"0AAAAAAAAAAAAAAAAAAAAAAB"); // seqner
        attachment.extend_from_slice(build_icp_body().said().to_qb64().as_bytes()); // saider
        let mut msg = body.as_bytes().to_vec();
        msg.extend_from_slice(&framed(&attachment));

        let err = EventMessage::parse(&msg).unwrap_err();
        let EventMessageError::UnexpectedGroup { group } = err else {
            panic!("expected UnexpectedGroup, got {err:?}");
        };
        assert_eq!(group, "SealSourceCouples");
    }

    #[test]
    fn nested_attachment_frame_is_rejected() {
        let body = build_icp_body();
        let inner = framed(&controller_sigs_group(1));
        let mut msg = body.as_bytes().to_vec();
        msg.extend_from_slice(&framed(&inner));

        let err = EventMessage::parse(&msg).unwrap_err();
        assert!(matches!(
            err,
            EventMessageError::UnexpectedGroup {
                group: "AttachmentGroup"
            }
        ));
    }

    #[test]
    fn truncated_attachment_is_a_frame_error() {
        let body = build_icp_body();
        let mut msg = framed_message(body.as_bytes(), 1);
        msg.truncate(msg.len() - 10);
        let err = EventMessage::parse(&msg).unwrap_err();
        assert!(matches!(
            err,
            EventMessageError::Frame(ParseError::NeedBytes(_))
        ));
    }

    #[test]
    fn tampered_body_is_a_body_error() {
        let body = build_icp_body();
        let mut msg = framed_message(body.as_bytes(), 1);
        // Flip the sequence number: the SAID no longer verifies.
        let tampered = String::from_utf8(msg.clone())
            .unwrap()
            .replace("\"s\":\"0\"", "\"s\":\"1\"");
        msg = tampered.into_bytes();
        let err = EventMessage::parse(&msg).unwrap_err();
        assert!(matches!(
            err,
            EventMessageError::Body(SerderError::SaidMismatch { .. })
        ));
    }

    #[test]
    fn empty_input_is_a_frame_error() {
        let err = EventMessage::parse(b"").unwrap_err();
        assert!(matches!(
            err,
            EventMessageError::Frame(ParseError::NeedBytes(1))
        ));
    }

    #[test]
    fn garbage_after_attachments_stays_in_the_remainder() {
        // Bytes that are not a CESR cold start belong to the next message;
        // this message's framing must not claim (or choke on) them.
        let body = build_icp_body();
        let mut msg = framed_message(body.as_bytes(), 1);
        msg.extend_from_slice(&[0x00, 0x01]);
        let (parsed, rest) = EventMessage::parse(&msg).unwrap();
        assert_eq!(parsed.sigs().len(), 1);
        assert_eq!(rest, &[0x00, 0x01]);
    }
}
