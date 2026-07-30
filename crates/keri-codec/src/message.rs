//! The read spine: one framed key event message off the wire.
//!
//! [`EventMessage::parse`] is the crate's front door for wire bytes. It
//! composes the modules end to end — `stream` finds the frame
//! ([`CesrMessage::parse`](cesr_stream::CesrMessage::parse): cold-start detection +
//! version-string size), this crate's body codec decodes the body
//! ([`Deserialize`] for [`KeriEvent`]: strict
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

#[cfg(test)]
use crate::error::{CodecError, SaidError};
use crate::codec::event::ParsedEvent;
use crate::error::{EventMessageError, InternalError, MessageError, ReceiptMessageError};
use crate::traits::Deserialize;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{vec, vec::Vec};
use cesr::core::matter::Matter;
use cesr::core::matter::code::{DigestCode, MatterCode, VerKeyCode};
use cesr::core::primitives::{Cigar, Number, Siger};
use cesr_stream::cold::ColdCode;
use cesr_stream::error::ParseError;
use cesr_stream::group::CesrGroup;
use cesr_stream::message::CesrMessage;
use keri_events::{BasicPrefix, Identifier, KeriEvent, MessageType, Receipt, Said};

/// A key event message as received from the wire: the parsed event, the
/// exact byte span its signatures sign, and its attached indexed signatures.
///
/// Constructed only by [`EventMessage::parse`], so `body` is by construction
/// the span `event` was deserialized from — the provenance the downstream
/// fold (`keri_rs::Signed`) otherwise has to take on faith.
///
/// The lifetime `'a` is carried by `body` alone. Only `body` is genuinely
/// zero-copy — it borrows `&'a [u8]` from the parsed input. Everything else is
/// owned and effectively `'static`:
///
/// - `event`'s primitives are freshly decoded from qb64 and detached with
///   `into_static` (near-free — a decoded payload owns no input bytes), so it
///   borrows nothing from `body`.
/// - `sigs` and `wigs` are `'static` [`Siger`]s riding the attachment groups'
///   copy-once shared buffer ([`CesrGroup::parse`] copies the input once into a
///   shared `Bytes`; the parse cores copy nothing further).
///
/// Callers should treat `'a` as the borrow of the signed span, not of the
/// whole message.
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
        let after_body = input.get(payload.len()..).ok_or_else(|| {
            EventMessageError::Body(
                InternalError::EventLayout("event payload exceeds its own input").into(),
            )
        })?;
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

/// One framed message of either kind off the wire: a key event or a
/// receipt, dispatched on the body's `t` field.
///
/// This is the entry point for mixed streams — a witness's KEL replay
/// interleaves key event messages with receipt messages, and the consumer
/// cannot know which comes next without parsing.
#[derive(Debug)]
pub enum Message<'a> {
    /// A key event message (`icp`/`rot`/`ixn`/`dip`/`drt`).
    Event(EventMessage<'a>),
    /// A receipt message (`rct`).
    Receipt(ReceiptMessage<'a>),
}

impl<'a> Message<'a> {
    /// Parse one framed message of either kind from the head of `input`,
    /// returning the message and the unconsumed remainder.
    ///
    /// The body's `t` field steers dispatch: `rct` parses as a
    /// [`ReceiptMessage`], every key event `message_type` as an
    /// [`EventMessage`]. A concatenated mixed stream parses by looping
    /// until the remainder is empty.
    ///
    /// # Errors
    ///
    /// Returns [`MessageError::Frame`]/[`MessageError::Body`] if framing or
    /// the head fails before the message type is known,
    /// [`MessageError::BareAttachment`] if the input starts with a CESR
    /// group instead of a body, or the chosen parser's error wrapped in
    /// [`MessageError::Event`] / [`MessageError::Receipt`].
    pub fn parse(input: &'a [u8]) -> Result<(Self, &'a [u8]), MessageError> {
        let CesrMessage::Event { payload, .. } = CesrMessage::parse(input)? else {
            return Err(MessageError::BareAttachment);
        };
        match ParsedEvent::peek_message_type(payload)? {
            MessageType::Rct => {
                let (message, rest) = ReceiptMessage::parse(input)?;
                Ok((Self::Receipt(message), rest))
            }
            MessageType::Icp
            | MessageType::Rot
            | MessageType::Ixn
            | MessageType::Dip
            | MessageType::Drt => {
                let (message, rest) = EventMessage::parse(input)?;
                Ok((Self::Event(message), rest))
            }
        }
    }
}

/// One non-transferable endorsement: the endorser's key prefix and its
/// non-indexed signature over the receipted event's serialized bytes
/// (a `-C` `NonTransReceiptCouples` element).
///
/// The prefix IS the verification key — which is why a transferable prefix
/// in this position is rejected at parse
/// ([`ReceiptMessageError::TransferableCouple`]).
#[derive(Debug)]
pub struct ReceiptCouple<'a> {
    receiptor: BasicPrefix<'a>,
    signature: Cigar<'a>,
}

impl<'a> ReceiptCouple<'a> {
    /// The endorser's non-transferable key prefix.
    #[must_use]
    pub const fn receiptor(&self) -> &BasicPrefix<'a> {
        &self.receiptor
    }

    /// The non-indexed signature over the receipted event's bytes.
    #[must_use]
    pub const fn signature(&self) -> &Cigar<'a> {
        &self.signature
    }
}

/// One transferable endorsement: the endorser's identifier, the
/// establishment coordinate `(sn, said)` whose keys signed, and the
/// indexed signatures over the receipted event's serialized bytes
/// (a `-F` `TransIdxSigGroups` element).
///
/// Verifying one requires the endorser's establishment event at that
/// coordinate — host-supplied evidence, the K5 judge's input.
#[derive(Debug)]
pub struct TransferableReceipt<'a> {
    receiptor: Identifier<'a>,
    sn: Number,
    said: Said<'a>,
    signatures: Vec<Siger<'a>>,
}

impl<'a> TransferableReceipt<'a> {
    /// The endorser's identifier (basic or self-addressing derivation).
    #[must_use]
    pub const fn receiptor(&self) -> &Identifier<'a> {
        &self.receiptor
    }

    /// Sequence number of the endorser's establishment event.
    #[must_use]
    pub const fn sn(&self) -> Number {
        self.sn
    }

    /// SAID of the endorser's establishment event.
    #[must_use]
    pub const fn said(&self) -> &Said<'a> {
        &self.said
    }

    /// Indexed signatures, indexed into that establishment event's key
    /// list.
    #[must_use]
    pub fn signatures(&self) -> &[Siger<'a>] {
        &self.signatures
    }
}

/// A receipt message as received from the wire: the parsed receipt body,
/// the exact byte span it was parsed from, and its endorsement groups.
///
/// Constructed only by [`ReceiptMessage::parse`] (directly or via
/// [`Message::parse`]), which guarantees at least one endorsement group is
/// present — a bare receipt body endorses nothing.
///
/// The lifetime `'a` is carried by `body` alone, exactly as on
/// [`EventMessage`]: everything else is owned and effectively `'static`.
pub struct ReceiptMessage<'a> {
    receipt: Receipt<'a>,
    body: &'a [u8],
    couples: Vec<ReceiptCouple<'a>>,
    wigs: Vec<Siger<'a>>,
    trans_receipts: Vec<TransferableReceipt<'a>>,
}

impl fmt::Debug for ReceiptMessage<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceiptMessage")
            .field("body_len", &self.body.len())
            .field("couples", &self.couples.len())
            .field("wigs", &self.wigs.len())
            .field("trans_receipts", &self.trans_receipts.len())
            .finish_non_exhaustive()
    }
}

impl<'a> ReceiptMessage<'a> {
    /// Parse one framed receipt message from the head of `input`,
    /// returning the message and the unconsumed remainder.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptMessageError::Frame`] if the CESR framing or an
    /// attachment group is malformed or truncated,
    /// [`ReceiptMessageError::Body`] if the body fails strict canonical
    /// deserialization (including a non-`rct` `t` field),
    /// [`ReceiptMessageError::BareAttachment`] if the input starts with a
    /// CESR group instead of a body,
    /// [`ReceiptMessageError::MissingEndorsement`] if no endorsement group
    /// is attached (keripy's parser refuses the same shape,
    /// `parsing.py:1434` at the pin),
    /// [`ReceiptMessageError::TransferableCouple`] if a couple carries a
    /// transferable prefix, or
    /// [`ReceiptMessageError::UnexpectedGroup`] for an attachment group
    /// that cannot belong to a receipt message.
    pub fn parse(input: &'a [u8]) -> Result<(Self, &'a [u8]), ReceiptMessageError> {
        let CesrMessage::Event { payload, .. } = CesrMessage::parse(input)? else {
            return Err(ReceiptMessageError::BareAttachment);
        };
        let receipt = Receipt::deserialize(payload)?;
        let after_body = input.get(payload.len()..).ok_or_else(|| {
            ReceiptMessageError::Body(
                InternalError::EventLayout("receipt payload exceeds its own input").into(),
            )
        })?;
        let mut couples = Vec::new();
        let mut wigs = Vec::new();
        let mut trans_receipts = Vec::new();
        let rest =
            consume_receipt_attachments(after_body, &mut couples, &mut wigs, &mut trans_receipts)?;
        if couples.is_empty() && wigs.is_empty() && trans_receipts.is_empty() {
            return Err(ReceiptMessageError::MissingEndorsement);
        }
        Ok((
            Self {
                receipt,
                body: payload,
                couples,
                wigs,
                trans_receipts,
            },
            rest,
        ))
    }

    /// The parsed receipt body.
    #[must_use]
    pub const fn receipt(&self) -> &Receipt<'a> {
        &self.receipt
    }

    /// The exact serialized receipt-body span, borrowed from the input.
    #[must_use]
    pub const fn body(&self) -> &'a [u8] {
        self.body
    }

    /// Non-transferable endorsements (`-C` `NonTransReceiptCouples`).
    #[must_use]
    pub fn couples(&self) -> &[ReceiptCouple<'a>] {
        &self.couples
    }

    /// Witness indexed signatures (`-B` `WitnessIdxSigs`), indexed into the
    /// receipted event's governing witness set.
    #[must_use]
    pub fn wigs(&self) -> &[Siger<'a>] {
        &self.wigs
    }

    /// Transferable endorsements (`-F` `TransIdxSigGroups`).
    #[must_use]
    pub fn trans_receipts(&self) -> &[TransferableReceipt<'a>] {
        &self.trans_receipts
    }
}

/// Route the attachment region following a receipt body into its typed
/// endorsement groups, returning the unconsumed remainder. The walk is the
/// same iterative one as [`consume_attachments`]; only the routing differs.
fn consume_receipt_attachments<'i>(
    input: &'i [u8],
    couples: &mut Vec<ReceiptCouple<'static>>,
    wigs: &mut Vec<Siger<'static>>,
    trans_receipts: &mut Vec<TransferableReceipt<'static>>,
) -> Result<&'i [u8], ReceiptMessageError> {
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
                    route_receipt_group(inner?, couples, wigs, trans_receipts)?;
                }
            }
            other => route_receipt_group(other, couples, wigs, trans_receipts)?,
        }
        rest = remainder;
    }
    Ok(rest)
}

/// Route one endorsement-bearing group; anything else cannot belong to a
/// receipt message (keripy's rct extraction set: cigars, wigers, tsgs —
/// `parsing.py:1434` at the pin).
fn route_receipt_group(
    group: CesrGroup,
    couples: &mut Vec<ReceiptCouple<'static>>,
    wigs: &mut Vec<Siger<'static>>,
    trans_receipts: &mut Vec<TransferableReceipt<'static>>,
) -> Result<(), ReceiptMessageError> {
    match group {
        CesrGroup::NonTransReceiptCouples(g) => {
            for (prefixer, signature) in g.into_vec().map_err(ReceiptMessageError::Frame)? {
                if prefixer.code().is_transferable() {
                    return Err(ReceiptMessageError::TransferableCouple {
                        prefix: prefixer.to_qb64(),
                    });
                }
                couples.push(ReceiptCouple {
                    receiptor: BasicPrefix::from_matter(prefixer),
                    signature,
                });
            }
            Ok(())
        }
        CesrGroup::WitnessIdxSigs(g) => {
            wigs.extend(g.into_vec().map_err(ReceiptMessageError::Frame)?);
            Ok(())
        }
        CesrGroup::TransIdxSigGroups(g) => {
            for (prefixer, seqner, saider, sigs) in
                g.into_vec().map_err(ReceiptMessageError::Frame)?
            {
                trans_receipts.push(TransferableReceipt {
                    receiptor: endorser_identifier(prefixer)?,
                    sn: seqner_number(&seqner)?,
                    said: Said::from_matter(saider),
                    signatures: sigs.into_vec().map_err(ReceiptMessageError::Frame)?,
                });
            }
            Ok(())
        }
        other => Err(ReceiptMessageError::UnexpectedGroup {
            group: group_name(&other),
        }),
    }
}

/// Lift a wide endorser prefix into an [`Identifier`]: a verification-key
/// code is a basic derivation, a digest code a self-addressing one — the
/// same admission rule the stream layer's element grammar enforces,
/// re-checked at this module's boundary.
fn endorser_identifier(
    prefixer: Matter<'static, MatterCode>,
) -> Result<Identifier<'static>, ReceiptMessageError> {
    if VerKeyCode::try_from(*prefixer.code()).is_ok() {
        let key = prefixer.narrow::<VerKeyCode>().map_err(|e| {
            ReceiptMessageError::Frame(ParseError::UnexpectedCodeType {
                expected: "VerKeyCode",
                source: e,
            })
        })?;
        return Ok(Identifier::Basic(BasicPrefix::from_matter(key)));
    }
    prefixer
        .narrow::<DigestCode>()
        .map(|digest| Identifier::SelfAddressing(Said::from_matter(digest)))
        .map_err(|e| {
            ReceiptMessageError::Frame(ParseError::UnexpectedCodeType {
                expected: "VerKeyCode or DigestCode",
                source: e,
            })
        })
}

/// Lift a seqner primitive into an ordinal [`Number`]: the raw big-endian
/// value, whatever number code carried it (keripy emits minimal `Number`
/// codes in `messagize` and 16-byte `Seqner`s elsewhere).
fn seqner_number(seqner: &Matter<'_, MatterCode>) -> Result<Number, ReceiptMessageError> {
    let raw = seqner.raw();
    if raw.len() > 16 {
        return Err(ReceiptMessageError::EndorserSnOutOfRange {
            qb64: seqner.to_qb64(),
        });
    }
    let value = raw
        .iter()
        .try_fold(0u128, |acc, byte| {
            acc.checked_shl(8).map(|shifted| shifted | u128::from(*byte))
        })
        .ok_or_else(|| ReceiptMessageError::EndorserSnOutOfRange {
            qb64: seqner.to_qb64(),
        })?;
    Ok(Number::new(value))
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
    use cesr_stream::error::ParseError;
    use keri_events::SigningThreshold;

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

    /// A genuine builder-produced inception body (valid SAID) to frame under test.
    fn build_icp_body() -> SerializedEvent {
        let kp = KeyPair::<Ed25519>::generate().unwrap();
        let verfer = kp.verfer(VerKeyCode::Ed25519).unwrap().into_static();
        let next = digest(DigestCode::Blake3_256, &verfer.to_qb64b()).unwrap();
        InceptionBuilder::new()
            .keys(vec![verfer.into()])
            .threshold(SigningThreshold::Simple(1))
            .next_keys(vec![next.into()])
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
            EventMessageError::Body(CodecError::Said(SaidError::SaidMismatch { .. }))
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

    // ── Receipt messages (#82) ───────────────────────────────────────────
    //
    // Spec invariants under test (KERI spec receipt section; keripy oracle
    // at pin de59bc7d): body grammar `v,t,d,i,s` with `d` = receipted
    // event's SAID (eventing.py:957), receipt signatures verify over the
    // RECEIPTED EVENT's serialized bytes (processReceipt,
    // eventing.py:4531+), couples are non-transferable by definition
    // (messagize, eventing.py:1684-1686), and a bare receipt endorses
    // nothing (parsing.py:1434).

    mod receipt {
        use super::*;
        use crate::traits::Serialize;
        use alloc::borrow::Cow;
        use alloc::format;
        use alloc::string::String;
        use cesr::core::indexer::code::IndexMode;
        use cesr::core::matter::builder::MatterBuilder;
        use cesr::core::matter::code::MatterCode;
        use cesr::crypto::{verify, verify_indexed};
        use cesr_stream::group::{NonTransReceiptCouples, TransIdxSigGroups, WitnessIdxSigs};
        use cesr_stream::group::ControllerIdxSigs as NestedSigs;
        use keri_events::MessageType;

        /// A controller with a real KEL inception plus an independent
        /// endorser key pair — receipts sign the EVENT's bytes, so the
        /// tests need genuine crypto, not fill-byte primitives.
        struct Receipted {
            event: SerializedEvent,
            receipt: Receipt<'static>,
        }

        fn receipted(sn_value: u128) -> Receipted {
            let event = build_icp_body();
            let receipt = Receipt::new(
                event.identifier().unwrap(),
                Number::new(sn_value),
                event.said().clone().into_static(),
            );
            Receipted { event, receipt }
        }

        fn wide_matter(code: MatterCode, raw: &[u8]) -> Matter<'static, MatterCode> {
            MatterBuilder::new()
                .with_code(code)
                .with_raw(Cow::<[u8]>::Owned(raw.to_vec()))
                .unwrap()
                .build()
                .unwrap()
        }

        /// keripy `Seqner` form: code `0A` (Salt128/Huge), 16-byte
        /// big-endian ordinal.
        fn seqner(sn_value: u128) -> Matter<'static, MatterCode> {
            wide_matter(MatterCode::Salt128, &sn_value.to_be_bytes())
        }

        // ── The body grammar, asserted against an INDEPENDENT rendering ──

        /// The exact body bytes per keripy `receipt()` (eventing.py:957):
        /// field order `v,t,d,i,s`, `d` the receipted event's SAID
        /// verbatim, `s` minimal lowercase hex, size backpatched into the
        /// 17-byte version string. The expected string is assembled by the
        /// test itself, not by the code under test.
        #[test]
        fn receipt_body_matches_spec_grammar_byte_for_byte() {
            for (sn_value, sn_hex) in [(0u128, "0"), (26, "1a"), (u128::MAX, &"f".repeat(32))] {
                let Receipted { event, receipt } = receipted(sn_value);
                let serialized = receipt.serialize().unwrap();

                let d = event.said().to_qb64();
                let i = event.identifier().unwrap().as_saider().unwrap().to_qb64();
                let skeleton = format!(
                    "{{\"v\":\"KERI10JSON000000_\",\"t\":\"rct\",\"d\":\"{d}\",\"i\":\"{i}\",\"s\":\"{sn_hex}\"}}"
                );
                let expected = skeleton.replace(
                    "KERI10JSON000000_",
                    &format!("KERI10JSON{:06x}_", skeleton.len()),
                );

                assert_eq!(
                    core::str::from_utf8(serialized.as_bytes()).unwrap(),
                    expected,
                    "sn={sn_value}"
                );
                assert_eq!(serialized.size(), expected.len());
            }
        }

        /// The body round-trips through the strict reader into the same
        /// domain value, and `d` is carried as DATA — a receipt whose `d`
        /// deliberately differs from any self-hash still parses (there is
        /// no self-SAID to verify, per the spec's receipt shape).
        #[test]
        fn receipt_body_round_trips_and_d_is_not_self_addressed() {
            let Receipted { receipt, .. } = receipted(3);
            let serialized = receipt.serialize().unwrap();
            let recovered = Receipt::deserialize(serialized.as_bytes()).unwrap();
            assert_eq!(recovered, receipt);
        }

        // ── Non-transferable couples: the signature signs the EVENT ──────

        #[test]
        fn couple_signature_verifies_over_receipted_event_bytes() {
            let Receipted { event, receipt } = receipted(0);
            let endorser = KeyPair::<Ed25519>::generate().unwrap();
            // Non-transferable derivation: the prefix IS the key (spec rule
            // for receipt couples).
            let endorser_prefix = endorser.verfer(VerKeyCode::Ed25519N).unwrap().into_static();
            let cigar = endorser.sign(event.as_bytes()).unwrap();

            let couples = NonTransReceiptCouples::from_couples(&[(
                endorser_prefix.clone(),
                cigar,
            )])
            .unwrap();
            let framed = receipt
                .serialize()
                .unwrap()
                .frame_v1(None, None, Some(&couples))
                .unwrap();

            let (parsed, rest) = ReceiptMessage::parse(&framed).unwrap();
            assert!(rest.is_empty());
            assert_eq!(parsed.receipt(), &receipt);
            assert_eq!(parsed.couples().len(), 1);
            let couple = &parsed.couples()[0];
            assert_eq!(couple.receiptor().as_matter(), &endorser_prefix);

            // The parsed couple verifies over the receipted event's bytes…
            verify(couple.receiptor().as_matter(), event.as_bytes(), couple.signature())
                .expect("endorsement must verify over the receipted event's serialization");
            // …and over nothing else.
            assert!(
                verify(couple.receiptor().as_matter(), parsed.body(), couple.signature())
                    .is_err(),
                "the signature signs the event, not the receipt body"
            );
        }

        // ── Witness indexed sigs: index into the governing witness set ───

        #[test]
        fn witness_indexed_sigs_verify_and_recover_their_indices() {
            let Receipted { event, receipt } = receipted(0);
            let witnesses: Vec<KeyPair<Ed25519>> = (0..2)
                .map(|_| KeyPair::<Ed25519>::generate().unwrap())
                .collect();
            let verfers: Vec<_> = witnesses
                .iter()
                .map(|w| w.verfer(VerKeyCode::Ed25519N).unwrap().into_static())
                .collect();
            let wigs_vec: Vec<Siger<'static>> = witnesses
                .iter()
                .enumerate()
                .map(|(index, w)| {
                    w.sign_indexed(
                            event.as_bytes(),
                            u32::try_from(index).unwrap(),
                            IndexMode::CurrentOnly,
                        )
                        .unwrap()
                })
                .collect();
            let wigs = WitnessIdxSigs::from_indexed_signatures(&wigs_vec).unwrap();

            let framed = receipt
                .serialize()
                .unwrap()
                .frame_v1(None, Some(&wigs), None)
                .unwrap();
            let (parsed, _) = ReceiptMessage::parse(&framed).unwrap();
            assert_eq!(parsed.wigs().len(), 2);

            let indices: Vec<u32> = verify_indexed(&verfers, event.as_bytes(), parsed.wigs())
                .collect::<Result<Vec<_>, _>>()
                .expect("every wig verifies against the witness set");
            assert_eq!(indices, vec![0, 1], "each wig verifies at its own index");
        }

        // ── Transferable endorsements: establishment coordinate + sigs ───

        #[test]
        fn transferable_endorsement_carries_coordinate_and_verifying_sigs() {
            let Receipted { event, receipt } = receipted(0);
            // The endorser has its own KEL; its receipt names ITS
            // establishment coordinate whose keys signed.
            let endorser_kel = build_icp_body();
            let endorser_key = KeyPair::<Ed25519>::generate().unwrap();
            let endorser_verfer = endorser_key.verfer(VerKeyCode::Ed25519).unwrap().into_static();
            let sig = endorser_key
                .sign_indexed(event.as_bytes(), 0, IndexMode::Both)
                .unwrap();
            let nested = NestedSigs::from_indexed_signatures(core::slice::from_ref(&sig)).unwrap();
            let trans = TransIdxSigGroups::from_groups(&[(
                wide_matter(MatterCode::Blake3_256, endorser_kel.said().as_matter().raw()),
                seqner(0),
                endorser_kel.said().as_matter().clone().into_static(),
                nested,
            )])
            .unwrap();

            let framed = receipt
                .serialize()
                .unwrap()
                .frame_v1(Some(&trans), None, None)
                .unwrap();
            let (parsed, _) = ReceiptMessage::parse(&framed).unwrap();
            assert_eq!(parsed.trans_receipts().len(), 1);
            let endorsement = &parsed.trans_receipts()[0];

            // Coordinate: (self-addressing AID, sn 0, establishment SAID).
            assert!(matches!(endorsement.receiptor(), Identifier::SelfAddressing(_)));
            assert_eq!(
                endorsement.receiptor().as_saider().unwrap().to_qb64(),
                endorser_kel.said().to_qb64()
            );
            assert_eq!(endorsement.sn().value(), 0);
            assert_eq!(endorsement.said(), endorser_kel.said());

            // The nested sigs verify over the receipted event's bytes
            // against the endorser's key at the named coordinate.
            let indices: Vec<u32> = verify_indexed(
                core::slice::from_ref(&endorser_verfer),
                event.as_bytes(),
                endorsement.signatures(),
            )
            .collect::<Result<Vec<_>, _>>()
            .expect("the endorsement sigs verify against the endorser's key");
            assert_eq!(indices, vec![0]);
        }

        /// keripy `messagize` writes seqners as minimal `Number` codes and
        /// the older Seqner form as 16-byte `0A` — both are ordinals and
        /// must lift to the same value.
        #[test]
        fn seqner_lifts_identically_from_huge_and_minimal_forms() {
            let Receipted { receipt, .. } = receipted(0);
            let sn_value = 0x1a2bu128;
            for seqner_matter in [
                seqner(sn_value),
                wide_matter(MatterCode::Salt128, &sn_value.to_be_bytes()),
            ] {
                let nested = NestedSigs::from_indexed_signatures(&[]).unwrap();
                let trans = TransIdxSigGroups::from_groups(&[(
                    wide_matter(MatterCode::Blake3_256, &[6u8; 32]),
                    seqner_matter,
                    receipt.said().as_matter().clone().into_static(),
                    nested,
                )])
                .unwrap();
                let framed = receipt
                    .serialize()
                    .unwrap()
                    .frame_v1(Some(&trans), None, None)
                    .unwrap();
                let (parsed, _) = ReceiptMessage::parse(&framed).unwrap();
                assert_eq!(parsed.trans_receipts()[0].sn().value(), sn_value);
            }
        }

        // ── Frame layout: -V quadlet count and group order ───────────────

        #[test]
        fn frame_counter_counts_quadlets_and_groups_keep_spec_order() {
            let Receipted { event, receipt } = receipted(0);
            let endorser = KeyPair::<Ed25519>::generate().unwrap();
            let couples = NonTransReceiptCouples::from_couples(&[(
                endorser.verfer(VerKeyCode::Ed25519N).unwrap().into_static(),
                endorser.sign(event.as_bytes()).unwrap(),
            )])
            .unwrap();
            let wig = endorser
                .sign_indexed(event.as_bytes(), 0, IndexMode::CurrentOnly)
                .unwrap();
            let wigs =
                WitnessIdxSigs::from_indexed_signatures(core::slice::from_ref(&wig)).unwrap();
            let nested = NestedSigs::from_indexed_signatures(core::slice::from_ref(&wig)).unwrap();
            let trans = TransIdxSigGroups::from_groups(&[(
                wide_matter(MatterCode::Blake3_256, &[6u8; 32]),
                seqner(0),
                receipt.said().as_matter().clone().into_static(),
                nested,
            )])
            .unwrap();

            let serialized = receipt.serialize().unwrap();
            let framed = serialized
                .frame_v1(Some(&trans), Some(&wigs), Some(&couples))
                .unwrap();

            // After the body: a `-V` counter whose count is the attachment
            // region's length in quadlets (keripy eventing.py:1692-1694).
            let attachment_start = serialized.as_bytes().len();
            let counter = &framed[attachment_start..attachment_start + 4];
            assert_eq!(&counter[..2], b"-V");
            let quadlets: u32 =
                cesr::b64::decode_int(core::str::from_utf8(&counter[2..]).unwrap()).unwrap();
            let region = &framed[attachment_start + 4..];
            assert_eq!(region.len(), usize::try_from(quadlets).unwrap() * 4);

            // Group order inside the region: -F, then -B, then -C
            // (keripy messagize V1: sigers/tsgs, wigers, cigars).
            let region_str = core::str::from_utf8(region).unwrap();
            let f = region_str.find("-F").unwrap();
            let b = region_str.find("-B").unwrap();
            let c = region_str.find("-C").unwrap();
            assert!(f < b && b < c, "spec order -F < -B < -C, got {f}/{b}/{c}");

            // And the whole frame round-trips.
            let (parsed, rest) = ReceiptMessage::parse(&framed).unwrap();
            assert!(rest.is_empty());
            assert_eq!(parsed.couples().len(), 1);
            assert_eq!(parsed.wigs().len(), 1);
            assert_eq!(parsed.trans_receipts().len(), 1);
        }

        // ── Dispatch over mixed streams ──────────────────────────────────

        #[test]
        fn message_parse_dispatches_a_mixed_witness_stream() {
            let icp = build_icp_body();
            let event_msg = framed_message(icp.as_bytes(), 1);
            let receipt = Receipt::new(
                icp.identifier().unwrap(),
                Number::new(0),
                icp.said().clone().into_static(),
            );
            let endorser = KeyPair::<Ed25519>::generate().unwrap();
            let couples = NonTransReceiptCouples::from_couples(&[(
                endorser.verfer(VerKeyCode::Ed25519N).unwrap().into_static(),
                endorser.sign(icp.as_bytes()).unwrap(),
            )])
            .unwrap();
            let receipt_msg = receipt
                .serialize()
                .unwrap()
                .frame_v1(None, None, Some(&couples))
                .unwrap();

            let mut stream = event_msg;
            stream.extend_from_slice(&receipt_msg);

            let (first, rest1) = Message::parse(&stream).unwrap();
            let Message::Event(event) = first else {
                panic!("expected Event, got {first:?}");
            };
            assert_eq!(event.event().message_type(), MessageType::Icp);
            assert_eq!(rest1, receipt_msg.as_slice(), "remainder is exactly the receipt");

            let (second, rest2) = Message::parse(rest1).unwrap();
            let Message::Receipt(parsed) = second else {
                panic!("expected Receipt, got {second:?}");
            };
            assert_eq!(parsed.receipt(), &receipt);
            assert!(rest2.is_empty());
        }

        // ── Defensive boundaries ─────────────────────────────────────────

        /// A bare receipt body endorses nothing — keripy's parser refuses
        /// the same shape (parsing.py:1434-1439).
        #[test]
        fn bare_receipt_body_is_missing_endorsement() {
            let serialized = receipted(1).receipt.serialize().unwrap();
            let err = ReceiptMessage::parse(serialized.as_bytes()).unwrap_err();
            assert!(matches!(err, ReceiptMessageError::MissingEndorsement));
        }

        /// Spec rule: a couple's prefix IS the verification key, so a
        /// transferable prefix is unverifiable. keripy refuses it at write
        /// time (messagize, eventing.py:1684-1686) but skips it on read —
        /// this parser rejects on read too, so the shape must be crafted
        /// as raw wire bytes.
        #[test]
        fn transferable_couple_prefix_is_rejected_on_read() {
            let Receipted { event, receipt } = receipted(1);
            let endorser = KeyPair::<Ed25519>::generate().unwrap();
            let transferable_prefix =
                endorser.verfer(VerKeyCode::Ed25519).unwrap().into_static();
            let cigar = endorser.sign(event.as_bytes()).unwrap();

            let mut msg = receipt.serialize().unwrap().as_bytes().to_vec();
            let mut attachment = build_counter_qb64(CounterCodeV1::NonTransReceiptCouples, 1);
            attachment.extend_from_slice(transferable_prefix.to_qb64().as_bytes());
            attachment.extend_from_slice(cigar.to_qb64().as_bytes());
            msg.extend_from_slice(&framed(&attachment));

            let err = ReceiptMessage::parse(&msg).unwrap_err();
            let ReceiptMessageError::TransferableCouple { prefix } = err else {
                panic!("expected TransferableCouple, got {err:?}");
            };
            assert_eq!(prefix, transferable_prefix.to_qb64());
        }

        /// The same rule holds on the write side.
        #[test]
        fn transferable_couple_prefix_is_rejected_on_write() {
            let Receipted { event, receipt } = receipted(1);
            let endorser = KeyPair::<Ed25519>::generate().unwrap();
            let couples = NonTransReceiptCouples::from_couples(&[(
                endorser.verfer(VerKeyCode::Ed25519).unwrap().into_static(),
                endorser.sign(event.as_bytes()).unwrap(),
            )])
            .unwrap();
            let err = receipt
                .serialize()
                .unwrap()
                .frame_v1(None, None, Some(&couples))
                .unwrap_err();
            assert!(matches!(err, crate::error::FrameError::TransferableCouple { .. }));
        }

        /// All groups empty (present but count 0) is still no endorsement.
        #[test]
        fn empty_endorsement_groups_cannot_frame() {
            let serialized = receipted(1).receipt.serialize().unwrap();
            let empty = NestedSigs::from_indexed_signatures(&[]).unwrap();
            let err = serialized
                .frame_v1(None, Some(&WitnessIdxSigs::from_indexed_signatures(&[]).unwrap()), None)
                .unwrap_err();
            assert!(matches!(err, crate::error::FrameError::MissingEndorsement));
            drop(empty);
        }

        /// Controller indexed sigs belong to key event messages, never to
        /// receipts (keripy's rct extraction set: cigars, wigers, tsgs).
        #[test]
        fn controller_sigs_group_cannot_belong_to_a_receipt() {
            let serialized = receipted(1).receipt.serialize().unwrap();
            let mut msg = serialized.as_bytes().to_vec();
            msg.extend_from_slice(&framed(&controller_sigs_group(1)));
            let err = ReceiptMessage::parse(&msg).unwrap_err();
            assert!(matches!(
                err,
                ReceiptMessageError::UnexpectedGroup {
                    group: "ControllerIdxSigs"
                }
            ));
        }

        /// An `rct` body fed to the key-event spine fails typed, never
        /// panics, and never mis-parses as an event.
        #[test]
        fn receipt_body_through_event_parse_is_a_typed_body_error() {
            let serialized = receipted(1).receipt.serialize().unwrap();
            let err = EventMessage::parse(serialized.as_bytes()).unwrap_err();
            assert!(matches!(
                err,
                EventMessageError::Body(CodecError::Deserialize(
                    crate::error::DeserializeError::ReceiptNotKeyEvent
                ))
            ));
        }

        #[test]
        fn truncated_receipt_attachment_is_a_frame_error() {
            let Receipted { event, receipt } = receipted(1);
            let endorser = KeyPair::<Ed25519>::generate().unwrap();
            let couples = NonTransReceiptCouples::from_couples(&[(
                endorser.verfer(VerKeyCode::Ed25519N).unwrap().into_static(),
                endorser.sign(event.as_bytes()).unwrap(),
            )])
            .unwrap();
            let mut msg = receipt
                .serialize()
                .unwrap()
                .frame_v1(None, None, Some(&couples))
                .unwrap();
            msg.truncate(msg.len() - 10);
            let err = ReceiptMessage::parse(&msg).unwrap_err();
            assert!(matches!(
                err,
                ReceiptMessageError::Frame(ParseError::NeedBytes(_))
            ));
        }

        /// Non-canonical receipt bodies are rejected at their exact
        /// deviation: a non-hex `s` value.
        #[test]
        fn receipt_with_invalid_hex_sn_is_a_body_error() {
            let serialized = receipted(1).receipt.serialize().unwrap();
            let tampered = String::from_utf8(serialized.as_bytes().to_vec())
                .unwrap()
                .replace("\"s\":\"1\"", "\"s\":\"z\"");
            let err = Receipt::deserialize(tampered.as_bytes()).unwrap_err();
            assert!(matches!(
                err,
                CodecError::Deserialize(crate::error::DeserializeError::InvalidPrimitive {
                    field: "s",
                    ..
                })
            ));
        }
    }
}
