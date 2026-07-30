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
}
