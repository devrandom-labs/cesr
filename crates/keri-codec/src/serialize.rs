//! KERI event serialization to canonical JSON with SAID computation.
//!
//! Each event serializer builds ordered JSON matching keripy's wire format,
//! computes the SAID (self-addressing identifier), and returns a
//! [`SerializedEvent`] containing the final bytes.

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, boxed::Box, format, string::String, string::ToString, vec, vec::Vec};
use cesr::core::matter::code::DigestCode;
use cesr::core::primitives::Saider;
use core::ops::Range;
use keri_events::{
    DelegatedInceptionEvent, DelegatedRotationEvent, Identifier, Ilk, InceptionEvent,
    InteractionEvent, KeriEvent, RotationEvent,
};

use crate::error::{FrameError, SerderError};
use crate::primitives::to_qb64_string;
use crate::said::{compute_digest, said_placeholder};
use crate::traits::Serialize;
use bytes::BytesMut;
use cesr::core::counter::CounterCodeV1;
use cesr::core::version::{SerializationKind, VERSION_SIZE_MAX, VersionError};
use cesr_stream::encode::EncodeCount;
use cesr_stream::error::ParseError;
use cesr_stream::group::{ControllerIdxSigs, WitnessIdxSigs};
use cesr_stream::version::{CesrEncode, V1};

// ---------------------------------------------------------------------------
// The Serialize impls (the public write surface) over the single
// canonical writer
// ---------------------------------------------------------------------------

/// Serializes any [`KeriEvent`] variant by dispatching to the variant's
/// event-specific impl.
impl Serialize for KeriEvent<'_> {
    fn serialize(&self) -> Result<SerializedEvent, SerderError> {
        match self {
            Self::Inception(e) => e.serialize(),
            Self::Rotation(e) => e.serialize(),
            Self::Interaction(e) => e.serialize(),
            Self::DelegatedInception(e) => e.serialize(),
            Self::DelegatedRotation(e) => e.serialize(),
        }
    }
}

/// Serializes an [`InceptionEvent`] (`icp`).
///
/// The `i` field follows the event's [`Identifier`] derivation: for a
/// self-addressing prefix both `d` and `i` are set to the computed SAID
/// (the double-SAID property); for a basic-derivation prefix `i` is the
/// public key serialized verbatim and only `d` carries the SAID, computed
/// with `i` left intact (single-SAID), matching keripy's `makify`.
///
/// The resulting JSON has field order:
/// `v, t, d, i, s, kt, k, nt, n, bt, b, c, a`.
impl Serialize for InceptionEvent<'_> {
    fn serialize(&self) -> Result<SerializedEvent, SerderError> {
        serialize_event(EventRef::Inception(self))
    }
}

/// Serializes a [`RotationEvent`] (`rot`).
///
/// Only the `d` field is self-addressing; `i` is the existing AID prefix.
///
/// The resulting JSON has field order:
/// `v, t, d, i, s, p, kt, k, nt, n, bt, br, ba, a`.
impl Serialize for RotationEvent<'_> {
    fn serialize(&self) -> Result<SerializedEvent, SerderError> {
        serialize_event(EventRef::Rotation(self))
    }
}

/// Serializes an [`InteractionEvent`] (`ixn`).
///
/// The resulting JSON has field order: `v, t, d, i, s, p, a`.
impl Serialize for InteractionEvent<'_> {
    fn serialize(&self) -> Result<SerializedEvent, SerderError> {
        serialize_event(EventRef::Interaction(self))
    }
}

/// Serializes a [`DelegatedInceptionEvent`] (`dip`).
///
/// The `i` field follows the event's [`Identifier`] derivation exactly as
/// for regular inceptions: self-addressing prefixes get the computed SAID in
/// both `d` and `i` (double-SAID — the only derivation keripy's `delcept`
/// produces), while a basic prefix is serialized verbatim with a
/// single-SAID `d`. The `di` field carries the delegator's prefix.
///
/// The resulting JSON has field order:
/// `v, t, d, i, s, kt, k, nt, n, bt, b, c, a, di`.
impl Serialize for DelegatedInceptionEvent<'_> {
    fn serialize(&self) -> Result<SerializedEvent, SerderError> {
        serialize_event(EventRef::DelegatedInception(self))
    }
}

/// Serializes a [`DelegatedRotationEvent`] (`drt`).
///
/// Only the `d` field is self-addressing; `i` is the existing AID prefix.
/// The delegator is established at inception and looked up from the KEL, so
/// there is no `di` field — the only difference from `rot` is the ilk
/// (`drt`).
///
/// The resulting JSON has field order:
/// `v, t, d, i, s, p, kt, k, nt, n, bt, br, ba, a`.
impl Serialize for DelegatedRotationEvent<'_> {
    fn serialize(&self) -> Result<SerializedEvent, SerderError> {
        serialize_event(EventRef::DelegatedRotation(self))
    }
}

/// Borrowed view over any KERI event, used to hand an event to the writer
/// without cloning it into a [`KeriEvent`].
#[derive(Clone, Copy)]
pub enum EventRef<'e> {
    /// Inception (`icp`).
    Inception(&'e InceptionEvent<'e>),
    /// Rotation (`rot`).
    Rotation(&'e RotationEvent<'e>),
    /// Interaction (`ixn`).
    Interaction(&'e InteractionEvent<'e>),
    /// Delegated inception (`dip`).
    DelegatedInception(&'e DelegatedInceptionEvent<'e>),
    /// Delegated rotation (`drt`).
    DelegatedRotation(&'e DelegatedRotationEvent<'e>),
}

impl EventRef<'_> {
    /// The event type (ilk) of the referenced event.
    #[must_use]
    pub const fn ilk(self) -> Ilk {
        match self {
            Self::Inception(_) => Ilk::Icp,
            Self::Rotation(_) => Ilk::Rot,
            Self::Interaction(_) => Ilk::Ixn,
            Self::DelegatedInception(_) => Ilk::Dip,
            Self::DelegatedRotation(_) => Ilk::Drt,
        }
    }

    /// The digest code of the event's `d` field, which steers the SAID
    /// computation (and the `i` backpatch for double-SAID events).
    ///
    /// Builders select it via their `said_code` setter; parsed events carry
    /// the code inferred from the `d` value, so re-serialization preserves
    /// the original digest algorithm instead of forcing Blake3-256.
    #[must_use]
    pub const fn said_code(self) -> DigestCode {
        match self {
            Self::Inception(e) => *e.said().code(),
            Self::Rotation(e) => *e.said().code(),
            Self::Interaction(e) => *e.said().code(),
            Self::DelegatedInception(e) => *e.inception().said().code(),
            Self::DelegatedRotation(e) => *e.rotation().said().code(),
        }
    }

    /// Whether the event's identifier prefix is set to the computed SAID
    /// (the double-SAID property of self-addressing inception and delegated
    /// inception).
    ///
    /// Derived from the event's [`Identifier`] variant: a basic-derivation
    /// inception (`i` is a public key, `i != d`) is single-SAID — only `d`
    /// is dummied and backpatched, and `i` is serialized verbatim, matching
    /// keripy's `makify` (only digestive said-field codes are dummied).
    #[must_use]
    pub const fn is_double_said(self) -> bool {
        match self {
            Self::Inception(e) => matches!(e.prefix(), Identifier::SelfAddressing(_)),
            Self::DelegatedInception(e) => {
                matches!(e.inception().prefix(), Identifier::SelfAddressing(_))
            }
            Self::Rotation(_) | Self::Interaction(_) | Self::DelegatedRotation(_) => false,
        }
    }
}

impl<'e> From<&'e KeriEvent<'e>> for EventRef<'e> {
    fn from(event: &'e KeriEvent<'e>) -> Self {
        match event {
            KeriEvent::Inception(e) => Self::Inception(e),
            KeriEvent::Rotation(e) => Self::Rotation(e),
            KeriEvent::Interaction(e) => Self::Interaction(e),
            KeriEvent::DelegatedInception(e) => Self::DelegatedInception(e),
            KeriEvent::DelegatedRotation(e) => Self::DelegatedRotation(e),
        }
    }
}

/// Byte ranges of the backpatchable slots inside a rendered event body.
///
/// Ranges are absolute indices into the buffer as it stands when the
/// writer's `render` returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EventLayout {
    /// The six-hex-digit size field inside the version string.
    pub size: Range<usize>,
    /// The `d` field's qb64 SAID value (placeholder until spliced).
    pub said: Range<usize>,
    /// The `i` field's qb64 value for double-SAID events (`icp`/`dip`).
    pub prefix: Option<Range<usize>>,
}

/// Body rendering for a [`SerializationKind`].
pub(crate) trait RenderBody {
    /// Render `event`'s body in this serialization kind into `buf`
    /// (appending), reporting the backpatchable slot layout.
    ///
    /// The trait is local to this crate because [`SerializationKind`] is a
    /// foreign type: the impl lives here — not in `version.rs` — so the
    /// version module stays free of event/render knowledge; the enum is the
    /// domain type, rendering is serialize-module behavior.
    ///
    /// The rendered body must carry a zero-size version string
    /// (`KERI10JSON000000_`) and `said_placeholder` in every SAID slot; the
    /// orchestration in [`serialize_event`] backpatches the measured size,
    /// computes the SAID over the size-corrected bytes, and splices it into
    /// the reported slots.
    ///
    /// # Errors
    ///
    /// Returns [`SerderError::UnsupportedSerializationKind`] for kinds with
    /// no body codec (everything but JSON today — mirroring the strict
    /// reader, which rejects non-JSON version strings), or any render error.
    fn render(
        self,
        event: EventRef<'_>,
        said_placeholder: &str,
        buf: &mut Vec<u8>,
    ) -> Result<EventLayout, SerderError>;
}

impl RenderBody for SerializationKind {
    fn render(
        self,
        event: EventRef<'_>,
        said_placeholder: &str,
        buf: &mut Vec<u8>,
    ) -> Result<EventLayout, SerderError> {
        match self {
            Self::Json => event.render(said_placeholder, buf),
            Self::Cbor | Self::Mgpk | Self::Cesr => {
                Err(SerderError::UnsupportedSerializationKind(self))
            }
        }
    }
}

/// Serialize an event through the single canonical writer: render once with
/// a placeholder SAID and zero-size version string, backpatch the measured
/// size in place, compute the SAID over the size-corrected bytes, and
/// splice it into the reported slot(s).
///
/// The SAID digest algorithm is the event's own ([`EventRef::said_code`]) —
/// not a hardcoded Blake3-256 — so parsed events re-serialize under their
/// original code and builders can select any [`DigestCode`].
///
/// # Errors
///
/// Returns [`SerderError`] if rendering fails or the event exceeds the
/// version string's size capacity.
pub(crate) fn serialize_event(event: EventRef<'_>) -> Result<SerializedEvent, SerderError> {
    let digest_code = event.said_code();
    let placeholder = said_placeholder(digest_code)?;

    let mut buf = Vec::new();
    let layout = SerializationKind::Json.render(event, &placeholder, &mut buf)?;

    let size = buf.len();
    let size_u32 = u32::try_from(size)
        .ok()
        .filter(|s| *s <= VERSION_SIZE_MAX)
        .ok_or(SerderError::Version(VersionError::FieldOverflow {
            field: "size",
            max: VERSION_SIZE_MAX,
        }))?;
    patch_slot(&mut buf, &layout.size, format!("{size_u32:06x}").as_bytes())?;

    let said = compute_digest(&buf, digest_code)?;
    let said_qb64 = to_qb64_string(&said);
    patch_slot(&mut buf, &layout.said, said_qb64.as_bytes())?;

    let prefix = layout
        .prefix
        .as_ref()
        .map(|slot| {
            patch_slot(&mut buf, slot, said_qb64.as_bytes())?;
            Ok::<_, SerderError>(said.clone())
        })
        .transpose()?;

    Ok(SerializedEvent {
        raw: buf,
        said,
        prefix,
        ilk: event.ilk(),
        size,
        event: (),
    })
}

/// Overwrite a fixed-width slot in place, verifying bounds and width.
fn patch_slot(buf: &mut [u8], slot: &Range<usize>, replacement: &[u8]) -> Result<(), SerderError> {
    let dst = buf
        .get_mut(slot.clone())
        .ok_or(SerderError::InvalidEventLayout("slot out of bounds"))?;
    if dst.len() != replacement.len() {
        return Err(SerderError::InvalidEventLayout(
            "slot width does not match replacement",
        ));
    }
    dst.copy_from_slice(replacement);
    Ok(())
}

/// A fully serialized KERI event with computed SAID.
///
/// The type parameter `E` carries the deserialized event when constructed via
/// a typed builder. The default `()` preserves backward compatibility for
/// untyped serialization paths.
///
/// Produced by event-specific serializer functions; there is no public
/// constructor.
pub struct SerializedEvent<E = ()> {
    pub(crate) raw: Vec<u8>,
    pub(crate) said: Saider<'static>,
    pub(crate) prefix: Option<Saider<'static>>,
    pub(crate) ilk: Ilk,
    pub(crate) size: usize,
    pub(crate) event: E,
}

impl<E> SerializedEvent<E> {
    /// The canonical JSON bytes (SAID has been spliced in).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// The computed SAID for this event.
    #[must_use]
    pub const fn said(&self) -> &Saider<'static> {
        &self.said
    }

    /// The self-addressing prefix, if this is an inception or delegated
    /// inception event whose identifier is self-addressing (`i == d`).
    /// `None` for basic-derivation inceptions, whose prefix is the public
    /// key carried in the event itself, and for all other ilks.
    #[must_use]
    pub const fn prefix(&self) -> Option<&Saider<'static>> {
        self.prefix.as_ref()
    }

    /// The identifier prefix as an [`Identifier`], if this event carries a
    /// self-addressing prefix (inception or delegated inception).
    ///
    /// This is the ergonomic bridge for building a self-addressing KEL chain:
    /// feed the returned value into a rotation or interaction builder's
    /// `prefix` setter to construct the next event without re-parsing the
    /// serialized JSON. Returns `None` for `rot`/`ixn` events, which do not
    /// store a self-addressing prefix (their identifier is carried forward from
    /// the inception), and for basic-derivation inceptions, whose identifier
    /// is the public key already held by the caller.
    #[must_use]
    pub fn identifier(&self) -> Option<Identifier<'static>> {
        self.prefix.clone().map(Identifier::SelfAddressing)
    }

    /// The event type (ilk).
    #[must_use]
    pub const fn ilk(&self) -> Ilk {
        self.ilk
    }

    /// Total serialized size in bytes.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.size
    }

    /// The deserialized event, if this was constructed with a typed builder.
    #[must_use]
    pub const fn event(&self) -> &E {
        &self.event
    }

    /// Consume the wrapper and return the typed event.
    #[must_use]
    pub fn into_event(self) -> E {
        self.event
    }

    /// Frames this event with its attachments as a KERI/CESR V1 message —
    /// the byte-exact write mirror of
    /// [`EventMessage::parse`](crate::EventMessage::parse).
    ///
    /// Layout, exactly as keripy's `messagize` emits it (at the pin,
    /// `src/keri/core/eventing.py`): body, then one `-V` attachment group
    /// counter whose count is the attachment region's size in quadlets
    /// (4-char units, `eventing.py:1692-1694`), then the `-A` controller
    /// indexed signature group (`eventing.py:1622-1624`), then the optional
    /// `-B` witness indexed signature group (`eventing.py:1668-1673`).
    /// Empty groups are omitted, mirroring messagize's `if sigers:` /
    /// `if wigers:` guards (`eventing.py:1605`, `1668`), and the `-V`
    /// counter auto-promotes to its big `--V` form above 4095 quadlets like
    /// keripy's `Counter` (`counting.py:872-875`).
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::MissingAuthenticator`] if both groups are
    /// empty (messagize refuses the same shape, `eventing.py:1582-1583`),
    /// or [`FrameError::Encode`] if a group count or the quadlet count
    /// exceeds its counter code's capacity.
    pub fn frame_v1(
        &self,
        sigs: &ControllerIdxSigs,
        wigs: Option<&WitnessIdxSigs>,
    ) -> Result<Vec<u8>, FrameError> {
        let mut attachment = BytesMut::new();
        if sigs.count() > 0 {
            CesrEncode::<V1>::encode_cesr(sigs, &mut attachment)?;
        }
        if let Some(receipts) = wigs.filter(|w| w.count() > 0) {
            CesrEncode::<V1>::encode_cesr(receipts, &mut attachment)?;
        }
        if attachment.is_empty() {
            return Err(FrameError::MissingAuthenticator);
        }
        // Group qb64 is quadlet-aligned by construction; keripy still
        // checks before counting (`eventing.py:1687-1689`), and so do we —
        // a misaligned region must fail typed, never frame corrupt bytes.
        if !attachment.len().is_multiple_of(4) {
            return Err(FrameError::Encode(ParseError::Malformed(format!(
                "attachment region of {} bytes is not whole quadlets",
                attachment.len()
            ))));
        }
        let quadlets = u32::try_from(attachment.len() / 4).map_err(|_| {
            FrameError::Encode(ParseError::Malformed(format!(
                "attachment region of {} bytes exceeds the quadlet count range",
                attachment.len()
            )))
        })?;
        let counter = CounterCodeV1::AttachmentGroup.encode_count_auto(quadlets)?;
        let mut msg = self.raw.clone();
        msg.extend_from_slice(&counter);
        msg.extend_from_slice(&attachment);
        Ok(msg)
    }
}

#[cfg(test)]
#[allow(clippy::panic, reason = "panics are expected in test assertions")]
mod tests {
    use super::*;
    use alloc::borrow::Cow;
    use cesr::core::matter::builder::MatterBuilder;
    use cesr::core::matter::code::{DigestCode, VerKeyCode};
    use cesr::core::primitives::{Diger, Prefixer, Saider, Verfer};
    use keri_events::SigningThreshold;
    use keri_events::sequence::SequenceNumber;
    use keri_events::toad::Toad;
    use keri_events::{
        DelegatedInceptionEvent, DelegatedRotationEvent, InceptionEvent, InteractionEvent,
        RotationEvent, ThresholdForm,
    };

    fn make_prefixer() -> Prefixer<'static> {
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn make_saider() -> Saider<'static> {
        MatterBuilder::new()
            .with_code(DigestCode::Blake3_256)
            .with_raw(Cow::<[u8]>::Owned(vec![1u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn make_verfer() -> Verfer<'static> {
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![1u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn make_diger() -> Diger<'static> {
        MatterBuilder::new()
            .with_code(DigestCode::Blake3_256)
            .with_raw(Cow::<[u8]>::Owned(vec![2u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    mod frame_v1 {
        use super::*;
        use crate::builder::icp::InceptionBuilder;
        use cesr::core::indexer::IndexerBuilder;
        use cesr::core::indexer::code::IndexedSigCode;
        use cesr::core::primitives::Siger;

        fn make_siger(index: u32) -> Siger<'static> {
            Siger::new(
                IndexerBuilder::new()
                    .with_code(IndexedSigCode::Ed25519)
                    .with_index(index)
                    .unwrap()
                    .with_raw(vec![0x5Au8; 64])
                    .unwrap(),
            )
        }

        fn build_event() -> SerializedEvent {
            InceptionBuilder::new()
                .keys(vec![make_verfer()])
                .threshold(SigningThreshold::Simple(1))
                .next_keys(vec![make_diger()])
                .next_threshold(SigningThreshold::Simple(1))
                .build()
                .unwrap()
        }

        fn empty_sigs() -> ControllerIdxSigs {
            ControllerIdxSigs::from_sigers(&[]).unwrap()
        }

        #[test]
        fn layout_is_body_then_v_counter_then_controller_sigs() {
            // keripy messagize shape: 1 Ed25519 siger (88 chars) + `-A`
            // counter (4 chars) = 92 chars = 23 quadlets -> `-VAX`.
            let event = build_event();
            let siger = make_siger(0);
            let sigs = ControllerIdxSigs::from_sigers(core::slice::from_ref(&siger)).unwrap();

            let framed = event.frame_v1(&sigs, None).unwrap();

            let mut expected = event.as_bytes().to_vec();
            expected.extend_from_slice(b"-VAX-AAB");
            expected.extend_from_slice(siger.to_qb64().as_bytes());
            assert_eq!(framed, expected);
        }

        #[test]
        fn witness_group_follows_controller_group() {
            // 2 groups: (4 + 88) + (4 + 88) = 184 chars = 46 quadlets -> `-VAu`.
            let event = build_event();
            let siger = make_siger(0);
            let wiger = make_siger(0);
            let sigs = ControllerIdxSigs::from_sigers(core::slice::from_ref(&siger)).unwrap();
            let wigs = WitnessIdxSigs::from_sigers(core::slice::from_ref(&wiger)).unwrap();

            let framed = event.frame_v1(&sigs, Some(&wigs)).unwrap();

            let mut expected = event.as_bytes().to_vec();
            expected.extend_from_slice(b"-VAu-AAB");
            expected.extend_from_slice(siger.to_qb64().as_bytes());
            expected.extend_from_slice(b"-BAB");
            expected.extend_from_slice(wiger.to_qb64().as_bytes());
            assert_eq!(framed, expected);
        }

        #[test]
        fn empty_controller_group_is_omitted_like_messagize() {
            // keripy `if sigers:` guard (eventing.py:1605): receipts-only
            // messages carry just the `-B` group inside the `-V` frame.
            let event = build_event();
            let wiger = make_siger(0);
            let wigs = WitnessIdxSigs::from_sigers(core::slice::from_ref(&wiger)).unwrap();

            let framed = event.frame_v1(&empty_sigs(), Some(&wigs)).unwrap();

            let mut expected = event.as_bytes().to_vec();
            expected.extend_from_slice(b"-VAX-BAB");
            expected.extend_from_slice(wiger.to_qb64().as_bytes());
            assert_eq!(framed, expected);
        }

        #[test]
        fn no_authenticator_is_rejected() {
            // keripy raises "Missing authenticator" (eventing.py:1582-1583).
            let event = build_event();
            let err = event.frame_v1(&empty_sigs(), None).unwrap_err();
            assert!(matches!(err, FrameError::MissingAuthenticator));

            let empty_wigs = WitnessIdxSigs::from_sigers(&[]).unwrap();
            let err_with_empty_wigs = event
                .frame_v1(&empty_sigs(), Some(&empty_wigs))
                .unwrap_err();
            assert!(matches!(
                err_with_empty_wigs,
                FrameError::MissingAuthenticator
            ));
        }

        #[test]
        fn controller_count_over_v1_counter_capacity_is_an_encode_error() {
            // 4096 sigers exceed the `-A` counter's soft capacity (ss=2,
            // max 4095) and V1 has no big controller-sig code
            // (CounterCodex_1_0, counting.py:58) — the frame must fail
            // typed, never emit a corrupt counter.
            let event = build_event();
            let sigers = vec![make_siger(0); 4096];
            let sigs = ControllerIdxSigs::from_sigers(&sigers).unwrap();
            let err = event.frame_v1(&sigs, None).unwrap_err();
            assert!(matches!(err, FrameError::Encode(ParseError::Malformed(_))));
        }
    }

    #[test]
    fn serialize_dispatches_icp() {
        let event = KeriEvent::Inception(InceptionEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(0),
            make_saider(),
            vec![make_verfer()],
            SigningThreshold::Simple(1),
            vec![make_diger()],
            SigningThreshold::Simple(1),
            vec![],
            Toad::exact(0, 0).unwrap(),
            vec![],
            vec![],
            ThresholdForm::HexString,
        ));
        let result = event.serialize().unwrap();
        assert_eq!(result.ilk(), Ilk::Icp);
    }

    #[test]
    fn serialize_dispatches_rot() {
        let event = KeriEvent::Rotation(RotationEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(1),
            make_saider(),
            make_saider(),
            vec![make_verfer()],
            SigningThreshold::Simple(1),
            vec![make_diger()],
            SigningThreshold::Simple(1),
            vec![],
            vec![],
            Toad::from_wire(0),
            vec![],
            ThresholdForm::HexString,
        ));
        let result = event.serialize().unwrap();
        assert_eq!(result.ilk(), Ilk::Rot);
    }

    #[test]
    fn serialize_dispatches_ixn() {
        let event = KeriEvent::Interaction(InteractionEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(1),
            make_saider(),
            make_saider(),
            vec![],
        ));
        let result = event.serialize().unwrap();
        assert_eq!(result.ilk(), Ilk::Ixn);
    }

    #[test]
    fn serialize_dispatches_dip() {
        let event = KeriEvent::DelegatedInception(DelegatedInceptionEvent::new(
            InceptionEvent::new(
                make_prefixer().into(),
                SequenceNumber::new(0),
                make_saider(),
                vec![make_verfer()],
                SigningThreshold::Simple(1),
                vec![make_diger()],
                SigningThreshold::Simple(1),
                vec![],
                Toad::exact(0, 0).unwrap(),
                vec![],
                vec![],
                ThresholdForm::HexString,
            ),
            make_prefixer().into(),
        ));
        let result = event.serialize().unwrap();
        assert_eq!(result.ilk(), Ilk::Dip);
    }

    #[test]
    fn serialize_dispatches_drt() {
        let event = KeriEvent::DelegatedRotation(DelegatedRotationEvent::new(RotationEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(1),
            make_saider(),
            make_saider(),
            vec![make_verfer()],
            SigningThreshold::Simple(1),
            vec![make_diger()],
            SigningThreshold::Simple(1),
            vec![],
            vec![],
            Toad::from_wire(0),
            vec![],
            ThresholdForm::HexString,
        )));
        let result = event.serialize().unwrap();
        assert_eq!(result.ilk(), Ilk::Drt);
    }

    #[test]
    fn serialized_event_default_event_is_unit() {
        let event = KeriEvent::Inception(InceptionEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(0),
            make_saider(),
            vec![make_verfer()],
            SigningThreshold::Simple(1),
            vec![make_diger()],
            SigningThreshold::Simple(1),
            vec![],
            Toad::exact(0, 0).unwrap(),
            vec![],
            vec![],
            ThresholdForm::HexString,
        ));
        let result = event.serialize().unwrap();
        assert_eq!(*result.event(), ());
        assert_eq!(result.into_event(), ());
    }

    #[test]
    fn identifier_bridges_inception_prefix() {
        use crate::builder::icp::InceptionBuilder;

        let verfer = MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(alloc::vec![7u8; 32])
            .unwrap()
            .build()
            .unwrap();

        let icp = InceptionBuilder::new()
            .keys(alloc::vec![verfer])
            .build()
            .unwrap();

        let id = icp
            .identifier()
            .expect("inception exposes a self-addressing identifier");
        let saider = id
            .as_saider()
            .expect("inception identifier must be self-addressing");
        assert_eq!(
            saider.raw(),
            icp.prefix().unwrap().raw(),
            "identifier wraps the prefix SAID"
        );
    }

    // patch_slot — the backpatch safety boundary: any layout inconsistency
    // must surface as a typed error, never a panic or silent corruption.

    #[test]
    fn patch_slot_overwrites_exact_window() {
        let mut buf = b"aaaaaa".to_vec();
        patch_slot(&mut buf, &(2..4), b"XY").unwrap();
        assert_eq!(&buf, b"aaXYaa");
    }

    #[test]
    fn patch_slot_out_of_bounds_is_rejected() {
        let mut buf = vec![0u8; 4];
        let result = patch_slot(&mut buf, &(2..8), b"XXXXXX");
        assert!(matches!(
            result,
            Err(SerderError::InvalidEventLayout("slot out of bounds"))
        ));
    }

    #[test]
    fn patch_slot_reversed_range_is_rejected() {
        let mut buf = vec![0u8; 8];
        // Struct-literal form: the `6..2` expression is a compile-time lint,
        // but a reversed Range can still arise at runtime.
        let result = patch_slot(&mut buf, &Range { start: 6, end: 2 }, b"");
        assert!(matches!(
            result,
            Err(SerderError::InvalidEventLayout("slot out of bounds"))
        ));
    }

    #[test]
    fn patch_slot_wrong_width_is_rejected() {
        let mut buf = vec![0u8; 8];
        let result = patch_slot(&mut buf, &(0..4), b"XX");
        assert!(matches!(
            result,
            Err(SerderError::InvalidEventLayout(
                "slot width does not match replacement"
            ))
        ));
    }

    // -----------------------------------------------------------------------
    // EventRef — ilk / double-SAID / From<&KeriEvent> mapping
    // -----------------------------------------------------------------------

    fn probe_icp_event() -> InceptionEvent<'static> {
        InceptionEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(0),
            make_saider(),
            vec![make_verfer()],
            SigningThreshold::Simple(1),
            vec![make_diger()],
            SigningThreshold::Simple(1),
            vec![],
            Toad::exact(0, 0).unwrap(),
            vec![],
            vec![],
            ThresholdForm::HexString,
        )
    }

    fn probe_rot_event() -> RotationEvent<'static> {
        RotationEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(1),
            make_saider(),
            make_saider(),
            vec![make_verfer()],
            SigningThreshold::Simple(1),
            vec![make_diger()],
            SigningThreshold::Simple(1),
            vec![],
            vec![],
            Toad::from_wire(0),
            vec![],
            ThresholdForm::HexString,
        )
    }

    fn probe_ixn_event() -> InteractionEvent<'static> {
        InteractionEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(1),
            make_saider(),
            make_saider(),
            vec![],
        )
    }

    fn probe_self_addressing_icp_event() -> InceptionEvent<'static> {
        InceptionEvent::new(
            Identifier::SelfAddressing(make_saider()),
            SequenceNumber::new(0),
            make_saider(),
            vec![make_verfer()],
            SigningThreshold::Simple(1),
            vec![make_diger()],
            SigningThreshold::Simple(1),
            vec![],
            Toad::exact(0, 0).unwrap(),
            vec![],
            vec![],
            ThresholdForm::HexString,
        )
    }

    #[test]
    fn event_ref_ilk_and_double_said_mapping() {
        // Double-SAID is a property of the prefix derivation, not the ilk
        // (#144): the probe icp/dip events carry a Basic prefix, so they are
        // single-SAID; their self-addressing counterparts are double-SAID.
        let icp = probe_icp_event();
        let icp_sa = probe_self_addressing_icp_event();
        let rot = probe_rot_event();
        let ixn = probe_ixn_event();
        let dip = DelegatedInceptionEvent::new(probe_icp_event(), make_prefixer().into());
        let dip_sa =
            DelegatedInceptionEvent::new(probe_self_addressing_icp_event(), make_prefixer().into());
        let drt = DelegatedRotationEvent::new(probe_rot_event());

        let cases: [(EventRef<'_>, Ilk, bool); 7] = [
            (EventRef::Inception(&icp), Ilk::Icp, false),
            (EventRef::Inception(&icp_sa), Ilk::Icp, true),
            (EventRef::Rotation(&rot), Ilk::Rot, false),
            (EventRef::Interaction(&ixn), Ilk::Ixn, false),
            (EventRef::DelegatedInception(&dip), Ilk::Dip, false),
            (EventRef::DelegatedInception(&dip_sa), Ilk::Dip, true),
            (EventRef::DelegatedRotation(&drt), Ilk::Drt, false),
        ];
        for (event, ilk, double_said) in cases {
            assert_eq!(event.ilk(), ilk);
            assert_eq!(event.is_double_said(), double_said, "ilk {ilk:?}");
        }
    }

    #[test]
    fn event_ref_from_keri_event_preserves_variant() {
        let events = [
            (KeriEvent::Inception(probe_icp_event()), Ilk::Icp),
            (KeriEvent::Rotation(probe_rot_event()), Ilk::Rot),
            (KeriEvent::Interaction(probe_ixn_event()), Ilk::Ixn),
            (
                KeriEvent::DelegatedInception(DelegatedInceptionEvent::new(
                    probe_icp_event(),
                    make_prefixer().into(),
                )),
                Ilk::Dip,
            ),
            (
                KeriEvent::DelegatedRotation(DelegatedRotationEvent::new(probe_rot_event())),
                Ilk::Drt,
            ),
        ];
        for (event, ilk) in &events {
            assert_eq!(EventRef::from(event).ilk(), *ilk);
        }
    }

    #[test]
    fn non_json_kinds_fail_loud_with_typed_error() {
        let ixn = probe_ixn_event();
        let placeholder = "#".repeat(44);
        for kind in [
            SerializationKind::Cbor,
            SerializationKind::Mgpk,
            SerializationKind::Cesr,
        ] {
            let mut buf = Vec::new();
            let result = kind.render(EventRef::Interaction(&ixn), &placeholder, &mut buf);
            let Err(SerderError::UnsupportedSerializationKind(k)) = result else {
                panic!("expected UnsupportedSerializationKind for {kind:?}");
            };
            assert_eq!(k, kind);
            assert!(buf.is_empty(), "unsupported kind must not write");
        }
    }

    // -----------------------------------------------------------------------
    // Opaque-seal scanner ⊆ serde_json `Value` parsing — every payload the
    // scanner accepts must reparse, so the strict reader can materialize any
    // stored anchor. (The production write path splices the caller-guaranteed
    // opaque payload verbatim — `Seal::encode`'s `Opaque` arm — and never
    // re-parses.) One known
    // carve-out: `Value` parsing recurses with a 128-deep limit while the
    // scanner is depth-unbounded by design (DoS hardening); the strategy's
    // generated depth stays far below the limit.
    // -----------------------------------------------------------------------

    use crate::deserialize::opaque_scan::OpaqueScan;
    use proptest::prelude::*;
    use serde_json::Value;

    fn json_fragment() -> impl Strategy<Value = &'static str> {
        prop_oneof![
            Just("{"),
            Just("}"),
            Just("["),
            Just("]"),
            Just(","),
            Just(":"),
            Just("\""),
            Just("\"k\""),
            Just("\"k\":"),
            Just("0"),
            Just("1"),
            Just("01"),
            Just("-"),
            Just("-0"),
            Just("-2.5e+10"),
            Just("1e2"),
            Just("."),
            Just("true"),
            Just("false"),
            Just("null"),
            Just("tru"),
            Just(" "),
            Just("\t"),
            Just("\"\\t\""),
            Just("\"\\x\""),
            Just("\"\\u00e9\""),
            Just("\"\\ud800\""),
            Just("\"\\udc00\""),
            Just("\"\\ud83d\\ude00\""),
            Just("\u{e9}"),
            Just("\u{1F600}"),
        ]
    }

    fn fragment_concat() -> impl Strategy<Value = String> {
        proptest::collection::vec(json_fragment(), 0..12).prop_map(|tokens| tokens.concat())
    }

    fn opaque_candidate() -> impl Strategy<Value = String> {
        prop_oneof![
            // Fragments spliced into value position of a well-formed wrapper:
            // maximizes accepted payloads exercising the value grammar.
            fragment_concat().prop_map(|s| alloc::format!("{{\"k\":{s}}}")),
            // Raw concatenations probe framing (braces, commas, truncation).
            fragment_concat(),
        ]
    }

    proptest! {
        #[test]
        fn opaque_scanner_accepts_subset_of_serde_json(payload in opaque_candidate()) {
            // Whole-payload acceptance: the scan must succeed AND span the
            // full candidate (object_len measures a prefix; a valid object
            // followed by trailing bytes is not an accepted payload).
            if OpaqueScan::object_len(payload.as_bytes()).is_ok_and(|len| len == payload.len()) {
                prop_assert!(
                    serde_json::from_str::<Value>(&payload).is_ok(),
                    "scanner accepted a payload serde_json rejects: {payload}"
                );
            }
        }
    }

    #[test]
    fn opaque_scanner_agrees_with_serde_json_at_f64_overflow_boundary() {
        // Without `float_roundtrip`, serde_json's imprecise float parse
        // disagrees with std's correctly-rounded parse right at the f64
        // overflow boundary (e.g. 1.7976931348623158e308). The feature is
        // enabled so both sides round identically; the assertion is the
        // agreement itself, per literal, not a hardcoded verdict.
        for literal in [
            // f64::MAX exactly.
            "1.7976931348623157e308",
            // Rounds down to f64::MAX under correct rounding.
            "1.7976931348623158e308",
            // One more digit: the historical disagreement case.
            "1.79769313486231585e308",
            // Cases that overflow under correct rounding.
            "1.7976931348623159e308",
            "1e309",
        ] {
            let payload = alloc::format!("{{\"k\":{literal}}}");
            let scanner =
                OpaqueScan::object_len(payload.as_bytes()).is_ok_and(|len| len == payload.len());
            let serde = serde_json::from_str::<Value>(&payload).is_ok();
            assert_eq!(
                scanner, serde,
                "scanner ({scanner}) and serde_json ({serde}) must agree on {literal}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Per-ilk writer behavior (folded from the former serialize/{icp,rot,
    // ixn,dip,drt}.rs delegate modules; the SUT is the Serialize impl)
    // -----------------------------------------------------------------------

    mod icp {
        use super::*;
        use crate::primitives::to_qb64_string;
        use keri_events::ConfigTrait;
        use keri_events::WeightedThreshold;
        use serde_json::Value;

        fn make_event() -> InceptionEvent<'static> {
            InceptionEvent::new(
                Identifier::SelfAddressing(make_saider()),
                SequenceNumber::new(0),
                make_saider(),
                vec![make_verfer()],
                SigningThreshold::Simple(1),
                vec![make_diger()],
                SigningThreshold::Simple(1),
                vec![make_prefixer()],
                Toad::exact(1, 1).unwrap(),
                vec![],
                vec![],
                ThresholdForm::HexString,
            )
        }

        fn make_basic_event() -> InceptionEvent<'static> {
            InceptionEvent::new(
                make_prefixer().into(),
                SequenceNumber::new(0),
                make_saider(),
                vec![make_verfer()],
                SigningThreshold::Simple(1),
                vec![make_diger()],
                SigningThreshold::Simple(1),
                vec![make_prefixer()],
                Toad::exact(1, 1).unwrap(),
                vec![],
                vec![],
                ThresholdForm::HexString,
            )
        }

        #[test]
        fn serialize_icp_field_order() {
            let event = make_event();
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            let keys: Vec<&String> = parsed.as_object().unwrap().keys().collect();
            assert_eq!(
                keys,
                &[
                    "v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a"
                ]
            );
        }

        #[test]
        fn serialize_icp_ilk() {
            let event = make_event();
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            assert_eq!(parsed["t"].as_str().unwrap(), "icp");
            assert_eq!(result.ilk(), Ilk::Icp);
        }

        #[test]
        fn serialize_icp_self_addressing_prefix() {
            let event = make_event();
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            let d = parsed["d"].as_str().unwrap();
            let i = parsed["i"].as_str().unwrap();
            assert_eq!(
                d, i,
                "d and i must be equal for self-addressing inception events"
            );
        }

        #[test]
        fn serialize_icp_basic_prefix_verbatim_single_said() {
            // #144: a basic-derivation inception carries its public key in `i`
            // and computes the SAID over the event with only `d` dummied.
            let event = make_basic_event();
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            let d = parsed["d"].as_str().unwrap();
            let i = parsed["i"].as_str().unwrap();

            assert_eq!(
                i,
                to_qb64_string(event.prefix().as_prefixer().unwrap()),
                "basic prefix must serialize verbatim"
            );
            assert_ne!(d, i, "basic inception is single-SAID");

            let placeholder = crate::said::said_placeholder(DigestCode::Blake3_256).unwrap();
            let mut verify_obj = parsed.clone();
            let obj = verify_obj.as_object_mut().unwrap();
            obj.insert("d".to_owned(), Value::String(placeholder));
            let reser = serde_json::to_string(&verify_obj).unwrap();
            let computed =
                crate::said::compute_digest(reser.as_bytes(), DigestCode::Blake3_256).unwrap();
            assert_eq!(
                d,
                crate::primitives::to_qb64_string(&computed),
                "single-SAID must verify with `i` left intact"
            );
        }

        #[test]
        fn serialize_icp_said_is_valid() {
            let event = make_event();
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            let d = parsed["d"].as_str().unwrap();

            assert!(d.starts_with('E'), "Blake3_256 SAID should start with 'E'");
            assert_eq!(d.len(), 44);

            let placeholder = crate::said::said_placeholder(DigestCode::Blake3_256).unwrap();
            let mut verify_obj = parsed.clone();
            let obj = verify_obj.as_object_mut().unwrap();
            obj.insert("d".to_owned(), Value::String(placeholder.clone()));
            obj.insert("i".to_owned(), Value::String(placeholder));
            let reser = serde_json::to_string(&verify_obj).unwrap();
            let computed =
                crate::said::compute_digest(reser.as_bytes(), DigestCode::Blake3_256).unwrap();
            let computed_qb64 = crate::primitives::to_qb64_string(&computed);
            assert_eq!(d, computed_qb64, "SAID verification should pass");
        }

        #[test]
        fn serialize_icp_version_string_size() {
            let event = make_event();
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            let vs_str = parsed["v"].as_str().unwrap();
            let (vs, _) = cesr::core::version::VersionString::parse(vs_str.as_bytes()).unwrap();
            assert_eq!(usize::try_from(vs.size()).unwrap(), result.size());
            assert_eq!(result.size(), result.as_bytes().len());
        }

        #[test]
        fn serialize_icp_simple_threshold() {
            let event = make_event();
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            assert_eq!(parsed["kt"].as_str().unwrap(), "1");
        }

        #[test]
        fn serialize_icp_weighted_threshold() {
            let event = InceptionEvent::new(
                make_prefixer().into(),
                SequenceNumber::new(0),
                make_saider(),
                vec![make_verfer(), make_verfer()],
                SigningThreshold::Weighted(
                    WeightedThreshold::from_nested(vec![
                        vec![(1, 2), (1, 2)],
                        vec![(1, 3), (1, 3), (1, 3)],
                    ])
                    .unwrap(),
                ),
                vec![make_diger()],
                SigningThreshold::Simple(1),
                vec![make_prefixer()],
                Toad::exact(1, 1).unwrap(),
                vec![],
                vec![],
                ThresholdForm::HexString,
            );
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            let kt = &parsed["kt"];
            assert!(kt.is_array(), "weighted threshold should be an array");
            let outer = kt.as_array().unwrap();
            assert_eq!(outer.len(), 2);
            let clause0 = outer[0].as_array().unwrap();
            assert_eq!(clause0.len(), 2);
            assert_eq!(clause0[0].as_str().unwrap(), "1/2");
            assert_eq!(clause0[1].as_str().unwrap(), "1/2");
            let clause1 = outer[1].as_array().unwrap();
            assert_eq!(clause1.len(), 3);
            assert_eq!(clause1[0].as_str().unwrap(), "1/3");
        }

        #[test]
        fn serialize_icp_keys_and_witnesses() {
            let event = InceptionEvent::new(
                make_prefixer().into(),
                SequenceNumber::new(0),
                make_saider(),
                vec![make_verfer(), make_verfer()],
                SigningThreshold::Simple(1),
                vec![make_diger(), make_diger(), make_diger()],
                SigningThreshold::Simple(1),
                vec![make_prefixer(), make_prefixer()],
                Toad::exact(1, 2).unwrap(),
                vec![],
                vec![],
                ThresholdForm::HexString,
            );
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();

            let k = parsed["k"].as_array().unwrap();
            assert_eq!(k.len(), 2);
            for v in k {
                let s = v.as_str().unwrap();
                assert_eq!(s.len(), 44, "qb64 key should be 44 chars");
            }

            let n = parsed["n"].as_array().unwrap();
            assert_eq!(n.len(), 3);
            for v in n {
                let s = v.as_str().unwrap();
                assert_eq!(s.len(), 44, "qb64 digest should be 44 chars");
            }

            let b = parsed["b"].as_array().unwrap();
            assert_eq!(b.len(), 2);
            for v in b {
                let s = v.as_str().unwrap();
                assert_eq!(s.len(), 44, "qb64 witness prefix should be 44 chars");
            }
        }

        #[test]
        fn serialize_icp_config_traits() {
            let event = InceptionEvent::new(
                make_prefixer().into(),
                SequenceNumber::new(0),
                make_saider(),
                vec![make_verfer()],
                SigningThreshold::Simple(1),
                vec![make_diger()],
                SigningThreshold::Simple(1),
                vec![make_prefixer()],
                Toad::exact(1, 1).unwrap(),
                vec![ConfigTrait::EstOnly],
                vec![],
                ThresholdForm::HexString,
            );
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            let c = parsed["c"].as_array().unwrap();
            assert_eq!(c.len(), 1);
            assert_eq!(c[0].as_str().unwrap(), "EO");
        }
    }

    mod rot {
        use super::*;

        fn make_event() -> RotationEvent<'static> {
            probe_rot_event()
        }

        #[test]
        fn serialize_rot_field_order() {
            let event = make_event();
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            let keys: Vec<&String> = parsed.as_object().unwrap().keys().collect();
            assert_eq!(
                keys,
                &[
                    "v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "a"
                ]
            );
        }

        #[test]
        fn serialize_rot_ilk() {
            let event = make_event();
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            assert_eq!(parsed["t"].as_str().unwrap(), "rot");
            assert_eq!(result.ilk(), Ilk::Rot);
        }

        #[test]
        fn serialize_rot_said_is_valid() {
            let event = make_event();
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            let d = parsed["d"].as_str().unwrap();

            assert!(d.starts_with('E'), "Blake3_256 SAID should start with 'E'");
            assert_eq!(d.len(), 44);

            crate::said::verify_said(result.as_bytes(), DigestCode::Blake3_256)
                .expect("SAID verification should pass");
        }

        #[test]
        fn serialize_rot_version_string_size() {
            let event = make_event();
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            let vs_str = parsed["v"].as_str().unwrap();
            let (vs, _) = cesr::core::version::VersionString::parse(vs_str.as_bytes()).unwrap();
            assert_eq!(usize::try_from(vs.size()).unwrap(), result.size());
            assert_eq!(result.size(), result.as_bytes().len());
        }

        #[test]
        fn serialize_rot_prefix_is_not_saidive() {
            let event = make_event();
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            let d = parsed["d"].as_str().unwrap();
            let i = parsed["i"].as_str().unwrap();
            assert_ne!(d, i, "rotation prefix must not equal the SAID");
        }

        #[test]
        fn serialize_rot_prior_event_said() {
            let event = make_event();
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            let p = parsed["p"].as_str().unwrap();
            assert_eq!(p.len(), 44, "prior event SAID should be 44 chars");
            assert!(p.starts_with('E'), "Blake3_256 qb64 should start with 'E'");
        }

        #[test]
        fn serialize_rot_witness_additions_removals() {
            let event = RotationEvent::new(
                make_prefixer().into(),
                SequenceNumber::new(1),
                make_saider(),
                make_saider(),
                vec![make_verfer()],
                SigningThreshold::Simple(1),
                vec![make_diger()],
                SigningThreshold::Simple(1),
                vec![make_prefixer(), make_prefixer()],
                vec![make_prefixer()],
                Toad::from_wire(1),
                vec![],
                ThresholdForm::HexString,
            );
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();

            let ba = parsed["ba"].as_array().unwrap();
            assert_eq!(ba.len(), 2);
            for v in ba {
                let s = v.as_str().unwrap();
                assert_eq!(s.len(), 44, "qb64 witness prefix should be 44 chars");
            }

            let br = parsed["br"].as_array().unwrap();
            assert_eq!(br.len(), 1);
            for v in br {
                let s = v.as_str().unwrap();
                assert_eq!(s.len(), 44, "qb64 witness prefix should be 44 chars");
            }
        }

        #[test]
        fn rot_wire_has_no_config_field() {
            let event = make_event();
            let out = event.serialize().unwrap();
            let json = core::str::from_utf8(out.as_bytes()).unwrap();
            assert!(!json.contains("\"c\":"), "v1 rot must not emit a c field");
        }
    }

    mod ixn {
        use super::*;
        use cesr::core::version::{VERSION_SIZE_MAX, VersionError, VersionString};
        use keri_events::Seal;

        fn make_event() -> InteractionEvent<'static> {
            probe_ixn_event()
        }

        #[test]
        fn serialize_ixn_field_order() {
            let event = make_event();
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            let keys: Vec<&String> = parsed.as_object().unwrap().keys().collect();
            assert_eq!(keys, &["v", "t", "d", "i", "s", "p", "a"]);
        }

        #[test]
        fn serialize_ixn_ilk() {
            let event = make_event();
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            assert_eq!(parsed["t"].as_str().unwrap(), "ixn");
            assert_eq!(result.ilk(), Ilk::Ixn);
        }

        #[test]
        fn serialize_ixn_rejects_event_beyond_version_size_capacity() {
            // Bug probe: an event whose JSON exceeds the six-hex-digit size
            // field (16 MiB - 1) previously rendered a widened version string,
            // silently corrupting the frame instead of returning an error.
            let anchors: Vec<Seal> = (0..340_000)
                .map(|_| Seal::Digest { d: make_saider() })
                .collect();
            let event = InteractionEvent::new(
                make_prefixer().into(),
                SequenceNumber::new(1),
                make_saider(),
                make_saider(),
                anchors,
            );
            let result = event.serialize();
            assert!(matches!(
                result,
                Err(SerderError::Version(VersionError::FieldOverflow {
                    field: "size",
                    max: VERSION_SIZE_MAX,
                }))
            ));
        }

        #[test]
        fn serialize_ixn_version_string_size_matches() {
            let event = make_event();
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            let vs_str = parsed["v"].as_str().unwrap();
            let (vs, _) = VersionString::parse(vs_str.as_bytes()).unwrap();
            assert_eq!(usize::try_from(vs.size()).unwrap(), result.size());
            assert_eq!(result.size(), result.as_bytes().len());
        }

        #[test]
        fn serialize_ixn_said_is_valid() {
            let event = make_event();
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            let d = parsed["d"].as_str().unwrap();

            assert!(d.starts_with('E'), "Blake3_256 SAID should start with 'E'");
            assert_eq!(d.len(), 44);

            crate::said::verify_said(result.as_bytes(), DigestCode::Blake3_256)
                .expect("SAID verification should pass");
        }

        #[test]
        fn serialize_ixn_with_digest_seal() {
            let event = InteractionEvent::new(
                make_prefixer().into(),
                SequenceNumber::new(3),
                make_saider(),
                make_saider(),
                vec![Seal::Digest { d: make_saider() }],
            );
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            let anchors = parsed["a"].as_array().unwrap();
            assert_eq!(anchors.len(), 1);
            assert!(anchors[0].get("d").is_some(), "seal should have 'd' field");
        }
    }

    mod dip {
        use super::*;
        use crate::primitives::identifier_to_qb64_string;
        use serde_json::Value;

        fn make_event() -> DelegatedInceptionEvent<'static> {
            DelegatedInceptionEvent::new(
                InceptionEvent::new(
                    Identifier::SelfAddressing(make_saider()),
                    SequenceNumber::new(0),
                    make_saider(),
                    vec![make_verfer()],
                    SigningThreshold::Simple(1),
                    vec![make_diger()],
                    SigningThreshold::Simple(1),
                    vec![make_prefixer()],
                    Toad::exact(1, 1).unwrap(),
                    vec![],
                    vec![],
                    ThresholdForm::HexString,
                ),
                make_prefixer().into(),
            )
        }

        #[test]
        fn serialize_dip_field_order() {
            let event = make_event();
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            let keys: Vec<&String> = parsed.as_object().unwrap().keys().collect();
            assert_eq!(
                keys,
                &[
                    "v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a", "di"
                ]
            );
        }

        #[test]
        fn serialize_dip_ilk() {
            let event = make_event();
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            assert_eq!(parsed["t"].as_str().unwrap(), "dip");
            assert_eq!(result.ilk(), Ilk::Dip);
        }

        #[test]
        fn serialize_dip_self_addressing_prefix() {
            let event = make_event();
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            let d = parsed["d"].as_str().unwrap();
            let i = parsed["i"].as_str().unwrap();
            assert_eq!(
                d, i,
                "d and i must be equal for self-addressing delegated inception events"
            );
        }

        #[test]
        fn serialize_dip_basic_prefix_verbatim_single_said() {
            // #144: the dip writer follows the Identifier variant exactly like
            // icp — a basic prefix is carried verbatim with a single-SAID `d`.
            let event = DelegatedInceptionEvent::new(probe_icp_event(), make_prefixer().into());
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            let d = parsed["d"].as_str().unwrap();
            let i = parsed["i"].as_str().unwrap();
            assert_eq!(
                i,
                identifier_to_qb64_string(event.inception().prefix()),
                "basic prefix must serialize verbatim"
            );
            assert_ne!(d, i, "basic delegated inception is single-SAID");
        }

        #[test]
        fn serialize_dip_said_is_valid() {
            let event = make_event();
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            let d = parsed["d"].as_str().unwrap();

            assert!(d.starts_with('E'), "Blake3_256 SAID should start with 'E'");
            assert_eq!(d.len(), 44);

            let placeholder = crate::said::said_placeholder(DigestCode::Blake3_256).unwrap();
            let mut verify_obj = parsed.clone();
            let obj = verify_obj.as_object_mut().unwrap();
            obj.insert("d".to_owned(), Value::String(placeholder.clone()));
            obj.insert("i".to_owned(), Value::String(placeholder));
            let reser = serde_json::to_string(&verify_obj).unwrap();
            let computed =
                crate::said::compute_digest(reser.as_bytes(), DigestCode::Blake3_256).unwrap();
            let computed_qb64 = crate::primitives::to_qb64_string(&computed);
            assert_eq!(d, computed_qb64, "SAID verification should pass");
        }

        #[test]
        fn serialize_dip_delegator() {
            let event = make_event();
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            let di = parsed["di"].as_str().unwrap();
            assert_eq!(
                di.len(),
                44,
                "delegator prefix should be a 44-char qb64 string"
            );
        }
    }

    mod drt {
        use super::*;

        fn make_event() -> DelegatedRotationEvent<'static> {
            DelegatedRotationEvent::new(probe_rot_event())
        }

        #[test]
        fn serialize_drt_field_order() {
            let event = make_event();
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            let keys: Vec<&String> = parsed.as_object().unwrap().keys().collect();
            assert_eq!(
                keys,
                &[
                    "v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "a"
                ]
            );
        }

        #[test]
        fn serialize_drt_ilk() {
            let event = make_event();
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            assert_eq!(parsed["t"].as_str().unwrap(), "drt");
            assert_eq!(result.ilk(), Ilk::Drt);
        }

        #[test]
        fn serialize_drt_said_is_valid() {
            let event = make_event();
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            let d = parsed["d"].as_str().unwrap();

            assert!(d.starts_with('E'), "Blake3_256 SAID should start with 'E'");
            assert_eq!(d.len(), 44);

            crate::said::verify_said(result.as_bytes(), DigestCode::Blake3_256)
                .expect("SAID verification should pass");
        }

        #[test]
        fn serialize_drt_prefix_is_not_saidive() {
            let event = make_event();
            let result = event.serialize().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(result.as_bytes()).unwrap();
            let d = parsed["d"].as_str().unwrap();
            let i = parsed["i"].as_str().unwrap();
            assert_ne!(d, i, "delegated rotation prefix must not equal the SAID");
        }

        #[test]
        fn drt_wire_has_no_config_field() {
            let event = make_event();
            let out = event.serialize().unwrap();
            let json = core::str::from_utf8(out.as_bytes()).unwrap();
            assert!(!json.contains("\"c\":"), "v1 drt must not emit a c field");
        }
    }
}
