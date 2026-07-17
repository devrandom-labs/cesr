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
/// Delegated inception event serializer.
pub mod dip;
/// Delegated rotation event serializer.
pub mod drt;
/// Inception event serializer.
pub mod icp;
/// Interaction event serializer.
pub mod ixn;
/// Canonical JSON body writer (the `SerializationKind::Json` codec).
mod json;
/// Rotation event serializer.
pub mod rot;

use crate::core::matter::code::DigestCode;
use crate::core::primitives::Saider;
use crate::keri::{
    DelegatedInceptionEvent, DelegatedRotationEvent, Identifier, Ilk, InceptionEvent,
    InteractionEvent, KeriEvent, RotationEvent,
};
use core::ops::Range;

use crate::core::counter::CounterCodeV1;
use crate::core::version::{SerializationKind, VERSION_SIZE_MAX, VersionError};
use crate::serder::error::{FrameError, SerderError};
use crate::serder::primitives::to_qb64_string;
use crate::serder::said::{compute_digest, said_placeholder};
use crate::stream::encode::encode_counter_auto_v1;
use crate::stream::error::ParseError;
use crate::stream::group::{ControllerIdxSigs, WitnessIdxSigs};
use crate::stream::version::{CesrEncode, V1};
use bytes::BytesMut;

pub use dip::serialize_delegated_inception;
pub use drt::serialize_delegated_rotation;
pub use icp::serialize_inception;
pub use ixn::serialize_interaction;
pub use rot::serialize_rotation;

/// Serialize any [`KeriEvent`] variant to canonical JSON with a computed SAID.
///
/// Dispatches to the event-specific serializer based on the variant.
///
/// # Errors
///
/// Returns [`SerderError`] if CESR primitive encoding or digest computation
/// fails.
pub fn serialize(event: &KeriEvent<'_>) -> Result<SerializedEvent, SerderError> {
    match event {
        KeriEvent::Inception(e) => serialize_inception(e),
        KeriEvent::Rotation(e) => serialize_rotation(e),
        KeriEvent::Interaction(e) => serialize_interaction(e),
        KeriEvent::DelegatedInception(e) => serialize_delegated_inception(e),
        KeriEvent::DelegatedRotation(e) => serialize_delegated_rotation(e),
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

impl SerializationKind {
    /// Render `event`'s body in this serialization kind into `buf`
    /// (appending), reporting the backpatchable slot layout.
    ///
    /// The inherent impl lives here — not in `version.rs` — so the version
    /// module stays free of event/render knowledge; the enum is the domain
    /// type, rendering is serialize-module behavior.
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
    pub(crate) fn render(
        self,
        event: EventRef<'_>,
        said_placeholder: &str,
        buf: &mut Vec<u8>,
    ) -> Result<EventLayout, SerderError> {
        match self {
            Self::Json => json::render(event, said_placeholder, buf),
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
    /// [`EventMessage::parse`](crate::serder::EventMessage::parse).
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
        let counter = encode_counter_auto_v1(CounterCodeV1::AttachmentGroup, quadlets)?;
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
    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::{DigestCode, VerKeyCode};
    use crate::core::primitives::{Diger, Prefixer, Saider, Verfer};
    use crate::keri::SigningThreshold;
    use crate::keri::sequence::SequenceNumber;
    use crate::keri::toad::Toad;
    use crate::keri::{
        DelegatedInceptionEvent, DelegatedRotationEvent, InceptionEvent, InteractionEvent,
        RotationEvent, ThresholdForm,
    };
    use alloc::borrow::Cow;

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
        use crate::core::indexer::IndexerBuilder;
        use crate::core::indexer::code::IndexedSigCode;
        use crate::core::primitives::Siger;
        use crate::serder::builder::icp::InceptionBuilder;

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
        let result = serialize(&event).unwrap();
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
        let result = serialize(&event).unwrap();
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
        let result = serialize(&event).unwrap();
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
        let result = serialize(&event).unwrap();
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
        let result = serialize(&event).unwrap();
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
        let result = serialize(&event).unwrap();
        assert_eq!(*result.event(), ());
        assert_eq!(result.into_event(), ());
    }

    #[test]
    fn identifier_bridges_inception_prefix() {
        use crate::serder::builder::icp::InceptionBuilder;

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
    // stored anchor. (The production write path splices the validated opaque
    // payload verbatim — `write_seal`'s `Seal::Opaque` arm — and never
    // re-parses.) One known
    // carve-out: `Value` parsing recurses with a 128-deep limit while the
    // scanner is depth-unbounded by design (DoS hardening); the strategy's
    // generated depth stays far below the limit.
    // -----------------------------------------------------------------------

    use crate::keri::OpaqueSeal;
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
            if OpaqueSeal::new(payload.clone()).is_ok() {
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
            let scanner = OpaqueSeal::new(payload.clone()).is_ok();
            let serde = serde_json::from_str::<Value>(&payload).is_ok();
            assert_eq!(
                scanner, serde,
                "scanner ({scanner}) and serde_json ({serde}) must agree on {literal}"
            );
        }
    }
}
