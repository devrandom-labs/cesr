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
use alloc::{borrow::ToOwned, format, string::String, vec, vec::Vec};
/// Delegated inception event serializer.
pub mod dip;
/// Direct serialization backend (hand-rolled canonical JSON writer).
pub mod direct;
/// Delegated rotation event serializer.
pub mod drt;
/// Inception event serializer.
pub mod icp;
/// Interaction event serializer.
pub mod ixn;
/// Rotation event serializer.
pub mod rot;

use crate::core::matter::code::{CesrCode, DigestCode};
use crate::core::matter::matter::Matter;
use crate::core::primitives::{Saider, Tholder};
use crate::keri::{
    DelegatedInceptionEvent, DelegatedRotationEvent, Identifier, Ilk, InceptionEvent,
    InteractionEvent, KeriEvent, RotationEvent, Seal,
};
use core::ops::Range;
use serde_json::{Map, Value};

use crate::serder::error::SerderError;
use crate::serder::primitives::{sn_to_hex, to_qb64_string};
use crate::serder::said::{compute_digest, said_placeholder};
use crate::serder::version::VERSION_SIZE_MAX;

pub use dip::serialize_delegated_inception;
pub use direct::DirectJson;
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
pub fn serialize(event: &KeriEvent) -> Result<SerializedEvent, SerderError> {
    match event {
        KeriEvent::Inception(e) => serialize_inception(e),
        KeriEvent::Rotation(e) => serialize_rotation(e),
        KeriEvent::Interaction(e) => serialize_interaction(e),
        KeriEvent::DelegatedInception(e) => serialize_delegated_inception(e),
        KeriEvent::DelegatedRotation(e) => serialize_delegated_rotation(e),
    }
}

// ---------------------------------------------------------------------------
// Serialization backend seam
// ---------------------------------------------------------------------------

/// Borrowed view over any KERI event, used to hand an event to a
/// serialization backend without cloning it into a [`KeriEvent`].
#[derive(Clone, Copy)]
pub enum EventRef<'e> {
    /// Inception (`icp`).
    Inception(&'e InceptionEvent),
    /// Rotation (`rot`).
    Rotation(&'e RotationEvent),
    /// Interaction (`ixn`).
    Interaction(&'e InteractionEvent),
    /// Delegated inception (`dip`).
    DelegatedInception(&'e DelegatedInceptionEvent),
    /// Delegated rotation (`drt`).
    DelegatedRotation(&'e DelegatedRotationEvent),
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

    /// Whether the event's identifier prefix is set to the computed SAID
    /// (the double-SAID property of inception and delegated inception).
    #[must_use]
    pub const fn is_double_said(self) -> bool {
        matches!(self, Self::Inception(_) | Self::DelegatedInception(_))
    }
}

impl<'e> From<&'e KeriEvent> for EventRef<'e> {
    fn from(event: &'e KeriEvent) -> Self {
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
/// Ranges are absolute indices into the buffer as it stands when
/// [`EventSerializer::render`] returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventLayout {
    /// The six-hex-digit size field inside the version string.
    pub size_slot: Range<usize>,
    /// The `d` field's qb64 SAID value (placeholder until spliced).
    pub said_slot: Range<usize>,
    /// The `i` field's qb64 value for double-SAID events (`icp`/`dip`).
    pub prefix_slot: Option<Range<usize>>,
}

/// A pluggable serialization backend: renders one event's canonical JSON
/// body into a caller-provided buffer and reports where the backpatchable
/// slots landed.
///
/// The rendered body must carry a zero-size version string
/// (`KERI10JSON000000_`) and `said_placeholder` in every SAID slot. The
/// shared orchestration in [`serialize_with`] backpatches the measured size,
/// computes the SAID over the size-corrected bytes, and splices it into the
/// reported slots. Backends only control *how* the bytes are produced —
/// every backend must render byte-identical output for the same event.
pub trait EventSerializer {
    /// Render `event` into `buf` (appending) and report the slot layout.
    ///
    /// # Errors
    ///
    /// Returns [`SerderError`] if the event cannot be rendered.
    fn render(
        &self,
        event: EventRef<'_>,
        said_placeholder: &str,
        buf: &mut Vec<u8>,
    ) -> Result<EventLayout, SerderError>;
}

/// The reference backend: renders through `serde_json` exactly as the
/// pre-seam serializers did.
#[derive(Debug, Clone, Copy, Default)]
pub struct SerdeJson;

impl EventSerializer for SerdeJson {
    fn render(
        &self,
        event: EventRef<'_>,
        said_placeholder: &str,
        buf: &mut Vec<u8>,
    ) -> Result<EventLayout, SerderError> {
        let json = match event {
            EventRef::Inception(e) => icp::render_json(e, said_placeholder)?,
            EventRef::Rotation(e) => rot::render_json(e, said_placeholder)?,
            EventRef::Interaction(e) => ixn::render_json(e, said_placeholder)?,
            EventRef::DelegatedInception(e) => dip::render_json(e, said_placeholder)?,
            EventRef::DelegatedRotation(e) => drt::render_json(e, said_placeholder)?,
        };
        extend_with_layout(buf, &json, said_placeholder, event.is_double_said())
    }
}

/// Serialize an event through an explicit backend.
///
/// Shared orchestration for every backend: render once with a placeholder
/// SAID and zero-size version string, backpatch the measured size in place,
/// compute the SAID over the size-corrected bytes, and splice it into the
/// reported slot(s). This replaces the historical three-render pipeline —
/// both slots are fixed-width, so one render suffices.
///
/// # Errors
///
/// Returns [`SerderError`] if rendering fails, the event exceeds the
/// version string's size capacity, or the backend reports an inconsistent
/// layout.
pub fn serialize_with<B: EventSerializer>(
    backend: &B,
    event: EventRef<'_>,
) -> Result<SerializedEvent, SerderError> {
    let digest_code = DigestCode::Blake3_256;
    let placeholder = said_placeholder(digest_code)?;

    let mut buf = Vec::new();
    let layout = backend.render(event, &placeholder, &mut buf)?;

    let size = buf.len();
    let size_u32 = u32::try_from(size)
        .ok()
        .filter(|s| *s <= VERSION_SIZE_MAX)
        .ok_or(SerderError::VersionStringOverflow {
            field: "size",
            max: VERSION_SIZE_MAX,
        })?;
    patch_slot(
        &mut buf,
        &layout.size_slot,
        format!("{size_u32:06x}").as_bytes(),
    )?;

    let said = compute_digest(&buf, digest_code)?;
    let said_qb64 = to_qb64_string(&said);
    patch_slot(&mut buf, &layout.said_slot, said_qb64.as_bytes())?;

    let prefix = layout
        .prefix_slot
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

/// The zero-size v1 JSON version string every render must start from.
const ZERO_SIZE_VSTRING: &[u8] = b"KERI10JSON000000_";
/// Length of the leading `{"v":"` that precedes the version string.
const VSTRING_OFFSET: usize = 6;
/// Offset of the six size hex digits inside the version string.
const SIZE_OFFSET_IN_VSTRING: usize = 10;
/// Width of the size field in hex digits.
const SIZE_WIDTH: usize = 6;

/// Append `json` to `buf` and locate the version-size and SAID slots,
/// validating the render's framing along the way.
fn extend_with_layout(
    buf: &mut Vec<u8>,
    json: &str,
    placeholder: &str,
    double_said: bool,
) -> Result<EventLayout, SerderError> {
    let base = buf.len();
    let bytes = json.as_bytes();

    let vs_end = VSTRING_OFFSET.checked_add(ZERO_SIZE_VSTRING.len()).ok_or(
        SerderError::InvalidEventLayout("version-string bounds overflow"),
    )?;
    if bytes.get(..VSTRING_OFFSET) != Some(br#"{"v":""#.as_slice())
        || bytes.get(VSTRING_OFFSET..vs_end) != Some(ZERO_SIZE_VSTRING)
    {
        return Err(SerderError::InvalidEventLayout(
            "rendered JSON does not begin with a zero-size v1 version string",
        ));
    }

    let said_rel = find_subslice(bytes, placeholder.as_bytes(), 0).ok_or(
        SerderError::InvalidEventLayout("SAID placeholder not found"),
    )?;
    let said_rel_end = said_rel
        .checked_add(placeholder.len())
        .ok_or(SerderError::InvalidEventLayout("SAID slot bounds overflow"))?;

    let prefix_slot = if double_said {
        let rel = find_subslice(bytes, placeholder.as_bytes(), said_rel_end).ok_or(
            SerderError::InvalidEventLayout("second SAID placeholder not found"),
        )?;
        let rel_end = rel
            .checked_add(placeholder.len())
            .ok_or(SerderError::InvalidEventLayout(
                "prefix slot bounds overflow",
            ))?;
        Some(abs_range(base, rel..rel_end)?)
    } else {
        None
    };

    let size_start = VSTRING_OFFSET
        .checked_add(SIZE_OFFSET_IN_VSTRING)
        .ok_or(SerderError::InvalidEventLayout("size slot bounds overflow"))?;
    let size_end = size_start
        .checked_add(SIZE_WIDTH)
        .ok_or(SerderError::InvalidEventLayout("size slot bounds overflow"))?;

    let layout = EventLayout {
        size_slot: abs_range(base, size_start..size_end)?,
        said_slot: abs_range(base, said_rel..said_rel_end)?,
        prefix_slot,
    };
    buf.extend_from_slice(bytes);
    Ok(layout)
}

/// Translate a render-relative range into a buffer-absolute range.
fn abs_range(base: usize, rel: Range<usize>) -> Result<Range<usize>, SerderError> {
    let start = base
        .checked_add(rel.start)
        .ok_or(SerderError::InvalidEventLayout("slot offset overflow"))?;
    let end = base
        .checked_add(rel.end)
        .ok_or(SerderError::InvalidEventLayout("slot offset overflow"))?;
    Ok(start..end)
}

/// First occurrence of `needle` in `haystack` at or after `from`.
fn find_subslice(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    haystack
        .get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
        .and_then(|rel| from.checked_add(rel))
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
    /// inception event.
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
    /// the inception).
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
}

/// Convert a [`Seal`] to a JSON object ([`serde_json::Value`]).
///
/// qb64 encoding of CESR primitives is infallible, so this never fails.
pub(crate) fn seal_to_json(seal: &Seal) -> Value {
    let mut map = Map::new();
    match seal {
        Seal::Digest { d } => {
            map.insert("d".to_owned(), Value::String(to_qb64_string(d)));
        }
        Seal::Root { rd } => {
            map.insert("rd".to_owned(), Value::String(to_qb64_string(rd)));
        }
        Seal::Source { s, d } => {
            map.insert("s".to_owned(), Value::String(sn_to_hex(s.value())));
            map.insert("d".to_owned(), Value::String(to_qb64_string(d)));
        }
        Seal::Event { i, s, d } => {
            map.insert("i".to_owned(), Value::String(to_qb64_string(i)));
            map.insert("s".to_owned(), Value::String(sn_to_hex(s.value())));
            map.insert("d".to_owned(), Value::String(to_qb64_string(d)));
        }
        Seal::Last { i } => {
            map.insert("i".to_owned(), Value::String(to_qb64_string(i)));
        }
    }
    Value::Object(map)
}

/// Convert a [`Tholder`] to a JSON value.
///
/// - `Tholder::Simple(n)` becomes a hex string (e.g., `"1"`, `"a"` for 10).
/// - `Tholder::Weighted` with a single clause becomes a flat array of fraction
///   strings (e.g., `["1/2","1/2"]`); multiple clauses become nested arrays.
///
/// This matches keripy's `Tholder.sith` property.
pub(crate) fn tholder_to_json(tholder: &Tholder) -> Value {
    match tholder {
        Tholder::Simple(n) => Value::String(format!("{n:x}")),
        Tholder::Weighted(clauses) => {
            let outer: Vec<Value> = clauses
                .iter()
                .map(|clause| {
                    let inner: Vec<Value> = clause
                        .iter()
                        .map(|(num, den)| Value::String(weight_to_string(*num, *den)))
                        .collect();
                    Value::Array(inner)
                })
                .collect();
            if let [single] = <[Value]>::as_ref(&outer) {
                single.clone()
            } else {
                Value::Array(outer)
            }
        }
    }
}

/// Render one weight fraction the way keripy's `Tholder.sith` does: whole
/// values collapse to their integer string (`0`, `1`), everything else stays
/// `num/den`. A zero denominator is malformed (rejected by both
/// `Tholder::check_well_formed` and the deserializer) but must render as a
/// plain fraction rather than dividing by zero.
pub(crate) fn weight_to_string(num: u64, den: u64) -> String {
    if den != 0 && (num == 0 || num == den) {
        format!("{}", num / den)
    } else {
        format!("{num}/{den}")
    }
}

/// Convert a slice of [`Matter`] primitives to a JSON array of qb64 strings.
///
/// qb64 encoding of CESR primitives is infallible, so this never fails.
pub(crate) fn matters_to_json_array<C: CesrCode>(matters: &[Matter<'_, C>]) -> Value {
    let mut arr = Vec::with_capacity(matters.len());
    for m in matters {
        arr.push(Value::String(to_qb64_string(m)));
    }
    Value::Array(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::builder::MatterBuilder;

    #[test]
    fn tholder_zero_denominator_renders_without_panicking() {
        // Bug probe: a (0, 0) weight previously hit `0 / 0` inside
        // tholder_to_json and panicked. Malformed weights must render as a
        // plain fraction; rejection happens at parse/validation boundaries.
        let tholder = Tholder::Weighted(vec![vec![(0, 0), (1, 0)]]);
        let rendered = tholder_to_json(&tholder);
        assert_eq!(rendered, serde_json::json!(["0/0", "1/0"]));
    }
    use crate::core::matter::code::{DigestCode, VerKeyCode};
    use crate::core::primitives::{Diger, Prefixer, Saider, Seqner, Tholder, Verfer};
    use crate::keri::{
        DelegatedInceptionEvent, DelegatedRotationEvent, InceptionEvent, InteractionEvent,
        RotationEvent,
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

    #[test]
    fn serialize_dispatches_icp() {
        let event = KeriEvent::Inception(InceptionEvent::new(
            make_prefixer().into(),
            Seqner::new(0),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![],
            0,
            vec![],
            vec![],
        ));
        let result = serialize(&event).unwrap();
        assert_eq!(result.ilk(), Ilk::Icp);
    }

    #[test]
    fn serialize_dispatches_rot() {
        let event = KeriEvent::Rotation(RotationEvent::new(
            make_prefixer().into(),
            Seqner::new(1),
            make_saider(),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![],
            vec![],
            0,
            vec![],
            vec![],
        ));
        let result = serialize(&event).unwrap();
        assert_eq!(result.ilk(), Ilk::Rot);
    }

    #[test]
    fn serialize_dispatches_ixn() {
        let event = KeriEvent::Interaction(InteractionEvent::new(
            make_prefixer().into(),
            Seqner::new(1),
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
                Seqner::new(0),
                make_saider(),
                vec![make_verfer()],
                Tholder::Simple(1),
                vec![make_diger()],
                Tholder::Simple(1),
                vec![],
                0,
                vec![],
                vec![],
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
            Seqner::new(1),
            make_saider(),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![],
            vec![],
            0,
            vec![],
            vec![],
        )));
        let result = serialize(&event).unwrap();
        assert_eq!(result.ilk(), Ilk::Drt);
    }

    #[test]
    fn serialized_event_default_event_is_unit() {
        let event = KeriEvent::Inception(InceptionEvent::new(
            make_prefixer().into(),
            Seqner::new(0),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![],
            0,
            vec![],
            vec![],
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

    #[test]
    fn tholder_to_json_weighted_boundary_values() {
        let tholder = Tholder::Weighted(vec![vec![(0, 1), (1, 2), (1, 1)]]);
        let json = tholder_to_json(&tholder);
        let arr = json.as_array().expect("should be array");
        assert_eq!(arr[0].as_str().expect("0"), "0");
        assert_eq!(arr[1].as_str().expect("1/2"), "1/2");
        assert_eq!(arr[2].as_str().expect("1"), "1");
    }

    // -----------------------------------------------------------------------
    // weight_to_string — exact mapping table (shared by both backends)
    // -----------------------------------------------------------------------

    #[test]
    fn weight_to_string_exact_mapping() {
        // Whole values collapse to their integer string; everything else —
        // including malformed zero denominators and unreduced fractions —
        // stays num/den verbatim (keripy does not reduce).
        assert_eq!(weight_to_string(0, 1), "0");
        assert_eq!(weight_to_string(1, 1), "1");
        assert_eq!(weight_to_string(2, 2), "1");
        assert_eq!(weight_to_string(u64::MAX, u64::MAX), "1");
        assert_eq!(weight_to_string(1, 2), "1/2");
        assert_eq!(weight_to_string(2, 4), "2/4");
        assert_eq!(weight_to_string(3, 2), "3/2");
        assert_eq!(weight_to_string(0, 0), "0/0");
        assert_eq!(weight_to_string(1, 0), "1/0");
        assert_eq!(weight_to_string(u64::MAX, 1), "18446744073709551615/1");
    }

    // -----------------------------------------------------------------------
    // EventRef — ilk / double-SAID / From<&KeriEvent> mapping
    // -----------------------------------------------------------------------

    fn probe_icp_event() -> InceptionEvent {
        InceptionEvent::new(
            make_prefixer().into(),
            Seqner::new(0),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![],
            0,
            vec![],
            vec![],
        )
    }

    fn probe_rot_event() -> RotationEvent {
        RotationEvent::new(
            make_prefixer().into(),
            Seqner::new(1),
            make_saider(),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![],
            vec![],
            0,
            vec![],
            vec![],
        )
    }

    fn probe_ixn_event() -> InteractionEvent {
        InteractionEvent::new(
            make_prefixer().into(),
            Seqner::new(1),
            make_saider(),
            make_saider(),
            vec![],
        )
    }

    #[test]
    fn event_ref_ilk_and_double_said_mapping() {
        let icp = probe_icp_event();
        let rot = probe_rot_event();
        let ixn = probe_ixn_event();
        let dip = DelegatedInceptionEvent::new(probe_icp_event(), make_prefixer().into());
        let drt = DelegatedRotationEvent::new(probe_rot_event());

        let cases: [(EventRef<'_>, Ilk, bool); 5] = [
            (EventRef::Inception(&icp), Ilk::Icp, true),
            (EventRef::Rotation(&rot), Ilk::Rot, false),
            (EventRef::Interaction(&ixn), Ilk::Ixn, false),
            (EventRef::DelegatedInception(&dip), Ilk::Dip, true),
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

    // -----------------------------------------------------------------------
    // Hostile-backend boundary: EventSerializer is a PUBLIC trait, so
    // serialize_with must survive any layout a buggy or malicious backend
    // reports — typed InvalidEventLayout, never a panic or corrupt frame.
    // -----------------------------------------------------------------------

    struct HostileBackend {
        rendered: &'static [u8],
        layout: EventLayout,
    }

    impl EventSerializer for HostileBackend {
        fn render(
            &self,
            _event: EventRef<'_>,
            _said_placeholder: &str,
            buf: &mut Vec<u8>,
        ) -> Result<EventLayout, SerderError> {
            buf.extend_from_slice(self.rendered);
            Ok(self.layout.clone())
        }
    }

    fn expect_layout_error(backend: &HostileBackend) {
        let ixn = probe_ixn_event();
        let result = serialize_with(backend, EventRef::Interaction(&ixn));
        assert!(
            matches!(result, Err(SerderError::InvalidEventLayout(_))),
            "a bogus layout must surface as InvalidEventLayout, never panic"
        );
    }

    #[test]
    fn hostile_backend_out_of_bounds_size_slot_is_rejected() {
        expect_layout_error(&HostileBackend {
            rendered: b"0123456789",
            layout: EventLayout {
                size_slot: 100..106,
                said_slot: 0..2,
                prefix_slot: None,
            },
        });
    }

    #[test]
    fn hostile_backend_wrong_width_size_slot_is_rejected() {
        // Slot inside bounds but 2 bytes wide; the size patch is 6 bytes.
        expect_layout_error(&HostileBackend {
            rendered: b"0123456789",
            layout: EventLayout {
                size_slot: 0..2,
                said_slot: 2..4,
                prefix_slot: None,
            },
        });
    }

    #[test]
    fn hostile_backend_wrong_width_said_slot_is_rejected() {
        // Valid 6-wide size slot, but the SAID slot cannot hold a 44-char qb64.
        expect_layout_error(&HostileBackend {
            rendered: b"0123456789",
            layout: EventLayout {
                size_slot: 0..6,
                said_slot: 6..8,
                prefix_slot: None,
            },
        });
    }

    #[test]
    fn hostile_backend_reversed_range_is_rejected() {
        // Constructed as a struct literal: a hostile impl can produce a
        // reversed Range at runtime even though the `6..0` expression form
        // is a compile-time lint.
        expect_layout_error(&HostileBackend {
            rendered: b"0123456789",
            layout: EventLayout {
                size_slot: Range { start: 6, end: 0 },
                said_slot: 0..2,
                prefix_slot: None,
            },
        });
    }

    #[test]
    fn hostile_backend_out_of_bounds_prefix_slot_is_rejected() {
        // Big enough render for the size + SAID patches to land; the prefix
        // slot lies past the end of the buffer.
        const RENDERED: [u8; 64] = [b'x'; 64];
        expect_layout_error(&HostileBackend {
            rendered: &RENDERED,
            layout: EventLayout {
                size_slot: 0..6,
                said_slot: 6..50,
                prefix_slot: Some(1000..1044),
            },
        });
    }

    // -----------------------------------------------------------------------
    // extend_with_layout — framing validation and base-offset arithmetic
    // -----------------------------------------------------------------------

    fn placeholder() -> String {
        said_placeholder(DigestCode::Blake3_256).expect("Blake3-256 has a fixed placeholder")
    }

    #[test]
    fn extend_with_layout_rejects_render_without_version_head() {
        let ph = placeholder();
        let mut buf = Vec::new();
        let result = extend_with_layout(&mut buf, "{\"x\":1}", &ph, false);
        assert!(matches!(result, Err(SerderError::InvalidEventLayout(_))));
    }

    #[test]
    fn extend_with_layout_rejects_nonzero_size_version_head() {
        let ph = placeholder();
        let mut buf = Vec::new();
        let json = format!("{{\"v\":\"KERI10JSON0000a1_\",\"d\":\"{ph}\"}}");
        let result = extend_with_layout(&mut buf, &json, &ph, false);
        assert!(
            matches!(result, Err(SerderError::InvalidEventLayout(_))),
            "a render must start from a zero-size version string"
        );
    }

    #[test]
    fn extend_with_layout_rejects_missing_placeholder() {
        let ph = placeholder();
        let mut buf = Vec::new();
        let json = "{\"v\":\"KERI10JSON000000_\",\"t\":\"ixn\"}";
        let result = extend_with_layout(&mut buf, json, &ph, false);
        assert!(matches!(result, Err(SerderError::InvalidEventLayout(_))));
    }

    #[test]
    fn extend_with_layout_rejects_missing_second_placeholder_for_double_said() {
        let ph = placeholder();
        let mut buf = Vec::new();
        let json = format!("{{\"v\":\"KERI10JSON000000_\",\"d\":\"{ph}\"}}");
        let result = extend_with_layout(&mut buf, &json, &ph, true);
        assert!(
            matches!(result, Err(SerderError::InvalidEventLayout(_))),
            "double-SAID events must report two placeholder slots"
        );
    }

    #[test]
    fn extend_with_layout_offsets_are_absolute_into_prefilled_buffer() {
        let ph = placeholder();
        let mut buf = b"PREFILLED".to_vec();
        let base = buf.len();
        let json = format!("{{\"v\":\"KERI10JSON000000_\",\"d\":\"{ph}\",\"i\":\"{ph}\"}}");
        let layout = extend_with_layout(&mut buf, &json, &ph, true).unwrap();

        assert_eq!(&buf[layout.size_slot.clone()], b"000000");
        assert_eq!(&buf[layout.said_slot.clone()], ph.as_bytes());
        let prefix_slot = layout.prefix_slot.expect("double-SAID reports two slots");
        assert_eq!(&buf[prefix_slot.clone()], ph.as_bytes());
        assert!(
            layout.said_slot.start > base && prefix_slot.start > layout.said_slot.end,
            "slots must be absolute (past the prefilled bytes) and in order"
        );
        assert_eq!(&buf[..base], b"PREFILLED");
    }

    // -----------------------------------------------------------------------
    // SerdeJson::render appends — callers may reuse a non-empty buffer
    // -----------------------------------------------------------------------

    #[test]
    fn serde_json_render_into_prefilled_buffer_reports_absolute_slots() {
        let ph = placeholder();
        let ixn = probe_ixn_event();
        let mut buf = b"JUNK".to_vec();
        let layout = SerdeJson
            .render(EventRef::Interaction(&ixn), &ph, &mut buf)
            .unwrap();
        assert_eq!(&buf[..4], b"JUNK", "render must append, not overwrite");
        assert_eq!(&buf[layout.size_slot], b"000000");
        assert_eq!(&buf[layout.said_slot], ph.as_bytes());
        assert!(layout.prefix_slot.is_none(), "ixn is single-SAID");
    }
}
