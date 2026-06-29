//! KERI event serialization to canonical JSON with SAID computation.
//!
//! Each event serializer builds ordered JSON matching keripy's wire format,
//! computes the SAID (self-addressing identifier), and returns a
//! [`SerializedEvent`] containing the final bytes.

/// Delegated inception event serializer.
pub mod dip;
/// Delegated rotation event serializer.
pub mod drt;
/// Inception event serializer.
pub mod icp;
/// Interaction event serializer.
pub mod ixn;
/// Rotation event serializer.
pub mod rot;

use crate::core::matter::code::CesrCode;
use crate::core::matter::matter::Matter;
use crate::core::primitives::{Saider, Tholder};
use crate::keri::{Ilk, KeriEvent, Seal};
use serde_json::{Map, Value};

use crate::error::SerderError;
use crate::primitives::{sn_to_hex, to_qb64_string};

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
pub fn serialize(event: &KeriEvent) -> Result<SerializedEvent, SerderError> {
    match event {
        KeriEvent::Inception(e) => serialize_inception(e),
        KeriEvent::Rotation(e) => serialize_rotation(e),
        KeriEvent::Interaction(e) => serialize_interaction(e),
        KeriEvent::DelegatedInception(e) => serialize_delegated_inception(e),
        KeriEvent::DelegatedRotation(e) => serialize_delegated_rotation(e),
    }
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
/// # Errors
///
/// Returns [`SerderError`] if any CESR primitive cannot be encoded to qb64.
pub(crate) fn seal_to_json(seal: &Seal) -> Result<Value, SerderError> {
    let mut map = Map::new();
    match seal {
        Seal::Digest { d } => {
            map.insert("d".to_owned(), Value::String(to_qb64_string(d)?));
        }
        Seal::Root { rd } => {
            map.insert("rd".to_owned(), Value::String(to_qb64_string(rd)?));
        }
        Seal::Source { s, d } => {
            map.insert("s".to_owned(), Value::String(sn_to_hex(s.value())));
            map.insert("d".to_owned(), Value::String(to_qb64_string(d)?));
        }
        Seal::Event { i, s, d } => {
            map.insert("i".to_owned(), Value::String(to_qb64_string(i)?));
            map.insert("s".to_owned(), Value::String(sn_to_hex(s.value())));
            map.insert("d".to_owned(), Value::String(to_qb64_string(d)?));
        }
        Seal::Last { i } => {
            map.insert("i".to_owned(), Value::String(to_qb64_string(i)?));
        }
    }
    Ok(Value::Object(map))
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
                        .map(|(num, den)| {
                            if *num == 0 || (*den != 0 && *num == *den) {
                                Value::String(format!("{}", *num / *den))
                            } else {
                                Value::String(format!("{num}/{den}"))
                            }
                        })
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

/// Convert a slice of [`Matter`] primitives to a JSON array of qb64 strings.
///
/// # Errors
///
/// Returns [`SerderError`] if any primitive cannot be encoded to qb64.
pub(crate) fn matters_to_json_array<C: CesrCode>(
    matters: &[Matter<'_, C>],
) -> Result<Value, SerderError> {
    let mut arr = Vec::with_capacity(matters.len());
    for m in matters {
        arr.push(Value::String(to_qb64_string(m)?));
    }
    Ok(Value::Array(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::{DigestCode, VerKeyCode};
    use crate::core::primitives::{Diger, Prefixer, Saider, Seqner, Tholder, Verfer};
    use crate::keri::{
        DelegatedInceptionEvent, DelegatedRotationEvent, InceptionEvent, InteractionEvent,
        RotationEvent,
    };
    use std::borrow::Cow;

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
    fn tholder_to_json_weighted_boundary_values() {
        let tholder = Tholder::Weighted(vec![vec![(0, 1), (1, 2), (1, 1)]]);
        let json = tholder_to_json(&tholder);
        let arr = json.as_array().expect("should be array");
        assert_eq!(arr[0].as_str().expect("0"), "0");
        assert_eq!(arr[1].as_str().expect("1/2"), "1/2");
        assert_eq!(arr[2].as_str().expect("1"), "1");
    }
}
