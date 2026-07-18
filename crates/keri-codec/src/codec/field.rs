//! The lift layer: scanned wire-views (`W`) → domain types, the third pipeline
//! stage (scan → SAID-verify → **lift**). Each [`FromWire`] impl replaces a
//! bespoke `parse_qb64_*`/`*_from_parsed` free function; [`Field`] carries the
//! JSON field name with the value so it is never a loose positional argument.
//!
//! Lift runs *after* SAID verification, over borrowed scan-stage views — it
//! cannot run earlier because it consumes the views the verified scan produced.

#[cfg(feature = "alloc")]
use alloc::{borrow::ToOwned, format, vec::Vec};
use core::marker::PhantomData;

use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::{CesrCode, DigestCode, MatterCode, VerKeyCode};
use cesr::core::matter::error::{MatterBuildError, ValidationError};
use cesr::core::matter::matter::Matter;
use keri_events::{ConfigTrait, Identifier, SequenceNumber};

use crate::error::SerderError;

/// Lift a scanned wire-view `W` into `Self`, tagging any failure with the JSON
/// `field` it came from.
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) trait FromWire<'a, W>: Sized {
    /// Lift `wire` into `Self`.
    ///
    /// # Errors
    ///
    /// Returns [`SerderError`] (with `field`) when `wire` is not this type's
    /// valid domain form.
    fn from_wire(field: &'static str, wire: W) -> Result<Self, SerderError>;
}

/// A wire value tagged with the JSON field it belongs to.
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) struct Field<'a, W>(pub(crate) &'static str, pub(crate) W, PhantomData<&'a ()>);

impl<'a, W> Field<'a, W> {
    /// Tag `value` with `field`.
    pub(crate) const fn new(field: &'static str, value: W) -> Self {
        Self(field, value, PhantomData)
    }

    /// Lift into `T`.
    ///
    /// # Errors
    ///
    /// Propagates the [`FromWire`] impl's error, tagged with this field.
    pub(crate) fn decode<T: FromWire<'a, W>>(self) -> Result<T, SerderError> {
        T::from_wire(self.0, self.1)
    }
}

impl<'s, W: Copy> Field<'_, &'s [W]> {
    /// Tag a slice for list lift. The slice borrow (`'s`) is independent of the
    /// element data lifetime (`'a`): the elements are `Copy` and copied out
    /// during lift, so the borrowed `Vec` view need not outlive the call.
    pub(crate) const fn each(field: &'static str, items: &'s [W]) -> Self {
        Self(field, items, PhantomData)
    }
}

/// Map a qb64 build error to the field-tagged codec error (mirrors the private
/// helper of the same name in `deserialize.rs`, which the not-yet-migrated
/// builders still use; it is deleted there in a later task). Module-private, so
/// it stays off the free-fn ratchet.
fn map_qb64_error(field: &'static str, err: MatterBuildError) -> SerderError {
    match err {
        MatterBuildError::Validation(source) => SerderError::InvalidPrimitive { field, source },
        MatterBuildError::Parsing(source) => SerderError::UnparseablePrimitive { field, source },
    }
}

// One impl for every qb64 Matter primitive — `Verfer`≡`Prefixer` (VerKeyCode),
// `Saider`≡`Diger` (DigestCode), `Verser` (VerserCode) are all `Matter<'a, C>`,
// so type-keyed narrow does what six `parse_qb64_*` fns did by hand.
impl<'a, C: CesrCode + TryFrom<MatterCode, Error = ValidationError>> FromWire<'a, &'a str>
    for Matter<'a, C>
{
    fn from_wire(field: &'static str, s: &'a str) -> Result<Self, SerderError> {
        MatterBuilder::new()
            .from_qualified_base64(s.as_bytes())
            .map_err(|e| map_qb64_error(field, e))?
            .narrow::<C>()
            .map_err(|source| SerderError::InvalidPrimitive { field, source })
    }
}

// A KERI prefix is a verkey (basic) or a digest (self-addressing); try VerKey,
// fall back to Digest (was `parse_qb64_identifier`).
impl<'a> FromWire<'a, &'a str> for Identifier<'a> {
    fn from_wire(field: &'static str, s: &'a str) -> Result<Self, SerderError> {
        if let Ok(basic) = Matter::<VerKeyCode>::from_wire(field, s) {
            return Ok(Identifier::Basic(basic));
        }
        Matter::<DigestCode>::from_wire(field, s).map(Identifier::SelfAddressing)
    }
}

// Sequence number: lowercase hex u128 (was `parse_sn`).
impl<'a> FromWire<'a, &'a str> for SequenceNumber {
    fn from_wire(field: &'static str, s: &'a str) -> Result<Self, SerderError> {
        let n = u128::from_str_radix(s, 16).map_err(|_| SerderError::InvalidPrimitive {
            field,
            source: ValidationError::UnknownMatterCode(format!("invalid hex {field}: {s}")),
        })?;
        Ok(Self::new(n))
    }
}

// Config traits (was `config_from_parsed`, via the Vec blanket).
impl<'a> FromWire<'a, &'a str> for ConfigTrait {
    fn from_wire(field: &'static str, s: &'a str) -> Result<Self, SerderError> {
        // UnknownIlk replicates the tolerant-path behavior kept for parity.
        let _ = field;
        Self::from_code(s).map_err(|_| SerderError::UnknownIlk(s.to_owned()))
    }
}

// The list collapse: one blanket for every `Vec<&str>`/`Vec<ParsedSeal>` field,
// replacing all four `*_from_parsed` collectors.
impl<'a, 's, W: Copy, T: FromWire<'a, W>> FromWire<'a, &'s [W]> for Vec<T> {
    fn from_wire(field: &'static str, items: &'s [W]) -> Result<Self, SerderError> {
        items
            .iter()
            .copied()
            .map(|w| T::from_wire(field, w))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::borrow::Cow;
    use cesr::core::matter::code::VerKeyCode;
    use cesr::core::primitives::{Diger, Verfer};

    fn verfer_qb64() -> alloc::string::String {
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(alloc::vec![0u8; 32]))
            .unwrap()
            .build()
            .unwrap()
            .to_qb64()
    }

    #[test]
    fn matter_lift_narrows_to_target_code() {
        let s = verfer_qb64();
        let v: Verfer = Field::new("k", s.as_str()).decode().unwrap();
        assert_eq!(*v.code(), VerKeyCode::Ed25519);
    }

    #[test]
    fn matter_lift_wrong_code_is_typed_error() {
        let s = verfer_qb64(); // a verkey, ask for a digest
        let err = Field::new("d", s.as_str()).decode::<Diger>().unwrap_err();
        assert!(matches!(
            err,
            SerderError::InvalidPrimitive { field: "d", .. }
        ));
    }

    #[test]
    fn sn_lift_hex() {
        let n: SequenceNumber = Field::new("s", "ff").decode().unwrap();
        assert_eq!(n.value(), 255);
    }

    #[test]
    fn sn_lift_rejects_non_hex() {
        let err = Field::new("s", "zz")
            .decode::<SequenceNumber>()
            .unwrap_err();
        assert!(matches!(
            err,
            SerderError::InvalidPrimitive { field: "s", .. }
        ));
    }

    #[test]
    fn vec_blanket_empty_one_and_malformed() {
        let ok = verfer_qb64();
        let no_keys: &[&str] = &[];
        let empty: Vec<Verfer> = Field::each("k", no_keys).decode().unwrap();
        assert!(empty.is_empty());

        let one: Vec<Verfer> = Field::each("k", &[ok.as_str()]).decode().unwrap();
        assert_eq!(one.len(), 1);

        let bad = Field::each("k", &[ok.as_str(), "not-qb64"]).decode::<Vec<Verfer>>();
        assert!(matches!(
            bad,
            Err(SerderError::InvalidPrimitive { field: "k", .. }
                | SerderError::UnparseablePrimitive { field: "k", .. })
        ));
    }
}
