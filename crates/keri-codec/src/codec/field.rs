//! The lift layer: scanned wire-views (`W`) → domain types, the third pipeline
//! stage (scan → SAID-verify → **lift**). Each [`FromWire`] impl replaces a
//! bespoke `parse_qb64_*`/`*_from_parsed` free function; [`Field`] carries the
//! JSON field name with the value so it is never a loose positional argument.
//!
//! Lift runs *after* SAID verification, over borrowed scan-stage views — it
//! cannot run earlier because it consumes the views the verified scan produced.

#[cfg(feature = "alloc")]
use alloc::{borrow::ToOwned, format, vec::Vec};

use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::{CesrCode, DigestCode, MatterCode, VerKeyCode};
use cesr::core::matter::error::{MatterBuildError, ValidationError};
use cesr::core::matter::matter::Matter;
use keri_events::{ConfigTrait, Identifier, SequenceNumber};

use crate::error::DeserializeError;

/// Lift a scanned wire-view `W` into `Self`, or a typed [`DeserializeError`] on
/// failure. Scalar impls tag the error with `field`; composite views (seals)
/// tag their inner fields by their own names, and unknown config codes surface
/// as [`DeserializeError::UnknownIlk`] — each at parity with the legacy free fns
/// this trait replaced.
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) trait FromWire<W>: Sized {
    /// Lift `wire` into `Self`.
    ///
    /// # Errors
    ///
    /// Returns [`DeserializeError`] when `wire` is not this type's valid domain
    /// form. Scalar impls tag it with `field`; composite impls delegate to
    /// their inner fields' own tags.
    fn from_wire(field: &'static str, wire: W) -> Result<Self, DeserializeError>;
}

/// A wire value tagged with the JSON field it belongs to. Constructed only via
/// [`Field::new`]/[`Field::each`]; the fields are private so the tag never
/// drifts from its value.
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) struct Field<W>(&'static str, W);

impl<W> Field<W> {
    /// Tag `value` with `field`.
    pub(crate) const fn new(field: &'static str, value: W) -> Self {
        Self(field, value)
    }

    /// Lift into `T`.
    ///
    /// # Errors
    ///
    /// Propagates the [`FromWire`] impl's error, tagged as that impl decides.
    pub(crate) fn decode<T: FromWire<W>>(self) -> Result<T, DeserializeError> {
        T::from_wire(self.0, self.1)
    }
}

impl<'s, W: Copy> Field<&'s [W]> {
    /// Tag a slice for list lift. The slice borrow (`'s`) is independent of the
    /// element data lifetime: the elements are `Copy` and copied out during
    /// lift, so the borrowed `Vec` view need not outlive the call.
    pub(crate) const fn each(field: &'static str, items: &'s [W]) -> Self {
        Self(field, items)
    }
}

/// Map a qb64 build error to the field-tagged codec error (mirrors the private
/// helper of the same name in `deserialize.rs`, which the not-yet-migrated
/// builders still use; it is deleted there in a later task). Module-private, so
/// it stays off the free-fn ratchet.
fn map_qb64_error(field: &'static str, err: MatterBuildError) -> DeserializeError {
    match err {
        MatterBuildError::Validation(source) => {
            DeserializeError::InvalidPrimitive { field, source }
        }
        MatterBuildError::Parsing(source) => {
            DeserializeError::UnparseablePrimitive { field, source }
        }
    }
}

// One impl for every qb64 Matter primitive — `Verfer`≡`Prefixer` (VerKeyCode),
// `Saider`≡`Diger` (DigestCode), `Verser` (VerserCode) are all `Matter<'a, C>`,
// so type-keyed narrow does what six `parse_qb64_*` fns did by hand.
impl<'a, C: CesrCode + TryFrom<MatterCode, Error = ValidationError>> FromWire<&'a str>
    for Matter<'a, C>
{
    fn from_wire(field: &'static str, s: &'a str) -> Result<Self, DeserializeError> {
        MatterBuilder::new()
            .from_qualified_base64(s.as_bytes())
            .map_err(|e| map_qb64_error(field, e))?
            .narrow::<C>()
            .map_err(|source| DeserializeError::InvalidPrimitive { field, source })
    }
}

// A KERI prefix is a verkey (basic) or a digest (self-addressing); try VerKey,
// fall back to Digest (was `parse_qb64_identifier`).
impl<'a> FromWire<&'a str> for Identifier<'a> {
    fn from_wire(field: &'static str, s: &'a str) -> Result<Self, DeserializeError> {
        if let Ok(basic) = Matter::<VerKeyCode>::from_wire(field, s) {
            return Ok(Identifier::Basic(basic));
        }
        Matter::<DigestCode>::from_wire(field, s).map(Identifier::SelfAddressing)
    }
}

// Sequence number: lowercase hex u128 (was `parse_sn`).
impl<'a> FromWire<&'a str> for SequenceNumber {
    fn from_wire(field: &'static str, s: &'a str) -> Result<Self, DeserializeError> {
        let n = u128::from_str_radix(s, 16).map_err(|_| DeserializeError::InvalidPrimitive {
            field,
            source: ValidationError::UnknownMatterCode(format!("invalid hex {field}: {s}")),
        })?;
        Ok(Self::new(n))
    }
}

// Config traits (was `config_from_parsed`, via the Vec blanket). At parity with
// the legacy path, an unknown code surfaces as `UnknownIlk` (no `field` tag),
// so `field` is genuinely unused here.
impl<'a> FromWire<&'a str> for ConfigTrait {
    fn from_wire(field: &'static str, s: &'a str) -> Result<Self, DeserializeError> {
        let _ = field;
        Self::from_code(s).map_err(|_| DeserializeError::UnknownIlk(s.to_owned()))
    }
}

// The list collapse: one blanket for every `Vec<&str>`/`Vec<ParsedSeal>` field,
// replacing all four `*_from_parsed` collectors.
impl<'s, W: Copy, T: FromWire<W>> FromWire<&'s [W]> for Vec<T> {
    fn from_wire(field: &'static str, items: &'s [W]) -> Result<Self, DeserializeError> {
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
    use alloc::string::String;
    use cesr::core::matter::code::{DigestCode, VerKeyCode};
    use cesr::core::matter::error::ParsingError;
    use cesr::core::primitives::{Diger, Verfer, Verser};

    fn verfer_qb64() -> String {
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(alloc::vec![0u8; 32]))
            .unwrap()
            .build()
            .unwrap()
            .to_qb64()
    }

    fn diger_qb64() -> String {
        MatterBuilder::new()
            .with_code(DigestCode::Blake3_256)
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
    fn matter_lift_verser_via_generic_impl() {
        // Proves the generic `Matter<C>` impl narrows a non-key, non-digest
        // code (VerserCode) — it is not Ed25519/Blake3-only.
        let v: Verser = Field::new("t", "YKERIBAA").decode().unwrap();
        assert_eq!(v.to_qb64(), "YKERIBAA");
    }

    #[test]
    fn matter_lift_wrong_code_is_typed_error() {
        let s = verfer_qb64(); // a verkey, ask for a digest
        let err = Field::new("d", s.as_str()).decode::<Diger>().unwrap_err();
        assert!(matches!(
            err,
            DeserializeError::InvalidPrimitive { field: "d", .. }
        ));
    }

    #[test]
    fn matter_lift_malformed_qb64_is_unparseable() {
        // A malformed qb64 primitive (bad code) is a parse failure, not a
        // validation failure — it must not be collapsed into a
        // ValidationError. `Diger`/`Matter` does not implement `Debug`, so
        // `matches!` on the whole `Result` avoids requiring the `Ok` value
        // to be printable. Moved from the deleted `deserialize.rs` free-fn
        // test `unparseable_qb64_field_surfaces_as_parsing_domain_error`.
        let result = Field::new("d", "!!not-qb64!!").decode::<Diger>();
        assert!(
            matches!(
                result,
                Err(DeserializeError::UnparseablePrimitive { field: "d", .. })
            ),
            "expected UnparseablePrimitive parse-domain error"
        );
    }

    #[test]
    fn map_qb64_error_routes_validation_to_invalid_primitive() {
        // The Validation arm must land in InvalidPrimitive — the other half
        // of the routing a historical bug corrupted (it previously misrouted
        // Parsing into a stringified ValidationError). Pin both directions.
        // Moved from the deleted `deserialize.rs` copy of `map_qb64_error`.
        let err = map_qb64_error(
            "d",
            MatterBuildError::Validation(ValidationError::StructuralIntegrityError),
        );
        assert!(
            matches!(err, DeserializeError::InvalidPrimitive { field: "d", .. }),
            "expected InvalidPrimitive, got {err:?}"
        );
    }

    #[test]
    fn map_qb64_error_routes_parsing_to_unparseable_primitive() {
        let err = map_qb64_error("d", MatterBuildError::Parsing(ParsingError::EmptyStream));
        assert!(
            matches!(
                err,
                DeserializeError::UnparseablePrimitive { field: "d", .. }
            ),
            "expected UnparseablePrimitive, got {err:?}"
        );
    }

    #[test]
    fn identifier_lift_self_addressing_branch() {
        // A digest qb64 falls through the VerKey attempt to the Digest branch.
        let d = diger_qb64();
        let id: Identifier = Field::new("i", d.as_str()).decode().unwrap();
        assert!(matches!(id, Identifier::SelfAddressing(_)));
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
            DeserializeError::InvalidPrimitive { field: "s", .. }
        ));
    }

    #[test]
    fn config_lift_valid_and_unknown() {
        let ok: ConfigTrait = Field::new("c", "EO").decode().unwrap();
        assert_eq!(ok, ConfigTrait::EstOnly);

        let err = Field::new("c", "XYZ").decode::<ConfigTrait>().unwrap_err();
        assert!(matches!(err, DeserializeError::UnknownIlk(_)));
    }

    #[test]
    fn vec_blanket_empty_one_and_malformed() {
        let ok = verfer_qb64();
        let no_keys: &[&str] = &[];
        let empty: Vec<Verfer> = Field::each("k", no_keys).decode().unwrap();
        assert!(empty.is_empty());

        let one: Vec<Verfer> = Field::each("k", &[ok.as_str()]).decode().unwrap();
        assert_eq!(one.len(), 1);

        // A too-short/non-qb64 element fails at the qb64 parse (length) stage,
        // before any code narrowing — deterministically `UnparseablePrimitive`.
        let bad = Field::each("k", &[ok.as_str(), "not-qb64"]).decode::<Vec<Verfer>>();
        assert!(matches!(
            bad,
            Err(DeserializeError::UnparseablePrimitive { field: "k", .. })
        ));
    }
}
