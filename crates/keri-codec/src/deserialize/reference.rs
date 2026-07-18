//! The pre-#142 tolerant read path (`serde_json::Value` + re-render SAID
//! verification), preserved verbatim as the differential-test oracle for
//! the strict canonical parser. Test-only: never compiled into production.

use super::check_thresholds_well_formed;
use crate::said::infer_digest_code;
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, format, string::String, string::ToString, vec, vec::Vec};
use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::{CesrCode, DigestCode, VerKeyCode, VerserCode};
use cesr::core::matter::error::{MatterBuildError, ValidationError};
use cesr::core::matter::matter::Matter;
use cesr::core::primitives::{Diger, Prefixer, Saider, Verfer, Verser};
use cesr::core::version::{SerializationKind, VERSION_STRING_LEN, VersionString};
use keri_events::threshold_form::ThresholdForm;
use keri_events::toad::Toad;
use keri_events::{
    ConfigTrait, DelegatedInceptionEvent, DelegatedRotationEvent, Identifier, Ilk, InceptionEvent,
    InteractionEvent, KeriEvent, OpaqueSeal, RotationEvent, Seal, SequenceNumber, SigningThreshold,
    WeightedThreshold,
};
use serde_json::Value;

use crate::deserialize::opaque_scan::OpaqueScan;
use crate::error::SerderError;

// ---------------------------------------------------------------------------
// Primitive parsing helpers — the oracle's own copy of the pre-#193 lift
// layer. Kept independent of the strict path's `Field`/`FromWire` vocabulary
// (`codec::field`) so this differential oracle never shares an implementation
// with the code it is checking.
// ---------------------------------------------------------------------------

fn parse_qb64_prefixer<'a>(s: &'a str, field: &'static str) -> Result<Prefixer<'a>, SerderError> {
    let matter = MatterBuilder::new()
        .from_qualified_base64(s.as_bytes())
        .map_err(|e| map_qb64_error(field, e))?;
    matter
        .narrow::<VerKeyCode>()
        .map_err(|e| SerderError::InvalidPrimitive { field, source: e })
}

/// Parse a qb64 string as a KERI identifier prefix, which may be either a
/// verification key (basic derivation) or a digest (self-addressing derivation).
///
/// Tries `VerKeyCode` first (basic derivation like `D`); if that fails, tries
/// `DigestCode` (self-addressing like `E`). Returns the typed [`Identifier`]
/// enum preserving the original code.
fn parse_qb64_identifier<'a>(
    s: &'a str,
    field: &'static str,
) -> Result<Identifier<'a>, SerderError> {
    let matter = MatterBuilder::new()
        .from_qualified_base64(s.as_bytes())
        .map_err(|e| map_qb64_error(field, e))?;

    if let Ok(narrowed) = matter.narrow::<VerKeyCode>() {
        return Ok(Identifier::Basic(narrowed));
    }

    let digest_matter = MatterBuilder::new()
        .from_qualified_base64(s.as_bytes())
        .map_err(|e| map_qb64_error(field, e))?;
    let saider = digest_matter
        .narrow::<DigestCode>()
        .map_err(|e| SerderError::InvalidPrimitive { field, source: e })?;
    Ok(Identifier::SelfAddressing(saider))
}

fn parse_qb64_verfer<'a>(s: &'a str, field: &'static str) -> Result<Verfer<'a>, SerderError> {
    parse_qb64_prefixer(s, field)
}

fn parse_qb64_diger<'a>(s: &'a str, field: &'static str) -> Result<Diger<'a>, SerderError> {
    let matter = MatterBuilder::new()
        .from_qualified_base64(s.as_bytes())
        .map_err(|e| map_qb64_error(field, e))?;
    matter
        .narrow::<DigestCode>()
        .map_err(|e| SerderError::InvalidPrimitive { field, source: e })
}

fn parse_qb64_saider<'a>(s: &'a str, field: &'static str) -> Result<Saider<'a>, SerderError> {
    parse_qb64_diger(s, field)
}

fn parse_qb64_verser<'a>(s: &'a str, field: &'static str) -> Result<Verser<'a>, SerderError> {
    let matter = MatterBuilder::new()
        .from_qualified_base64(s.as_bytes())
        .map_err(|e| map_qb64_error(field, e))?;
    matter
        .narrow::<VerserCode>()
        .map_err(|e| SerderError::InvalidPrimitive { field, source: e })
}

fn map_qb64_error(field: &'static str, err: MatterBuildError) -> SerderError {
    match err {
        MatterBuildError::Validation(source) => SerderError::InvalidPrimitive { field, source },
        MatterBuildError::Parsing(source) => SerderError::UnparseablePrimitive { field, source },
    }
}

fn parse_sn(s: &str) -> Result<u128, SerderError> {
    u128::from_str_radix(s, 16).map_err(|_| SerderError::InvalidPrimitive {
        field: "s",
        source: ValidationError::UnknownMatterCode(format!("invalid hex sn: {s}")),
    })
}

fn parse_weight(s: &str) -> Result<(u64, u64), SerderError> {
    if let Some((num_s, den_s)) = s.split_once('/') {
        let num: u64 = num_s.parse().map_err(|_| SerderError::InvalidPrimitive {
            field: "kt",
            source: ValidationError::UnknownMatterCode(format!("invalid fraction numerator: {s}")),
        })?;
        let den: u64 = den_s.parse().map_err(|_| SerderError::InvalidPrimitive {
            field: "kt",
            source: ValidationError::UnknownMatterCode(format!(
                "invalid fraction denominator: {s}"
            )),
        })?;
        if den == 0 {
            return Err(SerderError::InvalidPrimitive {
                field: "kt",
                source: ValidationError::UnknownMatterCode(format!(
                    "zero denominator in weight: {s}"
                )),
            });
        }
        Ok((num, den))
    } else {
        let val: u64 = s.parse().map_err(|_| SerderError::InvalidPrimitive {
            field: "kt",
            source: ValidationError::UnknownMatterCode(format!("invalid weight: {s}")),
        })?;
        Ok((val, 1))
    }
}

// ---------------------------------------------------------------------------
// Tolerant deserialization entry points (oracle)
// ---------------------------------------------------------------------------

/// Deserialize any KERI event from canonical JSON bytes (tolerant oracle).
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn deserialize_event(raw: &[u8]) -> Result<KeriEvent<'static>, SerderError> {
    validate_version_string(raw)?;
    let val: Value = serde_json::from_slice(raw)?;
    let ilk_str = get_str(&val, "t")?;
    let ilk = Ilk::from_code(ilk_str).map_err(|_| SerderError::UnknownIlk(ilk_str.to_owned()))?;

    match ilk {
        Ilk::Icp => Ok(KeriEvent::Inception(deserialize_inception(raw)?)),
        Ilk::Rot => Ok(KeriEvent::Rotation(deserialize_rotation(raw)?)),
        Ilk::Ixn => Ok(KeriEvent::Interaction(deserialize_interaction(raw)?)),
        Ilk::Dip => Ok(KeriEvent::DelegatedInception(
            deserialize_delegated_inception(raw)?,
        )),
        Ilk::Drt => Ok(KeriEvent::DelegatedRotation(
            deserialize_delegated_rotation(raw)?,
        )),
        _ => Err(SerderError::UnknownIlk(ilk_str.to_owned())),
    }
}

/// Deserialize an inception event from canonical JSON bytes (tolerant oracle).
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn deserialize_inception(raw: &[u8]) -> Result<InceptionEvent<'static>, SerderError> {
    validate_version_string(raw)?;
    let val: Value = serde_json::from_slice(raw)?;
    let digest_code = infer_digest_code(get_str(&val, "d")?)?;
    let d_str = get_str(&val, "d")?;
    let i_str = get_str(&val, "i")?;

    if d_str == i_str {
        verify_said_double(raw, digest_code)?;
    } else {
        verify_said_single(raw, digest_code)?;
    }

    let said = parse_qb64_diger(get_str(&val, "d")?, "d")?;
    let prefix = parse_qb64_identifier(get_str(&val, "i")?, "i")?;
    let sn = parse_sn(get_str(&val, "s")?)?;
    let kt = get_field(&val, "kt")?;
    let nt = get_field(&val, "nt")?;
    let bt = get_field(&val, "bt")?;
    let form = threshold_form_of(bt);
    check_form_consistency("kt", kt, form)?;
    check_form_consistency("nt", nt, form)?;
    let threshold = tholder_from_json(kt, "signing")?;
    let keys = parse_qb64_verfer_array(get_field(&val, "k")?)?;
    let next_threshold = tholder_from_json(nt, "next signing")?;
    let next_keys = parse_qb64_diger_array(get_field(&val, "n")?)?;
    check_thresholds_well_formed(&threshold, keys.len(), &next_threshold, next_keys.len())?;
    let witness_threshold_wire = parse_witness_threshold(bt)?;
    let witnesses = parse_qb64_prefixer_array(get_field(&val, "b")?)?;
    let config = parse_config_array(get_field(&val, "c")?)?;
    let anchors = parse_seal_array(get_field(&val, "a")?)?;
    let witness_threshold = Toad::exact(witness_threshold_wire, witnesses.len())?;

    Ok(InceptionEvent::new(
        prefix,
        SequenceNumber::new(sn),
        said,
        keys,
        threshold,
        next_keys,
        next_threshold,
        witnesses,
        witness_threshold,
        config,
        anchors,
        form,
    )
    .into_static())
}

/// Deserialize a rotation event from canonical JSON bytes (tolerant oracle).
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn deserialize_rotation(raw: &[u8]) -> Result<RotationEvent<'static>, SerderError> {
    validate_version_string(raw)?;
    let val: Value = serde_json::from_slice(raw)?;
    let digest_code = infer_digest_code(get_str(&val, "d")?)?;

    verify_said_single(raw, digest_code)?;

    let said = parse_qb64_diger(get_str(&val, "d")?, "d")?;
    let prefix = parse_qb64_identifier(get_str(&val, "i")?, "i")?;
    let sn = parse_sn(get_str(&val, "s")?)?;
    let prior_event_said = parse_qb64_diger(get_str(&val, "p")?, "p")?;
    let kt = get_field(&val, "kt")?;
    let nt = get_field(&val, "nt")?;
    let bt = get_field(&val, "bt")?;
    let form = threshold_form_of(bt);
    check_form_consistency("kt", kt, form)?;
    check_form_consistency("nt", nt, form)?;
    let threshold = tholder_from_json(kt, "signing")?;
    let keys = parse_qb64_verfer_array(get_field(&val, "k")?)?;
    let next_threshold = tholder_from_json(nt, "next signing")?;
    let next_keys = parse_qb64_diger_array(get_field(&val, "n")?)?;
    check_thresholds_well_formed(&threshold, keys.len(), &next_threshold, next_keys.len())?;
    let witness_threshold = parse_witness_threshold(bt)?;
    let witness_removals = parse_qb64_prefixer_array(get_field(&val, "br")?)?;
    let witness_additions = parse_qb64_prefixer_array(get_field(&val, "ba")?)?;
    if val.get("c").is_some() {
        return Err(SerderError::UnexpectedField("c"));
    }
    let anchors = parse_seal_array(get_field(&val, "a")?)?;

    Ok(RotationEvent::new(
        prefix,
        SequenceNumber::new(sn),
        said,
        prior_event_said,
        keys,
        threshold,
        next_keys,
        next_threshold,
        witness_additions,
        witness_removals,
        Toad::from_wire(witness_threshold),
        anchors,
        form,
    )
    .into_static())
}

/// Deserialize an interaction event from canonical JSON bytes (tolerant oracle).
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn deserialize_interaction(
    raw: &[u8],
) -> Result<InteractionEvent<'static>, SerderError> {
    validate_version_string(raw)?;
    let val: Value = serde_json::from_slice(raw)?;
    let digest_code = infer_digest_code(get_str(&val, "d")?)?;

    verify_said_single(raw, digest_code)?;

    let said = parse_qb64_diger(get_str(&val, "d")?, "d")?;
    let prefix = parse_qb64_identifier(get_str(&val, "i")?, "i")?;
    let sn = parse_sn(get_str(&val, "s")?)?;
    let prior_event_said = parse_qb64_diger(get_str(&val, "p")?, "p")?;
    let anchors = parse_seal_array(get_field(&val, "a")?)?;

    Ok(InteractionEvent::new(
        prefix,
        SequenceNumber::new(sn),
        said,
        prior_event_said,
        anchors,
    )
    .into_static())
}

/// Deserialize a delegated inception event from canonical JSON bytes
/// (tolerant oracle).
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn deserialize_delegated_inception(
    raw: &[u8],
) -> Result<DelegatedInceptionEvent<'static>, SerderError> {
    validate_version_string(raw)?;
    let val: Value = serde_json::from_slice(raw)?;
    let digest_code = infer_digest_code(get_str(&val, "d")?)?;
    let d_str = get_str(&val, "d")?;
    let i_str = get_str(&val, "i")?;

    if d_str == i_str {
        verify_said_double(raw, digest_code)?;
    } else {
        verify_said_single(raw, digest_code)?;
    }

    let said = parse_qb64_diger(get_str(&val, "d")?, "d")?;
    let prefix = parse_qb64_identifier(get_str(&val, "i")?, "i")?;
    let sn = parse_sn(get_str(&val, "s")?)?;
    let kt = get_field(&val, "kt")?;
    let nt = get_field(&val, "nt")?;
    let bt = get_field(&val, "bt")?;
    let form = threshold_form_of(bt);
    check_form_consistency("kt", kt, form)?;
    check_form_consistency("nt", nt, form)?;
    let threshold = tholder_from_json(kt, "signing")?;
    let keys = parse_qb64_verfer_array(get_field(&val, "k")?)?;
    let next_threshold = tholder_from_json(nt, "next signing")?;
    let next_keys = parse_qb64_diger_array(get_field(&val, "n")?)?;
    check_thresholds_well_formed(&threshold, keys.len(), &next_threshold, next_keys.len())?;
    let witness_threshold_wire = parse_witness_threshold(bt)?;
    let witnesses = parse_qb64_prefixer_array(get_field(&val, "b")?)?;
    let config = parse_config_array(get_field(&val, "c")?)?;
    let anchors = parse_seal_array(get_field(&val, "a")?)?;
    let delegator = parse_qb64_identifier(get_str(&val, "di")?, "di")?;
    let witness_threshold = Toad::exact(witness_threshold_wire, witnesses.len())?;

    Ok(DelegatedInceptionEvent::new(
        InceptionEvent::new(
            prefix,
            SequenceNumber::new(sn),
            said,
            keys,
            threshold,
            next_keys,
            next_threshold,
            witnesses,
            witness_threshold,
            config,
            anchors,
            form,
        ),
        delegator,
    )
    .into_static())
}

/// Deserialize a delegated rotation event from canonical JSON bytes
/// (tolerant oracle).
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn deserialize_delegated_rotation(
    raw: &[u8],
) -> Result<DelegatedRotationEvent<'static>, SerderError> {
    let rotation = deserialize_rotation(raw)?;
    Ok(DelegatedRotationEvent::new(rotation))
}

// ---------------------------------------------------------------------------
// Version string validation
// ---------------------------------------------------------------------------

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn validate_version_string(raw: &[u8]) -> Result<(), SerderError> {
    let val: Value = serde_json::from_slice(raw)?;
    let vs_str = val
        .get("v")
        .and_then(Value::as_str)
        .ok_or(SerderError::MissingField("v"))?;

    if vs_str.len() < VERSION_STRING_LEN {
        return Err(SerderError::InvalidVersionString(format!(
            "version string too short: {}",
            vs_str.len()
        )));
    }
    let (vs, _) = VersionString::parse(vs_str.as_bytes())?;
    if vs.kind() != SerializationKind::Json {
        return Err(SerderError::InvalidVersionString(format!(
            "expected JSON, got {}",
            vs.kind().as_str()
        )));
    }
    let expected_size =
        usize::try_from(vs.size()).map_err(|e| SerderError::InvalidVersionString(e.to_string()))?;
    if expected_size != raw.len() {
        return Err(SerderError::InvalidVersionString(format!(
            "version string size {} does not match actual size {}",
            expected_size,
            raw.len()
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SAID verification helpers
// ---------------------------------------------------------------------------

/// Verify a single-SAID event (rot, ixn, drt): only `d` is replaced with a
/// placeholder before computing the digest.
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn verify_said_single(raw: &[u8], code: DigestCode) -> Result<(), SerderError> {
    let mut value: Value = serde_json::from_slice(raw)?;
    let obj = value
        .as_object_mut()
        .ok_or(SerderError::MissingField("d"))?;

    let original_said = obj
        .get("d")
        .and_then(Value::as_str)
        .ok_or(SerderError::MissingField("d"))?
        .to_owned();

    let placeholder = code
        .placeholder()
        .map_err(|e| SerderError::PlaceholderPrimitive { source: e.into() })?;
    obj.insert("d".to_owned(), Value::String(placeholder));

    let reser = serde_json::to_string(&value)?;
    let computed = Saider::digest(code, reser.as_bytes())?;
    let computed_qb64 = computed.to_qb64();

    if original_said != computed_qb64 {
        return Err(SerderError::SaidMismatch {
            expected: original_said,
            computed: computed_qb64,
        });
    }
    Ok(())
}

/// Verify a double-SAID event (icp, dip): both `d` and `i` are replaced with
/// placeholders before computing the digest.
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn verify_said_double(raw: &[u8], code: DigestCode) -> Result<(), SerderError> {
    let mut value: Value = serde_json::from_slice(raw)?;
    let obj = value
        .as_object_mut()
        .ok_or(SerderError::MissingField("d"))?;

    let original_said = obj
        .get("d")
        .and_then(Value::as_str)
        .ok_or(SerderError::MissingField("d"))?
        .to_owned();

    let placeholder = code
        .placeholder()
        .map_err(|e| SerderError::PlaceholderPrimitive { source: e.into() })?;
    obj.insert("d".to_owned(), Value::String(placeholder.clone()));
    obj.insert("i".to_owned(), Value::String(placeholder));

    let reser = serde_json::to_string(&value)?;
    let computed = Saider::digest(code, reser.as_bytes())?;
    let computed_qb64 = computed.to_qb64();

    if original_said != computed_qb64 {
        return Err(SerderError::SaidMismatch {
            expected: original_said,
            computed: computed_qb64,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Array parsing helpers
// ---------------------------------------------------------------------------

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn parse_qb64_prefixer_array(
    val: &Value,
) -> Result<Vec<Prefixer<'static>>, SerderError> {
    let arr = val.as_array().ok_or(SerderError::MissingField("b"))?;
    arr.iter()
        .map(|v| {
            let s = v.as_str().ok_or(SerderError::MissingField("b"))?;
            parse_qb64_prefixer(s, "b").map(Matter::into_static)
        })
        .collect()
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn parse_qb64_verfer_array(val: &Value) -> Result<Vec<Verfer<'static>>, SerderError> {
    let arr = val.as_array().ok_or(SerderError::MissingField("k"))?;
    arr.iter()
        .map(|v| {
            let s = v.as_str().ok_or(SerderError::MissingField("k"))?;
            parse_qb64_verfer(s, "k").map(Matter::into_static)
        })
        .collect()
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn parse_qb64_diger_array(val: &Value) -> Result<Vec<Diger<'static>>, SerderError> {
    let arr = val.as_array().ok_or(SerderError::MissingField("n"))?;
    arr.iter()
        .map(|v| {
            let s = v.as_str().ok_or(SerderError::MissingField("n"))?;
            parse_qb64_diger(s, "n").map(Matter::into_static)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Signing-threshold parsing
// ---------------------------------------------------------------------------

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn tholder_from_json(
    val: &Value,
    field: &'static str,
) -> Result<SigningThreshold, SerderError> {
    if let Some(s) = val.as_str() {
        let n = u64::from_str_radix(s, 16).map_err(|_| SerderError::InvalidPrimitive {
            field: "kt",
            source: ValidationError::UnknownMatterCode(format!("invalid hex threshold: {s}")),
        })?;
        return Ok(SigningThreshold::Simple(n));
    }

    if let Some(n) = val.as_u64() {
        return Ok(SigningThreshold::Simple(n));
    }

    if let Some(outer) = val.as_array() {
        // keripy flattens single-clause weighted thresholds: [["1/2","1/2"]]
        // becomes ["1/2","1/2"]. Detect flat vs nested by checking if the
        // first element is a string (flat) or an array (nested).
        let is_flat = outer.first().is_some_and(Value::is_string);

        let clauses: Result<Vec<Vec<(u64, u64)>>, SerderError> = if is_flat {
            // Flat list of fraction strings → single clause
            let clause: Result<Vec<(u64, u64)>, SerderError> = outer
                .iter()
                .map(|frac_val| {
                    let frac_str = frac_val.as_str().ok_or(SerderError::MissingField("kt"))?;
                    parse_weight(frac_str)
                })
                .collect();
            Ok(vec![clause?])
        } else {
            // Nested list of lists
            outer
                .iter()
                .map(|clause_val| {
                    let clause_arr = clause_val
                        .as_array()
                        .ok_or(SerderError::MissingField("kt"))?;
                    clause_arr
                        .iter()
                        .map(|frac_val| {
                            let frac_str =
                                frac_val.as_str().ok_or(SerderError::MissingField("kt"))?;
                            parse_weight(frac_str)
                        })
                        .collect()
                })
                .collect()
        };
        let weighted = WeightedThreshold::from_nested(clauses?)
            .map_err(|source| SerderError::SigningThresholdOutOfRange { field, source })?;
        return Ok(SigningThreshold::Weighted(weighted));
    }

    Err(SerderError::MissingField("kt"))
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn parse_witness_threshold(val: &Value) -> Result<u32, SerderError> {
    if let Some(n) = val.as_u64() {
        return u32::try_from(n).map_err(|_| SerderError::InvalidPrimitive {
            field: "bt",
            source: ValidationError::UnknownMatterCode(format!(
                "witness threshold {n} exceeds u32::MAX"
            )),
        });
    }
    let s = val.as_str().ok_or(SerderError::MissingField("bt"))?;
    let n = u128::from_str_radix(s, 16).map_err(|_| SerderError::InvalidPrimitive {
        field: "bt",
        source: ValidationError::UnknownMatterCode(format!("invalid hex bt: {s}")),
    })?;
    u32::try_from(n).map_err(|_| SerderError::InvalidPrimitive {
        field: "bt",
        source: ValidationError::UnknownMatterCode(format!(
            "witness threshold {n} exceeds u32::MAX"
        )),
    })
}

/// Mirror of the strict path's `threshold_form_of`: a JSON-number `bt`
/// signals keripy `intive=True`, a JSON-string `bt` signals hex. Anything
/// else is treated as hex (the downstream `parse_witness_threshold` rejects
/// truly malformed `bt`).
fn threshold_form_of(bt: &Value) -> ThresholdForm {
    if bt.is_number() {
        ThresholdForm::Integer
    } else {
        ThresholdForm::HexString
    }
}

/// Mirror of the strict path's `check_form_consistency`: a simple-numeric
/// `kt`/`nt` must agree with `bt`'s wire form; weighted (array) thresholds
/// are exempt. An integer-form value above `u32::MAX` is a disagreement
/// (keripy's `MaxIntThold` would have forced hex).
fn check_form_consistency(
    field: &'static str,
    t: &Value,
    form: ThresholdForm,
) -> Result<(), SerderError> {
    let consistent = if t.is_array() {
        true
    } else {
        match form {
            ThresholdForm::HexString => t.is_string(),
            ThresholdForm::Integer => t.as_u64().is_some_and(|n| u32::try_from(n).is_ok()),
        }
    };
    if consistent {
        Ok(())
    } else {
        Err(SerderError::MixedThresholdForms { field })
    }
}

// ---------------------------------------------------------------------------
// Seal parsing
// ---------------------------------------------------------------------------

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn seal_from_json(val: &Value) -> Result<Seal<'static>, SerderError> {
    let obj = val.as_object().ok_or(SerderError::MissingField("a"))?;

    let n = obj.len();
    let str_field = |k: &str| obj.get(k).and_then(Value::as_str);

    // A typed branch matches on key set, field count, AND all matched
    // values being JSON strings — mirroring the strict scanner, where a
    // non-string value fails `string()` and the whole object falls back
    // to the opaque capture below.
    if n == 3
        && let (Some(i), Some(s), Some(d)) = (str_field("i"), str_field("s"), str_field("d"))
    {
        return Ok(Seal::Event {
            i: parse_qb64_prefixer(i, "i")?,
            s: SequenceNumber::new(parse_sn(s)?),
            d: parse_qb64_saider(d, "d")?,
        }
        .into_static());
    }
    if n == 2
        && let (Some(s), Some(d)) = (str_field("s"), str_field("d"))
    {
        return Ok(Seal::Source {
            s: SequenceNumber::new(parse_sn(s)?),
            d: parse_qb64_saider(d, "d")?,
        }
        .into_static());
    }
    if n == 2
        && let (Some(bi), Some(d)) = (str_field("bi"), str_field("d"))
    {
        return Ok(Seal::Back {
            bi: parse_qb64_prefixer(bi, "bi")?,
            d: parse_qb64_saider(d, "d")?,
        }
        .into_static());
    }
    if n == 2
        && let (Some(t), Some(d)) = (str_field("t"), str_field("d"))
    {
        return Ok(Seal::Kind {
            t: parse_qb64_verser(t, "t")?,
            d: parse_qb64_saider(d, "d")?,
        }
        .into_static());
    }
    if n == 1
        && let Some(rd) = str_field("rd")
    {
        return Ok(Seal::Root {
            rd: parse_qb64_saider(rd, "rd")?,
        }
        .into_static());
    }
    if n == 1
        && let Some(d) = str_field("d")
    {
        return Ok(Seal::Digest {
            d: parse_qb64_saider(d, "d")?,
        }
        .into_static());
    }
    if n == 1
        && let Some(i) = str_field("i")
    {
        return Ok(Seal::Last {
            i: parse_qb64_prefixer(i, "i")?,
        }
        .into_static());
    }
    // Non-codex anchor: keep it verbatim. `preserve_order` keeps the
    // wire key order through the serde_json round-trip; note the oracle
    // NORMALIZES exotic number/escape spellings (it re-serializes a
    // parsed `Value`), so strict-vs-oracle comparisons must use
    // normalization-stable payloads (integers, minimal escaping). The
    // strict path is the wire-fidelity authority.
    let raw = serde_json::to_string(val).map_err(SerderError::from)?;
    OpaqueScan::object_len(raw.as_bytes())
        .map_err(|source| SerderError::InvalidAnchor { offset: 0, source })?;
    Ok(Seal::Opaque(OpaqueSeal::new_unchecked(raw)))
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn parse_seal_array(val: &Value) -> Result<Vec<Seal<'static>>, SerderError> {
    let arr = val.as_array().ok_or(SerderError::MissingField("a"))?;
    arr.iter().map(seal_from_json).collect()
}

// ---------------------------------------------------------------------------
// Config parsing
// ---------------------------------------------------------------------------

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn parse_config_array(val: &Value) -> Result<Vec<ConfigTrait>, SerderError> {
    let arr = val.as_array().ok_or(SerderError::MissingField("c"))?;
    arr.iter()
        .map(|v| {
            let s = v.as_str().ok_or(SerderError::MissingField("c"))?;
            ConfigTrait::from_code(s).map_err(|_| SerderError::UnknownIlk(s.to_owned()))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// JSON field access helpers
// ---------------------------------------------------------------------------

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn get_str<'a>(val: &'a Value, field: &'static str) -> Result<&'a str, SerderError> {
    val.get(field)
        .and_then(Value::as_str)
        .ok_or(SerderError::MissingField(field))
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn get_field<'a>(val: &'a Value, field: &'static str) -> Result<&'a Value, SerderError> {
    val.get(field).ok_or(SerderError::MissingField(field))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Serialize;
    use alloc::borrow::Cow;
    use cesr::core::matter::builder::MatterBuilder;
    use cesr::core::matter::code::{CesrCode, DigestCode, VerKeyCode};
    use cesr::core::primitives::{Prefixer, Saider};

    fn weighted(clauses: Vec<Vec<(u64, u64)>>) -> SigningThreshold {
        SigningThreshold::Weighted(WeightedThreshold::from_nested(clauses).unwrap())
    }

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

    fn qb64(m: &cesr::core::matter::matter::Matter<'_, impl CesrCode>) -> String {
        m.to_qb64()
    }

    fn probe_icp() -> InceptionEvent<'static> {
        InceptionEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(0),
            make_saider(),
            vec![make_verfer()],
            SigningThreshold::Simple(1),
            vec![make_saider()],
            SigningThreshold::Simple(1),
            vec![make_prefixer()],
            Toad::exact(1, 1).unwrap(),
            vec![ConfigTrait::EstOnly],
            vec![Seal::Digest { d: make_saider() }],
            ThresholdForm::HexString,
        )
    }

    fn probe_rot() -> RotationEvent<'static> {
        RotationEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(2),
            make_saider(),
            make_saider(),
            vec![make_verfer()],
            SigningThreshold::Simple(1),
            vec![make_saider()],
            SigningThreshold::Simple(1),
            vec![make_prefixer()],
            vec![],
            Toad::from_wire(1),
            vec![],
            ThresholdForm::HexString,
        )
    }

    // -----------------------------------------------------------------------
    // Oracle round-trips: every tolerant entry point stays green on writer
    // output (the property the differential suite diffs the strict path
    // against).
    // -----------------------------------------------------------------------

    #[test]
    fn oracle_roundtrips_icp() {
        let ser = probe_icp().serialize().unwrap();
        let event = deserialize_inception(ser.as_bytes()).unwrap();
        assert_eq!(qb64(event.said()), qb64(ser.said()));
        assert!(matches!(
            deserialize_event(ser.as_bytes()).unwrap(),
            KeriEvent::Inception(_)
        ));
    }

    #[test]
    fn oracle_roundtrips_rot() {
        let ser = probe_rot().serialize().unwrap();
        let event = deserialize_rotation(ser.as_bytes()).unwrap();
        assert_eq!(qb64(event.said()), qb64(ser.said()));
        assert!(matches!(
            deserialize_event(ser.as_bytes()).unwrap(),
            KeriEvent::Rotation(_)
        ));
    }

    #[test]
    fn oracle_roundtrips_ixn() {
        let ixn = InteractionEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(3),
            make_saider(),
            make_saider(),
            vec![Seal::Digest { d: make_saider() }],
        );
        let ser = ixn.serialize().unwrap();
        let event = deserialize_interaction(ser.as_bytes()).unwrap();
        assert_eq!(qb64(event.said()), qb64(ser.said()));
        assert!(matches!(
            deserialize_event(ser.as_bytes()).unwrap(),
            KeriEvent::Interaction(_)
        ));
    }

    #[test]
    fn oracle_roundtrips_dip() {
        let dip = DelegatedInceptionEvent::new(probe_icp(), make_prefixer().into());
        let ser = dip.serialize().unwrap();
        let event = deserialize_delegated_inception(ser.as_bytes()).unwrap();
        assert_eq!(qb64(event.inception().said()), qb64(ser.said()));
        assert!(matches!(
            deserialize_event(ser.as_bytes()).unwrap(),
            KeriEvent::DelegatedInception(_)
        ));
    }

    #[test]
    fn oracle_roundtrips_drt() {
        let drt = DelegatedRotationEvent::new(probe_rot());
        let ser = drt.serialize().unwrap();
        let event = deserialize_delegated_rotation(ser.as_bytes()).unwrap();
        assert_eq!(qb64(event.rotation().said()), qb64(ser.said()));
        assert!(matches!(
            deserialize_event(ser.as_bytes()).unwrap(),
            KeriEvent::DelegatedRotation(_)
        ));
    }

    // -----------------------------------------------------------------------
    // Signing-threshold parsing
    // -----------------------------------------------------------------------

    #[test]
    fn tholder_simple_from_json() {
        let val = Value::String("3".to_owned());
        let th = tholder_from_json(&val, "signing").unwrap();
        assert_eq!(th, SigningThreshold::Simple(3));
    }

    #[test]
    fn tholder_weighted_from_json() {
        let val = serde_json::json!([["1/2", "1/2"], ["1/3", "1/3", "1/3"]]);
        let th = tholder_from_json(&val, "signing").unwrap();
        assert_eq!(
            th,
            weighted(vec![vec![(1, 2), (1, 2)], vec![(1, 3), (1, 3), (1, 3)],])
        );
    }

    #[test]
    fn tholder_invalid_returns_error() {
        let val = Value::Bool(true);
        let result = tholder_from_json(&val, "signing");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Seal parsing
    // -----------------------------------------------------------------------

    #[test]
    fn seal_digest_from_json() {
        let saider = make_saider();
        let qb64_str = qb64(&saider);
        let val = serde_json::json!({"d": qb64_str});
        let seal = seal_from_json(&val).unwrap();
        assert!(matches!(seal, Seal::Digest { .. }));
    }

    #[test]
    fn seal_root_from_json() {
        let saider = make_saider();
        let qb64_str = qb64(&saider);
        let val = serde_json::json!({"rd": qb64_str});
        let seal = seal_from_json(&val).unwrap();
        assert!(matches!(seal, Seal::Root { .. }));
    }

    #[test]
    fn seal_source_from_json() {
        let saider = make_saider();
        let qb64_str = qb64(&saider);
        let val = serde_json::json!({"s": "1", "d": qb64_str});
        let seal = seal_from_json(&val).unwrap();
        let Seal::Source { s, d } = seal else {
            unreachable!()
        };
        assert_eq!(s.value(), 1);
        assert_eq!(qb64(&d), qb64_str);
    }

    #[test]
    fn seal_event_from_json() {
        let saider = make_saider();
        let prefixer = make_prefixer();
        let d_str = qb64(&saider);
        let i_str = qb64(&prefixer);
        let val = serde_json::json!({"i": i_str, "s": "a", "d": d_str});
        let seal = seal_from_json(&val).unwrap();
        let Seal::Event { i, s, d } = seal else {
            unreachable!()
        };
        assert_eq!(qb64(&i), i_str);
        assert_eq!(s.value(), 10);
        assert_eq!(qb64(&d), d_str);
    }

    #[test]
    fn seal_last_from_json() {
        let prefixer = make_prefixer();
        let i_str = qb64(&prefixer);
        let val = serde_json::json!({"i": i_str});
        let seal = seal_from_json(&val).unwrap();
        let Seal::Last { i } = seal else {
            unreachable!()
        };
        assert_eq!(qb64(&i), i_str);
    }

    // -----------------------------------------------------------------------
    // intive=True integer threshold deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn tholder_from_json_integer() {
        let val = serde_json::json!(2);
        let tholder = tholder_from_json(&val, "signing").unwrap();
        assert_eq!(tholder, SigningThreshold::Simple(2));
    }

    #[test]
    fn parse_witness_threshold_integer() {
        let val = serde_json::json!(3);
        let bt = parse_witness_threshold(&val).unwrap();
        assert_eq!(bt, 3);
    }
}
