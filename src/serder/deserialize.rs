//! KERI event deserialization from canonical JSON with SAID verification.
//!
//! Parses JSON-encoded KERI events produced by the serialization module,
//! reconstructing [`keri_core`] domain types.  Every deserialized event is
//! verified against its SAID before being returned.

use crate::core::matter::builder::MatterBuilder;
use crate::core::matter::code::{DigestCode, MatterCode, VerKeyCode};
use crate::core::matter::error::{MatterBuildError, ValidationError};
use crate::core::primitives::{Diger, Prefixer, Saider, Seqner, Tholder, Verfer};
use crate::keri::{
    ConfigTrait, DelegatedInceptionEvent, DelegatedRotationEvent, Identifier, Ilk, InceptionEvent,
    InteractionEvent, KeriEvent, RotationEvent, Seal,
};
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, format, string::String, string::ToString, vec, vec::Vec};
use serde_json::Value;

use crate::serder::error::SerderError;
use crate::serder::primitives::to_qb64_string;
use crate::serder::said::{compute_digest, said_placeholder};
use crate::serder::version::{SerKind, VERSION_STRING_LEN, VersionString};

// ---------------------------------------------------------------------------
// Public deserialization entry points
// ---------------------------------------------------------------------------

/// Deserialize any KERI event from canonical JSON bytes.
///
/// Parses the `t` (ilk) field to dispatch to the appropriate event-specific
/// deserializer, then verifies the SAID before returning.
///
/// # Errors
///
/// Returns [`SerderError`] if JSON parsing fails, required fields are missing
/// or invalid, or the SAID does not verify.
pub fn deserialize_event(raw: &[u8]) -> Result<KeriEvent, SerderError> {
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

/// Deserialize an inception event from canonical JSON bytes.
///
/// Verifies the double-SAID property (both `d` and `i` are replaced with
/// placeholders during verification).
///
/// # Errors
///
/// Returns [`SerderError`] if JSON parsing fails, required fields are missing
/// or invalid, or the SAID does not verify.
pub fn deserialize_inception(raw: &[u8]) -> Result<InceptionEvent, SerderError> {
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
    let threshold = tholder_from_json(get_field(&val, "kt")?)?;
    let keys = parse_qb64_verfer_array(get_field(&val, "k")?)?;
    let next_threshold = tholder_from_json(get_field(&val, "nt")?)?;
    let next_keys = parse_qb64_diger_array(get_field(&val, "n")?)?;
    let witness_threshold = parse_witness_threshold(get_field(&val, "bt")?)?;
    let witnesses = parse_qb64_prefixer_array(get_field(&val, "b")?)?;
    let config = parse_config_array(get_field(&val, "c")?)?;
    let anchors = parse_seal_array(get_field(&val, "a")?)?;

    Ok(InceptionEvent::new(
        prefix,
        Seqner::new(sn),
        said,
        keys,
        threshold,
        next_keys,
        next_threshold,
        witnesses,
        witness_threshold,
        config,
        anchors,
    ))
}

/// Deserialize a rotation event from canonical JSON bytes.
///
/// # Errors
///
/// Returns [`SerderError`] if JSON parsing fails, required fields are missing
/// or invalid, or the SAID does not verify.
pub fn deserialize_rotation(raw: &[u8]) -> Result<RotationEvent, SerderError> {
    let val: Value = serde_json::from_slice(raw)?;
    let digest_code = infer_digest_code(get_str(&val, "d")?)?;

    verify_said_single(raw, digest_code)?;

    let said = parse_qb64_diger(get_str(&val, "d")?, "d")?;
    let prefix = parse_qb64_identifier(get_str(&val, "i")?, "i")?;
    let sn = parse_sn(get_str(&val, "s")?)?;
    let prior_event_said = parse_qb64_diger(get_str(&val, "p")?, "p")?;
    let threshold = tholder_from_json(get_field(&val, "kt")?)?;
    let keys = parse_qb64_verfer_array(get_field(&val, "k")?)?;
    let next_threshold = tholder_from_json(get_field(&val, "nt")?)?;
    let next_keys = parse_qb64_diger_array(get_field(&val, "n")?)?;
    let witness_threshold = parse_witness_threshold(get_field(&val, "bt")?)?;
    let witness_removals = parse_qb64_prefixer_array(get_field(&val, "br")?)?;
    let witness_additions = parse_qb64_prefixer_array(get_field(&val, "ba")?)?;
    let config = match val.get("c") {
        Some(c_val) => parse_config_array(c_val)?,
        None => vec![],
    };
    let anchors = parse_seal_array(get_field(&val, "a")?)?;

    Ok(RotationEvent::new(
        prefix,
        Seqner::new(sn),
        said,
        prior_event_said,
        keys,
        threshold,
        next_keys,
        next_threshold,
        witness_additions,
        witness_removals,
        witness_threshold,
        config,
        anchors,
    ))
}

/// Deserialize an interaction event from canonical JSON bytes.
///
/// # Errors
///
/// Returns [`SerderError`] if JSON parsing fails, required fields are missing
/// or invalid, or the SAID does not verify.
pub fn deserialize_interaction(raw: &[u8]) -> Result<InteractionEvent, SerderError> {
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
        Seqner::new(sn),
        said,
        prior_event_said,
        anchors,
    ))
}

/// Deserialize a delegated inception event from canonical JSON bytes.
///
/// Verifies the double-SAID property (both `d` and `i` are replaced with
/// placeholders during verification).
///
/// # Errors
///
/// Returns [`SerderError`] if JSON parsing fails, required fields are missing
/// or invalid, or the SAID does not verify.
pub fn deserialize_delegated_inception(raw: &[u8]) -> Result<DelegatedInceptionEvent, SerderError> {
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
    let threshold = tholder_from_json(get_field(&val, "kt")?)?;
    let keys = parse_qb64_verfer_array(get_field(&val, "k")?)?;
    let next_threshold = tholder_from_json(get_field(&val, "nt")?)?;
    let next_keys = parse_qb64_diger_array(get_field(&val, "n")?)?;
    let witness_threshold = parse_witness_threshold(get_field(&val, "bt")?)?;
    let witnesses = parse_qb64_prefixer_array(get_field(&val, "b")?)?;
    let config = parse_config_array(get_field(&val, "c")?)?;
    let anchors = parse_seal_array(get_field(&val, "a")?)?;
    let delegator = parse_qb64_identifier(get_str(&val, "di")?, "di")?;

    Ok(DelegatedInceptionEvent::new(
        InceptionEvent::new(
            prefix,
            Seqner::new(sn),
            said,
            keys,
            threshold,
            next_keys,
            next_threshold,
            witnesses,
            witness_threshold,
            config,
            anchors,
        ),
        delegator,
    ))
}

/// Deserialize a delegated rotation event from canonical JSON bytes.
///
/// # Errors
///
/// Returns [`SerderError`] if JSON parsing fails, required fields are missing
/// or invalid, or the SAID does not verify.
pub fn deserialize_delegated_rotation(raw: &[u8]) -> Result<DelegatedRotationEvent, SerderError> {
    let rotation = deserialize_rotation(raw)?;
    Ok(DelegatedRotationEvent::new(rotation))
}

// ---------------------------------------------------------------------------
// Version string validation
// ---------------------------------------------------------------------------

fn validate_version_string(raw: &[u8]) -> Result<(), SerderError> {
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
    let vs = VersionString::parse(vs_str)?;
    if vs.kind != SerKind::Json {
        return Err(SerderError::InvalidVersionString(format!(
            "expected JSON, got {}",
            vs.kind.as_str()
        )));
    }
    let expected_size =
        usize::try_from(vs.size).map_err(|e| SerderError::InvalidVersionString(e.to_string()))?;
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
fn verify_said_single(raw: &[u8], code: DigestCode) -> Result<(), SerderError> {
    let mut value: Value = serde_json::from_slice(raw)?;
    let obj = value
        .as_object_mut()
        .ok_or(SerderError::MissingField("d"))?;

    let original_said = obj
        .get("d")
        .and_then(Value::as_str)
        .ok_or(SerderError::MissingField("d"))?
        .to_owned();

    let placeholder = said_placeholder(code)?;
    obj.insert("d".to_owned(), Value::String(placeholder));

    let reser = serde_json::to_string(&value)?;
    let computed = compute_digest(reser.as_bytes(), code)?;
    let computed_qb64 = to_qb64_string(&computed)?;

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
fn verify_said_double(raw: &[u8], code: DigestCode) -> Result<(), SerderError> {
    let mut value: Value = serde_json::from_slice(raw)?;
    let obj = value
        .as_object_mut()
        .ok_or(SerderError::MissingField("d"))?;

    let original_said = obj
        .get("d")
        .and_then(Value::as_str)
        .ok_or(SerderError::MissingField("d"))?
        .to_owned();

    let placeholder = said_placeholder(code)?;
    obj.insert("d".to_owned(), Value::String(placeholder.clone()));
    obj.insert("i".to_owned(), Value::String(placeholder));

    let reser = serde_json::to_string(&value)?;
    let computed = compute_digest(reser.as_bytes(), code)?;
    let computed_qb64 = to_qb64_string(&computed)?;

    if original_said != computed_qb64 {
        return Err(SerderError::SaidMismatch {
            expected: original_said,
            computed: computed_qb64,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Digest code inference
// ---------------------------------------------------------------------------

/// Infer the [`DigestCode`] from a qb64 SAID string by parsing its code prefix.
fn infer_digest_code(qb64_said: &str) -> Result<DigestCode, SerderError> {
    let matter_code = MatterCode::from_base64_stream(qb64_said.as_bytes()).map_err(|e| {
        SerderError::InvalidPrimitive {
            field: "d",
            source: ValidationError::UnknownMatterCode(e.to_string()),
        }
    })?;
    DigestCode::try_from(matter_code).map_err(|e| SerderError::InvalidPrimitive {
        field: "d",
        source: e,
    })
}

// ---------------------------------------------------------------------------
// Primitive parsing helpers
// ---------------------------------------------------------------------------

fn parse_qb64_prefixer(s: &str, field: &'static str) -> Result<Prefixer<'static>, SerderError> {
    let matter = MatterBuilder::new()
        .from_qualified_base64(s.as_bytes())
        .map_err(|e| map_qb64_error(field, e))?;
    let narrowed = matter
        .narrow::<VerKeyCode>()
        .map_err(|e| SerderError::InvalidPrimitive { field, source: e })?;
    Ok(narrowed.into_static())
}

/// Parse a qb64 string as a KERI identifier prefix, which may be either a
/// verification key (basic derivation) or a digest (self-addressing derivation).
///
/// Tries `VerKeyCode` first (basic derivation like `D`); if that fails, tries
/// `DigestCode` (self-addressing like `E`). Returns the typed [`Identifier`]
/// enum preserving the original code.
fn parse_qb64_identifier(s: &str, field: &'static str) -> Result<Identifier<'static>, SerderError> {
    let matter = MatterBuilder::new()
        .from_qualified_base64(s.as_bytes())
        .map_err(|e| map_qb64_error(field, e))?;

    if let Ok(narrowed) = matter.narrow::<VerKeyCode>() {
        return Ok(Identifier::Basic(narrowed.into_static()));
    }

    let digest_matter = MatterBuilder::new()
        .from_qualified_base64(s.as_bytes())
        .map_err(|e| map_qb64_error(field, e))?;
    let saider = digest_matter
        .narrow::<DigestCode>()
        .map_err(|e| SerderError::InvalidPrimitive { field, source: e })?;
    Ok(Identifier::SelfAddressing(saider.into_static()))
}

fn parse_qb64_verfer(s: &str, field: &'static str) -> Result<Verfer<'static>, SerderError> {
    parse_qb64_prefixer(s, field)
}

fn parse_qb64_diger(s: &str, field: &'static str) -> Result<Diger<'static>, SerderError> {
    let matter = MatterBuilder::new()
        .from_qualified_base64(s.as_bytes())
        .map_err(|e| map_qb64_error(field, e))?;
    let narrowed = matter
        .narrow::<DigestCode>()
        .map_err(|e| SerderError::InvalidPrimitive { field, source: e })?;
    Ok(narrowed.into_static())
}

fn parse_qb64_saider(s: &str, field: &'static str) -> Result<Saider<'static>, SerderError> {
    parse_qb64_diger(s, field)
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

fn parse_witness_threshold(val: &Value) -> Result<u32, SerderError> {
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

// ---------------------------------------------------------------------------
// Array parsing helpers
// ---------------------------------------------------------------------------

fn parse_qb64_prefixer_array(val: &Value) -> Result<Vec<Prefixer<'static>>, SerderError> {
    let arr = val.as_array().ok_or(SerderError::MissingField("b"))?;
    arr.iter()
        .map(|v| {
            let s = v.as_str().ok_or(SerderError::MissingField("b"))?;
            parse_qb64_prefixer(s, "b")
        })
        .collect()
}

fn parse_qb64_verfer_array(val: &Value) -> Result<Vec<Verfer<'static>>, SerderError> {
    let arr = val.as_array().ok_or(SerderError::MissingField("k"))?;
    arr.iter()
        .map(|v| {
            let s = v.as_str().ok_or(SerderError::MissingField("k"))?;
            parse_qb64_verfer(s, "k")
        })
        .collect()
}

fn parse_qb64_diger_array(val: &Value) -> Result<Vec<Diger<'static>>, SerderError> {
    let arr = val.as_array().ok_or(SerderError::MissingField("n"))?;
    arr.iter()
        .map(|v| {
            let s = v.as_str().ok_or(SerderError::MissingField("n"))?;
            parse_qb64_diger(s, "n")
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tholder parsing
// ---------------------------------------------------------------------------

fn tholder_from_json(val: &Value) -> Result<Tholder, SerderError> {
    if let Some(s) = val.as_str() {
        let n = u64::from_str_radix(s, 16).map_err(|_| SerderError::InvalidPrimitive {
            field: "kt",
            source: ValidationError::UnknownMatterCode(format!("invalid hex threshold: {s}")),
        })?;
        return Ok(Tholder::Simple(n));
    }

    if let Some(n) = val.as_u64() {
        return Ok(Tholder::Simple(n));
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
        return Ok(Tholder::Weighted(clauses?));
    }

    Err(SerderError::MissingField("kt"))
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
// Seal parsing
// ---------------------------------------------------------------------------

fn seal_from_json(val: &Value) -> Result<Seal, SerderError> {
    let obj = val.as_object().ok_or(SerderError::MissingField("a"))?;

    let has = |k: &str| obj.contains_key(k);
    let n = obj.len();

    // Match by key presence (order-independent) and field count.
    if has("i") && has("s") && has("d") && n == 3 {
        let i = parse_qb64_prefixer(
            obj["i"].as_str().ok_or(SerderError::MissingField("i"))?,
            "i",
        )?;
        let s_val = parse_sn(obj["s"].as_str().ok_or(SerderError::MissingField("s"))?)?;
        let digest = parse_qb64_saider(
            obj["d"].as_str().ok_or(SerderError::MissingField("d"))?,
            "d",
        )?;
        Ok(Seal::Event {
            i,
            s: Seqner::new(s_val),
            d: digest,
        })
    } else if has("s") && has("d") && n == 2 {
        let s_val = parse_sn(obj["s"].as_str().ok_or(SerderError::MissingField("s"))?)?;
        let digest = parse_qb64_saider(
            obj["d"].as_str().ok_or(SerderError::MissingField("d"))?,
            "d",
        )?;
        Ok(Seal::Source {
            s: Seqner::new(s_val),
            d: digest,
        })
    } else if has("rd") && n == 1 {
        let root_digest = parse_qb64_saider(
            obj["rd"].as_str().ok_or(SerderError::MissingField("rd"))?,
            "rd",
        )?;
        Ok(Seal::Root { rd: root_digest })
    } else if has("d") && n == 1 {
        let digest = parse_qb64_saider(
            obj["d"].as_str().ok_or(SerderError::MissingField("d"))?,
            "d",
        )?;
        Ok(Seal::Digest { d: digest })
    } else if has("i") && n == 1 {
        let i = parse_qb64_prefixer(
            obj["i"].as_str().ok_or(SerderError::MissingField("i"))?,
            "i",
        )?;
        Ok(Seal::Last { i })
    } else {
        Err(SerderError::MissingField("a"))
    }
}

fn parse_seal_array(val: &Value) -> Result<Vec<Seal>, SerderError> {
    let arr = val.as_array().ok_or(SerderError::MissingField("a"))?;
    arr.iter().map(seal_from_json).collect()
}

// ---------------------------------------------------------------------------
// Config parsing
// ---------------------------------------------------------------------------

fn parse_config_array(val: &Value) -> Result<Vec<ConfigTrait>, SerderError> {
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

fn get_str<'a>(val: &'a Value, field: &'static str) -> Result<&'a str, SerderError> {
    val.get(field)
        .and_then(Value::as_str)
        .ok_or(SerderError::MissingField(field))
}

fn get_field<'a>(val: &'a Value, field: &'static str) -> Result<&'a Value, SerderError> {
    val.get(field).ok_or(SerderError::MissingField(field))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::{CesrCode, DigestCode, VerKeyCode};
    use crate::core::primitives::{Diger, Prefixer, Saider, Seqner, Tholder, Verfer};
    use crate::keri::{
        DelegatedInceptionEvent, DelegatedRotationEvent, InceptionEvent, InteractionEvent,
        RotationEvent,
    };
    use crate::serder::serialize::{
        serialize, serialize_delegated_inception, serialize_delegated_rotation,
        serialize_inception, serialize_interaction, serialize_rotation,
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

    fn qb64(m: &crate::core::matter::matter::Matter<'_, impl CesrCode>) -> String {
        crate::serder::primitives::to_qb64_string(m).unwrap()
    }

    // -----------------------------------------------------------------------
    // Roundtrip tests: serialize -> deserialize -> compare fields
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrip_icp() {
        let event = InceptionEvent::new(
            make_prefixer().into(),
            Seqner::new(0),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![make_prefixer()],
            1,
            vec![ConfigTrait::EstOnly],
            vec![],
        );
        let serialized = serialize_inception(&event).unwrap();
        let deserialized = deserialize_inception(serialized.as_bytes()).unwrap();

        assert_eq!(deserialized.sn().value(), 0);
        assert_eq!(deserialized.keys().len(), 1);
        assert_eq!(deserialized.next_keys().len(), 1);
        assert_eq!(*deserialized.threshold(), Tholder::Simple(1));
        assert_eq!(*deserialized.next_threshold(), Tholder::Simple(1));
        assert_eq!(deserialized.witnesses().len(), 1);
        assert_eq!(deserialized.witness_threshold(), 1);
        assert_eq!(deserialized.config(), [ConfigTrait::EstOnly]);
        assert!(deserialized.anchors().is_empty());
        assert_eq!(qb64(deserialized.said()), qb64(serialized.said()));
        assert_eq!(
            deserialized.prefix().as_saider().unwrap().raw(),
            deserialized.said().raw(),
            "self-addressing prefix raw bytes should match SAID raw bytes"
        );
    }

    #[test]
    fn roundtrip_rot() {
        let event = RotationEvent::new(
            make_prefixer().into(),
            Seqner::new(1),
            make_saider(),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![make_prefixer()],
            vec![],
            1,
            vec![],
            vec![],
        );
        let serialized = serialize_rotation(&event).unwrap();
        let deserialized = deserialize_rotation(serialized.as_bytes()).unwrap();

        assert_eq!(deserialized.sn().value(), 1);
        assert_eq!(deserialized.keys().len(), 1);
        assert_eq!(deserialized.next_keys().len(), 1);
        assert_eq!(*deserialized.threshold(), Tholder::Simple(1));
        assert_eq!(deserialized.witness_additions().len(), 1);
        assert!(deserialized.witness_removals().is_empty());
        assert_eq!(deserialized.witness_threshold(), 1);
        assert!(deserialized.config().is_empty());
        assert!(deserialized.anchors().is_empty());
        assert_eq!(qb64(deserialized.said()), qb64(serialized.said()));
        assert_eq!(
            crate::serder::primitives::identifier_to_qb64_string(deserialized.prefix()).unwrap(),
            crate::serder::primitives::identifier_to_qb64_string(event.prefix()).unwrap()
        );
    }

    #[test]
    fn roundtrip_ixn() {
        let event = InteractionEvent::new(
            make_prefixer().into(),
            Seqner::new(3),
            make_saider(),
            make_saider(),
            vec![
                Seal::Digest { d: make_saider() },
                Seal::Source {
                    s: Seqner::new(1),
                    d: make_saider(),
                },
            ],
        );
        let serialized = serialize_interaction(&event).unwrap();
        let deserialized = deserialize_interaction(serialized.as_bytes()).unwrap();

        assert_eq!(deserialized.sn().value(), 3);
        assert_eq!(deserialized.anchors().len(), 2);
        assert_eq!(qb64(deserialized.said()), qb64(serialized.said()));
        assert_eq!(
            crate::serder::primitives::identifier_to_qb64_string(deserialized.prefix()).unwrap(),
            crate::serder::primitives::identifier_to_qb64_string(event.prefix()).unwrap()
        );
    }

    #[test]
    fn roundtrip_dip() {
        let event = DelegatedInceptionEvent::new(
            InceptionEvent::new(
                make_prefixer().into(),
                Seqner::new(0),
                make_saider(),
                vec![make_verfer()],
                Tholder::Simple(1),
                vec![make_diger()],
                Tholder::Simple(1),
                vec![make_prefixer()],
                1,
                vec![],
                vec![],
            ),
            make_prefixer().into(),
        );
        let serialized = serialize_delegated_inception(&event).unwrap();
        let deserialized = deserialize_delegated_inception(serialized.as_bytes()).unwrap();

        assert_eq!(deserialized.inception().sn().value(), 0);
        assert_eq!(deserialized.inception().keys().len(), 1);
        assert_eq!(deserialized.inception().witnesses().len(), 1);
        assert_eq!(deserialized.inception().witness_threshold(), 1);
        assert_eq!(
            qb64(deserialized.inception().said()),
            qb64(serialized.said())
        );
        assert_eq!(
            crate::serder::primitives::identifier_to_qb64_string(deserialized.delegator()).unwrap(),
            crate::serder::primitives::identifier_to_qb64_string(event.delegator()).unwrap()
        );
    }

    #[test]
    fn roundtrip_drt() {
        let event = DelegatedRotationEvent::new(RotationEvent::new(
            make_prefixer().into(),
            Seqner::new(1),
            make_saider(),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![make_prefixer()],
            vec![],
            1,
            vec![],
            vec![],
        ));
        let serialized = serialize_delegated_rotation(&event).unwrap();
        let deserialized = deserialize_delegated_rotation(serialized.as_bytes()).unwrap();

        assert_eq!(deserialized.rotation().sn().value(), 1);
        assert_eq!(deserialized.rotation().keys().len(), 1);
        assert_eq!(deserialized.rotation().witness_additions().len(), 1);
        assert!(deserialized.rotation().witness_removals().is_empty());
        assert_eq!(
            qb64(deserialized.rotation().said()),
            qb64(serialized.said())
        );
        assert_eq!(
            crate::serder::primitives::identifier_to_qb64_string(deserialized.rotation().prefix())
                .unwrap(),
            crate::serder::primitives::identifier_to_qb64_string(event.rotation().prefix())
                .unwrap()
        );
    }

    // -----------------------------------------------------------------------
    // Unified dispatch via deserialize_event
    // -----------------------------------------------------------------------

    #[test]
    fn deserialize_event_dispatches_icp() {
        let icp = InceptionEvent::new(
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
        );
        let ser = serialize(&KeriEvent::Inception(icp)).unwrap();
        let deser = deserialize_event(ser.as_bytes()).unwrap();
        assert!(matches!(deser, KeriEvent::Inception(_)));
    }

    #[test]
    fn deserialize_event_dispatches_rot() {
        let rot = RotationEvent::new(
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
        );
        let ser = serialize(&KeriEvent::Rotation(rot)).unwrap();
        let deser = deserialize_event(ser.as_bytes()).unwrap();
        assert!(matches!(deser, KeriEvent::Rotation(_)));
    }

    #[test]
    fn deserialize_event_dispatches_ixn() {
        let ixn = InteractionEvent::new(
            make_prefixer().into(),
            Seqner::new(1),
            make_saider(),
            make_saider(),
            vec![],
        );
        let ser = serialize(&KeriEvent::Interaction(ixn)).unwrap();
        let deser = deserialize_event(ser.as_bytes()).unwrap();
        assert!(matches!(deser, KeriEvent::Interaction(_)));
    }

    // -----------------------------------------------------------------------
    // SAID tamper detection
    // -----------------------------------------------------------------------

    #[test]
    fn tampered_said_fails_verification() {
        let event = InceptionEvent::new(
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
        );
        let serialized = serialize_inception(&event).unwrap();
        let mut json_str = String::from_utf8(serialized.as_bytes().to_vec()).unwrap();

        // Tamper with the JSON by modifying the sn value
        json_str = json_str.replace("\"s\":\"0\"", "\"s\":\"1\"");

        let result = deserialize_inception(json_str.as_bytes());
        assert!(
            result.is_err(),
            "tampered event should fail SAID verification"
        );
        let err = result.err().unwrap();
        assert!(matches!(err, SerderError::SaidMismatch { .. }));
    }

    #[test]
    fn tampered_rot_said_fails() {
        let event = RotationEvent::new(
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
        );
        let serialized = serialize_rotation(&event).unwrap();
        let mut json_str = String::from_utf8(serialized.as_bytes().to_vec()).unwrap();

        json_str = json_str.replace("\"s\":\"1\"", "\"s\":\"2\"");

        let result = deserialize_rotation(json_str.as_bytes());
        assert!(
            result.is_err(),
            "tampered rotation should fail SAID verification"
        );
    }

    // -----------------------------------------------------------------------
    // Tholder parsing
    // -----------------------------------------------------------------------

    #[test]
    fn tholder_simple_from_json() {
        let val = Value::String("3".to_owned());
        let th = tholder_from_json(&val).unwrap();
        assert_eq!(th, Tholder::Simple(3));
    }

    #[test]
    fn tholder_weighted_from_json() {
        let val = serde_json::json!([["1/2", "1/2"], ["1/3", "1/3", "1/3"]]);
        let th = tholder_from_json(&val).unwrap();
        assert_eq!(
            th,
            Tholder::Weighted(vec![vec![(1, 2), (1, 2)], vec![(1, 3), (1, 3), (1, 3)],])
        );
    }

    #[test]
    fn tholder_invalid_returns_error() {
        let val = Value::Bool(true);
        let result = tholder_from_json(&val);
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
    // Seal roundtrips through serialize/deserialize
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrip_all_seal_types() {
        let seals = vec![
            Seal::Digest { d: make_saider() },
            Seal::Root { rd: make_saider() },
            Seal::Source {
                s: Seqner::new(5),
                d: make_saider(),
            },
            Seal::Event {
                i: make_prefixer(),
                s: Seqner::new(0xff),
                d: make_saider(),
            },
            Seal::Last { i: make_prefixer() },
        ];
        let event = InteractionEvent::new(
            make_prefixer().into(),
            Seqner::new(2),
            make_saider(),
            make_saider(),
            seals,
        );
        let serialized = serialize_interaction(&event).unwrap();
        let deserialized = deserialize_interaction(serialized.as_bytes()).unwrap();

        assert_eq!(deserialized.anchors().len(), 5);

        let Seal::Digest { d: dig_d } = &deserialized.anchors()[0] else {
            unreachable!()
        };
        assert_eq!(*dig_d.code(), DigestCode::Blake3_256);

        let Seal::Root { rd: root_rd } = &deserialized.anchors()[1] else {
            unreachable!()
        };
        assert_eq!(*root_rd.code(), DigestCode::Blake3_256);

        let Seal::Source { s: src_s, d: src_d } = &deserialized.anchors()[2] else {
            unreachable!()
        };
        assert_eq!(src_s.value(), 5);
        assert_eq!(*src_d.code(), DigestCode::Blake3_256);

        let Seal::Event {
            i: ev_i,
            s: ev_sn,
            d: ev_d,
        } = &deserialized.anchors()[3]
        else {
            unreachable!()
        };
        assert_eq!(*ev_i.code(), VerKeyCode::Ed25519);
        assert_eq!(ev_sn.value(), 0xff);
        assert_eq!(*ev_d.code(), DigestCode::Blake3_256);

        let Seal::Last { i: last_i } = &deserialized.anchors()[4] else {
            unreachable!()
        };
        assert_eq!(*last_i.code(), VerKeyCode::Ed25519);
    }

    // -----------------------------------------------------------------------
    // Weighted threshold roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrip_weighted_threshold() {
        let event = InceptionEvent::new(
            make_prefixer().into(),
            Seqner::new(0),
            make_saider(),
            vec![make_verfer(), make_verfer()],
            Tholder::Weighted(vec![vec![(1, 2), (1, 2)]]),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![],
            0,
            vec![],
            vec![],
        );
        let serialized = serialize_inception(&event).unwrap();
        let deserialized = deserialize_inception(serialized.as_bytes()).unwrap();

        assert_eq!(
            *deserialized.threshold(),
            Tholder::Weighted(vec![vec![(1, 2), (1, 2)]])
        );
    }

    // -----------------------------------------------------------------------
    // Config trait roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrip_config_traits() {
        let event = InceptionEvent::new(
            make_prefixer().into(),
            Seqner::new(0),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![],
            0,
            vec![ConfigTrait::EstOnly, ConfigTrait::DoNotDelegate],
            vec![],
        );
        let serialized = serialize_inception(&event).unwrap();
        let deserialized = deserialize_inception(serialized.as_bytes()).unwrap();

        assert_eq!(
            deserialized.config(),
            [ConfigTrait::EstOnly, ConfigTrait::DoNotDelegate]
        );
    }

    // -----------------------------------------------------------------------
    // Weighted threshold boundary values (0 and 1)
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrip_weighted_threshold_boundary_values() {
        let event = InceptionEvent::new(
            make_prefixer().into(),
            Seqner::new(0),
            make_saider(),
            vec![make_verfer(), make_verfer(), make_verfer()],
            Tholder::Weighted(vec![vec![(0, 1), (1, 2), (1, 1)]]),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![],
            0,
            vec![],
            vec![],
        );
        let serialized = serialize_inception(&event).unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(serialized.as_bytes()).expect("valid json");
        let kt = json["kt"].as_array().expect("kt is array");

        assert_eq!(kt[0].as_str().expect("0 boundary"), "0");
        assert_eq!(kt[1].as_str().expect("fraction"), "1/2");
        assert_eq!(kt[2].as_str().expect("1 boundary"), "1");

        let deserialized = deserialize_inception(serialized.as_bytes()).unwrap();
        assert_eq!(
            *deserialized.threshold(),
            Tholder::Weighted(vec![vec![(0, 1), (1, 2), (1, 1)]])
        );
    }

    // -----------------------------------------------------------------------
    // intive=True integer threshold deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn tholder_from_json_integer() {
        let val = serde_json::json!(2);
        let tholder = tholder_from_json(&val).unwrap();
        assert_eq!(tholder, Tholder::Simple(2));
    }

    #[test]
    fn parse_witness_threshold_integer() {
        let val = serde_json::json!(3);
        let bt = parse_witness_threshold(&val).unwrap();
        assert_eq!(bt, 3);
    }

    // -----------------------------------------------------------------------
    // parse_weight handles boundary values
    // -----------------------------------------------------------------------

    #[test]
    fn parse_weight_fraction() {
        let (n, d) = parse_weight("1/3").unwrap();
        assert_eq!((n, d), (1, 3));
    }

    #[test]
    fn parse_weight_zero() {
        let (n, d) = parse_weight("0").unwrap();
        assert_eq!((n, d), (0, 1));
    }

    #[test]
    fn parse_weight_one() {
        let (n, d) = parse_weight("1").unwrap();
        assert_eq!((n, d), (1, 1));
    }

    // -----------------------------------------------------------------------
    // Parse-failure routing: a malformed qb64 code is a parsing-domain error
    // -----------------------------------------------------------------------

    #[test]
    fn unparseable_qb64_field_surfaces_as_parsing_domain_error() {
        // A malformed qb64 primitive (bad code) is a parse failure, not a
        // validation failure — it must not be collapsed into a ValidationError.
        // `Diger`/`Matter` does not implement `Debug`, so `matches!` on the
        // whole `Result` avoids requiring the `Ok` value to be printable.
        let result = parse_qb64_diger("!!not-qb64!!", "d");
        assert!(
            matches!(
                result,
                Err(SerderError::UnparseablePrimitive { field: "d", .. })
            ),
            "expected UnparseablePrimitive parse-domain error"
        );
    }
}
