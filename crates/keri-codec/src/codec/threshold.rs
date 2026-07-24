//! The threshold wire grammar — `kt`/`nt` (signing threshold) and `bt`
//! (witness count), both directions.
//!
//! The wire form of a threshold is (value, [`ThresholdForm`]): keripy's
//! `intive=True` emits bare integers, the default emits quoted lowercase
//! hex, and weighted thresholds are always arrays. The form is carried by
//! the der-style context wrappers [`ThresholdField`]/[`CountField`] on the
//! encode side and recovered structurally on the decode side
//! ([`ParsedTholder`]/[`ParsedCount`] preserve which spelling was read).

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{format, string::String, vec, vec::Vec};

use cesr::core::matter::error::ValidationError;

use crate::codec::field::FromWire;
use crate::codec::scanner::Scanner;
use crate::codec::{Decode, Encode, JsonWriter};
use crate::error::DeserializeError;
use keri_events::{SigningThreshold, ThresholdForm, Toad, WeightedThreshold};

/// A `kt`/`nt` threshold value as it appears on the wire.
#[derive(Debug)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) enum ParsedTholder<'a> {
    /// Hex string form, e.g. `"1"`, `"a"`.
    Hex(&'a str),
    /// keripy `intive=True` integer form, e.g. `1`.
    Number(&'a str),
    /// Weighted clauses; a flat array is normalized to a single clause.
    Weighted(Vec<Vec<&'a str>>),
}

/// A `bt` witness-threshold value as it appears on the wire.
#[derive(Debug)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) enum ParsedCount<'a> {
    /// Hex string form.
    Hex(&'a str),
    /// keripy `intive=True` integer form.
    Number(&'a str),
}

/// The wire form of a `kt`/`nt` field: a threshold plus its rendered form.
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) struct ThresholdField<'a> {
    /// The threshold value.
    pub(crate) threshold: &'a SigningThreshold,
    /// Hex-string or bare-integer spelling.
    pub(crate) form: ThresholdForm,
}

impl Encode for ThresholdField<'_> {
    /// A simple threshold renders as a quoted hex string under
    /// [`ThresholdForm::HexString`] or as bare ASCII decimal (no quotes)
    /// under [`ThresholdForm::Integer`]; single weighted clauses are
    /// flattened and multiple clauses nested, always as an array regardless
    /// of form. An integer-form value is guaranteed `<= u32::MAX` by the
    /// parse/build validation
    /// ([`crate::error::BuilderError::MixedThresholdForms`]/[`crate::error::BuilderError::IntegerFormOverflow`]);
    /// the `debug_assert` documents that invariant without silently capping.
    fn encode(&self, out: &mut Vec<u8>) {
        match self.threshold {
            SigningThreshold::Simple(n) => match self.form {
                ThresholdForm::HexString => JsonWriter::write_str(out, &format!("{n:x}")),
                ThresholdForm::Integer => {
                    debug_assert!(
                        u32::try_from(*n).is_ok(),
                        "integer-form threshold exceeds keripy MaxIntThold"
                    );
                    out.extend_from_slice(format!("{n}").as_bytes());
                }
            },
            SigningThreshold::Weighted(w) => {
                let mut clauses = w.clauses();
                match (clauses.next(), clauses.next()) {
                    (Some(single), None) => Self::weight_clause(out, single),
                    (Some(first), Some(second)) => {
                        out.push(b'[');
                        Self::weight_clause(out, first);
                        out.push(b',');
                        Self::weight_clause(out, second);
                        for clause in clauses {
                            out.push(b',');
                            Self::weight_clause(out, clause);
                        }
                        out.push(b']');
                    }
                    (None, _) => out.extend_from_slice(b"[]"),
                }
            }
        }
    }
}

/// The wire form of a `bt` field: the witness threshold plus its form.
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) struct CountField {
    /// The witness threshold.
    pub(crate) toad: Toad,
    /// Hex-string or bare-integer spelling.
    pub(crate) form: ThresholdForm,
}

impl Encode for CountField {
    /// A quoted lowercase-hex string under [`ThresholdForm::HexString`],
    /// bare ASCII decimal (no quotes) under [`ThresholdForm::Integer`].
    /// `Toad` is a `u32`, so the integer always fits.
    fn encode(&self, out: &mut Vec<u8>) {
        match self.form {
            ThresholdForm::HexString => {
                JsonWriter::write_str(out, &format!("{:x}", self.toad.value()));
            }
            ThresholdForm::Integer => {
                out.extend_from_slice(format!("{}", self.toad.value()).as_bytes());
            }
        }
    }
}

impl ThresholdField<'_> {
    /// Render one weight fraction the way keripy's `Tholder.sith` does: whole
    /// values collapse to their integer string (`0`, `1`), everything else stays
    /// `num/den`. A zero denominator is malformed (rejected by both
    /// `SigningThreshold::check_well_formed` and the deserializer) but must
    /// render as a plain fraction rather than dividing by zero.
    fn weight_to_string(num: u64, den: u64) -> String {
        if den != 0 && (num == 0 || num == den) {
            format!("{}", num / den)
        } else {
            format!("{num}/{den}")
        }
    }
}

impl ThresholdField<'_> {
    fn weight_clause(buf: &mut Vec<u8>, clause: &[(u64, u64)]) {
        buf.push(b'[');
        for (idx, (num, den)) in clause.iter().enumerate() {
            if idx > 0 {
                buf.push(b',');
            }
            JsonWriter::write_str(buf, &Self::weight_to_string(*num, *den));
        }
        buf.push(b']');
    }
}

impl<'a> Decode<'a> for ParsedTholder<'a> {
    fn decode(sc: &mut Scanner<'a>) -> Result<Self, DeserializeError> {
        match sc.peek() {
            Some(b'"') => Ok(ParsedTholder::Hex(sc.string()?.value)),
            Some(b'0'..=b'9') => Ok(ParsedTholder::Number(sc.integer()?)),
            Some(b'[') => Self::weighted(sc),
            _ => Err(sc.err("threshold (hex string, integer, or weighted array)")),
        }
    }
}

impl<'a> ParsedTholder<'a> {
    fn weighted(sc: &mut Scanner<'a>) -> Result<Self, DeserializeError> {
        sc.expect("[")?;
        if sc.take_lit("]") {
            return Ok(ParsedTholder::Weighted(Vec::new()));
        }
        match sc.peek() {
            Some(b'"') => {
                let clause = sc.tail_list(|s| s.string().map(|sp| sp.value))?;
                Ok(ParsedTholder::Weighted(vec![clause]))
            }
            Some(b'[') => {
                let clauses = sc.tail_list(Scanner::string_array)?;
                Ok(ParsedTholder::Weighted(clauses))
            }
            _ => Err(sc.err("weight fraction string or clause array")),
        }
    }
}

impl<'a> Decode<'a> for ParsedCount<'a> {
    fn decode(sc: &mut Scanner<'a>) -> Result<Self, DeserializeError> {
        match sc.peek() {
            Some(b'"') => Ok(ParsedCount::Hex(sc.string()?.value)),
            Some(b'0'..=b'9') => Ok(ParsedCount::Number(sc.integer()?)),
            _ => Err(sc.err("count (hex string or integer)")),
        }
    }
}

// The kt/nt lift (was `tholder_from_parsed` + `parse_weight`); weighted
// clauses reuse `WeightedThreshold::from_nested`'s own well-formedness check
// (weight count <= u32::MAX), so only the per-weight parse is done here.
impl<'a> FromWire<&'a ParsedTholder<'a>> for SigningThreshold {
    fn from_wire(field: &'static str, t: &'a ParsedTholder<'a>) -> Result<Self, DeserializeError> {
        match t {
            ParsedTholder::Hex(s) => Ok(Self::Simple(
                u64::from_str_radix(s, 16).map_err(|_| threshold_num_err(field, s))?,
            )),
            ParsedTholder::Number(s) => Ok(Self::Simple(
                s.parse::<u64>().map_err(|_| threshold_num_err(field, s))?,
            )),
            ParsedTholder::Weighted(clauses) => {
                let nested: Vec<Vec<(u64, u64)>> = clauses
                    .iter()
                    .map(|clause| clause.iter().map(|w| parse_weight(field, w)).collect())
                    .collect::<Result<_, DeserializeError>>()?;
                WeightedThreshold::from_nested(nested)
                    .map(Self::Weighted)
                    .map_err(|source| DeserializeError::ThresholdOutOfRange { field, source })
            }
        }
    }
}

// The bt lift (was `witness_threshold_wire`): bare u32, no witness-count
// context — `build_*` wraps the result with `Toad::exact`/`Toad::from_wire`.
impl<'a> FromWire<&'a ParsedCount<'a>> for u32 {
    fn from_wire(field: &'static str, c: &'a ParsedCount<'a>) -> Result<Self, DeserializeError> {
        let n: u128 = match c {
            ParsedCount::Hex(s) => u128::from_str_radix(s, 16).map_err(|_| count_err(field, s))?,
            ParsedCount::Number(s) => s.parse::<u128>().map_err(|_| count_err(field, s))?,
        };
        Self::try_from(n).map_err(|_| count_err(field, &format!("{n} exceeds u32::MAX")))
    }
}

fn threshold_num_err(field: &'static str, s: &str) -> DeserializeError {
    DeserializeError::InvalidPrimitive {
        field,
        source: ValidationError::UnknownMatterCode(format!("invalid threshold: {s}")),
    }
}

fn count_err(field: &'static str, s: &str) -> DeserializeError {
    DeserializeError::InvalidPrimitive {
        field,
        source: ValidationError::UnknownMatterCode(format!("invalid count: {s}")),
    }
}

/// Parse one weight fraction (`"1/2"` or a whole `"1"`), rejecting a zero
/// denominator: a `(n, 0)` weight previously survived parse and could reach
/// `weight_to_string`'s `num / den` on re-render (bug probe:
/// `parse_weight_rejects_zero_denominator`, mirrored in this module's tests).
fn parse_weight(field: &'static str, s: &str) -> Result<(u64, u64), DeserializeError> {
    if let Some((num_s, den_s)) = s.split_once('/') {
        let num = num_s
            .parse::<u64>()
            .map_err(|_| threshold_num_err(field, s))?;
        let den = den_s
            .parse::<u64>()
            .map_err(|_| threshold_num_err(field, s))?;
        if den == 0 {
            return Err(threshold_num_err(field, s));
        }
        Ok((num, den))
    } else {
        Ok((
            s.parse::<u64>().map_err(|_| threshold_num_err(field, s))?,
            1,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::field::Field;

    #[test]
    fn tholder_shapes() {
        assert!(matches!(
            ParsedTholder::decode(&mut Scanner::new(b"\"a\"")).unwrap(),
            ParsedTholder::Hex("a")
        ));
        assert!(matches!(
            ParsedTholder::decode(&mut Scanner::new(b"2,")).unwrap(),
            ParsedTholder::Number("2")
        ));
        let ParsedTholder::Weighted(flat) =
            ParsedTholder::decode(&mut Scanner::new(b"[\"1/2\",\"1/2\"]")).unwrap()
        else {
            unreachable!()
        };
        assert_eq!(flat, vec![vec!["1/2", "1/2"]]);
        let ParsedTholder::Weighted(nested) =
            ParsedTholder::decode(&mut Scanner::new(b"[[\"1/2\",\"1/2\"],[\"1\"]]")).unwrap()
        else {
            unreachable!()
        };
        assert_eq!(nested, vec![vec!["1/2", "1/2"], vec!["1"]]);
        let ParsedTholder::Weighted(empty) =
            ParsedTholder::decode(&mut Scanner::new(b"[]")).unwrap()
        else {
            unreachable!()
        };
        assert!(empty.is_empty());
        assert!(ParsedTholder::decode(&mut Scanner::new(b"true")).is_err());
    }

    #[test]
    fn count_shapes() {
        assert!(matches!(
            ParsedCount::decode(&mut Scanner::new(b"\"0\"")).unwrap(),
            ParsedCount::Hex("0")
        ));
        assert!(matches!(
            ParsedCount::decode(&mut Scanner::new(b"3,")).unwrap(),
            ParsedCount::Number("3")
        ));
        assert!(ParsedCount::decode(&mut Scanner::new(b"[]")).is_err());
    }

    #[test]
    fn weighted_rejects_non_string_non_array_element() {
        let mut sc = Scanner::new(b"[true]");
        assert!(matches!(
            ParsedTholder::weighted(&mut sc),
            Err(DeserializeError::NonCanonical { offset: 1, .. })
        ));
    }

    fn weighted_threshold(clauses: Vec<Vec<(u64, u64)>>) -> SigningThreshold {
        SigningThreshold::Weighted(WeightedThreshold::from_nested(clauses).unwrap())
    }

    // write_tholder — canonical location for flatten/nest/empty rendering.

    #[test]
    fn write_tholder_empty_weighted_shapes() {
        // Boundary shapes the strategies under-sample: an empty clause list
        // and a single empty clause both flatten to "[]"; two empty clauses
        // stay nested.
        for (kt, expected) in [
            (weighted_threshold(vec![]), "[]"),
            (weighted_threshold(vec![vec![]]), "[]"),
            (weighted_threshold(vec![vec![], vec![]]), "[[],[]]"),
        ] {
            let mut buf = Vec::new();
            ThresholdField {
                threshold: &kt,
                form: ThresholdForm::HexString,
            }
            .encode(&mut buf);
            assert_eq!(core::str::from_utf8(&buf).unwrap(), expected);
        }
    }

    #[test]
    fn write_tholder_zero_denominator_renders_without_panicking() {
        // Bug probe (ported from the deleted tholder_to_json test): a (0, 0)
        // weight previously hit `0 / 0` and panicked. Malformed weights must
        // render as a plain fraction; rejection happens at parse/validation.
        let tholder = weighted_threshold(vec![vec![(0, 0), (1, 0)]]);
        let mut buf = Vec::new();
        ThresholdField {
            threshold: &tholder,
            form: ThresholdForm::HexString,
        }
        .encode(&mut buf);
        assert_eq!(core::str::from_utf8(&buf).unwrap(), r#"["0/0","1/0"]"#);
    }

    #[test]
    fn write_tholder_single_clause_flattens_and_multi_nests() {
        let single = weighted_threshold(vec![vec![(1, 2), (1, 2)]]);
        let mut buf = Vec::new();
        ThresholdField {
            threshold: &single,
            form: ThresholdForm::HexString,
        }
        .encode(&mut buf);
        assert_eq!(core::str::from_utf8(&buf).unwrap(), r#"["1/2","1/2"]"#);

        let multi = weighted_threshold(vec![vec![(1, 2)], vec![(1, 1)]]);
        buf.clear();
        ThresholdField {
            threshold: &multi,
            form: ThresholdForm::HexString,
        }
        .encode(&mut buf);
        assert_eq!(core::str::from_utf8(&buf).unwrap(), r#"[["1/2"],["1"]]"#);
    }

    // weight_to_string — exact mapping table.

    // FromWire lift — SigningThreshold (kt/nt) and u32 count (bt).

    #[test]
    fn signing_threshold_lift_simple_hex() {
        let pt = ParsedTholder::decode(&mut Scanner::new(b"\"2\"")).unwrap();
        let t: SigningThreshold = Field::new("kt", &pt).decode().unwrap();
        assert_eq!(t, SigningThreshold::Simple(2));
    }

    #[test]
    fn count_lift_u32_hex() {
        let pc = ParsedCount::decode(&mut Scanner::new(b"\"a\"")).unwrap();
        let n: u32 = Field::new("bt", &pc).decode().unwrap();
        assert_eq!(n, 10);
    }

    // Weighted-clause weight parsing — boundary values. Moved from the
    // deleted `deserialize.rs` free-fn tests of the same name; re-expressed
    // against the `SigningThreshold` `FromWire` lift (the new SUT).

    #[test]
    fn signing_threshold_lift_weighted_fraction() {
        let pt = ParsedTholder::Weighted(vec![vec!["1/3"]]);
        let t: SigningThreshold = Field::new("kt", &pt).decode().unwrap();
        assert_eq!(t, weighted_threshold(vec![vec![(1, 3)]]));
    }

    #[test]
    fn signing_threshold_lift_weighted_zero() {
        let pt = ParsedTholder::Weighted(vec![vec!["0"]]);
        let t: SigningThreshold = Field::new("kt", &pt).decode().unwrap();
        assert_eq!(t, weighted_threshold(vec![vec![(0, 1)]]));
    }

    #[test]
    fn signing_threshold_lift_weighted_one() {
        let pt = ParsedTholder::Weighted(vec![vec!["1"]]);
        let t: SigningThreshold = Field::new("kt", &pt).decode().unwrap();
        assert_eq!(t, weighted_threshold(vec![vec![(1, 1)]]));
    }

    #[test]
    fn signing_threshold_lift_rejects_zero_denominator() {
        // Bug probe: "0/0" and "1/0" previously parsed into (0,0)/(1,0), and
        // a (0,0) weight made re-serialization divide by zero (panic on
        // untrusted-derived data). Must fail while the bug exists.
        assert!(matches!(
            Field::new("kt", &ParsedTholder::Weighted(vec![vec!["0/0"]]))
                .decode::<SigningThreshold>(),
            Err(DeserializeError::InvalidPrimitive { field: "kt", .. })
        ));
        assert!(matches!(
            Field::new("kt", &ParsedTholder::Weighted(vec![vec!["1/0"]]))
                .decode::<SigningThreshold>(),
            Err(DeserializeError::InvalidPrimitive { field: "kt", .. })
        ));
    }

    // Overflow boundaries: the conversion layer between parsed decimal/hex
    // text and fixed-width integers must reject overflow as a typed error,
    // never wrap or saturate. Moved from the deleted `deserialize.rs`
    // free-fn tests `tholder_number_overflow_is_invalid_primitive` /
    // `witness_threshold_overflow_is_invalid_primitive`.

    #[test]
    fn signing_threshold_lift_number_overflow_is_invalid_primitive() {
        let over_u64 = "18446744073709551616"; // u64::MAX + 1
        assert!(matches!(
            Field::new("kt", &ParsedTholder::Number(over_u64)).decode::<SigningThreshold>(),
            Err(DeserializeError::InvalidPrimitive { field: "kt", .. })
        ));
        let max_u64 = "18446744073709551615";
        assert!(matches!(
            Field::new("kt", &ParsedTholder::Number(max_u64)).decode::<SigningThreshold>(),
            Ok(SigningThreshold::Simple(u64::MAX))
        ));
    }

    #[test]
    fn count_lift_overflow_is_invalid_primitive() {
        assert!(matches!(
            Field::new("bt", &ParsedCount::Number("4294967296")).decode::<u32>(), // u32::MAX + 1
            Err(DeserializeError::InvalidPrimitive { field: "bt", .. })
        ));
        assert_eq!(
            Field::new("bt", &ParsedCount::Number("4294967295"))
                .decode::<u32>()
                .unwrap(),
            u32::MAX
        );
        assert!(matches!(
            Field::new(
                "bt",
                &ParsedCount::Number("340282366920938463463374607431768211456") // u128::MAX + 1
            )
            .decode::<u32>(),
            Err(DeserializeError::InvalidPrimitive { field: "bt", .. })
        ));
        assert!(matches!(
            Field::new("bt", &ParsedCount::Hex("100000000")).decode::<u32>(), // > u32::MAX in hex
            Err(DeserializeError::InvalidPrimitive { field: "bt", .. })
        ));
    }

    #[test]
    fn weight_to_string_exact_mapping() {
        // Whole values collapse to their integer string; everything else —
        // including malformed zero denominators and unreduced fractions —
        // stays num/den verbatim (keripy does not reduce).
        assert_eq!(ThresholdField::weight_to_string(0, 1), "0");
        assert_eq!(ThresholdField::weight_to_string(1, 1), "1");
        assert_eq!(ThresholdField::weight_to_string(2, 2), "1");
        assert_eq!(ThresholdField::weight_to_string(u64::MAX, u64::MAX), "1");
        assert_eq!(ThresholdField::weight_to_string(1, 2), "1/2");
        assert_eq!(ThresholdField::weight_to_string(2, 4), "2/4");
        assert_eq!(ThresholdField::weight_to_string(3, 2), "3/2");
        assert_eq!(ThresholdField::weight_to_string(0, 0), "0/0");
        assert_eq!(ThresholdField::weight_to_string(1, 0), "1/0");
        assert_eq!(
            ThresholdField::weight_to_string(u64::MAX, 1),
            "18446744073709551615/1"
        );
    }
}
