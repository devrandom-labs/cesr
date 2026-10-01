//! A09 public-path JSON payload regressions. The happy bytes are emitted and
//! checked by docs/audits/2026-09-29-a09-oracle.py using actual pinned keripy.
mod common;

use std::borrow::Cow;

use cesr::core::matter::code::DigestCode;
use cesr_stream::group::ControllerIdxSigs;
use keri_codec::SadCodes;
use keri_codec::{CodecError, Deserialize, DeserializeError, Exn, IpexMessage, Message, Serialize};
use keri_events::Acdc;
use keri_events::acdc::SadBlock;
use serde::Deserialize as SerdeDeserialize;

use common::{Fallible, Key};

const HAPPY: &str = include_str!("corpus/json_payload/happy.jsonl");
const ACDC: &str = include_str!("corpus/json_payload/acdc.jsonl");
const IPEX: &str = include_str!("corpus/ipex/happy.jsonl");

#[derive(SerdeDeserialize)]
struct JsonPayloadVector {
    case: String,
    raw: String,
    message: String,
    typed_ipex: bool,
}

fn plain_ipex(name: &str) -> Fallible<String> {
    for line in IPEX.lines() {
        let row: serde_json::Value = serde_json::from_str(line)?;
        if row["case"] == name {
            return Ok(row["raw"].as_str().ok_or("missing raw body")?.to_owned());
        }
    }
    Err(format!("missing IPEX case {name}").into())
}

#[test]
fn pinned_generic_payloads_verify_original_bytes_and_escaped_messages_lift() -> Fallible<()> {
    let seed_raw = plain_ipex("agree")?;
    let seed = Exn::deserialize(seed_raw.as_bytes(), keri_codec::JsonLimits::new(4096, 64))?;
    let signer = Key::new()?;
    let mut cases = 0;
    for line in HAPPY.lines() {
        let row: JsonPayloadVector = serde_json::from_str(line)?;
        cases += 1;
        let parsed = Exn::deserialize(row.raw.as_bytes(), keri_codec::JsonLimits::new(4096, 64))?;
        assert_eq!(
            parsed.serialize()?.as_bytes(),
            row.raw.as_bytes(),
            "{}",
            row.case
        );
        if row.typed_ipex {
            let built = Exn::ipex_agree(seed.issuer(), seed.datetime(), &row.message, None)?;
            let serialized = built.serialize()?;
            assert_eq!(serialized.as_bytes(), row.raw.as_bytes(), "{}", row.case);
            let IpexMessage::Agree(agree) =
                IpexMessage::parse(&parsed, keri_codec::JsonLimits::new(4096, 64))?
            else {
                return Err(format!("{} did not lift to typed agree", row.case).into());
            };
            assert_eq!(agree.message(), row.message, "{}", row.case);
            let signature = signer.sign(serialized.as_bytes(), 0)?;
            let frame =
                serialized.frame_v1(&ControllerIdxSigs::from_indexed_signatures(&[signature])?)?;
            let (Message::Exn(message), rest) = Message::parse(&frame, common::message_limits())?
            else {
                return Err(format!("{} did not frame as EXN", row.case).into());
            };
            assert!(rest.is_empty(), "{}", row.case);
            assert_eq!(message.body(), row.raw.as_bytes(), "{}", row.case);
            assert_eq!(
                IpexMessage::parse(message.exn(), keri_codec::JsonLimits::new(4096, 64))?
                    .route()
                    .route(),
                "/ipex/agree"
            );
        }
    }
    assert_eq!(cases, 6, "the pinned JSON corpus was truncated");

    let original = vectors_for_tamper()?;
    let tampered = original.replace("quote", "house");
    assert_ne!(tampered, original);
    assert!(
        matches!(
            Exn::deserialize(tampered.as_bytes(), keri_codec::JsonLimits::new(4096, 64)),
            Err(CodecError::Said(_))
        ),
        "changing signed human text must invalidate the original SAID"
    );
    Ok(())
}

fn vectors_for_tamper() -> Fallible<String> {
    for line in HAPPY.lines() {
        let row: JsonPayloadVector = serde_json::from_str(line)?;
        if row.case == "escaped_quote_backslash" {
            return Ok(row.raw);
        }
    }
    Err("missing escaped quote vector".into())
}

#[test]
fn apply_accepts_ordinary_json_attributes_and_rejects_invalid_or_duplicate_values() -> Fallible<()>
{
    let seed_raw = plain_ipex("apply")?;
    let seed = Exn::deserialize(seed_raw.as_bytes(), keri_codec::JsonLimits::new(4096, 64))?;
    let IpexMessage::Apply(apply) =
        IpexMessage::parse(&seed, keri_codec::JsonLimits::new(4096, 64))?
    else {
        return Err("seed did not parse as apply".into());
    };
    let attrs = SadBlock::new_unchecked(Cow::Borrowed(
        r#"{"note":"A \"quote\" and 🎵","neg":-7,"decimal":1.25,"exp":1e-07,"nested":{"x":[true,null]}}"#,
    ));
    let built = Exn::ipex_apply(
        seed.issuer(),
        seed.datetime(),
        "line\nfeed",
        apply.schema(),
        &attrs,
        apply.recipient(),
    )?;
    let body = built.serialize()?;
    assert!(
        body.as_bytes()
            .windows(attrs.payload().len())
            .any(|w| w == attrs.payload().as_bytes())
    );
    let parsed = Exn::deserialize(body.as_bytes(), keri_codec::JsonLimits::new(4096, 64))?;
    let IpexMessage::Apply(lifted) =
        IpexMessage::parse(&parsed, keri_codec::JsonLimits::new(4096, 64))?
    else {
        return Err("ordinary attributes did not lift as apply".into());
    };
    assert_eq!(lifted.message(), "line\nfeed");
    assert_eq!(lifted.attrs().payload(), attrs.payload());

    for bad in [
        r#"{"x":"\q"}"#,
        r#"{"x":"\uD800"}"#,
        r#"{"x":01}"#,
        r#"{"x":1e}"#,
        r#"{"x":NaN}"#,
        r#"{"x":1, "y":2}"#,
        r#"{"x":1,"x":2}"#,
        r#"{"child":{"x":1,"x":2}}"#,
    ] {
        let bad_attrs = SadBlock::new_unchecked(Cow::Borrowed(bad));
        let result = Exn::ipex_apply(
            seed.issuer(),
            seed.datetime(),
            "x",
            apply.schema(),
            &bad_attrs,
            apply.recipient(),
        );
        assert!(
            matches!(
                result,
                Err(CodecError::Deserialize(
                    DeserializeError::NonCanonical { .. }
                ))
            ),
            "malformed/duplicate JSON was not rejected as typed noncanonical: {bad}: {result:?}"
        );
    }
    Ok(())
}

#[test]
fn pinned_acdc_subjects_keep_their_signed_json_bytes() -> Fallible<()> {
    let mut cases = 0;
    for line in ACDC.lines() {
        let row: serde_json::Value = serde_json::from_str(line)?;
        let name = row["case"].as_str().ok_or("missing case")?;
        let raw = row["raw"].as_str().ok_or("missing raw")?;
        let credential = Acdc::deserialize(raw.as_bytes(), keri_codec::JsonLimits::new(4096, 64))?;
        assert_eq!(credential.serialize()?.as_bytes(), raw.as_bytes(), "{name}");
        cases += 1;
    }
    assert_eq!(cases, 2, "the pinned ACDC JSON corpus was truncated");
    Ok(())
}

#[test]
fn escaped_control_without_short_form_decodes_from_signed_body() -> Fallible<()> {
    let seed_raw = plain_ipex("agree")?;
    let seed = Exn::deserialize(seed_raw.as_bytes(), keri_codec::JsonLimits::new(4096, 64))?;
    let message = "a\u{001f}b";
    let body = Exn::ipex_agree(seed.issuer(), seed.datetime(), message, None)?.serialize()?;
    assert!(body.as_bytes().windows(6).any(|w| w == br"\u001f"));
    let parsed = Exn::deserialize(body.as_bytes(), keri_codec::JsonLimits::new(4096, 64))?;
    let IpexMessage::Agree(lifted) =
        IpexMessage::parse(&parsed, keri_codec::JsonLimits::new(4096, 64))?
    else {
        return Err("control message did not lift".into());
    };
    assert_eq!(lifted.message(), message);
    Ok(())
}

#[test]
fn alternate_or_malformed_payload_spellings_fail_as_typed_json_errors() -> Fallible<()> {
    let vectors: Vec<JsonPayloadVector> = HAPPY
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    let find = |case: &str| -> Fallible<&str> {
        Ok(vectors
            .iter()
            .find(|row| row.case == case)
            .ok_or("missing JSON payload vector")?
            .raw
            .as_str())
    };
    let mutations = [
        (
            "escaped surrogate pair",
            find("raw_utf8")?.replace("🎵", r"\ud83c\udfb5"),
        ),
        (
            "duplicate nested key",
            find("nested")?.replace("\"child\":", "\"m\":\"duplicate\",\"child\":"),
        ),
        (
            "nonfinite token",
            find("negative_decimal_exponent")?.replace("\"neg\":-7", "\"neg\":NaN"),
        ),
        (
            "whitespace",
            find("nested")?.replace(",\"e\":{}", ", \"e\":{}"),
        ),
    ];
    for (name, mut raw) in mutations {
        let size = format!("{:06x}", raw.len());
        raw.replace_range(16..22, &size);
        let result = Exn::deserialize(raw.as_bytes(), keri_codec::JsonLimits::new(4096, 64));
        assert!(
            matches!(
                result,
                Err(CodecError::Deserialize(
                    DeserializeError::NonCanonical { .. }
                ))
            ),
            "{name} was not rejected as typed noncanonical JSON: {result:?}"
        );
    }
    Ok(())
}

#[test]
fn rfc_number_spelling_keeps_the_actual_signed_bytes() -> Fallible<()> {
    let row: JsonPayloadVector = HAPPY
        .lines()
        .map(serde_json::from_str::<JsonPayloadVector>)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .find(|item| item.case == "negative_decimal_exponent")
        .ok_or("missing exponent vector")?;
    // The pinned writer emits 1e-07 and its raw reader rejects 1e-7. This
    // RFC 8259 read extension is safe only when the SAID is recomputed over
    // and verified against the actual received spelling.
    let mut raw = row.raw.replace("1e-07", "1e-7").into_bytes();
    let codes = SadCodes::from_pairs(&[("d", DigestCode::Blake3_256)])?;
    codes.saidify(&mut raw)?;
    let parsed = Exn::deserialize(&raw, keri_codec::JsonLimits::new(4096, 64))?;
    assert_eq!(parsed.serialize()?.as_bytes(), raw.as_slice());
    assert!(raw.windows(4).any(|w| w == b"1e-7"));
    Ok(())
}
