//! Caller-visible contract for the public generic SAD SAID path
//! (`SadCodes`, `saidify_sad`, `verify_sad`, `ParsedSad`).
//!
//! This binary imports ONLY the public crate surface — it is the external
//! caller fixture proving the API is reachable from outside `keri-codec`.
//! It also pins keripy parity for the generic path: keripy `Saider.saidify`
//! (pinned oracle `de59bc7d834955c5b0273c62f6b8b6a0df150dc3`) dummies every
//! configured digestive field in one canonical serialization, computes each
//! digest, and backfills per label; a missing configured label is an error.

use std::error::Error;

use base64::Engine as _;
use cesr::core::matter::code::{CesrCode, DigestCode};
use keri_codec::{SadCodes, saidify_sad, verify_sad};

type Fallible<T> = Result<T, Box<dyn Error>>;

/// A 44-character Blake3-256 SAID placeholder (the code's fixed full size).
fn blake3_placeholder() -> Fallible<String> {
    Ok(DigestCode::Blake3_256.placeholder()?)
}

/// An 88-character SHA3-512 SAID placeholder (the code's fixed full size).
fn sha3_placeholder() -> Fallible<String> {
    Ok(DigestCode::SHA3_512.placeholder()?)
}

/// `{"v":"KERI10JSON000000_","t":"cred","d":"<44#>","u":"hello"}` — a
/// canonical ACDC-style SAD with a zero-sized version string and one
/// non-digestive passthrough field. Size digits are patched by saidify.
fn sized_sad_with_placeholder() -> Fallible<Vec<u8>> {
    Ok(format!(
        "{{\"v\":\"KERI10JSON000000_\",\"t\":\"cred\",\"d\":\"{}\",\"u\":\"hello\"}}",
        blake3_placeholder()?
    )
    .into_bytes())
}

/// `{"d":"<44#>","i":"<44#>","u":1}` — keripy icp shape: two digestive
/// fields under the same code plus a non-digestive integer field.
fn unversioned_multi_label() -> Fallible<Vec<u8>> {
    Ok(format!(
        "{{\"d\":\"{}\",\"i\":\"{}\",\"u\":1}}",
        blake3_placeholder()?,
        blake3_placeholder()?
    )
    .into_bytes())
}

#[test]
fn saidify_backfills_digestive_fields_and_output_verifies() -> Fallible<()> {
    let codes = SadCodes::from_pairs(&[("d", DigestCode::Blake3_256)])?;
    let mut sad = sized_sad_with_placeholder()?;

    // The parsed SAD borrows the buffer; extract owned values so the borrow
    // ends before later reads of `sad`.
    let backfilled_d = saidify_sad(&mut sad, &codes)?
        .said("d")
        .ok_or("said('d') missing")?
        .to_owned();

    // The placeholder slot is replaced by a real SAID; the buffer length is
    // fixed because every slot is spliced at its placeholder width.
    assert_eq!(backfilled_d.len(), 44);
    assert_ne!(backfilled_d, blake3_placeholder()?);
    assert!(backfilled_d.starts_with('E'), "Blake3-256 qb64 prefix");

    // Round trip: the saidified bytes verify under the same configuration.
    let verified_d = verify_sad(&sad, &codes)?.said("d").map(str::to_owned);
    assert_eq!(verified_d.as_deref(), Some(backfilled_d.as_str()));

    // Idempotence: saidifying already-saidified bytes is a fixed point.
    let mut again = sad.clone();
    saidify_sad(&mut again, &codes)?;
    assert_eq!(again, sad);
    verify_sad(&again, &codes)?;

    Ok(())
}

#[test]
fn saidify_patches_version_size_field() -> Fallible<()> {
    let codes = SadCodes::from_pairs(&[("d", DigestCode::Blake3_256)])?;
    let mut sad = sized_sad_with_placeholder()?;
    saidify_sad(&mut sad, &codes)?;

    // The version value's six size digits sit at bytes [16..22]. They must
    // now encode the total serialization length in hex.
    let len = sad.len();
    assert_eq!(&sad[16..22], format!("{len:06x}").as_bytes());

    // Verify accepts the patched size...
    verify_sad(&sad, &codes)?;

    // ...and rejects a tampered size digit before any digest comparison.
    let mut wrong = sad.clone();
    wrong[21] = b'9';
    let tampered_err = verify_sad(&wrong, &codes).unwrap_err();
    assert!(
        matches!(tampered_err, keri_codec::CodecError::Version(_)),
        "expected version error, got {tampered_err:?}"
    );

    Ok(())
}

#[test]
fn multi_label_same_code_shares_the_prefix_digest() -> Fallible<()> {
    let codes =
        SadCodes::from_pairs(&[("d", DigestCode::Blake3_256), ("i", DigestCode::Blake3_256)])?;
    let mut sad = unversioned_multi_label()?;

    let parsed = saidify_sad(&mut sad, &codes)?;
    let d = parsed.said("d").ok_or("said('d')")?;
    let i = parsed.said("i").ok_or("said('i')")?;
    assert_eq!(d, i, "self-certifying icp: i equals d under the same code");

    verify_sad(&sad, &codes)?;

    Ok(())
}

#[test]
fn multi_label_mixed_codes_backfill_under_their_own_code() -> Fallible<()> {
    let codes =
        SadCodes::from_pairs(&[("d", DigestCode::Blake3_256), ("i", DigestCode::SHA3_512)])?;
    let mut sad = format!(
        "{{\"d\":\"{}\",\"i\":\"{}\"}}",
        blake3_placeholder()?,
        sha3_placeholder()?
    )
    .into_bytes();

    let parsed = saidify_sad(&mut sad, &codes)?;
    let d = parsed.said("d").ok_or("said('d')")?;
    let i = parsed.said("i").ok_or("said('i')")?;
    assert_ne!(d, i, "different codes digest different dummied renders");
    assert_eq!(i.len(), 88);

    verify_sad(&sad, &codes)?;

    Ok(())
}

#[test]
fn nested_fields_are_validated_but_not_dummied() -> Fallible<()> {
    let codes = SadCodes::from_pairs(&[("d", DigestCode::Blake3_256)])?;
    // Nested `d` inside an array of objects: real-looking value that saidify
    // must leave byte-identical (only top-level configured labels digest).
    let nested = "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let mut sad = format!(
        "{{\"d\":\"{}\",\"a\":[{{\"d\":\"{nested}\"}}]}}",
        blake3_placeholder()?
    )
    .into_bytes();

    let parsed = saidify_sad(&mut sad, &codes)?;
    let expected = format!(
        "{{\"d\":\"{}\",\"a\":[{{\"d\":\"{nested}\"}}]}}",
        parsed.said("d").ok_or("said('d')")?
    );
    assert_eq!(sad, expected.into_bytes(), "nested field untouched");

    // The nested value participates in the digest as plain content: tampering
    // it breaks verification of the top-level SAID.
    let mut tampered = sad.clone();
    let pos = tampered
        .windows(nested.len())
        .position(|w| w == nested.as_bytes())
        .ok_or("nested value not found")?;
    tampered[pos] = b'B';
    let tampered_err = verify_sad(&tampered, &codes).unwrap_err();
    assert!(
        matches!(tampered_err, keri_codec::CodecError::Said(_)),
        "expected SAID mismatch, got {tampered_err:?}"
    );

    Ok(())
}

#[test]
fn non_canonical_serializations_are_refused() -> Fallible<()> {
    let codes = SadCodes::from_pairs(&[("d", DigestCode::Blake3_256)])?;
    let said = "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("whitespace", b"{ \"d\" : \"x\" }".to_vec()),
        ("escaped string", b"{\"d\":\"\\u0041\"}".to_vec()),
        (
            "duplicate label",
            format!("{{\"d\":\"{said}\",\"d\":\"{said}\"}}").into_bytes(),
        ),
        (
            "trailing bytes",
            format!("{{\"d\":\"{said}\"}}x").into_bytes(),
        ),
        ("leading-zero integer", b"{\"n\":01}".to_vec()),
        ("float value", b"{\"n\":1.5}".to_vec()),
        ("negative integer", b"{\"n\":-1}".to_vec()),
        ("non-string digestive field", b"{\"d\":123}".to_vec()),
        ("non-object document", b"[]".to_vec()),
        ("empty document", Vec::new()),
        ("unterminated document", b"{\"d\":\"x\"".to_vec()),
    ];
    for (name, mut raw) in cases {
        let verify_err = verify_sad(&raw, &codes).unwrap_err();
        assert!(
            matches!(verify_err, keri_codec::CodecError::Deserialize(_)),
            "{name}: expected canonicality rejection, got {verify_err:?}"
        );
        // The write path refuses the same non-canonical render.
        let saidify_err = saidify_sad(&mut raw, &codes).unwrap_err();
        assert!(
            matches!(saidify_err, keri_codec::CodecError::Deserialize(_)),
            "{name}: saidify expected canonicality rejection, got {saidify_err:?}"
        );
    }

    Ok(())
}

#[test]
fn missing_digestive_field_is_rejected_on_both_paths() -> Fallible<()> {
    let codes = SadCodes::from_pairs(&[("d", DigestCode::Blake3_256)])?;
    let raw = b"{\"t\":\"noid\"}".to_vec();
    let verify_err = verify_sad(&raw, &codes).unwrap_err();
    assert!(
        matches!(&verify_err, keri_codec::CodecError::Said(e) if matches!(e, keri_codec::SaidError::MissingDigestiveField { label } if label == "d")),
        "expected missing field, got {verify_err:?}"
    );
    let mut saidify_target = raw;
    let saidify_err = saidify_sad(&mut saidify_target, &codes).unwrap_err();
    assert!(
        matches!(&saidify_err, keri_codec::CodecError::Said(e) if matches!(e, keri_codec::SaidError::MissingDigestiveField { label } if label == "d")),
        "expected missing field, got {saidify_err:?}"
    );

    Ok(())
}

#[test]
fn write_path_enforces_placeholder_slot_width() -> Fallible<()> {
    let codes = SadCodes::from_pairs(&[("d", DigestCode::Blake3_256)])?;
    // 43-byte slot: saidify cannot splice a 44-byte SAID into it.
    let mut sad = b"{\"d\":\"EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}".to_vec();
    let saidify_err = saidify_sad(&mut sad, &codes).unwrap_err();
    assert!(
        matches!(&saidify_err, keri_codec::CodecError::Said(e) if matches!(e, keri_codec::SaidError::InvalidSlotWidth { expected: 44, found: 43, .. })),
        "expected slot width error, got {saidify_err:?}"
    );
    // The verify path tolerates any width: the value simply cannot match.
    let verify_err = verify_sad(&sad, &codes).unwrap_err();
    assert!(
        matches!(verify_err, keri_codec::CodecError::Said(_)),
        "expected SAID mismatch, got {verify_err:?}"
    );

    Ok(())
}

#[test]
fn version_string_is_validated_when_present() -> Fallible<()> {
    let codes = SadCodes::from_pairs(&[("d", DigestCode::Blake3_256)])?;
    // A `v` value that is not a 17-byte v1 version string.
    let mut sad = b"{\"v\":\"nope\",\"d\":\"\"}".to_vec();
    let verify_err = verify_sad(&sad, &codes).unwrap_err();
    assert!(
        matches!(verify_err, keri_codec::CodecError::Version(_)),
        "expected version error, got {verify_err:?}"
    );
    // Same refusal on the write path.
    let saidify_err = saidify_sad(&mut sad, &codes).unwrap_err();
    assert!(
        matches!(saidify_err, keri_codec::CodecError::Version(_)),
        "expected version error, got {saidify_err:?}"
    );

    Ok(())
}

#[test]
fn empty_configuration_and_empty_sad_boundaries() -> Fallible<()> {
    let empty = SadCodes::from_pairs(&[])?;
    // Vacuous law: nothing configured, nothing to digest.
    let mut sad = b"{}".to_vec();
    let parsed = saidify_sad(&mut sad, &empty)?;
    assert_eq!(parsed.said("d"), None);
    assert_eq!(parsed.as_bytes(), b"{}");
    verify_sad(b"{}", &empty)?;

    // An empty SAD still cannot satisfy a non-empty configuration.
    let codes = SadCodes::from_pairs(&[("d", DigestCode::Blake3_256)])?;
    let missing_err = verify_sad(b"{}", &codes).unwrap_err();
    assert!(
        matches!(&missing_err, keri_codec::CodecError::Said(e) if matches!(e, keri_codec::SaidError::MissingDigestiveField { label } if label == "d")),
        "expected missing field, got {missing_err:?}"
    );

    Ok(())
}

#[test]
fn sad_codes_rejects_invalid_configuration() {
    // Capacity: more labels than the fixed slot count.
    let over: Vec<(&str, DigestCode)> = ["a", "b", "c", "d", "e"]
        .into_iter()
        .map(|l| (l, DigestCode::Blake3_256))
        .collect();
    let capacity_err = SadCodes::from_pairs(&over).unwrap_err();
    assert!(matches!(capacity_err, keri_codec::SadCodesError::Capacity));

    // `v` is grammar-owned (the version string), never a SAID slot.
    let reserved_err = SadCodes::from_pairs(&[("v", DigestCode::Blake3_256)]).unwrap_err();
    assert!(matches!(
        reserved_err,
        keri_codec::SadCodesError::ReservedVersionLabel
    ));
}

/// The digest code that prefixes a qb64 value or matches a corpus code
/// field, if digestive — the qb64 code is always a leading substring of the
/// value, longest codes first. The corpus `code` field is the identifier
/// prefix's qb64 code; an EMPTY code means a basic (non-digestive)
/// identifier prefix — the sweep's `default_basic` case.
fn digestive_prefix_code(value: &str) -> Option<DigestCode> {
    const DIGESTIVE: [(&str, DigestCode); 9] = [
        ("0D", DigestCode::Blake3_512),
        ("0E", DigestCode::Blake2b_512),
        ("0F", DigestCode::SHA3_512),
        ("0G", DigestCode::SHA2_512),
        ("E", DigestCode::Blake3_256),
        ("F", DigestCode::Blake2b_256),
        ("G", DigestCode::Blake2s_256),
        ("H", DigestCode::SHA3_256),
        ("I", DigestCode::SHA2_256),
    ];
    DIGESTIVE
        .iter()
        .find(|(code, _)| value.starts_with(code))
        .map(|(_, digest)| *digest)
}

#[test]
fn keripy_said_code_sweep_verifies_and_yields_keripys_saids() -> Fallible<()> {
    // Differential proof over the keripy SAID-code sweep (#144/#148/#160):
    // keripy-generated wire bytes for every digestive identifier code.
    // These rows are self-addressing inceptions, so keripy's saids map is
    // {d: Blake3-256, i: <swept identifier code>}; the identifier is basic
    // (not digestive) for the `default_basic` row with an empty code field.
    // The configuration is read from the wire — the data-driven rule — and
    // each verified `d` must equal keripy's own recorded `said` byte-for-byte.
    let corpus = include_str!("corpus/keripy/parity/said_codes.jsonl");
    let mut rows_with_digestive_prefix = 0usize;
    for line in corpus.lines().filter(|l| !l.trim().is_empty()) {
        let row: serde_json::Value = serde_json::from_str(line)?;
        let raw_b64 = row
            .get("raw_b64")
            .and_then(|r| r.as_str())
            .ok_or("corpus row without raw_b64")?;
        let said = row
            .get("said")
            .and_then(|s| s.as_str())
            .ok_or("corpus row without said")?;
        let code = row.get("code").and_then(|c| c.as_str()).unwrap_or("");
        let pre = row
            .get("pre")
            .and_then(|p| p.as_str())
            .ok_or("corpus row without pre")?;
        let raw = base64::engine::general_purpose::STANDARD.decode(raw_b64)?;

        // `d` carries the SAID's own qb64 code (Blake3-256 for these rows);
        // `i` is digestive exactly when the swept identifier code names a
        // digest code, and the prefix value must agree with that code.
        let i_code = digestive_prefix_code(code);
        let mut codes = vec![(
            "d",
            digestive_prefix_code(said).ok_or("corpus row with non-digestive SAID")?,
        )];
        if let Some(found) = i_code {
            assert_eq!(
                digestive_prefix_code(pre),
                Some(found),
                "prefix and code field must agree for the swept code"
            );
            codes.push(("i", found));
            rows_with_digestive_prefix += 1;
        }
        let config = SadCodes::from_pairs(&codes)?;

        let parsed = verify_sad(&raw, &config)?;
        assert_eq!(
            parsed.said("d"),
            Some(said),
            "generic path must re-derive keripy's own SAID"
        );
        if i_code.is_some() {
            assert_eq!(
                parsed.said("i"),
                Some(pre),
                "generic path must verify the swept identifier prefix"
            );
        }
    }
    assert!(
        rows_with_digestive_prefix > 0,
        "corpus must exercise the double-SAID configuration shape"
    );

    Ok(())
}

#[test]
fn keripy_kel_events_verify_through_the_generic_path() -> Fallible<()> {
    // Differential proof on a genuine multi-event KEL: keripy-produced
    // inception -> rotation -> interaction, verified with configurations
    // derived from each event's wire codes. This KEL has a basic-derivation
    // genesis (`i` is an Ed25519 prefix, not digestive), so only `d` is
    // configured — the caller decides from the wire, per the data-driven law.
    let corpus = include_str!("corpus/kels.jsonl");
    let mut checked = 0usize;
    for line in corpus.lines().filter(|l| !l.trim().is_empty()) {
        let case: serde_json::Value = serde_json::from_str(line)?;
        let events = case
            .get("events")
            .and_then(|e| e.as_array())
            .ok_or("corpus line without events")?;
        for event in events {
            let raw_b64 = event
                .get("raw_b64")
                .and_then(|r| r.as_str())
                .ok_or("corpus event without raw_b64")?;
            let raw = base64::engine::general_purpose::STANDARD.decode(raw_b64)?;
            let wire: serde_json::Value = serde_json::from_slice(&raw)?;

            // keripy's per-ilk `saids` map: self-addressing inceptions
            // (`icp`, `dip`, `drt`) derive BOTH the identifier `i` and `d`;
            // events carrying an established identifier (`rot`, `ixn`, ...)
            // derive only `d`. The digest code of each configured label is
            // read from its qb64 prefix — the data-driven rule.
            let ilk = wire.get("t").and_then(|v| v.as_str()).unwrap_or("");
            let digestive_labels: &[&str] = match ilk {
                "icp" | "dip" | "drt" => &["d", "i"],
                _ => &["d"],
            };
            let mut codes: Vec<(&str, DigestCode)> = Vec::new();
            for label in digestive_labels {
                let value = wire.get(*label).and_then(|v| v.as_str());
                let code = value.and_then(digestive_prefix_code);
                if let Some(digest) = code {
                    codes.push((*label, digest));
                }
            }
            if codes.is_empty() {
                continue;
            }
            let config = SadCodes::from_pairs(&codes)?;
            verify_sad(&raw, &config)?;
            checked += 1;
        }
    }
    assert!(
        checked >= 3,
        "corpus differential checked only {checked} events"
    );

    Ok(())
}
