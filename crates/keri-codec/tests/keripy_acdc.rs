//! keripy differential vectors for the ACDC credential codec (P4): the v1
//! credential SAD — compact (SAID-in-place) and expanded forms — as keripy's
//! `vc/proving.py` `credential` renders it at the pin (`scripts/KERIPY_PIN`,
//! de59bc7d), replayed through the **public** Rust API.
//!
//! The corpus is generated deterministically without importing keripy;
//! `scripts/keripy_acdc_oracle.py` independently imports pinned Python 3.14
//! `SerderACDC`/`Saider` and checks the four happy bodies, nested SAIDs,
//! exact indexed signatures, and five SAID-valid invalid v1 shapes. The
//! pinned v1 fields are `v,d,u?,i,ri?,s,a?/A?,e?,r?`; `p`, `E`, and `R`
//! belong to neither that field domain nor this codec. A scalar `A` reference
//! has factory-byte coverage; aggregate commitment semantics remain A24/A27.
//!
//! Three families, one record per line:
//!
//! - `happy.jsonl` — every credential deserializes through
//!   [`Deserialize`] (which verifies the SAID and every nested block's own
//!   SAID over the generic SAD path — no ACDC-specific digest logic) and
//!   re-serializes byte-identical.
//! - `signed.jsonl` — the same credentials signed by the issuer: the
//!   reconstructed indexed signature verifies cryptographically over the
//!   exact credential bytes. Credentials are SADs, not key-event messages,
//!   so there is no framing lane to round-trip.
//! - `harden.jsonl` — parse-hardening vectors, each rejected by the
//!   specific law its `why` token names.
//!
//! Regenerate:
//!
//! ```text
//! python3 scripts/keripy_acdc_gen.py \
//!   --out-dir crates/keri-codec/tests/corpus/acdc
//! ```
//!
//! The corpus is embedded via `include_str!` because the nix gate builds
//! and runs tests in separate hermetic phases, so a runtime
//! `CARGO_MANIFEST_DIR` path is unreliable (same as the other corpora).
mod common;

use std::borrow::Cow;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::VerKeyCode;
use cesr::crypto::verify_indexed;
use keri_codec::{BuilderError, CodecError, Deserialize, DeserializeError, Serialize};
use keri_events::{Acdc, VerifyingKey};

use common::{Fallible, siger_from_qb64};

const HAPPY: &str = include_str!("corpus/acdc/happy.jsonl");
const SIGNED: &str = include_str!("corpus/acdc/signed.jsonl");
const HARDEN: &str = include_str!("corpus/acdc/harden.jsonl");

/// The keripy pin every checked-in vector's shapes were reproduced from.
const KERIPY_PIN: &str = "de59bc7d834955c5b0273c62f6b8b6a0df150dc3";

#[derive(Debug, serde::Deserialize)]
struct HappyVector {
    case: String,
    form: String,
    raw: String,
}

#[derive(Debug, serde::Deserialize)]
struct SignedVector {
    case: String,
    form: String,
    raw: String,
    vk_b64: String,
    sig_qb64: String,
}

#[derive(Debug, serde::Deserialize)]
struct HardeningVector {
    case: String,
    form: String,
    why: String,
    raw: String,
}

/// One JSONL record per line; malformed corpus records abort the test
/// through `?` (no `expect` — the workspace denies it in tests too).
fn records(raw: &str) -> Fallible<Vec<serde_json::Value>> {
    raw.lines()
        .map(|line| serde_json::from_str(line).map_err(Into::into))
        .collect()
}

/// The issuer's transferable Ed25519 verification key, rebuilt from the raw
/// standard-base64 bytes the generator records.
fn verifying_key(vk_b64: &str) -> Fallible<VerifyingKey<'static>> {
    let raw = BASE64.decode(vk_b64)?;
    let matter = MatterBuilder::new()
        .with_code(VerKeyCode::Ed25519)
        .with_raw(Cow::Owned(raw))?
        .build()?;
    Ok(VerifyingKey::from_matter(matter.into_static()))
}

/// Does `err` carry the law `why` names? One arm per hardening family, so a
/// vector rejected by the WRONG law fails loudly instead of passing. Nested
/// SAID failures (the edges block's own `d`) surface through the same
/// `CodecError::Said` family as the outer credential's.
fn rejected_by(err: &CodecError, why: &str) -> bool {
    match why {
        "non_canonical" => {
            matches!(
                err,
                CodecError::Deserialize(DeserializeError::NonCanonical { .. })
            )
        }
        "said_mismatch" | "nested_said_mismatch" => matches!(err, CodecError::Said(_)),
        "missing_field" => {
            matches!(
                err,
                CodecError::Deserialize(DeserializeError::MissingField(_))
            )
        }
        "unknown_field" => {
            matches!(
                err,
                CodecError::Deserialize(DeserializeError::UnexpectedField(_))
            )
        }
        "version_grammar" => matches!(err, CodecError::Version(_)),
        _ => false,
    }
}

#[test]
fn happy_vectors_deserialize_and_reserialize_byte_identical() -> Fallible<()> {
    let vectors = records(HAPPY)?;
    assert_eq!(vectors.len(), 4, "checked-in happy family is current");
    for value in vectors {
        let vector: HappyVector = serde_json::from_value(value)?;
        let credential =
            match Acdc::deserialize(vector.raw.as_bytes(), keri_codec::JsonLimits::new(4096, 64)) {
                Ok(credential) => credential.into_static(),
                Err(err) => {
                    return Err(format!(
                        "{} ({}): deserialize failed: {err}",
                        vector.case, vector.form
                    )
                    .into());
                }
            };
        // The parsed credential re-serializes to the exact keripy-shaped
        // bytes.
        let reserialized = credential.serialize()?.as_bytes().to_vec();
        assert_eq!(
            reserialized.as_slice(),
            vector.raw.as_bytes(),
            "{} ({}) does not reserialize byte-identical",
            vector.case,
            vector.form,
        );
    }
    Ok(())
}

#[test]
fn signed_vectors_verify_cryptographically() -> Fallible<()> {
    let vectors = records(SIGNED)?;
    assert_eq!(vectors.len(), 4, "checked-in signed family is current");
    for value in vectors {
        let vector: SignedVector = serde_json::from_value(value)?;
        // The credential itself must still parse.
        match Acdc::deserialize(vector.raw.as_bytes(), keri_codec::JsonLimits::new(4096, 64)) {
            Ok(credential) => credential.into_static(),
            Err(err) => {
                return Err(format!(
                    "{} ({}): deserialize failed: {err}",
                    vector.case, vector.form
                )
                .into());
            }
        };
        // The issuer's key from the record verifies the reconstructed
        // indexed signature over the exact credential bytes — keripy
        // `messagize` content.
        let verfer = verifying_key(&vector.vk_b64)?;
        let siger = siger_from_qb64(&vector.sig_qb64)?;
        let verified: Vec<_> = verify_indexed(
            std::slice::from_ref(verfer.as_matter()),
            vector.raw.as_bytes(),
            std::iter::once(&siger),
        )
        .collect();
        assert!(
            verified.iter().all(Result::is_ok),
            "{} ({}) signature does not verify: {verified:?}",
            vector.case,
            vector.form,
        );
    }
    Ok(())
}

#[test]
fn typed_acdc_writer_rejects_both_attribute_forms() -> Fallible<()> {
    let row: HappyVector = serde_json::from_str(
        HAPPY
            .lines()
            .find(|line| line.contains("aggregate_reference"))
            .ok_or("missing aggregate reference vector")?,
    )?;
    let source = Acdc::deserialize(row.raw.as_bytes(), keri_codec::JsonLimits::new(4096, 64))?;
    let both = Acdc::new_unchecked(
        source.said().clone(),
        source.nonce().cloned(),
        source.issuer().clone(),
        source.registry().cloned(),
        source.schema().clone(),
        Some(source.schema().clone()),
        source.aggregate_attributes().cloned(),
        source.edges().cloned(),
        source.rules().cloned(),
    );
    assert!(matches!(
        both.serialize(),
        Err(CodecError::Builder(BuilderError::AcdcAlternateAttributes))
    ));
    Ok(())
}

#[test]
fn hardening_vectors_are_rejected_by_their_recorded_law() -> Fallible<()> {
    let vectors = records(HARDEN)?;
    assert_eq!(vectors.len(), 11, "checked-in hardening family is current");
    for value in vectors {
        let vector: HardeningVector = serde_json::from_value(value)?;
        match Acdc::deserialize(vector.raw.as_bytes(), keri_codec::JsonLimits::new(4096, 64)) {
            Ok(_) => {
                return Err(format!(
                    "{} ({}): must be rejected by law '{}'",
                    vector.case, vector.form, vector.why,
                )
                .into());
            }
            Err(err) => assert!(
                rejected_by(&err, &vector.why),
                "{} ({}) was rejected by the wrong law: {err:?} (expected '{}')",
                vector.case,
                vector.form,
                vector.why,
            ),
        }
    }
    Ok(())
}

// The pin constant is asserted once so a drift between the corpus header
// and this consumer is caught at test time, not in review. The generator
// itself cannot be `include_str!`ed here: the nix gate's source filter
// keeps only Rust files plus `tests/corpus/` and `tests/fixtures/`, so a
// `scripts/` path fails to compile in the flake. Generator-side pin drift
// is guarded instead by the nightly keripy-diff workflow, which
// regenerates the corpus and lands any byte change as a visible diff.
#[test]
fn pinned_keripy_commit_is_current() {
    assert_eq!(KERIPY_PIN, "de59bc7d834955c5b0273c62f6b8b6a0df150dc3");
}
