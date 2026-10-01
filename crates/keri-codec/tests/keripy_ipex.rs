//! keripy differential vectors for the exn/IPEX lane (P4): the KERI `exn`
//! exchange envelope carrying the six IPEX routes — apply, offer, agree,
//! grant, admit, spurn — as keripy's `vc/protocoling.py` factories render
//! them at the pin (`scripts/KERIPY_PIN`, de59bc7d), replayed through the
//! **public** Rust API.
//!
//! The deterministic generator (`scripts/keripy_ipex_gen.py`) reproduces
//! shapes. `scripts/keripy_ipex_oracle.py` independently imports pinned
//! Python 3.14 `exchange`, `specialExchange`, all six `vc.protocoling`
//! factories, readers and `IpexHandler.verify`: all seven happy bodies,
//! embedded ACDC/TEL/KEL readers and exact indexed signatures match. The
//! reference handler's prior-route verdicts are separate from this codec's
//! typed route lift; conversation persistence/authorization remains A28.
//!
//! Three families, one record per line:
//!
//! - `happy.jsonl` — every envelope deserializes through
//!   [`Exn::deserialize`] (SAID + embeds-map SAID + every embedded SAD
//!   verified over the generic SAD path), lifts into the typed
//!   [`IpexMessage`] at its route, and re-serializes byte-identical.
//! - `signed.jsonl` — the same envelopes signed by the sender: the
//!   reconstructed indexed signature verifies cryptographically, the
//!   framed message round-trips through [`Message::parse`]'s exn lane,
//!   and the typed lift re-parses from the framed body.
//! - `harden.jsonl` — parse-hardening vectors at two levels: `level:
//!   "exn"` rejects in [`Exn::deserialize`]; `level: "route"` parses as a
//!   generic envelope and is rejected by [`IpexMessage::parse`] with the
//!   law its `why` token names.
//!
//! Regenerate:
//!
//! ```text
//! python3 scripts/keripy_ipex_gen.py \
//!   --out-dir crates/keri-codec/tests/corpus/ipex
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
use cesr::core::primitives::Siger;
use cesr::crypto::{IndexedVerifyError, verify_indexed};
use cesr_stream::group::ControllerIdxSigs;
use keri_codec::{
    CodecError, Deserialize, DeserializeError, Exn, IpexMessage, IpexRoute, Message, Serialize,
};
use keri_events::VerifyingKey;
use keri_events::acdc::SadBlock;

use common::{Fallible, Key, siger_from_qb64};

const HAPPY: &str = include_str!("corpus/ipex/happy.jsonl");
const SIGNED: &str = include_str!("corpus/ipex/signed.jsonl");
const HARDEN: &str = include_str!("corpus/ipex/harden.jsonl");

/// The keripy pin every checked-in vector's shapes were reproduced from.
const KERIPY_PIN: &str = "de59bc7d834955c5b0273c62f6b8b6a0df150dc3";

#[derive(Debug, serde::Deserialize)]
struct HappyVector {
    case: String,
    route: String,
    raw: String,
}

#[derive(Debug, serde::Deserialize)]
struct SignedVector {
    case: String,
    route: String,
    raw: String,
    vk_b64: String,
    sig_qb64: String,
}

#[derive(Debug, serde::Deserialize)]
struct HardeningVector {
    case: String,
    route: String,
    level: String,
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

/// The sender's transferable Ed25519 verification key, rebuilt from the raw
/// standard-base64 bytes the generator records.
fn verifying_key(vk_b64: &str) -> Fallible<VerifyingKey<'static>> {
    let raw = BASE64.decode(vk_b64)?;
    let matter = MatterBuilder::new()
        .with_code(VerKeyCode::Ed25519)
        .with_raw(Cow::Owned(raw))?
        .build()?;
    Ok(VerifyingKey::from_matter(matter.into_static()))
}

/// The indexed-signature verification results for `sigs` over `body` under
/// `verfer` — the two consumer call sites (raw and reparsed) share the
/// reduction so both assertions stay uniform.
fn signature_results<'a>(
    verfer: &'a VerifyingKey<'a>,
    body: &'a [u8],
    sigs: impl IntoIterator<Item = &'a Siger<'a>> + 'a,
) -> Vec<Result<u32, IndexedVerifyError>> {
    verify_indexed(std::slice::from_ref(verfer.as_matter()), body, sigs).collect()
}

/// The typed lift every happy/signed record must survive, asserted against
/// the record's route and the shape facts the factories pin: offer embeds
/// its credential; grant embeds its credential with optional `iss`/`anc`;
/// replies carry a prior.
fn assert_route_shape(case: &str, route: &str, message: &IpexMessage<'_>) -> Fallible<()> {
    let expected =
        IpexRoute::from_route(route).ok_or_else(|| format!("{case}: unknown route {route}"))?;
    assert_eq!(
        message.route(),
        expected,
        "{case}: dispatched to the wrong typed route",
    );
    match message {
        IpexMessage::Apply(apply) => {
            assert!(!apply.message().is_empty(), "{case}: empty payload message");
            assert!(apply.prior().is_none(), "{case}: apply is an opener");
        }
        IpexMessage::Offer(offer) => {
            assert!(!offer.message().is_empty(), "{case}: empty payload message");
            assert!(offer.prior().is_none(), "{case}: offer is an opener");
        }
        IpexMessage::Agree(agree) => {
            assert!(!agree.message().is_empty(), "{case}: empty payload message");
            assert!(
                agree.prior().is_some(),
                "{case}: agree replies to the offer"
            );
        }
        IpexMessage::Grant(grant) => {
            assert!(!grant.message().is_empty(), "{case}: empty payload message");
            assert!(
                grant.prior().is_some(),
                "{case}: grant replies to the offer"
            );
            if case == "grant" {
                // The full grant embeds its TEL issuance and KEL anchor
                // alongside the credential.
                assert!(grant.iss().is_some(), "{case}: missing iss embed");
                assert!(grant.anc().is_some(), "{case}: missing anc embed");
            } else {
                assert!(grant.iss().is_none(), "{case}: unexpected iss embed");
                assert!(grant.anc().is_none(), "{case}: unexpected anc embed");
            }
        }
        IpexMessage::Admit(admit) => {
            assert!(!admit.message().is_empty(), "{case}: empty payload message");
            assert!(
                admit.prior().is_some(),
                "{case}: admit replies to the grant"
            );
        }
        IpexMessage::Spurn(spurn) => {
            assert!(!spurn.message().is_empty(), "{case}: empty payload message");
            assert!(spurn.prior().is_some(), "{case}: spurn names its prior");
        }
    }
    Ok(())
}

/// Does `err` carry the law `why` names? One arm per hardening family, so a
/// vector rejected by the WRONG law fails loudly instead of passing.
/// Envelope-level embeds-map SAID failures and outer SAID failures both
/// surface through `CodecError::Said`.
fn rejected_by(err: &CodecError, why: &str) -> bool {
    match why {
        "unknown_route" => {
            matches!(
                err,
                CodecError::Deserialize(DeserializeError::UnknownRoute(_))
            )
        }
        "unknown_embed" => {
            matches!(
                err,
                CodecError::Deserialize(DeserializeError::UnknownEmbed(_, _))
            )
        }
        "missing_field" => {
            matches!(
                err,
                CodecError::Deserialize(DeserializeError::MissingField(_))
            )
        }
        "attribute_said_form" => {
            matches!(
                err,
                CodecError::Deserialize(DeserializeError::AttributeSaidForm(_))
            )
        }
        "non_canonical" => {
            matches!(
                err,
                CodecError::Deserialize(DeserializeError::NonCanonical { .. })
            )
        }
        "said_mismatch" | "embeds_said_mismatch" => matches!(err, CodecError::Said(_)),
        _ => false,
    }
}

#[test]
fn happy_vectors_lift_typed_and_reserialize_byte_identical() -> Fallible<()> {
    let vectors = records(HAPPY)?;
    assert_eq!(vectors.len(), 7, "checked-in happy family is current");
    for value in vectors {
        let vector: HappyVector = serde_json::from_value(value)?;
        let exn =
            match Exn::deserialize(vector.raw.as_bytes(), keri_codec::JsonLimits::new(4096, 64)) {
                Ok(exn) => exn.into_static(),
                Err(err) => {
                    return Err(format!(
                        "{} ({}): deserialize failed: {err}",
                        vector.case, vector.route
                    )
                    .into());
                }
            };
        // The typed lift dispatches on the route and strictly parses the
        // payload and typed embeds.
        let lifted = match IpexMessage::parse(&exn, keri_codec::JsonLimits::new(4096, 64)) {
            Ok(lifted) => lifted,
            Err(err) => {
                return Err(format!(
                    "{} ({}): typed lift failed: {err}",
                    vector.case, vector.route
                )
                .into());
            }
        };
        assert_route_shape(&vector.case, &vector.route, &lifted)?;

        // The parsed envelope re-serializes to the exact keripy-shaped
        // bytes — embeds included.
        let reserialized = exn.serialize()?.as_bytes().to_vec();
        assert_eq!(
            reserialized.as_slice(),
            vector.raw.as_bytes(),
            "{} ({}) does not reserialize byte-identical",
            vector.case,
            vector.route,
        );
    }
    Ok(())
}

fn rebuild_route(
    source: &Exn<'_>,
    route: &IpexMessage<'_>,
    message: &str,
) -> Fallible<Exn<'static>> {
    Ok(match route {
        IpexMessage::Apply(apply) => Exn::ipex_apply(
            source.issuer(),
            source.datetime(),
            message,
            apply.schema(),
            apply.attrs(),
            apply.recipient(),
        )?,
        IpexMessage::Offer(offer) => Exn::ipex_offer(
            source.issuer(),
            source.datetime(),
            message,
            source.embed("acdc").ok_or("missing offer acdc")?,
            offer.prior(),
            keri_codec::JsonLimits::new(4096, 64),
        )?,
        IpexMessage::Agree(agree) => {
            Exn::ipex_agree(source.issuer(), source.datetime(), message, agree.prior())?
        }
        IpexMessage::Grant(grant) => Exn::ipex_grant(
            source.issuer(),
            source.datetime(),
            message,
            grant.recipient(),
            source.embed("acdc").ok_or("missing grant acdc")?,
            source.embed("iss"),
            source.embed("anc"),
            grant.prior(),
            keri_codec::JsonLimits::new(4096, 64),
        )?,
        IpexMessage::Admit(admit) => {
            Exn::ipex_admit(source.issuer(), source.datetime(), message, admit.prior())?
        }
        IpexMessage::Spurn(spurn) => {
            Exn::ipex_spurn(source.issuer(), source.datetime(), message, spurn.prior())?
        }
    })
}

#[test]
fn public_ipex_constructors_round_trip_every_route_and_embed_shape() -> Fallible<()> {
    let signer = Key::new()?;
    let vectors = records(HAPPY)?;
    assert_eq!(vectors.len(), 7);
    for value in vectors {
        let vector: HappyVector = serde_json::from_value(value)?;
        let source =
            Exn::deserialize(vector.raw.as_bytes(), keri_codec::JsonLimits::new(4096, 64))?;
        let route = IpexMessage::parse(&source, keri_codec::JsonLimits::new(4096, 64))?;
        let built = rebuild_route(
            &source,
            &route,
            match &route {
                IpexMessage::Apply(item) => item.message(),
                IpexMessage::Offer(item) => item.message(),
                IpexMessage::Agree(item) => item.message(),
                IpexMessage::Grant(item) => item.message(),
                IpexMessage::Admit(item) => item.message(),
                IpexMessage::Spurn(item) => item.message(),
            },
        )?;
        assert!(
            built.said().is_none(),
            "{}: builder claimed a SAID",
            vector.case
        );
        let serialized = built.serialize()?;
        assert_eq!(
            serialized.as_bytes(),
            vector.raw.as_bytes(),
            "{}",
            vector.case
        );
        let decoded =
            Exn::deserialize(serialized.as_bytes(), keri_codec::JsonLimits::new(4096, 64))?;
        assert_eq!(decoded.said(), Some(serialized.said()));
        assert_eq!(
            IpexMessage::parse(&decoded, keri_codec::JsonLimits::new(4096, 64))?.route(),
            route.route()
        );

        let signature = signer.sign(serialized.as_bytes(), 0)?;
        let frame =
            serialized.frame_v1(&ControllerIdxSigs::from_indexed_signatures(&[signature])?)?;
        let (Message::Exn(message), rest) = Message::parse(&frame, common::message_limits())?
        else {
            return Err(format!("{}: framed message did not route to EXN", vector.case).into());
        };
        assert!(rest.is_empty());
        assert_eq!(message.body(), serialized.as_bytes());
        assert_eq!(
            IpexMessage::parse(message.exn(), keri_codec::JsonLimits::new(4096, 64))?.route(),
            route.route()
        );

        // Empty human text is legal for each route. The optional prior and
        // grant `iss`/`anc` shape still follows the source vector.
        let empty = rebuild_route(&source, &route, "")?;
        let empty_serialized = empty.serialize()?;
        let empty_decoded = Exn::deserialize(
            empty_serialized.as_bytes(),
            keri_codec::JsonLimits::new(4096, 64),
        )?;
        assert_eq!(
            IpexMessage::parse(&empty_decoded, keri_codec::JsonLimits::new(4096, 64))?.route(),
            route.route()
        );
    }
    Ok(())
}

#[test]
fn public_ipex_constructors_reject_invalid_embedded_bodies() -> Fallible<()> {
    let json = keri_codec::JsonLimits::new(4096, 64);
    let vectors = records(HAPPY)?;
    let apply_record: HappyVector = serde_json::from_value(
        vectors
            .iter()
            .find(|value| value["case"] == "apply")
            .ok_or("missing apply vector")?
            .clone(),
    )?;
    let offer_record: HappyVector = serde_json::from_value(
        vectors
            .iter()
            .find(|value| value["case"] == "offer")
            .ok_or("missing offer vector")?
            .clone(),
    )?;
    let grant_record: HappyVector = serde_json::from_value(
        vectors
            .iter()
            .find(|value| value["case"] == "grant")
            .ok_or("missing grant vector")?
            .clone(),
    )?;
    let apply = Exn::deserialize(apply_record.raw.as_bytes(), json)?;
    let offer = Exn::deserialize(offer_record.raw.as_bytes(), json)?;
    let grant = Exn::deserialize(grant_record.raw.as_bytes(), json)?;
    let bad = SadBlock::new_unchecked(Cow::Borrowed("{}"));
    let IpexMessage::Apply(apply_payload) = IpexMessage::parse(&apply, json)? else {
        return Err("apply vector decoded as another route".into());
    };
    assert!(
        Exn::ipex_apply(
            apply.issuer(),
            apply.datetime(),
            "",
            apply_payload.schema(),
            &SadBlock::new_unchecked(Cow::Borrowed("[]")),
            apply_payload.recipient(),
        )
        .is_err()
    );
    assert!(Exn::ipex_offer(offer.issuer(), offer.datetime(), "", &bad, None, json).is_err());
    let valid_acdc = grant.embed("acdc").ok_or("grant acdc missing")?;
    assert!(
        Exn::ipex_grant(
            grant.issuer(),
            grant.datetime(),
            "",
            grant.issuer(),
            valid_acdc,
            Some(&bad),
            None,
            None,
            json
        )
        .is_err()
    );
    assert!(
        Exn::ipex_grant(
            grant.issuer(),
            grant.datetime(),
            "",
            grant.issuer(),
            valid_acdc,
            None,
            Some(&bad),
            None,
            json
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn public_ipex_optional_prior_branches_round_trip() -> Fallible<()> {
    let vectors = records(HAPPY)?;
    let find = |name: &str| -> Fallible<HappyVector> {
        Ok(serde_json::from_value(
            vectors
                .iter()
                .find(|value| value["case"] == name)
                .ok_or("missing IPEX vector")?
                .clone(),
        )?)
    };
    let apply_record = find("apply")?;
    let offer_record = find("offer")?;
    let grant_record = find("grant_minimal")?;
    let apply = Exn::deserialize(
        apply_record.raw.as_bytes(),
        keri_codec::JsonLimits::new(4096, 64),
    )?;
    let offer = Exn::deserialize(
        offer_record.raw.as_bytes(),
        keri_codec::JsonLimits::new(4096, 64),
    )?;
    let grant = Exn::deserialize(
        grant_record.raw.as_bytes(),
        keri_codec::JsonLimits::new(4096, 64),
    )?;
    let linked_offer = Exn::ipex_offer(
        offer.issuer(),
        offer.datetime(),
        "",
        offer.embed("acdc").ok_or("missing offer acdc")?,
        apply.said(),
        keri_codec::JsonLimits::new(4096, 64),
    )?;
    let linked_bytes = linked_offer.serialize()?;
    let linked = Exn::deserialize(
        linked_bytes.as_bytes(),
        keri_codec::JsonLimits::new(4096, 64),
    )?;
    let IpexMessage::Offer(linked_payload) =
        IpexMessage::parse(&linked, keri_codec::JsonLimits::new(4096, 64))?
    else {
        return Err("linked offer decoded as another route".into());
    };
    assert_eq!(linked_payload.prior(), apply.said());

    let unlinked_grant = Exn::ipex_grant(
        grant.issuer(),
        grant.datetime(),
        "",
        grant.issuer(),
        grant.embed("acdc").ok_or("missing grant acdc")?,
        None,
        None,
        None,
        keri_codec::JsonLimits::new(4096, 64),
    )?;
    let unlinked_bytes = unlinked_grant.serialize()?;
    let unlinked = Exn::deserialize(
        unlinked_bytes.as_bytes(),
        keri_codec::JsonLimits::new(4096, 64),
    )?;
    let IpexMessage::Grant(unlinked_payload) =
        IpexMessage::parse(&unlinked, keri_codec::JsonLimits::new(4096, 64))?
    else {
        return Err("unlinked grant decoded as another route".into());
    };
    assert!(unlinked_payload.prior().is_none());
    assert!(unlinked_payload.iss().is_none());
    assert!(unlinked_payload.anc().is_none());
    Ok(())
}

#[test]
fn signed_vectors_verify_frame_and_relift() -> Fallible<()> {
    let vectors = records(SIGNED)?;
    assert_eq!(vectors.len(), 7, "checked-in signed family is current");
    for value in vectors {
        let vector: SignedVector = serde_json::from_value(value)?;
        let exn =
            match Exn::deserialize(vector.raw.as_bytes(), keri_codec::JsonLimits::new(4096, 64)) {
                Ok(exn) => exn.into_static(),
                Err(err) => {
                    return Err(format!(
                        "{} ({}): deserialize failed: {err}",
                        vector.case, vector.route
                    )
                    .into());
                }
            };
        // The sender's key from the record verifies the reconstructed
        // indexed signature over the envelope bytes.
        let verfer = verifying_key(&vector.vk_b64)?;
        let siger = siger_from_qb64(&vector.sig_qb64)?;
        let verified = signature_results(&verfer, vector.raw.as_bytes(), std::iter::once(&siger));
        assert!(
            verified.iter().all(Result::is_ok),
            "{} ({}) signature does not verify: {verified:?}",
            vector.case,
            vector.route,
        );

        // Frame the signed message with the write spine and parse it back
        // with the read spine: the full public round trip through the exn
        // message lane.
        let framed = exn
            .serialize()?
            .frame_v1(&ControllerIdxSigs::from_indexed_signatures(&[siger])?)?;
        let (message, rest) = match Message::parse(&framed, common::message_limits()) {
            Ok(parsed) => parsed,
            Err(err) => {
                return Err(format!(
                    "{} ({}): framed parse failed: {err}",
                    vector.case, vector.route
                )
                .into());
            }
        };
        assert!(rest.is_empty(), "framed message leaves no remainder");
        let Message::Exn(lane) = &message else {
            return Err(format!(
                "{} ({}): dispatched to the wrong message lane",
                vector.case, vector.route,
            )
            .into());
        };
        assert_eq!(
            lane.body(),
            vector.raw.as_bytes(),
            "{} ({}) message body is not the signed span",
            vector.case,
            vector.route,
        );
        // The reparsed message's own signature re-verifies over its body.
        let reverified = signature_results(&verfer, lane.body(), lane.sigs().iter());
        assert!(
            reverified.iter().all(Result::is_ok),
            "{} ({}) reparsed signature does not verify: {reverified:?}",
            vector.case,
            vector.route,
        );
        // The typed lift works from the framed message's envelope too.
        let lifted = match IpexMessage::parse(lane.exn(), keri_codec::JsonLimits::new(4096, 64)) {
            Ok(lifted) => lifted,
            Err(err) => {
                return Err(format!(
                    "{} ({}): typed lift from framed message failed: {err}",
                    vector.case, vector.route
                )
                .into());
            }
        };
        assert_route_shape(&vector.case, &vector.route, &lifted)?;
    }
    Ok(())
}

#[test]
fn hardening_vectors_are_rejected_by_their_recorded_law() -> Fallible<()> {
    let vectors = records(HARDEN)?;
    assert_eq!(vectors.len(), 8, "checked-in hardening family is current");
    for value in vectors {
        let vector: HardeningVector = serde_json::from_value(value)?;
        match Exn::deserialize(vector.raw.as_bytes(), keri_codec::JsonLimits::new(4096, 64)) {
            Err(err) => {
                // Envelope-level rejection: the record must have said so.
                assert_eq!(
                    vector.level, "exn",
                    "{} ({}) rejected at the envelope but recorded as {}",
                    vector.case, vector.route, vector.level,
                );
                assert!(
                    rejected_by(&err, &vector.why),
                    "{} ({}) was rejected by the wrong law: {err:?} (expected '{}')",
                    vector.case,
                    vector.route,
                    vector.why,
                );
            }
            Ok(exn) => {
                let envelope = exn.into_static();
                // Route-level rejection: the envelope parses, the typed
                // lift must reject with the recorded law.
                assert_eq!(
                    vector.level, "route",
                    "{} ({}) parsed as an envelope but recorded as {}",
                    vector.case, vector.route, vector.level,
                );
                match IpexMessage::parse(&envelope, keri_codec::JsonLimits::new(4096, 64)) {
                    Ok(_) => {
                        return Err(format!(
                            "{} ({}): must be rejected by law '{}'",
                            vector.case, vector.route, vector.why,
                        )
                        .into());
                    }
                    Err(err) => assert!(
                        rejected_by(&err, &vector.why),
                        "{} ({}) was rejected by the wrong law: {err:?} (expected '{}')",
                        vector.case,
                        vector.route,
                        vector.why,
                    ),
                }
            }
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
