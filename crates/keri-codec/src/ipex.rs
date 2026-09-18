//! The six IPEX routes as typed builders and parsers over the [`Exn`]
//! envelope — the data-level mirror of keripy `vc/protocoling.py` at pin
//! `de59bc7d`.
//!
//! There is no conversation state machine here: the builders produce
//! envelope data, the parsers lift envelope data, and sequencing (apply →
//! offer → agree → grant → admit, or spurn) stays downstream.
//!
//! Verified per-route v1 shapes (locked in the parity ledger):
//!
//! | route | `r` | `a` payload | `e` embeds |
//! |---|---|---|---|
//! | apply | `/ipex/apply` | `{m,s,a,i}` | absent |
//! | offer | `/ipex/offer` | `{m}` | always present (`{}` or `{acdc}`) |
//! | agree | `/ipex/agree` | `{m}` | absent |
//! | grant | `/ipex/grant` | `{m,i}` | always present (`{}` or `{acdc,iss?,anc?}`) |
//! | admit | `/ipex/admit` | `{m}` | absent |
//! | spurn | `/ipex/spurn` | `{m}` | absent |
//!
//! All six factories pass `rp=""` and an empty `q` map; the recipient is
//! carried inside `a.i` for apply and grant. Offer, agree, admit, and spurn
//! default `dt` to `now` in keripy — here every builder takes `dt`
//! explicitly, because data-level construction never reads a clock.

use alloc::borrow::{Cow, ToOwned};
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use cesr::core::matter::code::{CesrCode, DigestCode};
use keri_events::Identifier;
use keri_events::KeriEvent;
use keri_events::acdc::{Acdc, SadBlock};
use keri_events::primitive::Said;
use keri_events::tel::TelEvent;

use crate::codec::scanner::Scanner;
use crate::codec::{Encode, JsonWriter};
use crate::exn::{Exn, ExnAttributes, ExnEmbeds};
use crate::traits::Deserialize;
use crate::{CodecError, DeserializeError};

/// The six IPEX routes — the handler paths keripy's `vc/protocoling.py`
/// factories target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpexRoute {
    /// Credential application (`/ipex/apply`).
    Apply,
    /// Credential offer (`/ipex/offer`).
    Offer,
    /// Offer agreement (`/ipex/agree`).
    Agree,
    /// Credential transfer (`/ipex/grant`).
    Grant,
    /// Grant admission (`/ipex/admit`).
    Admit,
    /// Rejection of the exchange (`/ipex/spurn`).
    Spurn,
}

impl IpexRoute {
    /// The route's handler path — the exn `r` value.
    #[must_use]
    pub const fn route(self) -> &'static str {
        match self {
            Self::Apply => "/ipex/apply",
            Self::Offer => "/ipex/offer",
            Self::Agree => "/ipex/agree",
            Self::Grant => "/ipex/grant",
            Self::Admit => "/ipex/admit",
            Self::Spurn => "/ipex/spurn",
        }
    }

    /// The route whose handler path is `route`.
    #[must_use]
    pub fn from_route(route: &str) -> Option<Self> {
        for (path, known) in [
            ("/ipex/apply", Self::Apply),
            ("/ipex/offer", Self::Offer),
            ("/ipex/agree", Self::Agree),
            ("/ipex/grant", Self::Grant),
            ("/ipex/admit", Self::Admit),
            ("/ipex/spurn", Self::Spurn),
        ] {
            if route == path {
                return Some(known);
            }
        }
        None
    }
}

/// The `/ipex/apply` payload: a credential request against a schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpexApply<'a> {
    /// Human-readable message (`a.m`).
    message: &'a str,
    /// Requested credential schema SAID (`a.s`).
    schema: Said<'a>,
    /// Requested attribute filter map (`a.a`) — canonical JSON, carried
    /// verbatim.
    attrs: SadBlock<'a>,
    /// Recipient identifier (`a.i`) — who will receive the credential.
    recipient: Identifier<'a>,
    /// The exchange chain link (`p`) — absent for a conversation opener.
    prior: Option<Said<'a>>,
}

impl IpexApply<'_> {
    /// The human-readable message (`a.m`).
    #[must_use]
    pub const fn message(&self) -> &str {
        self.message
    }

    /// The requested credential schema SAID (`a.s`).
    #[must_use]
    pub const fn schema(&self) -> &Said<'_> {
        &self.schema
    }

    /// The requested attribute filter map (`a.a`).
    #[must_use]
    pub const fn attrs(&self) -> &SadBlock<'_> {
        &self.attrs
    }

    /// The recipient identifier (`a.i`).
    #[must_use]
    pub const fn recipient(&self) -> &Identifier<'_> {
        &self.recipient
    }

    /// The exchange chain link (`p`).
    #[must_use]
    pub const fn prior(&self) -> Option<&Said<'_>> {
        self.prior.as_ref()
    }
}

/// The `/ipex/offer` payload: a credential offer with its embedded ACDC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpexOffer<'a> {
    /// Human-readable message (`a.m`).
    message: &'a str,
    /// The offered credential — typed and SAID-verified from the `e.acdc`
    /// embed (required for a typed offer).
    acdc: Acdc<'a>,
    /// The exchange chain link (`p`) — the apply's SAID.
    prior: Option<Said<'a>>,
}

impl IpexOffer<'_> {
    /// The human-readable message (`a.m`).
    #[must_use]
    pub const fn message(&self) -> &str {
        self.message
    }

    /// The offered credential (from the `e.acdc` embed).
    #[must_use]
    pub const fn acdc(&self) -> &Acdc<'_> {
        &self.acdc
    }

    /// The exchange chain link (`p`).
    #[must_use]
    pub const fn prior(&self) -> Option<&Said<'_>> {
        self.prior.as_ref()
    }
}

/// The `/ipex/agree` payload: acceptance of a credential offer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpexAgree<'a> {
    /// Human-readable message (`a.m`).
    message: &'a str,
    /// The exchange chain link (`p`) — the offer's SAID.
    prior: Option<Said<'a>>,
}

impl IpexAgree<'_> {
    /// The human-readable message (`a.m`).
    #[must_use]
    pub const fn message(&self) -> &str {
        self.message
    }

    /// The exchange chain link (`p`).
    #[must_use]
    pub const fn prior(&self) -> Option<&Said<'_>> {
        self.prior.as_ref()
    }
}

/// The `/ipex/grant` payload — the workhorse: a credential transfer with
/// its verifiable provenance embedded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpexGrant<'a> {
    /// Human-readable message (`a.m`).
    message: &'a str,
    /// Recipient identifier (`a.i`) — who the credential is granted to.
    recipient: Identifier<'a>,
    /// The granted credential — typed and SAID-verified from the `e.acdc`
    /// embed (required for a typed grant).
    acdc: Acdc<'a>,
    /// The credential's issuance TEL event, from the `e.iss` embed.
    iss: Option<TelEvent<'a>>,
    /// An anchoring KEL event's verified canonical body, from the `e.anc`
    /// embed. Stored as the body because `KeriEvent` exposes no derives —
    /// the typed event is validated at parse time and lifted on demand
    /// with `KeriEvent::deserialize`.
    anc: Option<SadBlock<'a>>,
    /// The exchange chain link (`p`) — the agree's SAID.
    prior: Option<Said<'a>>,
}

impl IpexGrant<'_> {
    /// The human-readable message (`a.m`).
    #[must_use]
    pub const fn message(&self) -> &str {
        self.message
    }

    /// The recipient identifier (`a.i`).
    #[must_use]
    pub const fn recipient(&self) -> &Identifier<'_> {
        &self.recipient
    }

    /// The granted credential (from the `e.acdc` embed).
    #[must_use]
    pub const fn acdc(&self) -> &Acdc<'_> {
        &self.acdc
    }

    /// The credential's issuance TEL event (from the `e.iss` embed).
    #[must_use]
    pub const fn iss(&self) -> Option<&TelEvent<'_>> {
        self.iss.as_ref()
    }

    /// An anchoring KEL event's verified canonical body (from the `e.anc`
    /// embed). The typed event was validated at parse time; lift it on
    /// demand with `KeriEvent::deserialize` over the body bytes.
    #[must_use]
    pub const fn anc(&self) -> Option<&SadBlock<'_>> {
        self.anc.as_ref()
    }

    /// The exchange chain link (`p`).
    #[must_use]
    pub const fn prior(&self) -> Option<&Said<'_>> {
        self.prior.as_ref()
    }
}

/// The `/ipex/admit` payload: acceptance of a credential grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpexAdmit<'a> {
    /// Human-readable message (`a.m`).
    message: &'a str,
    /// The exchange chain link (`p`) — the grant's SAID.
    prior: Option<Said<'a>>,
}

impl IpexAdmit<'_> {
    /// The human-readable message (`a.m`).
    #[must_use]
    pub const fn message(&self) -> &str {
        self.message
    }

    /// The exchange chain link (`p`).
    #[must_use]
    pub const fn prior(&self) -> Option<&Said<'_>> {
        self.prior.as_ref()
    }
}

/// The `/ipex/spurn` payload: rejection of an exchange message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpexSpurn<'a> {
    /// Human-readable message (`a.m`).
    message: &'a str,
    /// The exchange chain link (`p`) — the spurned message's SAID.
    prior: Option<Said<'a>>,
}

impl IpexSpurn<'_> {
    /// The human-readable message (`a.m`).
    #[must_use]
    pub const fn message(&self) -> &str {
        self.message
    }

    /// The exchange chain link (`p`).
    #[must_use]
    pub const fn prior(&self) -> Option<&Said<'_>> {
        self.prior.as_ref()
    }
}

/// A typed IPEX exchange message: the route + its verified payload and
/// embeds, lifted from one [`Exn`] envelope.
///
/// Parse from a deserialized envelope ([`IpexMessage::parse`]); build with
/// the route's constructor ([`ipex_apply`] through [`ipex_spurn`]).
#[allow(
    clippy::large_enum_variant,
    reason = "the six route payloads are the wire embeds' inline CESR models; the enum is matched once per message and never copied, so boxing would only add indirection"
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpexMessage<'a> {
    /// A credential application against a schema.
    Apply(IpexApply<'a>),
    /// A credential offer with its embedded ACDC.
    Offer(IpexOffer<'a>),
    /// Acceptance of a credential offer.
    Agree(IpexAgree<'a>),
    /// A credential transfer with its verifiable provenance embedded.
    Grant(IpexGrant<'a>),
    /// Acceptance of a credential grant.
    Admit(IpexAdmit<'a>),
    /// Rejection of an exchange message.
    Spurn(IpexSpurn<'a>),
}

impl<'a> IpexMessage<'a> {
    /// The route of this message.
    #[must_use]
    pub const fn route(&self) -> IpexRoute {
        match self {
            Self::Apply(_) => IpexRoute::Apply,
            Self::Offer(_) => IpexRoute::Offer,
            Self::Agree(_) => IpexRoute::Agree,
            Self::Grant(_) => IpexRoute::Grant,
            Self::Admit(_) => IpexRoute::Admit,
            Self::Spurn(_) => IpexRoute::Spurn,
        }
    }

    /// Typed lift of one IPEX exn envelope: dispatch on the route, then
    /// strictly parse the route's payload and — for offer and grant — the
    /// typed embeds. Every embedded SAD is re-verified under its own code.
    ///
    /// # Errors
    ///
    /// [`DeserializeError::UnknownRoute`] for a non-IPEX route;
    /// [`DeserializeError::MissingField`] when a required payload or embed
    /// field is absent; [`DeserializeError::UnknownEmbed`] for an embed
    /// label outside the route's verified shape; a [`CodecError`] from the
    /// underlying strict parse, SAID verification, or typed embed lift
    /// otherwise.
    pub fn parse(exn: &'a Exn<'a>) -> Result<Self, CodecError> {
        let route = IpexRoute::from_route(exn.route())
            .ok_or_else(|| DeserializeError::UnknownRoute(exn.route().to_owned()))?;
        let prior = exn.prior().cloned();
        let attrs = match exn.attributes() {
            ExnAttributes::Block(block) => block,
            // The ESSR SAID form carries no typed payload to lift; the
            // six routes' verified shape is a payload map.
            ExnAttributes::Said(_) => {
                return Err(DeserializeError::AttributeSaidForm(route.route().to_owned()).into());
            }
        };
        let mut sc = Scanner::new(attrs.payload().as_bytes());
        match route {
            IpexRoute::Apply => {
                let (message, schema, filter, recipient) = apply_payload(&mut sc)?;
                Ok(Self::Apply(IpexApply {
                    message,
                    schema,
                    attrs: filter,
                    recipient,
                    prior,
                }))
            }
            IpexRoute::Offer => {
                let message = message_only(&mut sc)?;
                Ok(Self::Offer(IpexOffer {
                    message,
                    acdc: required_acdc_embed(exn, route)?,
                    prior,
                }))
            }
            IpexRoute::Agree => Ok(Self::Agree(IpexAgree {
                message: message_only(&mut sc)?,
                prior,
            })),
            IpexRoute::Grant => {
                let (message, recipient) = grant_payload(&mut sc)?;
                let embeds = typed_embeds(exn, route)?;
                let acdc = embeds.acdc.ok_or(DeserializeError::MissingField("acdc"))?;
                Ok(Self::Grant(IpexGrant {
                    message,
                    recipient,
                    acdc,
                    iss: embeds.iss,
                    anc: embeds.anc,
                    prior,
                }))
            }
            IpexRoute::Admit => Ok(Self::Admit(IpexAdmit {
                message: message_only(&mut sc)?,
                prior,
            })),
            IpexRoute::Spurn => Ok(Self::Spurn(IpexSpurn {
                message: message_only(&mut sc)?,
                prior,
            })),
        }
    }
}

/// The offer/grant embeds as typed values, lifted per label.
struct TypedEmbeds<'a> {
    acdc: Option<Acdc<'a>>,
    iss: Option<TelEvent<'a>>,
    anc: Option<SadBlock<'a>>,
}

/// Lift an offer's required `acdc` embed.
///
/// # Errors
///
/// [`DeserializeError::MissingField`] when absent, [`DeserializeError::
/// UnknownEmbed`] for labels outside the route's shape, or the embed's own
/// strict parse/SAID error.
fn required_acdc_embed<'a>(exn: &'a Exn<'a>, route: IpexRoute) -> Result<Acdc<'a>, CodecError> {
    let embeds = typed_embeds(exn, route)?;
    embeds
        .acdc
        .ok_or_else(|| DeserializeError::MissingField("acdc").into())
}

/// Lift an exn's embeds map into typed values, rejecting labels outside
/// the route's verified shape.
///
/// # Errors
///
/// [`DeserializeError::UnknownEmbed`] for an unknown label; the embed's
/// own strict parse/SAID error otherwise.
fn typed_embeds<'a>(exn: &'a Exn<'a>, route: IpexRoute) -> Result<TypedEmbeds<'a>, CodecError> {
    let ExnEmbeds::Map { entries, .. } = exn.embeds() else {
        // Offer/grant factories always render `e` (possibly `{}`): a typed
        // message carries no embeds in the empty/absent forms.
        return Ok(TypedEmbeds {
            acdc: None,
            iss: None,
            anc: None,
        });
    };
    let mut typed = TypedEmbeds {
        acdc: None,
        iss: None,
        anc: None,
    };
    for (label, block) in entries {
        match (label.as_ref(), route) {
            ("acdc", IpexRoute::Offer | IpexRoute::Grant) => {
                typed.acdc = Some(Acdc::deserialize(block.payload().as_bytes())?);
            }
            ("iss", IpexRoute::Grant) => {
                typed.iss = Some(TelEvent::deserialize(block.payload().as_bytes())?);
            }
            ("anc", IpexRoute::Grant) => {
                // Typed validation only — the grant stores the verified
                // canonical body (`KeriEvent` exposes no derives); lift
                // on demand with `KeriEvent::deserialize`.
                KeriEvent::deserialize(block.payload().as_bytes())?;
                typed.anc = Some(block.clone());
            }
            _ => {
                return Err(DeserializeError::UnknownEmbed(
                    route.route().to_owned(),
                    label.to_string(),
                )
                .into());
            }
        }
    }
    Ok(typed)
}

/// Strictly parse the apply payload `{m,s,a,i}` in wire order.
///
/// # Errors
///
/// [`DeserializeError::NonCanonical`] on any deviation; [`CodecError`] for
/// an undecodable SAID or identifier.
fn apply_payload<'a>(
    sc: &mut Scanner<'a>,
) -> Result<(&'a str, Said<'a>, SadBlock<'a>, Identifier<'a>), CodecError> {
    use crate::codec::field::Field;

    sc.expect("{")?;
    sc.expect("\"m\":")?;
    let message = sc.string()?;
    sc.expect(",\"s\":")?;
    let schema = Field::new("s", sc.string()?.value).decode::<Said>()?;
    sc.expect(",\"a\":")?;
    let filter_span = sc.object_value_span()?;
    // `object_value_span` validates bounds and canonical grammar, so both
    // conversions below are defensively unreachable.
    let filter_bytes = sc
        .input
        .get(filter_span)
        .ok_or_else(|| sc.err("canonical attribute map"))?;
    let filter_payload =
        core::str::from_utf8(filter_bytes).map_err(|_| sc.err("canonical attribute map"))?;
    let filter = SadBlock::new(Cow::Borrowed(filter_payload));
    sc.expect(",\"i\":")?;
    let recipient = Field::new("i", sc.string()?.value).decode::<Identifier>()?;
    sc.expect("}")?;
    Ok((message.value, schema, filter, recipient))
}

/// Strictly parse the grant payload `{m,i}` in wire order.
///
/// # Errors
///
/// [`DeserializeError::NonCanonical`] on any deviation; [`CodecError`] for
/// an undecodable identifier.
fn grant_payload<'a>(sc: &mut Scanner<'a>) -> Result<(&'a str, Identifier<'a>), CodecError> {
    use crate::codec::field::Field;

    sc.expect("{")?;
    sc.expect("\"m\":")?;
    let message = sc.string()?;
    sc.expect(",\"i\":")?;
    let recipient = Field::new("i", sc.string()?.value).decode::<Identifier>()?;
    sc.expect("}")?;
    Ok((message.value, recipient))
}

/// Strictly parse the offer/agree/admit/spurn payload `{m}`.
///
/// # Errors
///
/// [`DeserializeError::NonCanonical`] on any deviation.
fn message_only<'a>(sc: &mut Scanner<'a>) -> Result<&'a str, CodecError> {
    sc.expect("{\"m\":")?;
    let message = sc.string()?;
    sc.expect("}")?;
    Ok(message.value)
}

// ---------------------------------------------------------------------------
// Builders — keripy `vc/protocoling.py` factories with explicit `dt`
// ---------------------------------------------------------------------------

impl Exn<'_> {
    /// Build an `/ipex/apply` exn — keripy `ipexApplyExn`.
    ///
    /// # Errors
    ///
    /// [`CodecError`] when the envelope cannot be rendered or its SAID cannot
    /// be computed (canonical wire bytes in, so this is construction-tooling
    /// failure, not data).
    #[allow(
        clippy::too_many_arguments,
        reason = "mirrors the keripy `ipexApplyExn` factory parameter list"
    )]
    pub fn ipex_apply(
        issuer: &Identifier<'_>,
        dt: &str,
        message: &str,
        schema: &Said<'_>,
        attrs: &SadBlock<'_>,
        recipient: &Identifier<'_>,
    ) -> Result<Exn<'static>, CodecError> {
        let payload = render_payload(|buf| {
            buf.push(b'{');
            JsonWriter::write_str(buf, "m");
            buf.push(b':');
            JsonWriter::write_str(buf, message);
            buf.push(b',');
            JsonWriter::write_str(buf, "s");
            buf.push(b':');
            JsonWriter::write_str(buf, &schema.to_qb64());
            buf.push(b',');
            JsonWriter::write_str(buf, "a");
            buf.push(b':');
            buf.extend_from_slice(attrs.payload().as_bytes());
            buf.push(b',');
            JsonWriter::write_str(buf, "i");
            buf.push(b':');
            recipient.encode(buf);
            buf.push(b'}');
        })?;
        build_envelope(
            issuer,
            IpexRoute::Apply,
            dt,
            &payload,
            ExnEmbeds::Absent,
            None,
            None,
        )
    }

    /// Build an `/ipex/offer` exn — keripy `ipexOfferExn` (always renders `e`).
    ///
    /// # Errors
    ///
    /// [`CodecError`] when the embeds map SAID or the envelope SAID cannot be
    /// computed.
    pub fn ipex_offer(
        issuer: &Identifier<'_>,
        dt: &str,
        message: &str,
        acdc: &SadBlock<'_>,
        prior: Option<&Said<'_>>,
    ) -> Result<Exn<'static>, CodecError> {
        let payload = message_payload(message)?;
        let embeds = embeds_map(&[("acdc", acdc)])?;
        build_envelope(issuer, IpexRoute::Offer, dt, &payload, embeds, None, prior)
    }

    /// Build an `/ipex/agree` exn — keripy `ipexAgreeExn`.
    ///
    /// # Errors
    ///
    /// [`CodecError`] when the envelope SAID cannot be computed.
    pub fn ipex_agree(
        issuer: &Identifier<'_>,
        dt: &str,
        message: &str,
        prior: Option<&Said<'_>>,
    ) -> Result<Exn<'static>, CodecError> {
        let payload = message_payload(message)?;
        build_envelope(
            issuer,
            IpexRoute::Agree,
            dt,
            &payload,
            ExnEmbeds::Absent,
            None,
            prior,
        )
    }

    /// Build an `/ipex/grant` exn — keripy `ipexGrantExn` (always renders `e`).
    ///
    /// The `iss` embed is the credential's issuance TEL event and `anc` an
    /// anchoring KEL event, both as canonical bodies; `None` entries are
    /// omitted from the embeds map.
    ///
    /// # Errors
    ///
    /// [`CodecError`] when the embeds map SAID or the envelope SAID cannot be
    /// computed.
    #[allow(
        clippy::too_many_arguments,
        reason = "mirrors the keripy `ipexGrantExn` factory parameter list"
    )]
    pub fn ipex_grant(
        issuer: &Identifier<'_>,
        dt: &str,
        message: &str,
        recipient: &Identifier<'_>,
        acdc: &SadBlock<'_>,
        iss: Option<&SadBlock<'_>>,
        anc: Option<&SadBlock<'_>>,
        prior: Option<&Said<'_>>,
    ) -> Result<Exn<'static>, CodecError> {
        let payload = render_payload(|buf| {
            buf.push(b'{');
            JsonWriter::write_str(buf, "m");
            buf.push(b':');
            JsonWriter::write_str(buf, message);
            buf.push(b',');
            JsonWriter::write_str(buf, "i");
            buf.push(b':');
            recipient.encode(buf);
            buf.push(b'}');
        })?;
        let mut labels = vec![("acdc", acdc)];
        if let Some(iss_block) = iss {
            labels.push(("iss", iss_block));
        }
        if let Some(anc_block) = anc {
            labels.push(("anc", anc_block));
        }
        let embeds = embeds_map(&labels)?;
        build_envelope(issuer, IpexRoute::Grant, dt, &payload, embeds, None, prior)
    }

    /// Build an `/ipex/admit` exn — keripy `ipexAdmitExn`.
    ///
    /// # Errors
    ///
    /// [`CodecError`] when the envelope SAID cannot be computed.
    pub fn ipex_admit(
        issuer: &Identifier<'_>,
        dt: &str,
        message: &str,
        prior: Option<&Said<'_>>,
    ) -> Result<Exn<'static>, CodecError> {
        let payload = message_payload(message)?;
        build_envelope(
            issuer,
            IpexRoute::Admit,
            dt,
            &payload,
            ExnEmbeds::Absent,
            None,
            prior,
        )
    }

    /// Build an `/ipex/spurn` exn — keripy `ipexSpurnExn`.
    ///
    /// # Errors
    ///
    /// [`CodecError`] when the envelope SAID cannot be computed.
    pub fn ipex_spurn(
        issuer: &Identifier<'_>,
        dt: &str,
        message: &str,
        prior: Option<&Said<'_>>,
    ) -> Result<Exn<'static>, CodecError> {
        let payload = message_payload(message)?;
        build_envelope(
            issuer,
            IpexRoute::Spurn,
            dt,
            &payload,
            ExnEmbeds::Absent,
            None,
            prior,
        )
    }
}

/// Render a canonical payload map through one scratch buffer.
///
/// # Errors
///
/// [`CodecError`] if the rendered payload is not UTF-8 — unreachable for
/// canonical JSON (the writer emits only ASCII), reported as the internal
/// layout error it would be.
fn render_payload(write: impl FnOnce(&mut Vec<u8>)) -> Result<String, CodecError> {
    let mut buf = Vec::new();
    write(&mut buf);
    core::str::from_utf8(&buf)
        .map(str::to_owned)
        .map_err(|_| crate::InternalError::EventLayout("canonical payload is not UTF-8").into())
}

/// The `{m}` payload shared by offer, agree, admit, and spurn.
///
/// # Errors
///
/// [`CodecError`] if the rendered payload is not UTF-8 (unreachable).
fn message_payload(message: &str) -> Result<String, CodecError> {
    render_payload(|buf| {
        buf.push(b'{');
        JsonWriter::write_str(buf, "m");
        buf.push(b':');
        JsonWriter::write_str(buf, message);
        buf.push(b'}');
    })
}

/// Build the SAIDified embeds map for the labels, in wire order —
/// `{"<label>":<payload>...,"d":<SAID>}` via the shared generic
/// [`SadCodes::saidify`] path (the embeds map has no version string).
///
/// # Errors
///
/// [`CodecError`] when the map cannot be SAIDified.
fn embeds_map(entries: &[(&str, &SadBlock<'_>)]) -> Result<ExnEmbeds<'static>, CodecError> {
    let code = DigestCode::Blake3_256;
    let placeholder = code
        .placeholder()
        .map_err(|e| crate::InternalError::PlaceholderPrimitive { source: e.into() })?;

    let mut buf = Vec::new();
    buf.push(b'{');
    for (index, (label, block)) in entries.iter().enumerate() {
        if index > 0 {
            buf.push(b',');
        }
        JsonWriter::write_str(&mut buf, label);
        buf.push(b':');
        buf.extend_from_slice(block.payload().as_bytes());
    }
    buf.extend_from_slice(b",\"d\":");
    JsonWriter::write_str(&mut buf, &placeholder);
    buf.push(b'}');

    // The generic path: per-label configuration over the bare map.
    let config = crate::SadCodes::from_pairs(&[("d", code)]).map_err(|_| {
        crate::InternalError::EventLayout("static embeds map SAID configuration rejected")
    })?;
    let mut map = buf;
    let parsed = config.saidify(&mut map)?;
    let said_span = parsed
        .said("d")
        .ok_or_else(|| CodecError::from(DeserializeError::MissingField("d")))?;

    // Decode through the shared pipeline so the stored SAID is the typed
    // value, not a raw span.
    let map_said = crate::codec::field::Field::new("d", said_span).decode::<Said>()?;
    let typed_entries = entries
        .iter()
        .map(|(label, block)| {
            (
                Cow::Owned(label.to_string()),
                // The embeds map detaches from the caller's buffers.
                (*block).clone().into_static(),
            )
        })
        .collect();
    Ok(ExnEmbeds::Map {
        said: map_said.into_static(),
        entries: typed_entries,
    })
}

/// Assemble the envelope for one route: pinned `rp=""`/`q={}` (the six
/// factories' values), the caller's `dt` and prior, a placeholder outer
/// SAID (the real one is computed at [`crate::Serialize`] time, exactly as
/// for ACDC credentials).
///
/// # Errors
///
/// [`CodecError`] when a placeholder cannot be derived (construction
/// tooling failure).
#[allow(
    clippy::too_many_arguments,
    reason = "one argument per wire field plus the embeds value; private orchestration for the six factories"
)]
fn build_envelope(
    issuer: &Identifier<'_>,
    route: IpexRoute,
    dt: &str,
    payload: &str,
    embeds: ExnEmbeds<'static>,
    reply_to: Option<Identifier<'static>>,
    prior: Option<&Said<'_>>,
) -> Result<Exn<'static>, CodecError> {
    // The outer SAID is a placeholder at construction — its real value is
    // computed over the rendered body at `Serialize` time, which is why the
    // issuer must be final here: the digest covers the `i` field.
    let placeholder = DigestCode::Blake3_256
        .placeholder()
        .map_err(|e| crate::InternalError::PlaceholderPrimitive { source: e.into() })?;
    let said = crate::codec::field::Field::new("d", placeholder.as_str())
        .decode::<Said>()?
        .into_static();
    Ok(Exn::new(
        said,
        issuer.clone().into_static(),
        reply_to,
        prior.cloned().map(Said::into_static),
        Cow::Owned(dt.to_owned()),
        Cow::Owned(route.route().to_owned()),
        SadBlock::new(Cow::Owned("{}".to_owned())),
        ExnAttributes::Block(SadBlock::new(Cow::Owned(payload.to_owned()))),
        embeds,
    ))
}
