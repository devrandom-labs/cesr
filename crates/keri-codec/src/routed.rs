//! Strict V1 routed query and reply bodies. These values are SAID-verified
//! wire data; authorization is a separate protocol decision.

use alloc::{boxed::Box, format, vec::Vec};
use core::str;

use cesr::core::matter::code::{CesrCode, DigestCode};
use cesr::core::version::VersionString;
use keri_events::acdc::SadBlock;
use keri_events::{
    BasicPrefix, ConfigTrait, Digest, Identifier, MessageType, Said, SigningThreshold, Toad,
    VerifyingKey,
};

use crate::codec::Decode;
use crate::codec::event::ParsedEvent;
use crate::codec::field::Field;
use crate::codec::scanner::Scanner;
use crate::codec::threshold::{ParsedCount, ParsedTholder};
use crate::error::{CodecError, InternalError, VersionGrammarError};
use crate::said::infer_digest_code;
use crate::{JsonLimits, SadCodes};

/// The exact V1 `qry` or `rpy` body with a verified self-addressing digest.
///
/// The sender is intentionally absent from this V1 body; it comes from the
/// authenticator attachment and its historical establishment evidence.
#[derive(Debug)]
pub struct RoutedBody<'a> {
    kind: MessageType,
    said: Said<'a>,
    datetime: &'a str,
    route: &'a str,
    reply_route: Option<&'a str>,
    payload: SadBlock<'a>,
    payload_text: &'a str,
}

/// Selected V1 reply payloads after route and subject fields have been
/// decoded. Signature and accepted-state checks still belong to the core.
#[derive(Debug)]
pub enum DiscoveryClaim<'a> {
    /// Add or cut an endpoint role for a controller identifier.
    EndpointRole {
        /// True for `/end/role/add`, false for `/end/role/cut`.
        add: bool,
        /// Controller whose authority must sign this claim.
        controller: Identifier<'a>,
        /// Named endpoint identifier.
        endpoint: Identifier<'a>,
        /// Endpoint role text.
        role: &'a str,
    },
    /// Endpoint location under a transport scheme.
    Location {
        /// Endpoint whose authority must sign this location.
        endpoint: Identifier<'a>,
        /// Transport scheme text.
        scheme: &'a str,
        /// Location URL text.
        url: &'a str,
    },
    /// Key-state notice for a specific accepted KEL coordinate.
    KeyState {
        /// Complete typed state projection carried by the notice.
        notice: Box<KeyStateNotice<'a>>,
    },
    /// An OOBI discovery hint; an unsigned hint never establishes trust.
    OobiHint {
        /// Controller named by the hint.
        controller: Identifier<'a>,
    },
}

impl DiscoveryClaim<'_> {
    /// The identifier whose historical authority must sign an in-band reply.
    #[must_use]
    pub const fn owner(&self) -> &Identifier<'_> {
        match self {
            Self::EndpointRole { controller, .. } | Self::OobiHint { controller } => controller,
            Self::Location { endpoint, .. } => endpoint,
            Self::KeyState { notice } => &notice.subject,
        }
    }
}

/// Accepted-state fields asserted by a V1 `/ksn/{aid}` reply. Every field
/// checked here is bound by the reply SAID and signer attachment.
#[derive(Debug)]
pub struct KeyStateNotice<'a> {
    /// Noticed AID.
    pub subject: Identifier<'a>,
    /// Latest KEL sequence.
    pub sn: u128,
    /// Latest KEL event SAID.
    pub said: Said<'a>,
    /// Latest event ilk.
    pub event_type: MessageType,
    /// Current signing threshold.
    pub threshold: SigningThreshold,
    /// Current controller keys.
    pub keys: Vec<VerifyingKey<'a>>,
    /// Next signing threshold.
    pub next_threshold: SigningThreshold,
    /// Next-key commitments.
    pub next_keys: Vec<Digest<'a>>,
    /// Witness threshold.
    pub witness_threshold: Toad,
    /// Current witnesses.
    pub witnesses: Vec<BasicPrefix<'a>>,
    /// Configuration traits.
    pub config: Vec<ConfigTrait>,
    /// Latest establishment sequence.
    pub last_est_sn: u128,
    /// Latest establishment SAID.
    pub last_est_said: Said<'a>,
    /// Delegator, when this state is delegated.
    pub delegator: Option<Identifier<'a>>,
}

/// Selected V1 `/logs` query selector.
#[derive(Debug)]
pub struct LogsQuery<'a> {
    /// KEL identifier to retrieve.
    pub target: Identifier<'a>,
    /// First requested KEL sequence.
    pub from_sn: u128,
    /// Route requested for the answer.
    pub reply_route: &'a str,
}

impl<'a> KeyStateNotice<'a> {
    #[allow(
        clippy::too_many_lines,
        reason = "the fixed V1 KSN field order is checked in one scanner pass"
    )]
    fn parse(payload: &'a str) -> Result<Self, CodecError> {
        let mut sc = Scanner::new(payload.as_bytes());
        sc.expect("{\"vn\":")?;
        let version = sc.value_span()?;
        if payload.as_bytes().get(version) != Some(b"[1,0]".as_slice()) {
            return Err(sc.err("V1 key-state notice version").into());
        }
        sc.expect(",\"i\":")?;
        let subject = Field::new("i", sc.string()?.value).decode::<Identifier>()?;
        sc.expect(",\"s\":")?;
        let sn = Field::new("s", sc.string()?.value)
            .decode::<cesr::core::primitives::Number>()?
            .value();
        sc.expect(",\"p\":")?;
        sc.string()?;
        sc.expect(",\"d\":")?;
        let said = Field::new("d", sc.string()?.value).decode::<Said>()?;
        sc.expect(",\"f\":")?;
        sc.string()?;
        sc.expect(",\"dt\":")?;
        sc.string()?;
        sc.expect(",\"et\":")?;
        let event_type =
            MessageType::from_code(sc.string()?.value).map_err(|_| sc.err("key event type"))?;
        if !matches!(
            event_type,
            MessageType::Icp
                | MessageType::Rot
                | MessageType::Ixn
                | MessageType::Dip
                | MessageType::Drt
        ) {
            return Err(sc.err("KEL event type").into());
        }
        sc.expect(",\"kt\":")?;
        let parsed_threshold = ParsedTholder::decode(&mut sc)?;
        let threshold = Field::new("kt", &parsed_threshold).decode::<SigningThreshold>()?;
        sc.expect(",\"k\":")?;
        let key_fields = sc.string_array()?;
        let keys = Field::each("k", &key_fields).decode::<Vec<VerifyingKey>>()?;
        sc.expect(",\"nt\":")?;
        let parsed_next_threshold = ParsedTholder::decode(&mut sc)?;
        let next_threshold =
            Field::new("nt", &parsed_next_threshold).decode::<SigningThreshold>()?;
        sc.expect(",\"n\":")?;
        let next_fields = sc.string_array()?;
        let next_keys = Field::each("n", &next_fields).decode::<Vec<Digest>>()?;
        sc.expect(",\"bt\":")?;
        let parsed_witness_threshold = ParsedCount::decode(&mut sc)?;
        let witness_count = Field::new("bt", &parsed_witness_threshold).decode::<u32>()?;
        sc.expect(",\"b\":")?;
        let witness_fields = sc.string_array()?;
        let witnesses = Field::each("b", &witness_fields).decode::<Vec<BasicPrefix>>()?;
        let witness_threshold = Toad::exact(witness_count, witnesses.len())
            .map_err(|_| sc.err("valid key-state witness threshold"))?;
        sc.expect(",\"c\":")?;
        let config_fields = sc.string_array()?;
        let config = Field::each("c", &config_fields).decode::<Vec<ConfigTrait>>()?;
        sc.expect(",\"ee\":{\"s\":")?;
        let last_est_sn = Field::new("ee.s", sc.string()?.value)
            .decode::<cesr::core::primitives::Number>()?
            .value();
        sc.expect(",\"d\":")?;
        let last_est_said = Field::new("ee.d", sc.string()?.value).decode::<Said>()?;
        sc.expect(",\"br\":")?;
        sc.string_array()?;
        sc.expect(",\"ba\":")?;
        sc.string_array()?;
        sc.expect("},\"di\":")?;
        let delegator = match sc.string()?.value {
            "" => None,
            value => Some(Field::new("di", value).decode::<Identifier>()?),
        };
        sc.expect("}")?;
        sc.finish()?;
        Ok(Self {
            subject,
            sn,
            said,
            event_type,
            threshold,
            keys,
            next_threshold,
            next_keys,
            witness_threshold,
            witnesses,
            config,
            last_est_sn,
            last_est_said,
            delegator,
        })
    }
}

impl<'a> RoutedBody<'a> {
    /// Parse one canonical V1 KERI JSON query or reply and verify its SAID.
    ///
    /// # Errors
    ///
    /// Rejects an invalid version, field order, payload grammar, primitive,
    /// digest, or work limit with a typed codec error.
    pub fn parse(raw: &'a [u8], limits: JsonLimits) -> Result<Self, CodecError> {
        VersionGrammarError::check_json_body(raw)?;
        let (mut sc, tag) = ParsedEvent::head(raw, limits)?;
        let kind = match tag.value {
            "qry" => MessageType::Qry,
            "rpy" => MessageType::Rpy,
            _ => return Err(sc.err("qry or rpy message type").into()),
        };
        sc.expect(",\"d\":")?;
        let said = sc.string()?.value;
        sc.expect(",\"dt\":")?;
        let datetime = sc.string()?.value;
        sc.expect(",\"r\":")?;
        let route = sc.string()?.value;
        let reply_route = if kind == MessageType::Qry {
            sc.expect(",\"rr\":")?;
            Some(sc.string()?.value)
        } else {
            None
        };
        if kind == MessageType::Qry {
            sc.expect(",\"q\":")?;
        } else {
            sc.expect(",\"a\":")?;
        }
        let span = sc.object_value_span()?;
        sc.expect("}")?;
        sc.finish()?;
        let payload = str::from_utf8(raw.get(span).ok_or(InternalError::EventLayout(
            "routed payload span out of bounds",
        ))?)
        .map_err(|_| InternalError::EventLayout("routed payload is not UTF-8"))?;
        let code = infer_digest_code(said)?;
        let codes = SadCodes::from_pairs(&[("d", code)])
            .map_err(|_| InternalError::EventLayout("routed SAID configuration rejected"))?;
        codes.verify(raw)?;
        Ok(Self {
            kind,
            said: Field::new("d", said).decode::<Said>()?,
            datetime,
            route,
            reply_route,
            payload: SadBlock::new_unchecked(alloc::borrow::Cow::Borrowed(payload)),
            payload_text: payload,
        })
    }

    /// Render a new V1 query with its fixed field order and computed SAID.
    /// `payload` must be a canonical JSON object containing route selectors.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical input fields or invalid JSON through the same
    /// strict parser used for incoming messages.
    pub fn write_query(
        datetime: &str,
        route: &str,
        reply_route: &str,
        payload: &str,
        limits: JsonLimits,
    ) -> Result<Vec<u8>, CodecError> {
        Self::write(
            (MessageType::Qry, Some(reply_route)),
            datetime,
            route,
            payload,
            limits,
        )
    }

    /// Render a new V1 reply with its fixed field order and computed SAID.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical input fields or invalid JSON through the same
    /// strict parser used for incoming messages.
    pub fn write_reply(
        datetime: &str,
        route: &str,
        payload: &str,
        limits: JsonLimits,
    ) -> Result<Vec<u8>, CodecError> {
        Self::write((MessageType::Rpy, None), datetime, route, payload, limits)
    }

    fn write(
        shape: (MessageType, Option<&str>),
        datetime: &str,
        route: &str,
        payload: &str,
        limits: JsonLimits,
    ) -> Result<Vec<u8>, CodecError> {
        let code = DigestCode::Blake3_256;
        let slot = code
            .placeholder()
            .map_err(|e| InternalError::PlaceholderPrimitive { source: e.into() })?;
        let suffix = shape.1.map_or_else(
            || format!(",\"a\":{payload}"),
            |rr| format!(",\"rr\":\"{rr}\",\"q\":{payload}"),
        );
        let mut raw = format!(
            "{{\"v\":\"{}\",\"t\":\"{}\",\"d\":\"{}\",\"dt\":\"{datetime}\",\"r\":\"{route}\"{suffix}}}",
            VersionString::keri_json_v1().to_str(), shape.0.code(), slot
        )
        .into_bytes();
        let codes = SadCodes::from_pairs(&[("d", code)])
            .map_err(|_| InternalError::EventLayout("routed SAID configuration rejected"))?;
        codes.saidify(&mut raw)?;
        RoutedBody::<'_>::parse(&raw, limits)?;
        Ok(raw)
    }

    /// Query or reply wire tag.
    #[must_use]
    pub const fn kind(&self) -> MessageType {
        self.kind
    }

    /// Verified body SAID.
    #[must_use]
    pub const fn said(&self) -> &Said<'a> {
        &self.said
    }

    /// Timestamp text covered by the SAID.
    #[must_use]
    pub const fn datetime(&self) -> &'a str {
        self.datetime
    }

    /// Route path covered by the SAID.
    #[must_use]
    pub const fn route(&self) -> &'a str {
        self.route
    }

    /// Query reply-route path; absent on replies.
    #[must_use]
    pub const fn reply_route(&self) -> Option<&'a str> {
        self.reply_route
    }

    /// Canonical `q` query selectors or `a` reply attributes.
    #[must_use]
    pub const fn payload(&self) -> &SadBlock<'a> {
        &self.payload
    }

    /// Decode the selected discovery reply route and its authorizing owner.
    /// Unknown routes return `None` for the host to route elsewhere.
    ///
    /// # Errors
    ///
    /// Rejects a known route with malformed or inconsistent selector fields.
    pub fn discovery_claim(&self) -> Result<Option<DiscoveryClaim<'a>>, CodecError> {
        if self.kind != MessageType::Rpy {
            return Ok(None);
        }
        let payload = self.payload_text.as_bytes();
        let field = |name| payload_string_field(payload, name);
        let claim = match self.route {
            "/end/role/add" | "/end/role/cut" => {
                let controller = decode_identifier(field("cid")?, "cid")?;
                let endpoint = decode_identifier(field("eid")?, "eid")?;
                let role = field("role")?;
                if role.is_empty() {
                    return Err(Scanner::new(payload).err("nonempty endpoint role").into());
                }
                DiscoveryClaim::EndpointRole {
                    add: self.route == "/end/role/add",
                    controller,
                    endpoint,
                    role,
                }
            }
            "/loc/scheme" => {
                let endpoint = decode_identifier(field("eid")?, "eid")?;
                let scheme = field("scheme")?;
                let url = field("url")?;
                if scheme.is_empty() || url.is_empty() {
                    return Err(Scanner::new(payload)
                        .err("nonempty location scheme and URL")
                        .into());
                }
                DiscoveryClaim::Location {
                    endpoint,
                    scheme,
                    url,
                }
            }
            "/oobi/witness" => DiscoveryClaim::OobiHint {
                controller: decode_identifier(field("cid")?, "cid")?,
            },
            route if route.starts_with("/ksn/") => {
                let subject =
                    decode_identifier(route.strip_prefix("/ksn/").unwrap_or_default(), "r")?;
                let notice = KeyStateNotice::parse(self.payload_text)?;
                if notice.subject != subject {
                    return Err(Scanner::new(payload)
                        .err("key-state route matches payload i")
                        .into());
                }
                DiscoveryClaim::KeyState {
                    notice: Box::new(notice),
                }
            }
            _ => return Ok(None),
        };
        Ok(Some(claim))
    }

    /// Decode the selected V1 `/logs` query selector. Other query routes
    /// return `None` for a different protocol lane.
    ///
    /// # Errors
    ///
    /// Rejects a malformed target AID or sequence selector.
    pub fn logs_query(&self) -> Result<Option<LogsQuery<'a>>, CodecError> {
        if self.kind != MessageType::Qry || self.route != "/logs" {
            return Ok(None);
        }
        let payload = self.payload_text.as_bytes();
        let target = decode_identifier(payload_string_field(payload, "i")?, "i")?;
        let from_sn = Field::new("s", payload_string_field(payload, "s")?)
            .decode::<cesr::core::primitives::Number>()?
            .value();
        let reply_route = self
            .reply_route
            .ok_or_else(|| Scanner::new(payload).err("reply route"))?;
        if reply_route.is_empty() {
            return Err(Scanner::new(payload).err("nonempty reply route").into());
        }
        Ok(Some(LogsQuery {
            target,
            from_sn,
            reply_route,
        }))
    }
}

fn decode_identifier<'a>(
    value: &'a str,
    field: &'static str,
) -> Result<Identifier<'a>, CodecError> {
    Field::new(field, value)
        .decode::<Identifier>()
        .map_err(Into::into)
}

/// Find a string field in an already-validated canonical object, skipping
/// unrelated values with the same iterative scanner used by the body parser.
fn payload_string_field<'a>(payload: &'a [u8], name: &'static str) -> Result<&'a str, CodecError> {
    let mut sc = Scanner::new(payload);
    sc.expect("{")?;
    if sc.take_lit("}")? {
        return Err(sc.err("required discovery field").into());
    }
    loop {
        let key = sc.string()?.value;
        sc.expect(":")?;
        if key == name {
            return Ok(sc.string()?.value);
        }
        sc.value_span()?;
        if sc.take_lit("}")? {
            return Err(sc.err("required discovery field").into());
        }
        sc.expect(",")?;
    }
}
