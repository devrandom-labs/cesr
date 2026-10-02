//! Pure selected V1 IPEX conversation and grant judgment.
//!
//! Accepted KEL/TEL/schema states and the prior conversation head are supplied
//! by the host. No lookup, persistence, transport or notification occurs here.

use alloc::string::String;

use keri_codec::{Deserialize, ExnMessage, IpexMessage, IpexRoute, JsonLimits, VerifiedSchema};
use keri_events::acdc::{Acdc, AcdcField};
use keri_events::{Identifier, KeriEvent, Said, Seal, TelEvent};

use crate::authority::Authority;
use crate::credential::{CredentialError, CredentialVerifier};
use crate::credential_wire::{
    ChainCredential, CredentialEvidence, CredentialVerificationError, CredentialVerificationLimits,
};
use crate::error::{Disposition, EvidenceKind, ExchangeError};
use crate::registry::{CredentialState, RegistryState};
use crate::state::KeyState;

/// Caller-selected JSON and credential-chain work limits.
#[derive(Debug, Clone, Copy)]
pub struct IpexLimits {
    /// EXN and embedded KEL/TEL JSON parser work budget.
    pub json: JsonLimits,
    /// Credential and chain work budget for a grant.
    pub credential: CredentialVerificationLimits,
}

/// Host-accepted facts used for one IPEX message. The exact EXN and embedded
/// ACDC bytes always come from [`ExnMessage`], never a separate host buffer.
pub struct IpexEvidence<'a, 'k> {
    /// Accepted historical KEL state whose keys signed the outer EXN.
    pub sender_state: Option<&'a KeyState<'k>>,
    /// SAID-verified schema for the offered or granted credential.
    pub schema: Option<&'a VerifiedSchema>,
    /// Accepted registry management state for a grant.
    pub registry: Option<&'a RegistryState>,
    /// Accepted per-credential TEL head for a grant.
    pub credential_state: Option<&'a CredentialState>,
    /// Accepted historical issuer KEL state for the pathed ACDC signature
    /// and the credential status decision.
    pub issuer_state: Option<&'a KeyState<'k>>,
    /// Accepted KEL state at the embedded grant anchor's coordinate.
    pub anchor_state: Option<&'a KeyState<'k>>,
    /// Host-resolved credential chain nodes.
    pub chain: &'a [ChainCredential<'a, 'k>],
}

impl<'a, 'k> IpexEvidence<'a, 'k> {
    /// Supply only the accepted historical EXN signer state for a response
    /// that carries no credential evidence (agree, admit or spurn).
    #[must_use]
    pub const fn sender(state: &'a KeyState<'k>) -> Self {
        Self {
            sender_state: Some(state),
            schema: None,
            registry: None,
            credential_state: None,
            issuer_state: None,
            anchor_state: None,
            chain: &[],
        }
    }
}

/// An authenticated, accepted linear IPEX conversation head. The host keys
/// it by `root` and commits it atomically with the message's replay marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpexConversation {
    root: Said<'static>,
    latest: Said<'static>,
    route: IpexRoute,
    applicant: Identifier<'static>,
    issuer: Identifier<'static>,
    schema: Said<'static>,
    offered_credential: Option<Said<'static>>,
    last_sender: Identifier<'static>,
}

impl IpexConversation {
    /// The opening apply SAID, used as the host's durable conversation key.
    #[must_use]
    pub const fn root(&self) -> &Said<'static> {
        &self.root
    }

    /// Last accepted EXN SAID, required as the next message's `p`.
    #[must_use]
    pub const fn latest(&self) -> &Said<'static> {
        &self.latest
    }

    /// Last accepted route.
    #[must_use]
    pub const fn route(&self) -> IpexRoute {
        self.route
    }

    /// Whether no further response can be accepted.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self.route, IpexRoute::Admit | IpexRoute::Spurn)
    }

    /// Start the selected two-party route with an authenticated `/ipex/apply`.
    /// Offer/grant without an apply do not bind both participants in this
    /// release profile, even though pinned keripy accepts direct starts.
    ///
    /// # Errors
    ///
    /// Missing signer state awaits KEL evidence. Wrong signatures, sender,
    /// route, prior or recipient are terminal.
    pub fn begin(
        msg: &ExnMessage<'_>,
        sender_state: Option<&KeyState<'_>>,
        limits: JsonLimits,
    ) -> Result<Self, IpexDecisionError> {
        let typed =
            IpexMessage::parse(msg.exn(), limits).map_err(|_| IpexDecisionError::MalformedRoute)?;
        let IpexMessage::Apply(apply) = typed else {
            return if msg.exn().prior().is_some() {
                Err(IpexDecisionError::MissingConversation)
            } else {
                Err(IpexDecisionError::UnsupportedStart)
            };
        };
        if msg.exn().prior().is_some() {
            return Err(IpexDecisionError::WrongPrior);
        }
        if !msg.pathed().is_empty() {
            return Err(IpexDecisionError::InvalidPathedProof);
        }
        authenticate(msg, sender_state)?;
        if msg.exn().issuer() == apply.recipient() {
            return Err(IpexDecisionError::WrongRecipient);
        }
        let said = msg.exn().said().ok_or(IpexDecisionError::MalformedRoute)?;
        Ok(Self {
            root: said.clone().into_static(),
            latest: said.clone().into_static(),
            route: IpexRoute::Apply,
            applicant: msg.exn().issuer().clone().into_static(),
            issuer: apply.recipient().clone().into_static(),
            schema: apply.schema().clone().into_static(),
            offered_credential: None,
            last_sender: msg.exn().issuer().clone().into_static(),
        })
    }

    /// Authenticate and accept the next response. Every check completes
    /// before mutation; a rejection leaves this head byte-for-byte intact.
    ///
    /// # Errors
    ///
    /// Missing accepted facts await retry; cross-bound, replayed, revoked,
    /// unsupported or malformed evidence is terminal.
    #[allow(
        clippy::too_many_lines,
        reason = "checks one authenticated conversation transition before its single state mutation"
    )]
    pub fn ingest_mut(
        &mut self,
        msg: &ExnMessage<'_>,
        evidence: &IpexEvidence<'_, '_>,
        limits: IpexLimits,
    ) -> Result<(), IpexDecisionError> {
        if self.is_terminal() {
            return Err(IpexDecisionError::Closed);
        }
        let said = msg.exn().said().ok_or(IpexDecisionError::MalformedRoute)?;
        if said == &self.latest {
            return Err(IpexDecisionError::Duplicate);
        }
        if msg.exn().prior() != Some(&self.latest) {
            return Err(IpexDecisionError::WrongPrior);
        }
        authenticate(msg, evidence.sender_state)?;
        let expected_sender = if self.last_sender == self.applicant {
            &self.issuer
        } else {
            &self.applicant
        };
        if msg.exn().issuer() != expected_sender {
            return Err(IpexDecisionError::WrongParticipant);
        }
        let typed = IpexMessage::parse(msg.exn(), limits.json)
            .map_err(|_| IpexDecisionError::MalformedRoute)?;
        let route = typed.route();
        if !allowed_response(self.route, route) {
            return Err(IpexDecisionError::InvalidTransition);
        }
        let offered = match typed {
            IpexMessage::Offer(offer) => {
                let raw = msg
                    .exn()
                    .embed("acdc")
                    .ok_or(IpexDecisionError::MalformedRoute)?
                    .payload();
                let schema = evidence.schema.ok_or(IpexDecisionError::MissingSchema)?;
                let credential = schema
                    .validate_credential(raw.as_bytes(), limits.json)
                    .map_err(|_| IpexDecisionError::InvalidCredential)?;
                bind_credential(&credential, &self.issuer, &self.applicant, &self.schema)?;
                if credential.said() != offer.acdc().said() {
                    return Err(IpexDecisionError::WrongCredential);
                }
                verify_pathed_acdc(msg, raw.as_bytes(), evidence.issuer_state, &self.issuer)?;
                Some(credential.said().clone().into_static())
            }
            IpexMessage::Grant(grant) => {
                if grant.recipient() != &self.applicant {
                    return Err(IpexDecisionError::WrongRecipient);
                }
                let raw = msg
                    .exn()
                    .embed("acdc")
                    .ok_or(IpexDecisionError::MalformedRoute)?
                    .payload();
                if Some(grant.acdc().said()) != self.offered_credential.as_ref() {
                    return Err(IpexDecisionError::WrongCredential);
                }
                verify_pathed_acdc(msg, raw.as_bytes(), evidence.issuer_state, &self.issuer)?;
                let credential = CredentialVerifier::verify(
                    &CredentialEvidence::from_host_accepted(
                        raw.as_bytes(),
                        evidence.schema,
                        evidence.registry,
                        evidence.credential_state,
                        evidence.issuer_state,
                    ),
                    evidence.chain,
                    limits.credential,
                )?;
                bind_credential(&credential, &self.issuer, &self.applicant, &self.schema)?;
                if credential.said() != grant.acdc().said() {
                    return Err(IpexDecisionError::WrongCredential);
                }
                bind_grant_anchor(
                    &grant,
                    &credential,
                    evidence.credential_state,
                    evidence.anchor_state,
                    limits.json,
                )?;
                None
            }
            IpexMessage::Agree(_) | IpexMessage::Admit(_) | IpexMessage::Spurn(_) => {
                if !msg.pathed().is_empty() {
                    return Err(IpexDecisionError::InvalidPathedProof);
                }
                None
            }
            IpexMessage::Apply(_) => return Err(IpexDecisionError::InvalidTransition),
        };
        self.latest = said.clone().into_static();
        self.route = route;
        self.last_sender = msg.exn().issuer().clone().into_static();
        if let Some(credential) = offered {
            self.offered_credential = Some(credential);
        }
        Ok(())
    }
}

/// A missing or contradicted IPEX acceptance fact.
#[derive(Debug, thiserror::Error)]
pub enum IpexDecisionError {
    /// No prior conversation head was supplied for a response.
    #[error("prior IPEX conversation state is missing")]
    MissingConversation,
    /// No accepted KEL state for the outer EXN sender.
    #[error("IPEX sender KEL state is missing")]
    MissingSenderState,
    /// No verified schema for the offered credential.
    #[error("IPEX credential schema is missing")]
    MissingSchema,
    /// No historical issuer KEL state for the pathed ACDC signature.
    #[error("IPEX ACDC proof issuer state is missing")]
    MissingProofIssuer,
    /// A pathed ACDC proof may still arrive with attachments.
    #[error("IPEX pathed ACDC proof is missing")]
    MissingPathedProof,
    /// No accepted KEL state at the grant anchor coordinate.
    #[error("IPEX grant anchor KEL state is missing")]
    MissingAnchorState,
    /// Credential/schema/TEL evidence for a grant failed.
    #[error(transparent)]
    Credential(#[from] CredentialVerificationError),
    /// The signed EXN sender did not authenticate.
    #[error(transparent)]
    Authentication(#[from] ExchangeError),
    /// The route or signed envelope is malformed.
    #[error("malformed IPEX route")]
    MalformedRoute,
    /// Direct offer/grant starts are outside the selected two-party profile.
    #[error("unsupported IPEX conversation start")]
    UnsupportedStart,
    /// Prior link names another accepted EXN.
    #[error("IPEX prior SAID does not match accepted head")]
    WrongPrior,
    /// Wrong sender for the current half of the two-party exchange.
    #[error("IPEX sender is not the expected participant")]
    WrongParticipant,
    /// The signed recipient is not the intended party.
    #[error("IPEX recipient does not match conversation")]
    WrongRecipient,
    /// The offered or granted body names another schema.
    #[error("IPEX credential schema does not match application")]
    WrongSchema,
    /// Credential body, SAID or issuer/issuee differs across messages.
    #[error("IPEX credential differs from conversation or participant")]
    WrongCredential,
    /// Supplied schema rejects the offered credential.
    #[error("offered credential does not fit supplied schema")]
    InvalidCredential,
    /// Pathed proof is malformed, extra, wrong-path or cryptographically invalid.
    #[error("invalid IPEX pathed ACDC proof")]
    InvalidPathedProof,
    /// Grant lacks its issuance and anchor body embeds.
    #[error("grant needs issuance TEL and KEL anchor embeds")]
    IncompleteGrant,
    /// Embedded TEL does not issue the embedded ACDC under its registry.
    #[error("grant issuance TEL does not bind embedded credential")]
    IssuanceMismatch,
    /// Embedded anchor is not the host-accepted issuer KEL anchor for TEL.
    #[error("grant KEL anchor does not bind embedded issuance TEL")]
    AnchorMismatch,
    /// The route cannot follow the accepted route.
    #[error("invalid IPEX route transition")]
    InvalidTransition,
    /// This EXN SAID was already accepted.
    #[error("duplicate IPEX response")]
    Duplicate,
    /// Admit or spurn closed this conversation.
    #[error("IPEX conversation is closed")]
    Closed,
}

impl IpexDecisionError {
    /// Missing host fact versus terminal contradiction.
    #[must_use]
    pub const fn disposition(&self) -> Disposition {
        match self {
            Self::MissingConversation => Disposition::Awaiting(EvidenceKind::IpexPrior),
            Self::MissingSenderState => Disposition::Awaiting(EvidenceKind::IpexSenderState),
            Self::MissingSchema => Disposition::Awaiting(EvidenceKind::CredentialSchema),
            Self::MissingProofIssuer => Disposition::Awaiting(EvidenceKind::IssuerState),
            Self::MissingPathedProof => Disposition::Awaiting(EvidenceKind::IpexPathedProof),
            Self::MissingAnchorState => Disposition::Awaiting(EvidenceKind::IpexAnchorState),
            Self::Credential(error) => error.disposition(),
            Self::Authentication(ExchangeError::Signatures(rejection)) => rejection.disposition(),
            Self::Authentication(ExchangeError::SenderMismatch)
            | Self::MalformedRoute
            | Self::UnsupportedStart
            | Self::WrongPrior
            | Self::WrongParticipant
            | Self::WrongRecipient
            | Self::WrongSchema
            | Self::WrongCredential
            | Self::InvalidCredential
            | Self::InvalidPathedProof
            | Self::IncompleteGrant
            | Self::IssuanceMismatch
            | Self::AnchorMismatch
            | Self::InvalidTransition
            | Self::Duplicate
            | Self::Closed => Disposition::Terminal,
        }
    }
}

fn authenticate(
    msg: &ExnMessage<'_>,
    state: Option<&KeyState<'_>>,
) -> Result<(), IpexDecisionError> {
    let accepted = state.ok_or(IpexDecisionError::MissingSenderState)?;
    accepted.verify_exn(msg)?;
    Ok(())
}

const fn allowed_response(prior: IpexRoute, next: IpexRoute) -> bool {
    matches!(
        (prior, next),
        (IpexRoute::Apply, IpexRoute::Offer | IpexRoute::Spurn)
            | (IpexRoute::Offer, IpexRoute::Agree | IpexRoute::Spurn)
            | (IpexRoute::Agree, IpexRoute::Grant | IpexRoute::Spurn)
            | (IpexRoute::Grant, IpexRoute::Admit | IpexRoute::Spurn)
    )
}

fn bind_credential(
    credential: &Acdc<'_>,
    issuer: &Identifier<'_>,
    applicant: &Identifier<'_>,
    schema: &Said<'_>,
) -> Result<(), IpexDecisionError> {
    if credential.issuer() != issuer {
        return Err(IpexDecisionError::WrongCredential);
    }
    if !matches!(credential.schema(), AcdcField::Said(said) if said == schema) {
        return Err(IpexDecisionError::WrongSchema);
    }
    let Some(AcdcField::Block(attributes)) = credential.attributes() else {
        return Err(IpexDecisionError::WrongCredential);
    };
    let attrs: serde_json::Value = serde_json::from_str(attributes.payload())
        .map_err(|_| IpexDecisionError::WrongCredential)?;
    if attrs.get("i").and_then(serde_json::Value::as_str)
        != Some(identifier_qb64(applicant).as_str())
    {
        return Err(IpexDecisionError::WrongCredential);
    }
    Ok(())
}

fn verify_pathed_acdc(
    msg: &ExnMessage<'_>,
    acdc_raw: &[u8],
    issuer_state: Option<&KeyState<'_>>,
    expected_issuer: &Identifier<'_>,
) -> Result<(), IpexDecisionError> {
    let state = issuer_state.ok_or(IpexDecisionError::MissingProofIssuer)?;
    if state.prefix() != expected_issuer {
        return Err(IpexDecisionError::InvalidPathedProof);
    }
    let [path] = msg.pathed() else {
        return if msg.pathed().is_empty() {
            Err(IpexDecisionError::MissingPathedProof)
        } else {
            Err(IpexDecisionError::InvalidPathedProof)
        };
    };
    if path.path_qb64() != "4AACA-e-acdc" {
        return Err(IpexDecisionError::InvalidPathedProof);
    }
    let signatures = path
        .controller_signatures()
        .map_err(|_| IpexDecisionError::InvalidPathedProof)?;
    Authority::new(state.keys(), state.threshold())
        .verify(acdc_raw, &signatures)
        .map_err(|_| IpexDecisionError::InvalidPathedProof)?;
    Ok(())
}

fn bind_grant_anchor(
    grant: &keri_codec::IpexGrant<'_>,
    credential: &Acdc<'_>,
    accepted_tel: Option<&CredentialState>,
    accepted_anchor: Option<&KeyState<'_>>,
    limits: JsonLimits,
) -> Result<(), IpexDecisionError> {
    let issue = grant.iss().ok_or(IpexDecisionError::IncompleteGrant)?;
    let Some(AcdcField::Said(registry)) = credential.registry() else {
        return Err(IpexDecisionError::IssuanceMismatch);
    };
    let (issued, governed) = match issue {
        TelEvent::Issue(event) => (event.credential_said(), event.registry_said()),
        TelEvent::BackedIssue(event) => (event.credential_said(), event.registry_said()),
        _ => return Err(IpexDecisionError::IssuanceMismatch),
    };
    if issued != credential.said() || governed != registry {
        return Err(IpexDecisionError::IssuanceMismatch);
    }
    let tel_state = accepted_tel.ok_or(IpexDecisionError::Credential(
        CredentialVerificationError::Status(CredentialError::MissingCredentialState),
    ))?;
    let tel_head_matches = issue.said() == tel_state.head();
    let tel_sn_matches = issue.sn() == tel_state.sn();
    if !(tel_head_matches && tel_sn_matches) {
        return Err(IpexDecisionError::IssuanceMismatch);
    }
    let anchor_raw = grant.anc().ok_or(IpexDecisionError::IncompleteGrant)?;
    let anchor = KeriEvent::deserialize(anchor_raw.payload().as_bytes(), limits)
        .map_err(|_| IpexDecisionError::AnchorMismatch)?;
    let accepted = accepted_anchor.ok_or(IpexDecisionError::MissingAnchorState)?;
    let anchor_is_issuer = anchor.prefix() == credential.issuer();
    let anchor_is_accepted = anchor.prefix() == accepted.prefix();
    let coordinate_matches = anchor.sn() == accepted.sn();
    let digest_matches = anchor.said() == accepted.latest_said();
    if !(anchor_is_issuer && anchor_is_accepted && coordinate_matches && digest_matches) {
        return Err(IpexDecisionError::AnchorMismatch);
    }
    let [Seal::Event { i, s, d }] = anchor.anchors() else {
        return Err(IpexDecisionError::AnchorMismatch);
    };
    if i != &Identifier::SelfAddressing(credential.said().clone())
        || *s != issue.sn()
        || d != issue.said()
    {
        return Err(IpexDecisionError::AnchorMismatch);
    }
    Ok(())
}

fn identifier_qb64(identifier: &Identifier<'_>) -> String {
    match identifier {
        Identifier::Basic(prefix) => prefix.to_qb64(),
        Identifier::SelfAddressing(said) => said.to_qb64(),
    }
}
