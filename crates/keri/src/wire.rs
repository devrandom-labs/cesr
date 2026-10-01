//! Optional wire-edge adapter (feature `wire`): a parsed
//! [`keri_codec::EventMessage`] converts straight into [`Signed`].
//!
//! The #128 sans-io boundary holds: the default crate takes parsed borrowed
//! values and exact bytes to verify, but does not parse wire format. This
//! adapter is the opt-in edge — exactly
//! like the optional async edge decided in #128 — and it closes the
//! `signed_bytes`-provenance honor system: `EventMessage` carries, by
//! construction, the exact span its signatures sign. The same edge serves
//! receipts: a [`keri_codec::TransferableReceipt`] converts into the K5
//! [`TransferableEndorsement`] judgment input.

use alloc::borrow::Cow;
use keri_codec::{
    DiscoveryClaim, EventMessage, ExnMessage, KeyStateNotice, RoutedMessage, TelMessage,
    TransferableReceipt,
};

use crate::authority::{Authority, Verified};
use crate::discovery::{
    DiscoveryError, DiscoveryReply, DiscoverySigner, DiscoveryVerdict, ReplyVersion,
};
use crate::error::ExchangeError;
use crate::receipt::TransferableEndorsement;
use crate::state::{KeyState, Signed};
use keri_events::Identifier;

impl<'e> From<&'e EventMessage<'e>> for Signed<'e> {
    fn from(msg: &'e EventMessage<'e>) -> Self {
        Self {
            event: msg.event(),
            body: msg.body(),
            sigs: Cow::Borrowed(msg.sigs()),
            wigs: Cow::Borrowed(msg.wigs()),
        }
    }
}

impl<'e> From<&'e TelMessage<'e>> for crate::registry::SignedTel<'e> {
    /// Lift a parsed, framed TEL message into the registry fold's
    /// signed-event carrier — the same conversion [`EventMessage`] gets for
    /// the key-event fold: the carrier preserves, by construction, the exact
    /// span its signatures sign.
    fn from(msg: &'e TelMessage<'e>) -> Self {
        Self {
            event: msg.event(),
            signed_bytes: msg.body(),
            sigs: Cow::Borrowed(msg.sigs()),
            source: msg.source().map(|source| {
                crate::registry::TelAnchorCoordinate::new(source.sn(), source.said().clone())
            }),
            backer_sigs: Cow::Borrowed(msg.backer_sigs()),
            accepted_anchor: None,
        }
    }
}

impl KeyState<'_> {
    /// Verify a signed exchange envelope against this key state — the exn
    /// ingest path's one judgment: the envelope's declared sender must be
    /// this key state's identifier, then the signatures verify over the
    /// exact signed body through the shared
    /// [`Authority::verify`](crate::Authority::verify) path. On success the
    /// returned [`Verified`] borrows the envelope's signature span, the same
    /// shape [`Signed`] verification returns.
    ///
    /// # Errors
    ///
    /// [`ExchangeError::SenderMismatch`] when the envelope's issuer is not
    /// this key state's prefix; [`ExchangeError::Signatures`] when the
    /// shared authority path rejects the signatures.
    pub fn verify_exn<'m>(&self, msg: &'m ExnMessage<'_>) -> Result<Verified<'m>, ExchangeError> {
        if self.prefix() != msg.exn().issuer() {
            return Err(ExchangeError::SenderMismatch);
        }
        Authority::new(self.keys(), self.threshold())
            .verify(msg.body(), msg.sigs())
            .map_err(ExchangeError::from)
    }
}

impl<'e> From<&'e TransferableReceipt<'e>> for TransferableEndorsement<'e> {
    fn from(receipt: &'e TransferableReceipt<'e>) -> Self {
        Self {
            receiptor: receipt.receiptor(),
            sn: receipt.sn(),
            said: receipt.said(),
            sigs: receipt.signatures(),
        }
    }
}

/// Optional wire-edge judgments for selected V1 discovery messages.
pub struct DiscoveryJudge;

impl DiscoveryJudge {
    /// Judge one parsed V1 discovery reply using host-supplied accepted KEL
    /// evidence and the prior durable reply version. OOBI replies remain hints.
    ///
    /// # Errors
    ///
    /// A missing historical KEL or subject state is awaiting evidence; malformed
    /// routes, signer mismatches, invalid signatures and replay are terminal.
    pub fn reply(
        msg: &RoutedMessage<'_>,
        historical_signer: Option<&KeyState<'_>>,
        accepted_subject: Option<&KeyState<'_>>,
        previous: Option<ReplyVersion>,
    ) -> Result<DiscoveryVerdict, DiscoveryError> {
        let claim = msg
            .routed()
            .discovery_claim()
            .map_err(|_| DiscoveryError::MalformedRoute)?
            .ok_or(DiscoveryError::UnsupportedRoute)?;
        if matches!(claim, DiscoveryClaim::OobiHint { .. }) {
            return Ok(DiscoveryVerdict::UntrustedHint);
        }
        let signer = match (msg.nontransferable_signers(), msg.transferable_signers()) {
            ([couple], []) => DiscoverySigner::Nontransferable {
                prefix: couple.receiptor(),
                signature: couple.signature(),
            },
            ([], [group]) => DiscoverySigner::Transferable {
                identifier: group.receiptor(),
                sn: group.sn(),
                said: group.said(),
                signatures: group.signatures(),
            },
            ([], []) => return Err(DiscoveryError::MissingSigner),
            _ => return Err(DiscoveryError::AmbiguousSigner),
        };
        let reply = DiscoveryReply {
            owner: claim.owner(),
            body: msg.body(),
            datetime: msg.routed().datetime(),
            signer,
        };
        let version = reply.judge(historical_signer, previous)?;
        if let DiscoveryClaim::KeyState { notice } = claim {
            let state = accepted_subject.ok_or(DiscoveryError::MissingSubjectState)?;
            if !notice_matches_state(&notice, state) {
                return Err(DiscoveryError::SubjectStateMismatch);
            }
        }
        Ok(DiscoveryVerdict::Authenticated(version))
    }
}

/// Authenticated requester and selected KEL query target. Network response
/// generation and any query cache remain host responsibilities.
#[derive(Debug)]
pub struct AuthenticatedLogsQuery {
    /// AID that signed the V1 query.
    pub requester: Identifier<'static>,
    /// AID whose KEL was requested.
    pub target: Identifier<'static>,
    /// First requested KEL sequence.
    pub from_sn: u128,
}

impl DiscoveryJudge {
    /// Verify the selected V1 `/logs` query against its attached signer and
    /// historical establishment state, then expose its target selectors.
    ///
    /// # Errors
    ///
    /// A missing historical signer state is awaiting; an unsupported route,
    /// inconsistent signer seal or invalid signature is terminal.
    pub fn query(
        msg: &RoutedMessage<'_>,
        historical_signer: Option<&KeyState<'_>>,
    ) -> Result<AuthenticatedLogsQuery, DiscoveryError> {
        let query = msg
            .routed()
            .logs_query()
            .map_err(|_| DiscoveryError::MalformedRoute)?
            .ok_or(DiscoveryError::UnsupportedRoute)?;
        let (requester, signer) = match (msg.nontransferable_signers(), msg.transferable_signers())
        {
            ([couple], []) => (
                Identifier::Basic(couple.receiptor().clone()),
                DiscoverySigner::Nontransferable {
                    prefix: couple.receiptor(),
                    signature: couple.signature(),
                },
            ),
            ([], [group]) => (
                group.receiptor().clone(),
                DiscoverySigner::Transferable {
                    identifier: group.receiptor(),
                    sn: group.sn(),
                    said: group.said(),
                    signatures: group.signatures(),
                },
            ),
            ([], []) => return Err(DiscoveryError::MissingSigner),
            _ => return Err(DiscoveryError::AmbiguousSigner),
        };
        DiscoveryReply {
            owner: &requester,
            body: msg.body(),
            datetime: msg.routed().datetime(),
            signer,
        }
        .judge(historical_signer, None)?;
        Ok(AuthenticatedLogsQuery {
            requester: requester.into_static(),
            target: query.target.into_static(),
            from_sn: query.from_sn,
        })
    }
}

fn notice_matches_state(notice: &KeyStateNotice<'_>, state: &KeyState<'_>) -> bool {
    state.prefix() == &notice.subject
        && state.sn().value() == notice.sn
        && state.latest_said() == &notice.said
        && state.latest_message_type() == notice.event_type
        && state.threshold() == &notice.threshold
        && state.keys() == notice.keys
        && state.next_threshold() == &notice.next_threshold
        && state.next_keys() == notice.next_keys
        && state.witness_threshold() == notice.witness_threshold
        && state.witnesses() == notice.witnesses
        && state.config() == notice.config
        && state.last_establishment().sn.value() == notice.last_est_sn
        && state.last_establishment().said == &notice.last_est_said
        && state.delegator() == notice.delegator.as_ref()
}

#[cfg(test)]
mod discovery_tests {
    use super::*;
    use alloc::boxed::Box;
    use keri_codec::{Deserialize, JsonLimits};
    use keri_events::KeriEvent;

    const CORPUS: &str = include_str!("../../keri-codec/tests/corpus/discovery/v1.jsonl");

    #[test]
    fn ksn_projection_detects_false_keys_and_establishment()
    -> Result<(), Box<dyn core::error::Error>> {
        let row: serde_json::Value =
            serde_json::from_str(CORPUS.lines().nth(5).ok_or("missing KSN")?)?;
        let event_raw = row["signer_est_raw"].as_str().ok_or("missing KEL")?;
        let event = KeriEvent::deserialize(event_raw.as_bytes(), JsonLimits::new(4096, 64))?;
        let KeriEvent::Inception(icp) = &event else {
            return Err("expected inception".into());
        };
        let snapshot = crate::KeyStateSnapshot::genesis(icp);
        let state = snapshot.view();
        let raw = row["raw"].as_str().ok_or("missing notice")?;
        let routed = keri_codec::RoutedBody::parse(raw.as_bytes(), JsonLimits::new(4096, 64))?;
        let Some(DiscoveryClaim::KeyState { mut notice }) = routed.discovery_claim()? else {
            return Err("expected KSN claim".into());
        };
        assert!(notice_matches_state(&notice, &state));
        notice.keys.clear();
        assert!(!notice_matches_state(&notice, &state));
        notice.keys = state.keys().to_vec();
        notice.last_est_sn += 1;
        assert!(!notice_matches_state(&notice, &state));
        Ok(())
    }
}
