//! Bounded V1 ACDC verification using exact credential bytes and host-accepted
//! KEL/TEL evidence. Retrieval and durable acceptance belong to the host.

use alloc::{string::String, vec::Vec};

use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::DigestCode;
use keri_codec::{JsonLimits, SchemaError, VerifiedSchema};
use keri_events::Identifier;
use keri_events::acdc::{Acdc, AcdcField};
use serde_json::Value;

use crate::credential::{CredentialError, CredentialVerifier};
use crate::error::{Disposition, EvidenceKind};
use crate::registry::{CredentialState, RegistryState};
use crate::state::KeyState;

/// Accepted host evidence for one exact ACDC body. Each state must have been
/// produced by an authenticated KEL/TEL fold and retained with provenance.
#[derive(Clone, Copy)]
pub struct CredentialEvidence<'a, 'k> {
    raw: &'a [u8],
    schema: Option<&'a VerifiedSchema>,
    registry: Option<&'a RegistryState>,
    credential_state: Option<&'a CredentialState>,
    issuer_state: Option<&'a KeyState<'k>>,
}

impl<'a, 'k> CredentialEvidence<'a, 'k> {
    /// Bind exact bytes to supplied host-accepted evidence. Missing facts may
    /// be `None` and produce an awaiting verdict.
    #[must_use]
    pub const fn from_host_accepted(
        raw: &'a [u8],
        schema: Option<&'a VerifiedSchema>,
        registry: Option<&'a RegistryState>,
        credential_state: Option<&'a CredentialState>,
        issuer_state: Option<&'a KeyState<'k>>,
    ) -> Self {
        Self {
            raw,
            schema,
            registry,
            credential_state,
            issuer_state,
        }
    }
}

/// One supplied chain node under the SAID requested by an `e.*.n` edge.
pub struct ChainCredential<'a, 'k> {
    /// Lookup key used by the host. The verifier compares it with parsed `d`.
    pub said: &'a str,
    /// Exact body and accepted evidence for that node.
    pub evidence: CredentialEvidence<'a, 'k>,
}

/// Work limits for one bounded verification, including all chain nodes.
#[derive(Debug, Clone, Copy)]
pub struct CredentialVerificationLimits {
    /// Canonical JSON field and nesting limits per document.
    pub json: JsonLimits,
    /// Maximum bytes in any credential body or edge/rule block.
    pub max_document_bytes: usize,
    /// Maximum number of credentials visited including the root.
    pub max_nodes: usize,
    /// Maximum chain edges from root to leaf.
    pub max_chain_depth: usize,
}

/// A failed credential validity decision. Only missing host facts are retryable.
#[derive(Debug, thiserror::Error)]
pub enum CredentialVerificationError {
    /// No verified schema was supplied for a credential.
    #[error("credential schema evidence is missing")]
    MissingSchema,
    /// Schema compilation or instance validation failed.
    #[error(transparent)]
    Schema(#[from] SchemaError),
    /// Accepted issuer/registry/TEL evidence failed.
    #[error(transparent)]
    Status(#[from] CredentialError),
    /// A named chain credential has not yet arrived.
    #[error("credential chain node {0} is missing")]
    MissingChain(String),
    /// Host supplied an unrelated body under a requested chain SAID.
    #[error("supplied chain body has a different SAID")]
    ChainClaimMismatch,
    /// Multiple supplied bodies claim the same chain SAID.
    #[error("ambiguous chain evidence for one SAID")]
    AmbiguousChain,
    /// The edge or rule form has no selected verification semantics.
    #[error("unsupported credential edge or nonempty rule form")]
    UnsupportedForm,
    /// Edge JSON is malformed or names a non-SAID node.
    #[error("malformed credential edge")]
    MalformedEdge,
    /// DI2I and unknown edge operators are outside the selected profile.
    #[error("unsupported credential edge operator")]
    UnsupportedOperator,
    /// An I2I edge does not bind the current issuer to the node's issuee.
    #[error("I2I chain node was not issued to the current issuer")]
    WrongIssuee,
    /// The chain revisits a credential on its current path.
    #[error("credential chain cycle")]
    Cycle,
    /// A caller-selected byte, node or depth limit was reached.
    #[error("credential verification resource limit exceeded")]
    ResourceLimit,
}

impl CredentialVerificationError {
    /// Host retry class for missing, rather than contradictory, evidence.
    #[must_use]
    pub const fn disposition(&self) -> Disposition {
        match self {
            Self::MissingSchema => Disposition::Awaiting(EvidenceKind::CredentialSchema),
            Self::MissingChain(_) => Disposition::Awaiting(EvidenceKind::CredentialChain),
            Self::Status(error) => error.disposition(),
            Self::Schema(_)
            | Self::ChainClaimMismatch
            | Self::AmbiguousChain
            | Self::UnsupportedForm
            | Self::MalformedEdge
            | Self::UnsupportedOperator
            | Self::WrongIssuee
            | Self::Cycle
            | Self::ResourceLimit => Disposition::Terminal,
        }
    }
}

impl CredentialVerifier {
    /// Validate schema fit, issuer/registry/TEL status and selected I2I/NI2I
    /// chains. `e` must be an inline edge map; `r` may be absent or empty.
    /// Disclosure, path signatures and DI2I have no validity claim here.
    ///
    /// # Errors
    ///
    /// Missing host evidence awaits retry. Invalid or unsupported supplied
    /// evidence is terminal. The result proves current validity only against
    /// the accepted evidence snapshot supplied by the host.
    pub fn verify<'a, 'k>(
        root: &CredentialEvidence<'a, 'k>,
        chain: &[ChainCredential<'a, 'k>],
        limits: CredentialVerificationLimits,
    ) -> Result<Acdc<'static>, CredentialVerificationError> {
        if limits.max_document_bytes > 1_048_576
            || limits.max_chain_depth > 64
            || limits.max_nodes > 1024
            || chain.len() >= limits.max_nodes
        {
            return Err(CredentialVerificationError::ResourceLimit);
        }
        VerificationWalk {
            chain,
            limits,
            path: Vec::new(),
            visited: 0,
        }
        .node(root, 0, None)
    }
}

struct VerificationWalk<'a, 'k, 'c> {
    chain: &'c [ChainCredential<'a, 'k>],
    limits: CredentialVerificationLimits,
    path: Vec<String>,
    visited: usize,
}

impl<'a, 'k> VerificationWalk<'a, 'k, '_> {
    fn node(
        &mut self,
        evidence: &CredentialEvidence<'a, 'k>,
        depth: usize,
        claimed_said: Option<&str>,
    ) -> Result<Acdc<'static>, CredentialVerificationError> {
        if depth > self.limits.max_chain_depth
            || self.visited >= self.limits.max_nodes
            || evidence.raw.len() > self.limits.max_document_bytes
        {
            return Err(CredentialVerificationError::ResourceLimit);
        }
        self.visited += 1;
        let schema = evidence
            .schema
            .ok_or(CredentialVerificationError::MissingSchema)?;
        let credential = schema.validate_credential(evidence.raw, self.limits.json)?;
        let said = credential.said().to_qb64();
        if claimed_said.is_some_and(|claim| claim != said) {
            return Err(CredentialVerificationError::ChainClaimMismatch);
        }
        if self.path.contains(&said) {
            return Err(CredentialVerificationError::Cycle);
        }
        check_rules(&credential)?;
        CredentialVerifier::status(
            &credential,
            evidence.registry,
            evidence.credential_state,
            evidence.issuer_state,
        )?;
        self.path.push(said);
        let outcome = self.edges(&credential, depth);
        self.path.pop();
        outcome?;
        Ok(credential)
    }
}

fn check_rules(credential: &Acdc<'_>) -> Result<(), CredentialVerificationError> {
    match credential.rules() {
        None => Ok(()),
        Some(AcdcField::Said(_)) => Err(CredentialVerificationError::UnsupportedForm),
        Some(AcdcField::Block(block)) => {
            let value: Value = serde_json::from_str(block.payload())
                .map_err(|_| CredentialVerificationError::UnsupportedForm)?;
            if value.as_object().is_some_and(serde_json::Map::is_empty) {
                Ok(())
            } else {
                Err(CredentialVerificationError::UnsupportedForm)
            }
        }
    }
}

impl VerificationWalk<'_, '_, '_> {
    fn edges(
        &mut self,
        credential: &Acdc<'_>,
        depth: usize,
    ) -> Result<(), CredentialVerificationError> {
        let Some(edges) = credential.edges() else {
            return Ok(());
        };
        let AcdcField::Block(block) = edges else {
            return Err(CredentialVerificationError::UnsupportedForm);
        };
        let value: Value = serde_json::from_str(block.payload())
            .map_err(|_| CredentialVerificationError::MalformedEdge)?;
        let map = value
            .as_object()
            .ok_or(CredentialVerificationError::MalformedEdge)?;
        if map.get("d").and_then(Value::as_str) != Some("") || map.contains_key("o") {
            return Err(CredentialVerificationError::UnsupportedForm);
        }
        for (label, node_value) in map {
            if label == "d" || label == "o" {
                continue;
            }
            let node = node_value
                .as_object()
                .ok_or(CredentialVerificationError::MalformedEdge)?;
            if node.len() > 2 || node.keys().any(|key| key != "n" && key != "o") {
                return Err(CredentialVerificationError::MalformedEdge);
            }
            let target = node
                .get("n")
                .and_then(Value::as_str)
                .ok_or(CredentialVerificationError::MalformedEdge)?;
            MatterBuilder::new()
                .from_qualified_base64(target.as_bytes())
                .map_err(|_| CredentialVerificationError::MalformedEdge)?
                .narrow::<DigestCode>()
                .map_err(|_| CredentialVerificationError::MalformedEdge)?;
            let operator = match node.get("o") {
                None => None,
                Some(Value::String(operation)) => Some(operation.as_str()),
                _ => return Err(CredentialVerificationError::MalformedEdge),
            };
            if !matches!(operator, None | Some("I2I" | "NI2I")) {
                return Err(CredentialVerificationError::UnsupportedOperator);
            }
            if self.path.iter().any(|said| said == target) {
                return Err(CredentialVerificationError::Cycle);
            }
            let mut matches = self
                .chain
                .iter()
                .filter(|candidate| candidate.said == target);
            let node_evidence = matches
                .next()
                .ok_or_else(|| CredentialVerificationError::MissingChain(target.into()))?;
            if matches.next().is_some() {
                return Err(CredentialVerificationError::AmbiguousChain);
            }
            let evidence = node_evidence.evidence;
            let parsed = self.node(&evidence, depth + 1, Some(target))?;
            let issuee = match parsed.attributes() {
                Some(AcdcField::Block(attributes)) => {
                    let data: Value = serde_json::from_str(attributes.payload())
                        .map_err(|_| CredentialVerificationError::WrongIssuee)?;
                    data.get("i").and_then(Value::as_str).map(String::from)
                }
                _ => None,
            };
            let needs_i2i = operator == Some("I2I") || (operator.is_none() && issuee.is_some());
            if needs_i2i && issuee.as_deref() != Some(identifier_qb64(credential.issuer()).as_str())
            {
                return Err(CredentialVerificationError::WrongIssuee);
            }
        }
        Ok(())
    }
}

fn identifier_qb64(identifier: &Identifier<'_>) -> String {
    match identifier {
        Identifier::Basic(prefix) => prefix.to_qb64(),
        Identifier::SelfAddressing(said) => said.to_qb64(),
    }
}

#[cfg(test)]
mod tests {
    use alloc::{boxed::Box, vec};

    use super::*;

    #[test]
    fn active_path_revisit_is_terminal_before_status_lookup()
    -> Result<(), Box<dyn std::error::Error>> {
        // Keep the selected pinned row inside this crate's published archive.
        let first = include_str!("../tests/fixtures/credential-issued.jsonl")
            .lines()
            .next()
            .ok_or("missing A27 corpus")?;
        let row: Value = serde_json::from_str(first)?;
        let schema = VerifiedSchema::from_bytes(
            row["schema"].as_str().ok_or("schema")?.as_bytes(),
            JsonLimits::new(4096, 64),
        )?;
        let raw = row["credential"].as_str().ok_or("credential")?;
        let evidence =
            CredentialEvidence::from_host_accepted(raw.as_bytes(), Some(&schema), None, None, None);
        let mut walk = VerificationWalk {
            chain: &[],
            limits: CredentialVerificationLimits {
                json: JsonLimits::new(4096, 64),
                max_document_bytes: 4096,
                max_nodes: 8,
                max_chain_depth: 4,
            },
            path: vec![row["credential_said"].as_str().ok_or("said")?.into()],
            visited: 0,
        };
        assert!(matches!(
            walk.node(&evidence, 1, None),
            Err(CredentialVerificationError::Cycle)
        ));
        Ok(())
    }
}
