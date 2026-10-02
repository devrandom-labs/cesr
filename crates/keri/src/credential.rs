//! Pure issuer, registry and TEL-status judgment for V1 ACDC credentials.
//!
//! A valid ACDC SAID authenticates its bytes, not the issuer's right to
//! issue it. The host supplies only states it has accepted through the KEL
//! and TEL folds. Schema and chain judgments are layered on this status
//! decision by the optional wire/schema adapter.

use keri_events::acdc::{Acdc, AcdcField};

use crate::error::{Disposition, EvidenceKind};
use crate::registry::{CredentialState, CredentialStatus, RegistryState};
use crate::state::KeyState;

/// A pure credential verifier with no storage, network or clock.
pub struct CredentialVerifier;

/// Missing or contradictory evidence in a credential status decision.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CredentialError {
    /// No accepted registry management state was supplied.
    #[error("credential registry state is required")]
    MissingRegistry,
    /// No accepted per-credential TEL state was supplied.
    #[error("credential TEL state is required")]
    MissingCredentialState,
    /// No accepted issuer KEL state was supplied.
    #[error("credential issuer KEL state is required")]
    MissingIssuerState,
    /// The selected registry-backed profile requires `ri` as a SAID.
    #[error("credential needs a registry SAID reference")]
    MissingRegistryReference,
    /// The credential names a different registry from supplied accepted state.
    #[error("credential registry reference contradicts accepted registry")]
    RegistryMismatch,
    /// The credential issuer differs from the accepted registry issuer.
    #[error("credential issuer contradicts accepted registry issuer")]
    IssuerMismatch,
    /// Supplied issuer KEL state does not represent this credential issuer.
    #[error("supplied issuer KEL state has another identifier")]
    IssuerStateMismatch,
    /// Accepted credential TEL state names another registry or credential.
    #[error("credential TEL state names another credential or registry")]
    CredentialStateMismatch,
    /// The credential has an accepted revocation head.
    #[error("credential is revoked")]
    Revoked,
}

impl CredentialError {
    /// Whether this candidate can be retried after evidence arrives.
    #[must_use]
    pub const fn disposition(&self) -> Disposition {
        match self {
            Self::MissingRegistry => Disposition::Awaiting(EvidenceKind::RegistryState),
            Self::MissingCredentialState => Disposition::Awaiting(EvidenceKind::CredentialTelState),
            Self::MissingIssuerState => Disposition::Awaiting(EvidenceKind::IssuerState),
            Self::MissingRegistryReference
            | Self::RegistryMismatch
            | Self::IssuerMismatch
            | Self::IssuerStateMismatch
            | Self::CredentialStateMismatch
            | Self::Revoked => Disposition::Terminal,
        }
    }
}

impl CredentialVerifier {
    /// Check the selected registry-backed credential's issuer and accepted
    /// TEL status. The registry and credential states are host-asserted
    /// accepted results of the validating KEL/TEL folds; this method checks
    /// their binding to the ACDC and does not itself validate JSON Schema.
    ///
    /// # Errors
    ///
    /// Missing accepted evidence is awaiting; unrelated or revoked
    /// evidence is terminal.
    pub fn status(
        credential: &Acdc<'_>,
        registry: Option<&RegistryState>,
        credential_state: Option<&CredentialState>,
        issuer_state: Option<&KeyState<'_>>,
    ) -> Result<(), CredentialError> {
        let reg = registry.ok_or(CredentialError::MissingRegistry)?;
        let state = credential_state.ok_or(CredentialError::MissingCredentialState)?;
        let issuer = issuer_state.ok_or(CredentialError::MissingIssuerState)?;
        let Some(AcdcField::Said(registry_said)) = credential.registry() else {
            return Err(CredentialError::MissingRegistryReference);
        };
        if registry_said != reg.id() {
            return Err(CredentialError::RegistryMismatch);
        }
        if credential.issuer() != reg.issuer() {
            return Err(CredentialError::IssuerMismatch);
        }
        if issuer.prefix() != credential.issuer() {
            return Err(CredentialError::IssuerStateMismatch);
        }
        if state.registry() != reg.id() || state.credential() != credential.said() {
            return Err(CredentialError::CredentialStateMismatch);
        }
        if state.status() == CredentialStatus::Revoked {
            return Err(CredentialError::Revoked);
        }
        Ok(())
    }
}
