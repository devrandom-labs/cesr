use crate::error::KeriError;

/// KERI infrastructure roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Identifier controller.
    Controller,
    /// Witness providing receipts.
    Witness,
    /// Watcher monitoring key event logs.
    Watcher,
    /// Registrar managing credential registries.
    Registrar,
    /// Judge evaluating duplicity.
    Judge,
    /// Generic peer participant.
    Peer,
    /// Gateway for protocol bridging.
    Gateway,
    /// Juror for adjudicating duplicity.
    Juror,
    /// Mailbox for asynchronous message delivery.
    Mailbox,
    /// Agent acting on behalf of a controller.
    Agent,
    /// Indexer for event log indexing.
    Indexer,
}

impl Role {
    /// Returns the KERI code for this role.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Controller => "controller",
            Self::Witness => "witness",
            Self::Watcher => "watcher",
            Self::Registrar => "registrar",
            Self::Judge => "judge",
            Self::Peer => "peer",
            Self::Gateway => "gateway",
            Self::Juror => "juror",
            Self::Mailbox => "mailbox",
            Self::Agent => "agent",
            Self::Indexer => "indexer",
        }
    }

    /// Parses a `Role` from its KERI code.
    ///
    /// # Errors
    ///
    /// Returns [`KeriError::UnknownRole`] if the code is not recognized.
    pub fn from_code(code: &str) -> Result<Self, KeriError> {
        match code {
            "controller" => Ok(Self::Controller),
            "witness" => Ok(Self::Witness),
            "watcher" => Ok(Self::Watcher),
            "registrar" => Ok(Self::Registrar),
            "judge" => Ok(Self::Judge),
            "peer" => Ok(Self::Peer),
            "gateway" => Ok(Self::Gateway),
            "juror" => Ok(Self::Juror),
            "mailbox" => Ok(Self::Mailbox),
            "agent" => Ok(Self::Agent),
            "indexer" => Ok(Self::Indexer),
            _ => Err(KeriError::UnknownRole(code.to_owned())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_VARIANTS: &[(Role, &str)] = &[
        (Role::Controller, "controller"),
        (Role::Witness, "witness"),
        (Role::Watcher, "watcher"),
        (Role::Registrar, "registrar"),
        (Role::Judge, "judge"),
        (Role::Peer, "peer"),
        (Role::Gateway, "gateway"),
        (Role::Juror, "juror"),
        (Role::Mailbox, "mailbox"),
        (Role::Agent, "agent"),
        (Role::Indexer, "indexer"),
    ];

    #[test]
    fn role_code_roundtrip() {
        for (variant, expected_code) in ALL_VARIANTS {
            assert_eq!(variant.code(), *expected_code);
            let parsed = Role::from_code(expected_code).unwrap();
            assert_eq!(parsed, *variant);
        }
    }

    #[test]
    fn role_from_code_valid() {
        assert_eq!(Role::from_code("controller").unwrap(), Role::Controller);
        assert_eq!(Role::from_code("peer").unwrap(), Role::Peer);
    }

    #[test]
    fn role_from_code_invalid() {
        let err = Role::from_code("unknown").unwrap_err();
        assert!(matches!(err, KeriError::UnknownRole(ref s) if s == "unknown"));
    }
}
