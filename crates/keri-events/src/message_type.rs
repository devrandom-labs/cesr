use crate::error::KeriError;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::borrow::ToOwned;

/// Wire tag for the `t` field — the KERI spec's "message type".
///
/// A small `Copy` tag held without the event body (at the wire edge and on
/// `SerializedEvent`).
///
/// # Scope (1.0 message-ilk decision, issue #82)
///
/// Every KERI message-type code has a stated home; none is a silent stub:
///
/// | code  | typed support                                             |
/// |-------|-----------------------------------------------------------|
/// | `icp` | here — [`InceptionEvent`](crate::InceptionEvent)          |
/// | `rot` | here — [`RotationEvent`](crate::RotationEvent)            |
/// | `ixn` | here — [`InteractionEvent`](crate::InteractionEvent)      |
/// | `dip` | here — [`DelegatedInceptionEvent`](crate::DelegatedInceptionEvent) |
/// | `drt` | here — [`DelegatedRotationEvent`](crate::DelegatedRotationEvent)  |
/// | `rct` | here — [`Receipt`](crate::Receipt) (an endorsement of a KEL coordinate, not a [`KeriEvent`](crate::KeriEvent)) |
/// | `vcp` | here — [`RegistryInception`](crate::RegistryInception) — TEL registry inception |
/// | `vrt` | here — [`RegistryRotation`](crate::RegistryRotation) — TEL registry rotation |
/// | `iss` | here — [`Issue`](crate::Issue) — TEL credential issue |
/// | `rev` | here — [`Revoke`](crate::Revoke) — TEL credential revoke |
/// | `bis` | here — [`BackedIssue`](crate::BackedIssue) — TEL backed issue |
/// | `brv` | here — [`BackedRevoke`](crate::BackedRevoke) — TEL backed revoke |
/// | `qry` | here — routed query body, validated by the codec             |
/// | `rpy` | here — routed reply body, validated by the codec             |
/// | `exn` | here — [`MessageType::Exn`] — the exchange envelope ilk; the envelope body is typed by the exchange lane, not this vocabulary |
///
/// A26 extends the original issue #82 scope decision: the selected V1
/// discovery profile needs `qry` and `rpy` on the wire. Route decisions
/// remain in the protocol layer; this enum only names the `t` code.
///
/// The TEL registry ilks (`vcp`/`vrt`/`iss`/`rev`/`bis`/`brv`) and the
/// exchange ilk (`exn`) were added in a deliberate revision of the 1.0
/// ilk-scope decision: `MessageType` is this crate's name for the wire's
/// `t` values, and a registry TEL is anchored in its issuer's KEL with
/// the same seal shape the KEL already types, so refusing a `t` value the
/// wire carries is a gap in the naming, not scope discipline. The
/// rationale is recorded in `docs/keripy-parity/ledger.md`. TEL
/// envelope-body typing lives in this crate; `exn` bodies and codec
/// parsing remain the serialized lane's job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// Inception — creates a new identifier.
    Icp,
    /// Rotation — rotates keys for an identifier.
    Rot,
    /// Interaction — anchors data without key changes.
    Ixn,
    /// Delegated inception — creates a delegated identifier.
    Dip,
    /// Delegated rotation — rotates keys for a delegated identifier.
    Drt,
    /// Receipt — endorses an already-created key event by its coordinate
    /// `(prefix, sn, said)`; carries no self-SAID and never enters a KEL.
    Rct,
    /// Transaction Event Log registry inception — establishes a registry.
    Vcp,
    /// Transaction Event Log registry rotation — rotates a registry's backers.
    Vrt,
    /// Transaction Event Log credential issue — registers a credential.
    Iss,
    /// Transaction Event Log credential revoke — revokes a credential.
    Rev,
    /// Transaction Event Log backed issue — a backer endorses an `iss`.
    Bis,
    /// Transaction Event Log backed revoke — a backer endorses a `rev`.
    Brv,
    /// Routed query (`qry`); route and payload are codec-level fields.
    Qry,
    /// Routed reply (`rpy`); route and payload are codec-level fields.
    Rpy,
    /// Exchange — the peer-to-peer exchange envelope ilk. Only the `t`
    /// tag is named here; the envelope body is typed by the exchange
    /// lane above this vocabulary.
    Exn,
}

impl MessageType {
    /// Returns the 3-character KERI code for this message type.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Icp => "icp",
            Self::Rot => "rot",
            Self::Ixn => "ixn",
            Self::Dip => "dip",
            Self::Drt => "drt",
            Self::Rct => "rct",
            Self::Vcp => "vcp",
            Self::Vrt => "vrt",
            Self::Iss => "iss",
            Self::Rev => "rev",
            Self::Bis => "bis",
            Self::Brv => "brv",
            Self::Qry => "qry",
            Self::Rpy => "rpy",
            Self::Exn => "exn",
        }
    }

    /// Parses a [`MessageType`] from a 3-character KERI code.
    ///
    /// # Errors
    ///
    /// Returns [`KeriError::UnknownMessageType`] if the code is not recognized.
    pub fn from_code(code: &str) -> Result<Self, KeriError> {
        match code {
            "icp" => Ok(Self::Icp),
            "rot" => Ok(Self::Rot),
            "ixn" => Ok(Self::Ixn),
            "dip" => Ok(Self::Dip),
            "drt" => Ok(Self::Drt),
            "rct" => Ok(Self::Rct),
            "vcp" => Ok(Self::Vcp),
            "vrt" => Ok(Self::Vrt),
            "iss" => Ok(Self::Iss),
            "rev" => Ok(Self::Rev),
            "bis" => Ok(Self::Bis),
            "brv" => Ok(Self::Brv),
            "qry" => Ok(Self::Qry),
            "rpy" => Ok(Self::Rpy),
            "exn" => Ok(Self::Exn),
            _ => Err(KeriError::UnknownMessageType(code.to_owned())),
        }
    }

    /// Returns `true` if this message type is an establishment event.
    #[must_use]
    pub const fn is_establishment(&self) -> bool {
        matches!(self, Self::Icp | Self::Rot | Self::Dip | Self::Drt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_VARIANTS: &[(MessageType, &str)] = &[
        (MessageType::Icp, "icp"),
        (MessageType::Rot, "rot"),
        (MessageType::Ixn, "ixn"),
        (MessageType::Dip, "dip"),
        (MessageType::Drt, "drt"),
        (MessageType::Rct, "rct"),
        (MessageType::Vcp, "vcp"),
        (MessageType::Vrt, "vrt"),
        (MessageType::Iss, "iss"),
        (MessageType::Rev, "rev"),
        (MessageType::Bis, "bis"),
        (MessageType::Brv, "brv"),
        (MessageType::Qry, "qry"),
        (MessageType::Rpy, "rpy"),
        (MessageType::Exn, "exn"),
    ];

    #[test]
    fn message_type_code_roundtrip() {
        for (variant, expected_code) in ALL_VARIANTS {
            assert_eq!(variant.code(), *expected_code);
            let parsed = MessageType::from_code(expected_code).unwrap();
            assert_eq!(parsed, *variant);
        }
    }

    #[test]
    fn message_type_from_code_valid() {
        assert_eq!(MessageType::from_code("icp").unwrap(), MessageType::Icp);
        assert_eq!(MessageType::from_code("drt").unwrap(), MessageType::Drt);
        assert_eq!(MessageType::from_code("vcp").unwrap(), MessageType::Vcp);
        assert_eq!(MessageType::from_code("exn").unwrap(), MessageType::Exn);
    }

    #[test]
    fn message_type_from_code_invalid() {
        let err = MessageType::from_code("zzz").unwrap_err();
        assert!(matches!(&err, KeriError::UnknownMessageType(s) if s == "zzz"));
    }

    #[test]
    fn establishment_message_types() {
        let establishment = [
            MessageType::Icp,
            MessageType::Rot,
            MessageType::Dip,
            MessageType::Drt,
        ];
        let non_establishment = [
            MessageType::Ixn,
            MessageType::Rct,
            MessageType::Vcp,
            MessageType::Vrt,
        ];

        for message_type in establishment {
            assert!(
                message_type.is_establishment(),
                "{message_type:?} should be establishment"
            );
        }
        for message_type in non_establishment {
            assert!(
                !message_type.is_establishment(),
                "{message_type:?} should not be establishment"
            );
        }
    }
}
