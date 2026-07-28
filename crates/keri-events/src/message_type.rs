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
/// `SerializedEvent`). The receipt/query/reply/exchange codes (`rct`, `qry`,
/// `rpy`, `exn`) are not yet supported and are rejected by
/// [`MessageType::from_code`].
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
    }

    #[test]
    fn message_type_from_code_invalid() {
        let err = MessageType::from_code("zzz").unwrap_err();
        assert!(matches!(&err, KeriError::UnknownMessageType(s) if s == "zzz"));

        // Dead codes: recognized by keripy but deliberately unsupported here.
        for code in ["rct", "qry", "rpy", "exn"] {
            let dead_err = MessageType::from_code(code).unwrap_err();
            assert!(
                matches!(&dead_err, KeriError::UnknownMessageType(s) if s == code),
                "{code} must be rejected as UnknownMessageType"
            );
        }
    }

    #[test]
    fn establishment_message_types() {
        let establishment = [
            MessageType::Icp,
            MessageType::Rot,
            MessageType::Dip,
            MessageType::Drt,
        ];
        let non_establishment = [MessageType::Ixn];

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
