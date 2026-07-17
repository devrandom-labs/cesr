use crate::error::KeriError;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::borrow::ToOwned;

/// KERI event type identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ilk {
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
    /// Receipt — acknowledges an event.
    Rct,
    /// Query — requests information.
    Qry,
    /// Reply — responds to a query.
    Rpy,
    /// Exchange — peer-to-peer message.
    Exn,
}

impl Ilk {
    /// Returns the 3-character KERI code for this ilk.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Icp => "icp",
            Self::Rot => "rot",
            Self::Ixn => "ixn",
            Self::Dip => "dip",
            Self::Drt => "drt",
            Self::Rct => "rct",
            Self::Qry => "qry",
            Self::Rpy => "rpy",
            Self::Exn => "exn",
        }
    }

    /// Parses an `Ilk` from a 3-character KERI code.
    ///
    /// # Errors
    ///
    /// Returns [`KeriError::UnknownIlk`] if the code is not recognized.
    pub fn from_code(code: &str) -> Result<Self, KeriError> {
        match code {
            "icp" => Ok(Self::Icp),
            "rot" => Ok(Self::Rot),
            "ixn" => Ok(Self::Ixn),
            "dip" => Ok(Self::Dip),
            "drt" => Ok(Self::Drt),
            "rct" => Ok(Self::Rct),
            "qry" => Ok(Self::Qry),
            "rpy" => Ok(Self::Rpy),
            "exn" => Ok(Self::Exn),
            _ => Err(KeriError::UnknownIlk(code.to_owned())),
        }
    }

    /// Returns `true` if this ilk is an establishment event.
    #[must_use]
    pub const fn is_establishment(&self) -> bool {
        matches!(self, Self::Icp | Self::Rot | Self::Dip | Self::Drt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_VARIANTS: &[(Ilk, &str)] = &[
        (Ilk::Icp, "icp"),
        (Ilk::Rot, "rot"),
        (Ilk::Ixn, "ixn"),
        (Ilk::Dip, "dip"),
        (Ilk::Drt, "drt"),
        (Ilk::Rct, "rct"),
        (Ilk::Qry, "qry"),
        (Ilk::Rpy, "rpy"),
        (Ilk::Exn, "exn"),
    ];

    #[test]
    fn ilk_code_roundtrip() {
        for (variant, expected_code) in ALL_VARIANTS {
            assert_eq!(variant.code(), *expected_code);
            let parsed = Ilk::from_code(expected_code).unwrap();
            assert_eq!(parsed, *variant);
        }
    }

    #[test]
    fn ilk_from_code_valid() {
        assert_eq!(Ilk::from_code("icp").unwrap(), Ilk::Icp);
        assert_eq!(Ilk::from_code("exn").unwrap(), Ilk::Exn);
    }

    #[test]
    fn ilk_from_code_invalid() {
        let err = Ilk::from_code("zzz").unwrap_err();
        assert!(matches!(err, KeriError::UnknownIlk(ref s) if s == "zzz"));
    }

    #[test]
    fn establishment_ilks() {
        let establishment = [Ilk::Icp, Ilk::Rot, Ilk::Dip, Ilk::Drt];
        let non_establishment = [Ilk::Ixn, Ilk::Rct, Ilk::Qry, Ilk::Rpy, Ilk::Exn];

        for ilk in establishment {
            assert!(ilk.is_establishment(), "{ilk:?} should be establishment");
        }
        for ilk in non_establishment {
            assert!(
                !ilk.is_establishment(),
                "{ilk:?} should not be establishment",
            );
        }
    }
}
