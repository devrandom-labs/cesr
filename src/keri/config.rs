use crate::keri::error::KeriError;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::borrow::ToOwned;

/// KERI configuration traits that constrain identifier behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfigTrait {
    /// Establishment-only: no interaction events allowed.
    EstOnly,
    /// Do not delegate: identifier cannot delegate to others.
    DoNotDelegate,
    /// No backers: no witness or backer support.
    NoBackers,
    /// Registrar backers: use registrar backers instead of witnesses.
    RegistrarBackers,
    /// No registrar backers.
    NoRegistrarBackers,
    /// Delegate is delegator: the delegate prefix equals the delegator prefix.
    DelegateIsDelegator,
}

impl ConfigTrait {
    /// Returns the KERI code for this configuration trait.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::EstOnly => "EO",
            Self::DoNotDelegate => "DND",
            Self::NoBackers => "NB",
            Self::RegistrarBackers => "RB",
            Self::NoRegistrarBackers => "NRB",
            Self::DelegateIsDelegator => "DID",
        }
    }

    /// Parses a `ConfigTrait` from its KERI code.
    ///
    /// # Errors
    ///
    /// Returns [`KeriError::UnknownConfigTrait`] if the code is not recognized.
    pub fn from_code(code: &str) -> Result<Self, KeriError> {
        match code {
            "EO" => Ok(Self::EstOnly),
            "DND" => Ok(Self::DoNotDelegate),
            "NB" => Ok(Self::NoBackers),
            "RB" => Ok(Self::RegistrarBackers),
            "NRB" => Ok(Self::NoRegistrarBackers),
            "DID" => Ok(Self::DelegateIsDelegator),
            _ => Err(KeriError::UnknownConfigTrait(code.to_owned())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_VARIANTS: &[(ConfigTrait, &str)] = &[
        (ConfigTrait::EstOnly, "EO"),
        (ConfigTrait::DoNotDelegate, "DND"),
        (ConfigTrait::NoBackers, "NB"),
        (ConfigTrait::RegistrarBackers, "RB"),
        (ConfigTrait::NoRegistrarBackers, "NRB"),
        (ConfigTrait::DelegateIsDelegator, "DID"),
    ];

    #[test]
    fn config_trait_code_roundtrip() {
        for (variant, expected_code) in ALL_VARIANTS {
            assert_eq!(variant.code(), *expected_code);
            let parsed = ConfigTrait::from_code(expected_code).unwrap();
            assert_eq!(parsed, *variant);
        }
    }

    #[test]
    fn config_trait_from_code_valid() {
        assert_eq!(ConfigTrait::from_code("EO").unwrap(), ConfigTrait::EstOnly);
        assert_eq!(
            ConfigTrait::from_code("DND").unwrap(),
            ConfigTrait::DoNotDelegate
        );
        assert_eq!(
            ConfigTrait::from_code("NB").unwrap(),
            ConfigTrait::NoBackers
        );
    }

    #[test]
    fn config_trait_from_code_invalid() {
        let err = ConfigTrait::from_code("XYZ").unwrap_err();
        assert!(matches!(err, KeriError::UnknownConfigTrait(ref s) if s == "XYZ"));
    }
}
