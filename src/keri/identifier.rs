use crate::core::primitives::{Prefixer, Saider};

/// A KERI identifier prefix — either a basic derivation (public key) or a
/// self-addressing derivation (SAID/digest).
///
/// In KERI, identifiers created with basic derivation use the public key as
/// the prefix (e.g., Ed25519 code `D`), while self-addressing identifiers
/// use the SAID of the inception event (e.g., `Blake3_256` code `E`).
pub enum Identifier<'a> {
    /// Basic derivation: the identifier IS the public key.
    Basic(Prefixer<'a>),
    /// Self-addressing derivation: the identifier IS a digest (SAID).
    SelfAddressing(Saider<'a>),
}

impl<'a> Identifier<'a> {
    /// Narrow to a basic (public key) identifier, if this is one.
    #[must_use]
    pub const fn as_prefixer(&self) -> Option<&Prefixer<'a>> {
        match self {
            Self::Basic(p) => Some(p),
            Self::SelfAddressing(_) => None,
        }
    }

    /// Narrow to a self-addressing (SAID) identifier, if this is one.
    #[must_use]
    pub const fn as_saider(&self) -> Option<&Saider<'a>> {
        match self {
            Self::SelfAddressing(s) => Some(s),
            Self::Basic(_) => None,
        }
    }

    /// Convert to `Identifier<'static>` by owning any borrowed fields.
    #[must_use]
    pub fn into_static(self) -> Identifier<'static> {
        match self {
            Self::Basic(p) => Identifier::Basic(p.into_static()),
            Self::SelfAddressing(s) => Identifier::SelfAddressing(s.into_static()),
        }
    }
}

impl<'a> From<Prefixer<'a>> for Identifier<'a> {
    fn from(p: Prefixer<'a>) -> Self {
        Self::Basic(p)
    }
}

impl<'a> From<Saider<'a>> for Identifier<'a> {
    fn from(s: Saider<'a>) -> Self {
        Self::SelfAddressing(s)
    }
}

impl PartialEq for Identifier<'_> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Basic(a), Self::Basic(b)) => a.raw() == b.raw() && a.code() == b.code(),
            (Self::SelfAddressing(a), Self::SelfAddressing(b)) => {
                a.raw() == b.raw() && a.code() == b.code()
            }
            _ => false,
        }
    }
}

impl Eq for Identifier<'_> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::{DigestCode, VerKeyCode};
    use std::borrow::Cow;

    fn make_prefixer() -> Prefixer<'static> {
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn make_saider() -> Saider<'static> {
        MatterBuilder::new()
            .with_code(DigestCode::Blake3_256)
            .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    #[test]
    fn widen_from_prefixer() {
        let id = Identifier::from(make_prefixer());
        assert!(id.as_prefixer().is_some());
        assert!(id.as_saider().is_none());
    }

    #[test]
    fn widen_from_saider() {
        let id = Identifier::from(make_saider());
        assert!(id.as_saider().is_some());
        assert!(id.as_prefixer().is_none());
    }

    #[test]
    fn narrow_to_prefixer() {
        let id = Identifier::from(make_prefixer());
        let p = id.as_prefixer().unwrap();
        assert_eq!(*p.code(), VerKeyCode::Ed25519);
    }

    #[test]
    fn narrow_to_saider() {
        let id = Identifier::from(make_saider());
        let s = id.as_saider().unwrap();
        assert_eq!(*s.code(), DigestCode::Blake3_256);
    }

    #[test]
    fn into_static_preserves_variant() {
        let id = Identifier::from(make_prefixer());
        let owned = id.into_static();
        assert!(owned.as_prefixer().is_some());
    }

    #[test]
    fn equality() {
        let a = Identifier::from(make_prefixer());
        let b = Identifier::from(make_prefixer());
        assert!(a == b, "same-variant identifiers should be equal");

        let c = Identifier::from(make_saider());
        assert!(a != c, "different-variant identifiers should not be equal");
    }

    #[test]
    fn is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Identifier<'static>>();
    }
}
