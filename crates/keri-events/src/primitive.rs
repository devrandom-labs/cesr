//! Role-distinct KERI primitive newtypes over cesr [`Matter`].
//!
//! CESR encodes a value's *code family* (e.g. `VerKeyCode`) but not its
//! *role*: a verification key (`k`) and a basic AID prefix (`i`) share
//! `VerKeyCode`, and a next-key digest (`n`) and a SAID (`d`) share
//! `DigestCode`. As bare `Matter<C>` those pairs are the same Rust type and
//! swap silently. These newtypes make the role a compile-time fact — a
//! [`VerifyingKey`] cannot be assigned where a [`BasicPrefix`] is expected.
//!
//! Each is a transparent wrapper: `Deref` gives read-through access to the
//! inner [`Matter`] (code, raw, qb64…), and encoding routes through that
//! inner value so wire bytes are identical to the pre-newtype representation.

use cesr::core::matter::code::{DigestCode, VerKeyCode};
use cesr::core::matter::matter::Matter;
use core::ops::Deref;

macro_rules! role_newtype {
    ($(#[$m:meta])* $name:ident, $code:ty) => {
        $(#[$m])*
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $name<'a>(Matter<'a, $code>);

        impl<'a> $name<'a> {
            /// Wrap a `Matter` in this role. Naming the role here is the
            /// safety checkpoint — the conversion site must state intent.
            #[must_use]
            pub const fn from_matter(inner: Matter<'a, $code>) -> Self {
                Self(inner)
            }

            /// The underlying CESR primitive.
            #[must_use]
            pub const fn as_matter(&self) -> &Matter<'a, $code> {
                &self.0
            }

            /// Detach from the source buffer by owning the inner primitive.
            #[must_use]
            pub fn into_static(self) -> $name<'static> {
                $name(self.0.into_static())
            }
        }

        impl<'a> Deref for $name<'a> {
            type Target = Matter<'a, $code>;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl<'a> From<Matter<'a, $code>> for $name<'a> {
            fn from(inner: Matter<'a, $code>) -> Self {
                Self(inner)
            }
        }
    };
}

role_newtype!(
    /// Verification key (`k`) — verifies signatures. keripy `Verfer`.
    VerifyingKey, VerKeyCode
);
role_newtype!(
    /// Next-key commitment or prior-event digest (`n`, `p`). keripy `Diger`.
    Digest, DigestCode
);
role_newtype!(
    /// Self-addressing identifier (`d`) — the event's SAID. keripy `Saider`.
    Said, DigestCode
);
role_newtype!(
    /// Basic AID prefix / witness prefix (`i`, `bi`, `b`). keripy `Prefixer`.
    BasicPrefix, VerKeyCode
);

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::borrow::Cow;
    use alloc::vec;
    use cesr::core::matter::builder::MatterBuilder;

    fn verkey_matter() -> Matter<'static, VerKeyCode> {
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn digest_matter() -> Matter<'static, DigestCode> {
        MatterBuilder::new()
            .with_code(DigestCode::Blake3_256)
            .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    #[test]
    fn deref_reads_through_to_inner_code() {
        let vk = VerifyingKey::from_matter(verkey_matter());
        assert_eq!(*vk.code(), VerKeyCode::Ed25519);
        assert_eq!(*vk.as_matter().code(), VerKeyCode::Ed25519);
    }

    #[test]
    fn into_static_preserves_value() {
        let d = Digest::from_matter(digest_matter());
        let owned: Digest<'static> = d.clone().into_static();
        assert_eq!(d, owned);
        assert_eq!(*owned.code(), DigestCode::Blake3_256);
    }

    #[test]
    fn same_family_roles_are_distinct_types() {
        fn takes_key(_: &VerifyingKey<'_>) {}
        fn takes_prefix(_: &BasicPrefix<'_>) {}
        let key = VerifyingKey::from_matter(verkey_matter());
        let prefix = BasicPrefix::from_matter(verkey_matter());
        takes_key(&key);
        takes_prefix(&prefix);
    }
}
