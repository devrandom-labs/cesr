use cesr::core::primitives::Number;

use crate::identifier::Identifier;
use crate::message_type::MessageType;
use crate::primitive::Said;

/// A receipt (`rct`) — an endorsement of one key event by its KEL coordinate.
///
/// A receipt names the event it endorses by `(prefix, sn, said)`; the actual
/// endorsement (who vouches, with which signature) travels as CESR
/// attachments on the receipt message, not in the body. Unlike the
/// [`KeriEvent`](crate::KeriEvent) family a receipt has **no self-SAID** —
/// its `d` field is the *receipted* event's SAID — and it never enters a
/// KEL, which is why it is a separate type rather than a `KeriEvent`
/// variant (the 1.0 ilk-scope decision, issue #82).
///
/// All three fields are plain data, so construction is public: there is no
/// computed digest to forge, hence no `internals` gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt<'a> {
    prefix: Identifier<'a>,
    sn: Number,
    said: Said<'a>,
}

impl<'a> Receipt<'a> {
    /// Wire tag for the `t` field.
    pub const MESSAGE_TYPE: MessageType = MessageType::Rct;

    /// Creates a receipt for the event at `(prefix, sn)` with digest `said`.
    ///
    /// Sequence number `0` is valid: inception events are receiptable (a
    /// witness receipts the `icp` that installed it).
    #[must_use]
    pub const fn new(prefix: Identifier<'a>, sn: Number, said: Said<'a>) -> Self {
        Self { prefix, sn, said }
    }

    /// Identifier prefix of the KEL holding the receipted event.
    #[must_use]
    pub const fn prefix(&self) -> &Identifier<'a> {
        &self.prefix
    }

    /// Sequence number of the receipted event.
    #[must_use]
    pub const fn sn(&self) -> Number {
        self.sn
    }

    /// SAID of the receipted event (not a self-SAID of the receipt).
    #[must_use]
    pub const fn said(&self) -> &Said<'a> {
        &self.said
    }

    /// Detach from the source buffer by owning every contained primitive.
    #[must_use]
    pub fn into_static(self) -> Receipt<'static> {
        Receipt {
            prefix: self.prefix.into_static(),
            sn: self.sn,
            said: self.said.into_static(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitive::BasicPrefix;
    use alloc::borrow::Cow;
    use alloc::vec;
    use cesr::core::matter::builder::MatterBuilder;
    use cesr::core::matter::code::{DigestCode, VerKeyCode};

    fn make_prefixer() -> BasicPrefix<'static> {
        BasicPrefix::from_matter(
            MatterBuilder::new()
                .with_code(VerKeyCode::Ed25519)
                .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
                .unwrap()
                .build()
                .unwrap(),
        )
    }

    fn make_saider() -> Said<'static> {
        Said::from_matter(
            MatterBuilder::new()
                .with_code(DigestCode::Blake3_256)
                .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
                .unwrap()
                .build()
                .unwrap(),
        )
    }

    #[test]
    fn construct_and_access_fields() {
        let receipt = Receipt::new(make_prefixer().into(), Number::new(0), make_saider());

        assert_eq!(
            *receipt.prefix().as_prefixer().unwrap().code(),
            VerKeyCode::Ed25519
        );
        assert_eq!(receipt.sn().value(), 0);
        assert_eq!(*receipt.said().code(), DigestCode::Blake3_256);
        assert_eq!(Receipt::MESSAGE_TYPE, MessageType::Rct);
    }

    #[test]
    fn is_send_sync_static() {
        fn assert_send_sync_static<T: Send + Sync + 'static>() {}
        assert_send_sync_static::<Receipt<'static>>();
    }

    /// Compile-time probe: covariance (see the rung-6 spec amendment).
    #[test]
    fn receipt_is_covariant() {
        fn coerce<'short>(r: &'short Receipt<'static>) -> &'short Receipt<'short> {
            r
        }
        let receipt = Receipt::new(make_prefixer().into(), Number::new(1), make_saider());
        let _ = coerce(&receipt);
    }
}
