//! Optional wire-edge adapter (feature `wire`): a parsed
//! [`keri_codec::EventMessage`] converts straight into [`Signed`].
//!
//! The #128 sans-io boundary holds: the default crate takes parsed borrowed
//! values and never sees bytes. This adapter is the opt-in edge — exactly
//! like the optional async edge decided in #128 — and it closes the
//! `signed_bytes`-provenance honor system: `EventMessage` carries, by
//! construction, the exact span its signatures sign. The same edge serves
//! receipts: a [`keri_codec::TransferableReceipt`] converts into the K5
//! [`TransferableEndorsement`] judgment input.

use keri_codec::{EventMessage, ExnMessage, TelMessage, TransferableReceipt};

use crate::authority::{Authority, Verified};
use crate::error::ExchangeError;
use crate::receipt::TransferableEndorsement;
use crate::state::{KeyState, Signed};

impl<'e> From<&'e EventMessage<'e>> for Signed<'e> {
    fn from(msg: &'e EventMessage<'e>) -> Self {
        Self {
            event: msg.event(),
            signed_bytes: msg.body(),
            sigs: msg.sigs().to_vec(),
            wigs: msg.wigs().to_vec(),
        }
    }
}

impl<'e> From<&'e TelMessage<'e>> for crate::registry::SignedTel<'e> {
    /// Lift a parsed, framed TEL message into the registry fold's
    /// signed-event carrier — the same conversion [`EventMessage`] gets for
    /// the key-event fold: the carrier preserves, by construction, the exact
    /// span its signatures sign.
    fn from(msg: &'e TelMessage<'e>) -> Self {
        Self {
            event: msg.event(),
            signed_bytes: msg.body(),
            sigs: msg.sigs().to_vec(),
        }
    }
}

impl KeyState<'_> {
    /// Verify a signed exchange envelope against this key state — the exn
    /// ingest path's one judgment: the envelope's declared sender must be
    /// this key state's identifier, then the signatures verify over the
    /// exact signed body through the shared
    /// [`Authority::verify`](crate::Authority::verify) path. On success the
    /// returned [`Verified`] borrows the envelope's signature span, the same
    /// shape [`Signed`] verification returns.
    ///
    /// # Errors
    ///
    /// [`ExchangeError::SenderMismatch`] when the envelope's issuer is not
    /// this key state's prefix; [`ExchangeError::Signatures`] when the
    /// shared authority path rejects the signatures.
    pub fn verify_exn<'m>(&self, msg: &'m ExnMessage<'_>) -> Result<Verified<'m>, ExchangeError> {
        if self.prefix() != msg.exn().issuer() {
            return Err(ExchangeError::SenderMismatch);
        }
        Authority::new(self.keys(), self.threshold())
            .verify(msg.body(), msg.sigs())
            .map_err(ExchangeError::from)
    }
}

impl<'e> From<&'e TransferableReceipt<'e>> for TransferableEndorsement<'e> {
    fn from(receipt: &'e TransferableReceipt<'e>) -> Self {
        Self {
            receiptor: receipt.receiptor(),
            sn: receipt.sn(),
            said: receipt.said(),
            sigs: receipt.signatures(),
        }
    }
}
