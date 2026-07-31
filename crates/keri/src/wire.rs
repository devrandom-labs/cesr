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

use keri_codec::{EventMessage, TransferableReceipt};

use crate::receipt::TransferableEndorsement;
use crate::state::Signed;

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
