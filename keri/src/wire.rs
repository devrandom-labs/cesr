//! Optional wire-edge adapter (feature `wire`): a parsed
//! [`cesr::serder::EventMessage`] converts straight into [`Signed`].
//!
//! The #128 sans-io boundary holds: the default crate takes parsed borrowed
//! values and never sees bytes. This adapter is the opt-in edge — exactly
//! like the optional async edge decided in #128 — and it closes the
//! `signed_bytes`-provenance honor system: `EventMessage` carries, by
//! construction, the exact span its signatures sign.

use cesr::serder::EventMessage;

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
