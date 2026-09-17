//! TEL — Transaction Event Log vocabulary (keripy `vdr/eventing.py`).
//!
//! A registry (keripy `Registry`) is a TEL anchored in its issuer's KEL:
//! the `vcp` establishes it, the `vrt` rotates it, and the credential
//! ilks — `iss`, `rev`, `bis`, `brv` — carry issuance and revocation
//! state for the credentials it governs. Field shapes are verified at
//! keripy pin `de59bc7d834955c5b0273c62f6b8b6a0df150dc3`
//! (`vdr/eventing.py:51-419`); see `docs/keripy-parity/` for the
//! divergence ledger.
//!
//! Like the KEL events, these types are pure data: the `v` version string
//! and all serialization/digest concerns belong to the codec, and every
//! all-field constructor is gated behind the `internals` feature.
//!
//! Reuse doctrine: the anchor of a backed issue/revoke (`ra`) is the
//! existing [`Seal::Event`] shape held as a required struct field — the
//! invalid state (a backed event without its anchor) is unrepresentable
//! instead of a runtime check.

use alloc::borrow::Cow;
use alloc::vec::Vec;

use cesr::core::primitives::{Noncer, Number};

use crate::config::ConfigTrait;
use crate::identifier::Identifier;
use crate::message_type::MessageType;
use crate::primitive::{BasicPrefix, Said};
use crate::seal::Seal;
use crate::toad::Toad;

/// Registry inception (`vcp`) — establishes a TEL (keripy `incept`,
/// `vdr/eventing.py:51-126`).
///
/// Wire fields: `v,t,d,i,ii,s,c,bt,b,n`. The registry identifier (`i`)
/// is the vcp SAID — in canonical output `i == d`, so the model stores
/// one value and the codec emits both labels from it. The sequence
/// number is pinned to 0 by the inception factory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryInception<'a> {
    /// The vcp SAID (`d`) — the registry identifier, since `i == d` in
    /// canonical output (the registry identity IS the vcp SAID).
    said: Said<'a>,
    /// The identifier anchoring the registry (`ii`) — its KEL carries
    /// the anchoring seal for every TEL event.
    issuer: Identifier<'a>,
    /// Configuration traits (`c`).
    config: Vec<ConfigTrait>,
    /// Backer threshold (`bt`) — 0 exactly when [`Self::backers`] is
    /// empty, per [`Toad`]'s law.
    backer_threshold: Toad,
    /// Backers (`b`) — the TEL analog of witnesses.
    backers: Vec<BasicPrefix<'a>>,
    /// Registry nonce (`n`) — keripy defaults it to a fresh `Salter`
    /// qb64 (a CESR `Noncer`).
    nonce: Noncer<'a>,
}

impl<'a> RegistryInception<'a> {
    /// Wire tag for the `t` field.
    pub const MESSAGE_TYPE: MessageType = MessageType::Vcp;

    /// Creates a new registry inception from all constituent fields.
    #[cfg(feature = "internals")]
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "constructor mirrors the full field set"
    )]
    pub const fn new(
        said: Said<'a>,
        issuer: Identifier<'a>,
        config: Vec<ConfigTrait>,
        backer_threshold: Toad,
        backers: Vec<BasicPrefix<'a>>,
        nonce: Noncer<'a>,
    ) -> Self {
        Self {
            said,
            issuer,
            config,
            backer_threshold,
            backers,
            nonce,
        }
    }

    /// The vcp SAID (`d`) — also the registry identifier (`i`).
    #[must_use]
    pub const fn said(&self) -> &Said<'a> {
        &self.said
    }

    /// The identifier anchoring the registry (`ii`).
    #[must_use]
    pub const fn issuer(&self) -> &Identifier<'a> {
        &self.issuer
    }

    /// Configuration traits (`c`).
    #[must_use]
    pub const fn config(&self) -> &Vec<ConfigTrait> {
        &self.config
    }

    /// Backer threshold (`bt`) — 0 exactly when [`Self::backers`] is empty.
    #[must_use]
    pub const fn backer_threshold(&self) -> Toad {
        self.backer_threshold
    }

    /// Backers (`b`).
    #[must_use]
    pub const fn backers(&self) -> &Vec<BasicPrefix<'a>> {
        &self.backers
    }

    /// Registry nonce (`n`).
    #[must_use]
    pub const fn nonce(&self) -> &Noncer<'a> {
        &self.nonce
    }

    /// The sequence number — inception events are pinned to 0.
    #[must_use]
    pub const fn sn(&self) -> Number {
        Number::new(0)
    }

    /// Detach from the source buffer by owning every borrowed field.
    #[must_use]
    pub fn into_static(self) -> RegistryInception<'static> {
        let backers = self
            .backers
            .into_iter()
            .map(BasicPrefix::into_static)
            .collect();
        RegistryInception {
            said: self.said.into_static(),
            issuer: self.issuer.into_static(),
            config: self.config,
            backer_threshold: self.backer_threshold,
            backers,
            nonce: self.nonce.into_static(),
        }
    }
}

/// Registry rotation (`vrt`) — rotates a TEL's backers (keripy `rotate`,
/// `vdr/eventing.py:127-225`).
///
/// Wire fields: `v,t,d,i,p,s,bt,br,ba`. The registry identifier (`i`)
/// is explicit here and distinct from this event's own SAID (`d`). The
/// sequence number is 1 or greater; the wire is authoritative and the
/// registry fold validates it, exactly like a KEL rotation's `s`.
///
/// The backer threshold (`bt`) is the from-wire form: the governing
/// backer set is computed by the fold from the prior registry state
/// plus [`Self::backer_cuts`] and [`Self::backer_additions`] — the
/// event body does not carry the full new list, so the fold validates
/// the threshold against the computed set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryRotation<'a> {
    /// The vrt SAID (`d`).
    said: Said<'a>,
    /// The registry identifier (`i`) — the vcp SAID of the rotated registry.
    registry: Said<'a>,
    /// The prior TEL event's SAID (`p`).
    prior: Said<'a>,
    /// Sequence number (`s`) — 1 or greater.
    sn: Number,
    /// Backer threshold (`bt`) — from-wire form; validated by the fold
    /// against the computed backer set.
    backer_threshold: Toad,
    /// Backers cut (`br`).
    backer_cuts: Vec<BasicPrefix<'a>>,
    /// Backers added (`ba`).
    backer_additions: Vec<BasicPrefix<'a>>,
}

impl<'a> RegistryRotation<'a> {
    /// Wire tag for the `t` field.
    pub const MESSAGE_TYPE: MessageType = MessageType::Vrt;

    /// Creates a new registry rotation from all constituent fields.
    #[cfg(feature = "internals")]
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "constructor mirrors the full field set"
    )]
    pub const fn new(
        said: Said<'a>,
        registry: Said<'a>,
        prior: Said<'a>,
        sn: Number,
        backer_threshold: Toad,
        backer_cuts: Vec<BasicPrefix<'a>>,
        backer_additions: Vec<BasicPrefix<'a>>,
    ) -> Self {
        Self {
            said,
            registry,
            prior,
            sn,
            backer_threshold,
            backer_cuts,
            backer_additions,
        }
    }

    /// The vrt SAID (`d`).
    #[must_use]
    pub const fn said(&self) -> &Said<'a> {
        &self.said
    }

    /// The registry identifier (`i`).
    #[must_use]
    pub const fn registry(&self) -> &Said<'a> {
        &self.registry
    }

    /// The prior TEL event's SAID (`p`).
    #[must_use]
    pub const fn prior(&self) -> &Said<'a> {
        &self.prior
    }

    /// Sequence number (`s`) — 1 or greater.
    #[must_use]
    pub const fn sn(&self) -> Number {
        self.sn
    }

    /// Backer threshold (`bt`) — from-wire form; the fold validates it
    /// against the computed backer set.
    #[must_use]
    pub const fn backer_threshold(&self) -> Toad {
        self.backer_threshold
    }

    /// Backers cut (`br`).
    #[must_use]
    pub const fn backer_cuts(&self) -> &Vec<BasicPrefix<'a>> {
        &self.backer_cuts
    }

    /// Backers added (`ba`).
    #[must_use]
    pub const fn backer_additions(&self) -> &Vec<BasicPrefix<'a>> {
        &self.backer_additions
    }

    /// Detach from the source buffer by owning every borrowed field.
    #[must_use]
    pub fn into_static(self) -> RegistryRotation<'static> {
        let backer_cuts = self
            .backer_cuts
            .into_iter()
            .map(BasicPrefix::into_static)
            .collect();
        let backer_additions = self
            .backer_additions
            .into_iter()
            .map(BasicPrefix::into_static)
            .collect();
        RegistryRotation {
            said: self.said.into_static(),
            registry: self.registry.into_static(),
            prior: self.prior.into_static(),
            sn: self.sn,
            backer_threshold: self.backer_threshold,
            backer_cuts,
            backer_additions,
        }
    }
}

/// Credential issue (`iss`) — registers a credential in a TEL (keripy
/// `issue`, `vdr/eventing.py:227-264`).
///
/// Wire fields: `v,t,d,i,s,ri,dt`. The identifier (`i`) is the
/// credential's SAID (keripy `vcdig`), not the issuer's. There is no
/// `p` field and the sequence number is pinned to 0 by the factory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issue<'a> {
    /// The iss SAID (`d`).
    said: Said<'a>,
    /// The credential's SAID (`i`) — keripy `vcdig`.
    credential_said: Said<'a>,
    /// The registry identifier (`ri`) — the governing vcp SAID.
    registry_said: Said<'a>,
    /// Issuance timestamp (`dt`) — RFC-3339 ISO-8601 text.
    datetime: Cow<'a, str>,
}

impl<'a> Issue<'a> {
    /// Wire tag for the `t` field.
    pub const MESSAGE_TYPE: MessageType = MessageType::Iss;

    /// Creates a new credential issue from all constituent fields.
    #[cfg(feature = "internals")]
    #[must_use]
    pub const fn new(
        said: Said<'a>,
        credential_said: Said<'a>,
        registry_said: Said<'a>,
        datetime: Cow<'a, str>,
    ) -> Self {
        Self {
            said,
            credential_said,
            registry_said,
            datetime,
        }
    }

    /// The iss SAID (`d`).
    #[must_use]
    pub const fn said(&self) -> &Said<'a> {
        &self.said
    }

    /// The credential's SAID (`i`).
    #[must_use]
    pub const fn credential_said(&self) -> &Said<'a> {
        &self.credential_said
    }

    /// The registry identifier (`ri`).
    #[must_use]
    pub const fn registry_said(&self) -> &Said<'a> {
        &self.registry_said
    }

    /// Issuance timestamp (`dt`).
    #[must_use]
    pub fn datetime(&self) -> &str {
        &self.datetime
    }

    /// The sequence number — issue events are pinned to 0.
    #[must_use]
    pub const fn sn(&self) -> Number {
        Number::new(0)
    }

    /// Detach from the source buffer by owning every borrowed field.
    #[must_use]
    pub fn into_static(self) -> Issue<'static> {
        Issue {
            said: self.said.into_static(),
            credential_said: self.credential_said.into_static(),
            registry_said: self.registry_said.into_static(),
            datetime: Cow::Owned(self.datetime.into_owned()),
        }
    }
}

/// Credential revoke (`rev`) — revokes a credential in a TEL (keripy
/// `revoke`, `vdr/eventing.py:267-313`).
///
/// Wire fields: `v,t,d,i,s,ri,p,dt`. The prior event SAID (`p`) chains
/// to the previous `iss` or `rev` digest, and the sequence number is
/// pinned to 1 by the factory — the credential status chain is
/// depth-one in v1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revoke<'a> {
    /// The rev SAID (`d`).
    said: Said<'a>,
    /// The credential's SAID (`i`).
    credential_said: Said<'a>,
    /// The registry identifier (`ri`).
    registry_said: Said<'a>,
    /// The prior TEL event's SAID (`p`) — the previous `iss` or `rev`.
    prior: Said<'a>,
    /// Revocation timestamp (`dt`) — RFC-3339 ISO-8601 text.
    datetime: Cow<'a, str>,
}

impl<'a> Revoke<'a> {
    /// Wire tag for the `t` field.
    pub const MESSAGE_TYPE: MessageType = MessageType::Rev;

    /// Creates a new credential revoke from all constituent fields.
    #[cfg(feature = "internals")]
    #[must_use]
    pub const fn new(
        said: Said<'a>,
        credential_said: Said<'a>,
        registry_said: Said<'a>,
        prior: Said<'a>,
        datetime: Cow<'a, str>,
    ) -> Self {
        Self {
            said,
            credential_said,
            registry_said,
            prior,
            datetime,
        }
    }

    /// The rev SAID (`d`).
    #[must_use]
    pub const fn said(&self) -> &Said<'a> {
        &self.said
    }

    /// The credential's SAID (`i`).
    #[must_use]
    pub const fn credential_said(&self) -> &Said<'a> {
        &self.credential_said
    }

    /// The registry identifier (`ri`).
    #[must_use]
    pub const fn registry_said(&self) -> &Said<'a> {
        &self.registry_said
    }

    /// The prior TEL event's SAID (`p`).
    #[must_use]
    pub const fn prior(&self) -> &Said<'a> {
        &self.prior
    }

    /// Revocation timestamp (`dt`).
    #[must_use]
    pub fn datetime(&self) -> &str {
        &self.datetime
    }

    /// The sequence number — revoke events are pinned to 1.
    #[must_use]
    pub const fn sn(&self) -> Number {
        Number::new(1)
    }

    /// Detach from the source buffer by owning every borrowed field.
    #[must_use]
    pub fn into_static(self) -> Revoke<'static> {
        Revoke {
            said: self.said.into_static(),
            credential_said: self.credential_said.into_static(),
            registry_said: self.registry_said.into_static(),
            prior: self.prior.into_static(),
            datetime: Cow::Owned(self.datetime.into_owned()),
        }
    }
}

/// Backed credential issue (`bis`) — a backer's endorsement of an `iss`
/// (keripy `backerIssue`, `vdr/eventing.py:316-365`).
///
/// Wire fields: `v,t,d,i,ii,s,ra,dt`. The registry is named by `ii`
/// (not `ri` as on `iss`), and the `ra` anchor carries the backed TEL
/// event's coordinate. The sequence number is pinned to 0.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackedIssue<'a> {
    /// The bis SAID (`d`).
    said: Said<'a>,
    /// The credential's SAID (`i`).
    credential_said: Said<'a>,
    /// The registry identifier (`ii`).
    registry_said: Said<'a>,
    /// The `ra` anchor — the [`Seal::Event`] shape (keripy `SealEvent`):
    /// the backed TEL event's `(i, s, d)` coordinate in the registry's
    /// own TEL. Required — a backed event without its anchor is
    /// unrepresentable; the codec enforces the event shape at parse.
    anchor: Seal<'a>,
    /// Backing timestamp (`dt`) — RFC-3339 ISO-8601 text.
    datetime: Cow<'a, str>,
}

impl<'a> BackedIssue<'a> {
    /// Wire tag for the `t` field.
    pub const MESSAGE_TYPE: MessageType = MessageType::Bis;

    /// Creates a new backed issue from all constituent fields.
    #[cfg(feature = "internals")]
    #[must_use]
    pub const fn new(
        said: Said<'a>,
        credential_said: Said<'a>,
        registry_said: Said<'a>,
        anchor: Seal<'a>,
        datetime: Cow<'a, str>,
    ) -> Self {
        Self {
            said,
            credential_said,
            registry_said,
            anchor,
            datetime,
        }
    }

    /// The bis SAID (`d`).
    #[must_use]
    pub const fn said(&self) -> &Said<'a> {
        &self.said
    }

    /// The credential's SAID (`i`).
    #[must_use]
    pub const fn credential_said(&self) -> &Said<'a> {
        &self.credential_said
    }

    /// The registry identifier (`ii`).
    #[must_use]
    pub const fn registry_said(&self) -> &Said<'a> {
        &self.registry_said
    }

    /// The `ra` anchor — the backed TEL event's coordinate.
    #[must_use]
    pub const fn anchor(&self) -> &Seal<'a> {
        &self.anchor
    }

    /// Backing timestamp (`dt`).
    #[must_use]
    pub fn datetime(&self) -> &str {
        &self.datetime
    }

    /// The sequence number — backed issue events are pinned to 0.
    #[must_use]
    pub const fn sn(&self) -> Number {
        Number::new(0)
    }

    /// Detach from the source buffer by owning every borrowed field.
    #[must_use]
    pub fn into_static(self) -> BackedIssue<'static> {
        BackedIssue {
            said: self.said.into_static(),
            credential_said: self.credential_said.into_static(),
            registry_said: self.registry_said.into_static(),
            anchor: self.anchor.into_static(),
            datetime: Cow::Owned(self.datetime.into_owned()),
        }
    }
}

/// Backed credential revoke (`brv`) — a backer's endorsement of a `rev`
/// (keripy `backerRevoke`, `vdr/eventing.py:368-419`).
///
/// Wire fields: `v,t,d,i,s,p,ra,dt` — no `ii` and no `ri`; the registry
/// is reachable through the [`Self::anchor`] coordinate. The prior event
/// SAID (`p`) chains to the previous TEL event, and the sequence number
/// is pinned to 1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackedRevoke<'a> {
    /// The brv SAID (`d`).
    said: Said<'a>,
    /// The credential's SAID (`i`).
    credential_said: Said<'a>,
    /// The prior TEL event's SAID (`p`).
    prior: Said<'a>,
    /// The `ra` anchor — the [`Seal::Event`] shape (keripy `SealEvent`):
    /// the backed TEL event's `(i, s, d)` coordinate in the registry's
    /// own TEL. Required — a backed event without its anchor is
    /// unrepresentable; the codec enforces the event shape at parse.
    anchor: Seal<'a>,
    /// Backing timestamp (`dt`) — RFC-3339 ISO-8601 text.
    datetime: Cow<'a, str>,
}

impl<'a> BackedRevoke<'a> {
    /// Wire tag for the `t` field.
    pub const MESSAGE_TYPE: MessageType = MessageType::Brv;

    /// Creates a new backed revoke from all constituent fields.
    #[cfg(feature = "internals")]
    #[must_use]
    pub const fn new(
        said: Said<'a>,
        credential_said: Said<'a>,
        prior: Said<'a>,
        anchor: Seal<'a>,
        datetime: Cow<'a, str>,
    ) -> Self {
        Self {
            said,
            credential_said,
            prior,
            anchor,
            datetime,
        }
    }

    /// The brv SAID (`d`).
    #[must_use]
    pub const fn said(&self) -> &Said<'a> {
        &self.said
    }

    /// The credential's SAID (`i`).
    #[must_use]
    pub const fn credential_said(&self) -> &Said<'a> {
        &self.credential_said
    }

    /// The prior TEL event's SAID (`p`).
    #[must_use]
    pub const fn prior(&self) -> &Said<'a> {
        &self.prior
    }

    /// The `ra` anchor — the backed TEL event's coordinate.
    #[must_use]
    pub const fn anchor(&self) -> &Seal<'a> {
        &self.anchor
    }

    /// Backing timestamp (`dt`).
    #[must_use]
    pub fn datetime(&self) -> &str {
        &self.datetime
    }

    /// The sequence number — backed revoke events are pinned to 1.
    #[must_use]
    pub const fn sn(&self) -> Number {
        Number::new(1)
    }

    /// Detach from the source buffer by owning every borrowed field.
    #[must_use]
    pub fn into_static(self) -> BackedRevoke<'static> {
        BackedRevoke {
            said: self.said.into_static(),
            credential_said: self.credential_said.into_static(),
            prior: self.prior.into_static(),
            anchor: self.anchor.into_static(),
            datetime: Cow::Owned(self.datetime.into_owned()),
        }
    }
}

/// A Transaction Event Log event — the six registry ilks.
///
/// Uniform accessors ([`Self::message_type`], [`Self::sn`],
/// [`Self::said`]) apply to every variant; ilk-specific fields live on
/// the variant types ([`RegistryInception`], [`RegistryRotation`],
/// [`Issue`], [`Revoke`], [`BackedIssue`], [`BackedRevoke`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TelEvent<'a> {
    /// Registry inception (`vcp`).
    RegistryInception(RegistryInception<'a>),
    /// Registry rotation (`vrt`).
    RegistryRotation(RegistryRotation<'a>),
    /// Credential issue (`iss`).
    Issue(Issue<'a>),
    /// Credential revoke (`rev`).
    Revoke(Revoke<'a>),
    /// Backed credential issue (`bis`).
    BackedIssue(BackedIssue<'a>),
    /// Backed credential revoke (`brv`).
    BackedRevoke(BackedRevoke<'a>),
}

impl<'a> TelEvent<'a> {
    /// The wire tag (`t`) of this TEL event.
    #[must_use]
    pub const fn message_type(&self) -> MessageType {
        match self {
            Self::RegistryInception(_) => MessageType::Vcp,
            Self::RegistryRotation(_) => MessageType::Vrt,
            Self::Issue(_) => MessageType::Iss,
            Self::Revoke(_) => MessageType::Rev,
            Self::BackedIssue(_) => MessageType::Bis,
            Self::BackedRevoke(_) => MessageType::Brv,
        }
    }

    /// The sequence number (`s`). Inception, issue, and backed issue are
    /// pinned to 0; revoke and backed revoke are pinned to 1; rotation
    /// carries its own.
    #[must_use]
    pub const fn sn(&self) -> Number {
        match self {
            Self::RegistryInception(event) => event.sn(),
            Self::RegistryRotation(event) => event.sn(),
            Self::Issue(event) => event.sn(),
            Self::Revoke(event) => event.sn(),
            Self::BackedIssue(event) => event.sn(),
            Self::BackedRevoke(event) => event.sn(),
        }
    }

    /// The event's own SAID (`d`).
    #[must_use]
    pub const fn said(&self) -> &Said<'a> {
        match self {
            Self::RegistryInception(event) => event.said(),
            Self::RegistryRotation(event) => event.said(),
            Self::Issue(event) => event.said(),
            Self::Revoke(event) => event.said(),
            Self::BackedIssue(event) => event.said(),
            Self::BackedRevoke(event) => event.said(),
        }
    }

    /// Detach from the source buffer by owning every borrowed field.
    #[must_use]
    pub fn into_static(self) -> TelEvent<'static> {
        match self {
            Self::RegistryInception(event) => TelEvent::RegistryInception(event.into_static()),
            Self::RegistryRotation(event) => TelEvent::RegistryRotation(event.into_static()),
            Self::Issue(event) => TelEvent::Issue(event.into_static()),
            Self::Revoke(event) => TelEvent::Revoke(event.into_static()),
            Self::BackedIssue(event) => TelEvent::BackedIssue(event.into_static()),
            Self::BackedRevoke(event) => TelEvent::BackedRevoke(event.into_static()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::borrow::Cow;
    use alloc::vec;
    use cesr::core::matter::builder::MatterBuilder;
    use cesr::core::matter::code::{DigestCode, NoncerCode, VerKeyCode};

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

    fn make_noncer() -> Noncer<'static> {
        MatterBuilder::new()
            .with_code(NoncerCode::Salt128)
            .with_raw(Cow::<[u8]>::Owned(vec![0u8; 16]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn saider() -> Said<'static> {
        make_saider()
    }

    #[test]
    fn construct_registry_inception_and_access_fields() {
        let event = RegistryInception::new(
            saider(),
            Identifier::Basic(make_prefixer()),
            vec![ConfigTrait::from_code("NB").unwrap()],
            Toad::exact(1, 1).unwrap(),
            vec![make_prefixer()],
            make_noncer(),
        );
        assert_eq!(RegistryInception::MESSAGE_TYPE, MessageType::Vcp);
        assert_eq!(event.sn().value(), 0);
        assert_eq!(event.issuer(), &Identifier::Basic(make_prefixer()));
        assert_eq!(event.config().len(), 1);
        assert_eq!(event.backer_threshold().value(), 1);
        assert_eq!(event.backers().len(), 1);
        assert_eq!(event.nonce(), &make_noncer());
        // The SAID doubles as the registry identifier (i == d).
        assert_eq!(event.said(), &saider());
    }

    #[test]
    fn construct_registry_rotation_and_access_fields() {
        let event = RegistryRotation::new(
            saider(),
            saider(),
            saider(),
            Number::new(1),
            Toad::from_wire(1),
            vec![make_prefixer()],
            vec![make_prefixer(), make_prefixer()],
        );
        assert_eq!(RegistryRotation::MESSAGE_TYPE, MessageType::Vrt);
        assert_eq!(event.sn().value(), 1);
        assert_eq!(event.registry(), &saider());
        assert_eq!(event.prior(), &saider());
        assert_eq!(event.backer_threshold().value(), 1);
        assert_eq!(event.backer_cuts().len(), 1);
        assert_eq!(event.backer_additions().len(), 2);
    }

    #[test]
    fn construct_issue_and_access_fields() {
        let event = Issue::new(
            saider(),
            saider(),
            saider(),
            Cow::Borrowed("2026-09-17T12:00:00+00:00"),
        );
        assert_eq!(Issue::MESSAGE_TYPE, MessageType::Iss);
        assert_eq!(event.sn().value(), 0);
        assert_eq!(event.credential_said(), &saider());
        assert_eq!(event.registry_said(), &saider());
        assert_eq!(event.datetime(), "2026-09-17T12:00:00+00:00");
    }

    #[test]
    fn construct_revoke_and_access_fields() {
        let event = Revoke::new(
            saider(),
            saider(),
            saider(),
            saider(),
            Cow::Borrowed("2026-09-17T12:00:00+00:00"),
        );
        assert_eq!(Revoke::MESSAGE_TYPE, MessageType::Rev);
        assert_eq!(event.sn().value(), 1);
        assert_eq!(event.credential_said(), &saider());
        assert_eq!(event.registry_said(), &saider());
        assert_eq!(event.prior(), &saider());
        assert_eq!(event.datetime(), "2026-09-17T12:00:00+00:00");
    }

    #[test]
    fn construct_backed_issue_with_required_anchor() {
        let anchor = Seal::Event {
            i: Identifier::SelfAddressing(saider()),
            s: Number::new(0),
            d: saider(),
        };
        let event = BackedIssue::new(
            saider(),
            saider(),
            saider(),
            anchor.clone(),
            Cow::Borrowed("2026-09-17T12:00:00+00:00"),
        );
        assert_eq!(BackedIssue::MESSAGE_TYPE, MessageType::Bis);
        assert_eq!(event.sn().value(), 0);
        assert_eq!(event.credential_said(), &saider());
        assert_eq!(event.registry_said(), &saider());
        assert_eq!(event.anchor(), &anchor);
        assert_eq!(event.datetime(), "2026-09-17T12:00:00+00:00");
    }

    #[test]
    fn construct_backed_revoke_with_required_anchor() {
        let anchor = Seal::Event {
            i: Identifier::SelfAddressing(saider()),
            s: Number::new(1),
            d: saider(),
        };
        let event = BackedRevoke::new(
            saider(),
            saider(),
            saider(),
            anchor.clone(),
            Cow::Borrowed("2026-09-17T12:00:00+00:00"),
        );
        assert_eq!(BackedRevoke::MESSAGE_TYPE, MessageType::Brv);
        assert_eq!(event.sn().value(), 1);
        assert_eq!(event.credential_said(), &saider());
        assert_eq!(event.prior(), &saider());
        assert_eq!(event.anchor(), &anchor);
        assert_eq!(event.datetime(), "2026-09-17T12:00:00+00:00");
    }

    #[test]
    fn tel_event_dispatch_matches_variants() {
        let anchor = Seal::Event {
            i: Identifier::SelfAddressing(saider()),
            s: Number::new(0),
            d: saider(),
        };
        let events = [
            TelEvent::RegistryInception(RegistryInception::new(
                saider(),
                Identifier::Basic(make_prefixer()),
                vec![],
                Toad::exact(0, 0).unwrap(),
                vec![],
                make_noncer(),
            )),
            TelEvent::RegistryRotation(RegistryRotation::new(
                saider(),
                saider(),
                saider(),
                Number::new(2),
                Toad::from_wire(0),
                vec![],
                vec![],
            )),
            TelEvent::Issue(Issue::new(
                saider(),
                saider(),
                saider(),
                Cow::Borrowed("2026-09-17T12:00:00+00:00"),
            )),
            TelEvent::Revoke(Revoke::new(
                saider(),
                saider(),
                saider(),
                saider(),
                Cow::Borrowed("2026-09-17T12:00:00+00:00"),
            )),
            TelEvent::BackedIssue(BackedIssue::new(
                saider(),
                saider(),
                saider(),
                anchor.clone(),
                Cow::Borrowed("2026-09-17T12:00:00+00:00"),
            )),
            TelEvent::BackedRevoke(BackedRevoke::new(
                saider(),
                saider(),
                saider(),
                anchor,
                Cow::Borrowed("2026-09-17T12:00:00+00:00"),
            )),
        ];

        let expected = [
            (MessageType::Vcp, 0u128),
            (MessageType::Vrt, 2),
            (MessageType::Iss, 0),
            (MessageType::Rev, 1),
            (MessageType::Bis, 0),
            (MessageType::Brv, 1),
        ];
        for (event, (message_type, sn)) in events.iter().zip(expected) {
            assert_eq!(event.message_type(), message_type);
            assert_eq!(event.sn().value(), sn);
            assert_eq!(event.said(), &saider());
        }
    }

    #[test]
    fn into_static_detaches_borrowed_fields() {
        let event = Issue::new(
            saider(),
            saider(),
            saider(),
            Cow::Borrowed("2026-09-17T12:00:00+00:00"),
        );
        let owned = event.into_static();
        assert_eq!(owned.datetime(), "2026-09-17T12:00:00+00:00");
        assert_eq!(owned.credential_said(), &saider());

        let anchored = BackedIssue::new(
            saider(),
            saider(),
            saider(),
            Seal::Event {
                i: Identifier::SelfAddressing(saider()),
                s: Number::new(0),
                d: saider(),
            },
            Cow::Borrowed("2026-09-17T12:00:00+00:00"),
        );
        let owned_anchored = anchored.into_static();
        assert_eq!(owned_anchored.datetime(), "2026-09-17T12:00:00+00:00");
        assert!(matches!(owned_anchored.anchor(), Seal::Event { .. }));
    }
}
