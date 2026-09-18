//! The exn exchange envelope model — codec-facing vocabulary for KERI's
//! `exn` ilk (keripy `SerderKERI`, protocol `KERI`, version 1.0).
//!
//! The envelope is data, not a conversation: it names a route ([`Exn::route`]),
//! a payload ([`Exn::attributes`]), and optionally embeds ([`Exn::embeds`]).
//! The six IPEX routes travel in it through [`crate::ipex`]'s typed builders
//! and parsers; nothing here carries exchange-protocol state.
//!
//! Wire laws pinned against keripy `de59bc7d` (`peer/exchanging.py:
//! `specialExchange`, `core/eventing.py: `exchange`):
//!
//! - `core.exchange` renders `v,t,d,i,rp,p,dt,r,q,a` — no `e`.
//! - `specialExchange` always renders `e`: `{}` when there are no embeds,
//!   otherwise `{<label>:<SAD>...,"d":<SAID>}` — the embeds map's own `d`
//!   is appended **after** the labels (`e["d"] = ""` then
//!   `Saider.saidify`, which updates the existing key in place).
//! - `rp` and `p` are always present; keripy writes `""` when unset.
//! - `a` is a field map, or — only for the v1 ESSR form — a bare SAID
//!   string; it is never independently SAIDified.

use alloc::borrow::Cow;
use alloc::vec::Vec;

use keri_events::Identifier;
use keri_events::acdc::SadBlock;
use keri_events::primitive::Said;

/// An exn exchange envelope (keripy `SerderKERI`, ilk `exn`).
///
/// Constructed by the [`crate::ipex`] builders or deserialized from wire
/// bytes ([`crate::Deserialize`]); there is no public field-by-field
/// constructor — the envelope's invariants (fixed field order, always-present
/// `rp`/`p`/`dt`/`q`) are established by construction paths that own them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exn<'a> {
    /// The envelope's SAID (`d`) — its identity as a self-addressing SAD.
    said: Said<'a>,
    /// Sender identifier (`i`) — required.
    issuer: Identifier<'a>,
    /// Receiver identifier (`rp`) — keripy's reply-to; `""` on the wire for
    /// the IPEX factories, so absent here.
    reply_to: Option<Identifier<'a>>,
    /// Prior exchange message SAID (`p`) — the conversation chain link;
    /// `""` on the wire when this route starts a conversation.
    prior: Option<Said<'a>>,
    /// Creation timestamp (`dt`) — RFC-3339 ISO-8601 text. Builders take it
    /// explicitly; nothing here reads a clock.
    datetime: Cow<'a, str>,
    /// Route (`r`) — the handler path, e.g. `/ipex/grant`. Stored verbatim;
    /// the IPEX layer types the six `/ipex/*` routes.
    route: Cow<'a, str>,
    /// Modifiers (`q`) — a generic canonical JSON object map; `{}` for every
    /// IPEX route at this pin.
    modifiers: SadBlock<'a>,
    /// Attributes (`a`) — the route's payload map, or the v1 ESSR SAID form.
    attributes: ExnAttributes<'a>,
    /// Embeds (`e`) — absent, empty, or the SAIDified per-label map.
    embeds: ExnEmbeds<'a>,
}

impl<'a> Exn<'a> {
    /// The envelope's SAID (`d`).
    #[must_use]
    pub const fn said(&self) -> &Said<'a> {
        &self.said
    }

    /// The sender identifier (`i`).
    #[must_use]
    pub const fn issuer(&self) -> &Identifier<'a> {
        &self.issuer
    }

    /// The receiver identifier (`rp`) — `None` for the wire `""` form.
    #[must_use]
    pub const fn reply_to(&self) -> Option<&Identifier<'a>> {
        self.reply_to.as_ref()
    }

    /// The prior exchange message SAID (`p`) — `None` for the wire `""` form.
    #[must_use]
    pub const fn prior(&self) -> Option<&Said<'a>> {
        self.prior.as_ref()
    }

    /// The creation timestamp (`dt`) — RFC-3339 ISO-8601 text.
    #[must_use]
    pub fn datetime(&self) -> &str {
        &self.datetime
    }

    /// The route (`r`) — the handler path, e.g. `/ipex/grant`.
    #[must_use]
    pub fn route(&self) -> &str {
        &self.route
    }

    /// The modifiers map (`q`) — a generic canonical JSON object.
    #[must_use]
    pub const fn modifiers(&self) -> &SadBlock<'a> {
        &self.modifiers
    }

    /// The attributes (`a`) — the route's payload, block or SAID form.
    #[must_use]
    pub const fn attributes(&self) -> &ExnAttributes<'a> {
        &self.attributes
    }

    /// The embeds (`e`) — absent, empty, or the per-label map.
    #[must_use]
    pub const fn embeds(&self) -> &ExnEmbeds<'a> {
        &self.embeds
    }

    /// The embedded SAD carried under one `e` label, if the embeds map form
    /// carries it. The payload is the embedded message's canonical body,
    /// preserved verbatim.
    #[must_use]
    pub fn embed(&self, label: &str) -> Option<&SadBlock<'a>> {
        match &self.embeds {
            ExnEmbeds::Map { entries, .. } => entries
                .iter()
                .find(|(entry_label, _)| entry_label.as_ref() == label)
                .map(|(_, block)| block),
            _ => None,
        }
    }

    /// Detach from the source buffer by owning every borrowed field.
    #[must_use]
    pub fn into_static(self) -> Exn<'static> {
        Exn {
            said: self.said.into_static(),
            issuer: self.issuer.into_static(),
            reply_to: self.reply_to.map(keri_events::Identifier::into_static),
            prior: self.prior.map(Said::into_static),
            datetime: Cow::Owned(self.datetime.into_owned()),
            route: Cow::Owned(self.route.into_owned()),
            modifiers: self.modifiers.into_static(),
            attributes: self.attributes.into_static(),
            embeds: self.embeds.into_static(),
        }
    }

    /// Crate-internal constructor — the single establishment point for the
    /// envelope's invariants. The [`crate::ipex`] builders and the parser's
    /// typed lift are the only callers.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "one argument per wire field; the constructor is the crate's single establishment point for the envelope invariants"
    )]
    pub(crate) const fn new(
        said: Said<'a>,
        issuer: Identifier<'a>,
        reply_to: Option<Identifier<'a>>,
        prior: Option<Said<'a>>,
        datetime: Cow<'a, str>,
        route: Cow<'a, str>,
        modifiers: SadBlock<'a>,
        attributes: ExnAttributes<'a>,
        embeds: ExnEmbeds<'a>,
    ) -> Self {
        Self {
            said,
            issuer,
            reply_to,
            prior,
            datetime,
            route,
            modifiers,
            attributes,
            embeds,
        }
    }
}

/// The exn `a` (attributes) field: the route's payload map, or — only for
/// the v1 ESSR exchange form — the bare SAID of an encrypted attachment.
///
/// In keripy the SAID form appears in the `diger` branch of
/// `peer/exchanging.py:specialExchange`; it is never independently
/// SAIDified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExnAttributes<'a> {
    /// The payload as a bare SAID string (v1 ESSR form).
    Said(Said<'a>),
    /// The payload as a canonical JSON object, carried verbatim.
    Block(SadBlock<'a>),
}

impl ExnAttributes<'_> {
    /// Detach from the source buffer by owning the payload.
    #[must_use]
    pub fn into_static(self) -> ExnAttributes<'static> {
        match self {
            Self::Said(said) => ExnAttributes::Said(said.into_static()),
            Self::Block(block) => ExnAttributes::Block(block.into_static()),
        }
    }
}

/// The exn `e` (embeds) field in its three verified v1 forms.
///
/// keripy `specialExchange` always renders `e` (empty `{}` when there are no
/// embeds) while `core.exchange` omits the key entirely — a compatible
/// parser must accept all three forms and a compatible writer must
/// reproduce the route's own form, not normalize between them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExnEmbeds<'a> {
    /// `core.exchange` — the `e` key is absent entirely.
    Absent,
    /// `specialExchange` with no embeds — the wire `e` is `{}` with no
    /// inner `d`.
    Empty,
    /// `specialExchange` with embeds. Each entry's payload is the embedded
    /// message's canonical body, carried verbatim. The map's own SAID
    /// (`d`) covers the entries and is the map's **last** key on the wire —
    /// keripy appends `e["d"]` after the labels and `Saider.saidify`
    /// updates the existing key in place.
    Map {
        /// The embeds map's own SAID (`d`).
        said: Said<'a>,
        /// The embeds in wire order: label → embedded canonical body.
        entries: Vec<(Cow<'a, str>, SadBlock<'a>)>,
    },
}

impl ExnEmbeds<'_> {
    /// Detach from the source buffer by owning every borrowed field.
    #[must_use]
    pub fn into_static(self) -> ExnEmbeds<'static> {
        match self {
            Self::Absent => ExnEmbeds::Absent,
            Self::Empty => ExnEmbeds::Empty,
            Self::Map { said, entries } => ExnEmbeds::Map {
                said: said.into_static(),
                entries: entries
                    .into_iter()
                    .map(|(label, block)| (Cow::Owned(label.into_owned()), block.into_static()))
                    .collect(),
            },
        }
    }
}
