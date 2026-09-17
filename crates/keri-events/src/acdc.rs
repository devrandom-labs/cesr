//! ACDC — Authentic Chained Data Container v1.1 credential SADs (keripy
//! `SerderACDC`, `core/serdering.py:2509-2700` at pin
//! `de59bc7d834955c5b0273c62f6b8b6a0df150dc3`).
//!
//! A credential is a self-addressing field map: unlike a KEL/TEL event it
//! has no `t` ilk and no sequence number — its identity is its SAID (`d`).
//! Section fields (`s`, `a`, `e`, `r`, and the registry reference `ri`)
//! are **block-or-SAID polymorphic**: the wire either carries the full
//! block inline or a bare SAID reference to it ([`AcdcField`]). The
//! aggregate fields `A`/`E`/`R` are the digest forms of those sections.
//!
//! Deliberate scope boundaries, per the approved blueprint:
//!
//! - Edge/rule blocks are typed as the generic SAIDified block
//!   ([`SadBlock`]) only. The ACDC spec's typed edge-node forms
//!   (`sad`/`nest` embeddings) are absent from the pinned keripy
//!   `SerderACDC` (grep for `nest`: no hits) and are a
//!   needs-verification item — they land in a later, bounded pass
//!   rather than being guessed here.
//! - The registry reference (`ri`) accepts the TEL SAID (the verified
//!   keripy v1 wire shape) *and* a status block, per the blueprint;
//!   the codec lane validates which forms the wire may carry.
//! - The `v` version string belongs to the codec, as for the events.

use alloc::borrow::Cow;

use cesr::core::primitives::Noncer;

use crate::identifier::Identifier;
use crate::primitive::{Digest, Said};

/// A SAIDified field map carried verbatim — the generic ACDC block.
///
/// Attributes, edges, rules, and status blocks are schema-defined or
/// spec-pending field maps: this crate preserves their compact canonical
/// JSON payload byte-for-byte and does not itself parse JSON (the same
/// doctrine as [`crate::OpaqueSeal`]); `keri-codec` enforces
/// well-formedness and SAID agreement at the boundary, and its generic
/// SAD spine parses the payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SadBlock<'a>(Cow<'a, str>);

impl<'a> SadBlock<'a> {
    /// Creates a new generic SAD block.
    #[cfg(feature = "internals")]
    #[must_use]
    pub const fn new(payload: Cow<'a, str>) -> Self {
        Self(payload)
    }

    /// The block's verbatim payload — one well-formed *compact* JSON
    /// object (the form keripy's canonical `json.dumps(...,
    /// separators=(",", ":"))` emits).
    #[must_use]
    pub fn payload(&self) -> &str {
        &self.0
    }

    /// Detach from the source buffer by owning the payload.
    #[must_use]
    pub fn into_static(self) -> SadBlock<'static> {
        SadBlock(Cow::Owned(self.0.into_owned()))
    }
}

/// Block-or-SAID polymorphism for an ACDC section field.
///
/// The wire either references the section by its bare SAID
/// ([`AcdcField::Said`]) or carries the full block inline
/// ([`AcdcField::Block`]) — keripy's `schema`/`attrib`/`edge`/`rule`
/// properties each branch on exactly this shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AcdcField<'a, B> {
    /// A bare SAID — the section's content lives elsewhere (in the
    /// schema cache, a chained credential, or the TEL).
    Said(Said<'a>),
    /// The section's full block, carried inline.
    Block(B),
}

impl<'a> AcdcField<'a, SadBlock<'a>> {
    /// Detach from the source buffer by owning every borrowed field.
    #[must_use]
    pub fn into_static(self) -> AcdcField<'static, SadBlock<'static>> {
        match self {
            Self::Said(said) => AcdcField::Said(said.into_static()),
            Self::Block(block) => AcdcField::Block(block.into_static()),
        }
    }
}

/// An ACDC v1.1 credential SAD (keripy `SerderACDC`, protocol
/// `Protocols.acdc`).
///
/// Wire fields: `v,d,u?,i?,ri?,s,a?,A?,e?,E?,r?,R?,p?` — `d` and `s`
/// are required, everything else is optional. The credential's own SAID
/// (`d`) is its identity; there is no `t` ilk and no sequence number.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Acdc<'a> {
    /// The credential's SAID (`d`) — its identity as a self-addressing
    /// SAD.
    said: Said<'a>,
    /// Salty uuid nonce (`u`) — the privacy-preserving randomizer
    /// (keripy `uuid`, a CESR `Noncer`).
    nonce: Option<Noncer<'a>>,
    /// Issuer identifier (`i`) — required on the wire for issuance
    /// ilks, absent for chained-data credentials.
    issuer: Option<Identifier<'a>>,
    /// Registry reference (`ri`) — the TEL SAID (verified keripy v1
    /// shape) or a status block, per the blueprint.
    registry: Option<AcdcField<'a, SadBlock<'a>>>,
    /// Schema (`s`) — required; block or bare SAID (keripy `schema`).
    schema: AcdcField<'a, SadBlock<'a>>,
    /// Attributes (`a`) — block or bare SAID; the block's `a.i` names
    /// the issuee (keripy `attrib`/`issuee`).
    attributes: Option<AcdcField<'a, SadBlock<'a>>>,
    /// Aggregate attributes (`A`) — the digest form of the attributes
    /// section (keripy `aggreg`).
    aggregate_attributes: Option<Digest<'a>>,
    /// Edges (`e`) — block or bare SAID (keripy `edge`); typed as the
    /// generic SAIDified block pending the bounded edge-form pass.
    edges: Option<AcdcField<'a, SadBlock<'a>>>,
    /// Aggregate edges (`E`) — the digest form of the edges section.
    aggregate_edges: Option<Digest<'a>>,
    /// Rules (`r`) — block or bare SAID (keripy `rule`).
    rules: Option<AcdcField<'a, SadBlock<'a>>>,
    /// Aggregate rules (`R`) — the digest form of the rules section.
    aggregate_rules: Option<Digest<'a>>,
    /// Prior chained-data SAID (`p`) — the credential this one chains
    /// from (keripy `Serder.prior`).
    prior: Option<Said<'a>>,
}

impl<'a> Acdc<'a> {
    /// Creates a new credential from all constituent fields.
    #[cfg(feature = "internals")]
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "constructor mirrors the full field set"
    )]
    pub const fn new(
        said: Said<'a>,
        nonce: Option<Noncer<'a>>,
        issuer: Option<Identifier<'a>>,
        registry: Option<AcdcField<'a, SadBlock<'a>>>,
        schema: AcdcField<'a, SadBlock<'a>>,
        attributes: Option<AcdcField<'a, SadBlock<'a>>>,
        aggregate_attributes: Option<Digest<'a>>,
        edges: Option<AcdcField<'a, SadBlock<'a>>>,
        aggregate_edges: Option<Digest<'a>>,
        rules: Option<AcdcField<'a, SadBlock<'a>>>,
        aggregate_rules: Option<Digest<'a>>,
        prior: Option<Said<'a>>,
    ) -> Self {
        Self {
            said,
            nonce,
            issuer,
            registry,
            schema,
            attributes,
            aggregate_attributes,
            edges,
            aggregate_edges,
            rules,
            aggregate_rules,
            prior,
        }
    }

    /// The credential's SAID (`d`).
    #[must_use]
    pub const fn said(&self) -> &Said<'a> {
        &self.said
    }

    /// Salty uuid nonce (`u`).
    #[must_use]
    pub const fn nonce(&self) -> Option<&Noncer<'a>> {
        self.nonce.as_ref()
    }

    /// Issuer identifier (`i`).
    #[must_use]
    pub const fn issuer(&self) -> Option<&Identifier<'a>> {
        self.issuer.as_ref()
    }

    /// Registry reference (`ri`).
    #[must_use]
    pub const fn registry(&self) -> Option<&AcdcField<'a, SadBlock<'a>>> {
        self.registry.as_ref()
    }

    /// Schema (`s`).
    #[must_use]
    pub const fn schema(&self) -> &AcdcField<'a, SadBlock<'a>> {
        &self.schema
    }

    /// Attributes (`a`).
    #[must_use]
    pub const fn attributes(&self) -> Option<&AcdcField<'a, SadBlock<'a>>> {
        self.attributes.as_ref()
    }

    /// Aggregate attributes (`A`).
    #[must_use]
    pub const fn aggregate_attributes(&self) -> Option<&Digest<'a>> {
        self.aggregate_attributes.as_ref()
    }

    /// Edges (`e`).
    #[must_use]
    pub const fn edges(&self) -> Option<&AcdcField<'a, SadBlock<'a>>> {
        self.edges.as_ref()
    }

    /// Aggregate edges (`E`).
    #[must_use]
    pub const fn aggregate_edges(&self) -> Option<&Digest<'a>> {
        self.aggregate_edges.as_ref()
    }

    /// Rules (`r`).
    #[must_use]
    pub const fn rules(&self) -> Option<&AcdcField<'a, SadBlock<'a>>> {
        self.rules.as_ref()
    }

    /// Aggregate rules (`R`).
    #[must_use]
    pub const fn aggregate_rules(&self) -> Option<&Digest<'a>> {
        self.aggregate_rules.as_ref()
    }

    /// Prior chained-data SAID (`p`).
    #[must_use]
    pub const fn prior(&self) -> Option<&Said<'a>> {
        self.prior.as_ref()
    }

    /// Detach from the source buffer by owning every borrowed field.
    #[must_use]
    pub fn into_static(self) -> Acdc<'static> {
        Acdc {
            said: self.said.into_static(),
            nonce: self.nonce.map(Noncer::into_static),
            issuer: self.issuer.map(Identifier::into_static),
            registry: self.registry.map(AcdcField::into_static),
            schema: self.schema.into_static(),
            attributes: self.attributes.map(AcdcField::into_static),
            aggregate_attributes: self.aggregate_attributes.map(Digest::into_static),
            edges: self.edges.map(AcdcField::into_static),
            aggregate_edges: self.aggregate_edges.map(Digest::into_static),
            rules: self.rules.map(AcdcField::into_static),
            aggregate_rules: self.aggregate_rules.map(Digest::into_static),
            prior: self.prior.map(Said::into_static),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::borrow::ToOwned;
    use alloc::vec;
    use cesr::core::matter::builder::MatterBuilder;
    use cesr::core::matter::code::{DigestCode, NoncerCode, VerKeyCode};

    const SCHEMA_BLOCK: &str = r#"{"d":"Elk00 forms","v":"ACDC10"}"#;

    /// The block payload behind a block-carried field, for assertions.
    fn payload_of<'a>(field: &'a AcdcField<'a, SadBlock<'a>>) -> Option<&'a str> {
        match field {
            AcdcField::Block(block) => Some(block.payload()),
            AcdcField::Said(_) => None,
        }
    }

    fn saider() -> Said<'static> {
        Said::from_matter(
            MatterBuilder::new()
                .with_code(DigestCode::Blake3_256)
                .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
                .unwrap()
                .build()
                .unwrap(),
        )
    }

    fn digester() -> Digest<'static> {
        Digest::from_matter(
            MatterBuilder::new()
                .with_code(DigestCode::Blake3_256)
                .with_raw(Cow::<[u8]>::Owned(vec![1u8; 32]))
                .unwrap()
                .build()
                .unwrap(),
        )
    }

    fn block() -> SadBlock<'static> {
        SadBlock::new(Cow::<str>::Owned(SCHEMA_BLOCK.to_owned()))
    }

    fn nonce() -> Noncer<'static> {
        MatterBuilder::new()
            .with_code(NoncerCode::Salt128)
            .with_raw(Cow::<[u8]>::Owned(vec![0u8; 16]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn issuer() -> Identifier<'static> {
        Identifier::Basic(crate::BasicPrefix::from_matter(
            MatterBuilder::new()
                .with_code(VerKeyCode::Ed25519)
                .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
                .unwrap()
                .build()
                .unwrap(),
        ))
    }

    #[test]
    fn construct_minimal_credential_with_schema_said() {
        let credential = Acdc::new(
            saider(),
            None,
            None,
            None,
            AcdcField::Said(saider()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(credential.said(), &saider());
        assert!(credential.nonce().is_none());
        assert!(credential.issuer().is_none());
        assert!(credential.registry().is_none());
        assert_eq!(credential.schema(), &AcdcField::Said(saider()));
        assert!(credential.attributes().is_none());
        assert!(credential.aggregate_attributes().is_none());
        assert!(credential.edges().is_none());
        assert!(credential.aggregate_edges().is_none());
        assert!(credential.rules().is_none());
        assert!(credential.aggregate_rules().is_none());
        assert!(credential.prior().is_none());
    }

    #[test]
    fn construct_full_credential_and_access_fields() {
        let credential = Acdc::new(
            saider(),
            Some(nonce()),
            Some(issuer()),
            Some(AcdcField::Said(saider())),
            AcdcField::Block(block()),
            Some(AcdcField::Block(block())),
            Some(digester()),
            Some(AcdcField::Said(saider())),
            Some(digester()),
            Some(AcdcField::Block(block())),
            Some(digester()),
            Some(saider()),
        );
        assert_eq!(credential.said(), &saider());
        assert_eq!(credential.nonce(), Some(&nonce()));
        assert_eq!(credential.issuer(), Some(&issuer()));
        assert_eq!(credential.registry(), Some(&AcdcField::Said(saider())));
        assert_eq!(credential.schema(), &AcdcField::Block(block()));
        assert_eq!(credential.attributes(), Some(&AcdcField::Block(block())));
        assert_eq!(credential.aggregate_attributes(), Some(&digester()));
        assert_eq!(credential.edges(), Some(&AcdcField::Said(saider())));
        assert_eq!(credential.aggregate_edges(), Some(&digester()));
        assert_eq!(credential.rules(), Some(&AcdcField::Block(block())));
        assert_eq!(credential.aggregate_rules(), Some(&digester()));
        assert_eq!(credential.prior(), Some(&saider()));
    }

    #[test]
    fn said_and_block_variants_are_distinguishable() {
        let by_said: AcdcField<'static, SadBlock<'static>> = AcdcField::Said(saider());
        let by_block: AcdcField<'static, SadBlock<'static>> = AcdcField::Block(block());
        assert_ne!(by_said, by_block);
        assert!(matches!(by_said, AcdcField::Said(_)));
        assert!(matches!(by_block, AcdcField::Block(_)));
    }

    #[test]
    fn sad_block_preserves_payload_verbatim() {
        let payload = r#"{"d":"Ek00","n":"Eek00","s":"Esaid"}"#;
        let buffer = payload.to_owned();
        let section = SadBlock::new(Cow::<str>::Borrowed(buffer.as_str()));
        assert_eq!(section.payload(), payload);
        let owned = section.into_static();
        assert_eq!(owned.payload(), payload);
    }

    #[test]
    fn into_static_detaches_all_borrowed_fields() {
        let buffer = SCHEMA_BLOCK.to_owned();
        let credential = Acdc::new(
            saider(),
            Some(nonce()),
            Some(issuer()),
            Some(AcdcField::Said(saider())),
            AcdcField::Block(SadBlock::new(Cow::<str>::Borrowed(buffer.as_str()))),
            Some(AcdcField::Said(saider())),
            Some(digester()),
            None,
            None,
            None,
            None,
            Some(saider()),
        );
        let owned = credential.into_static();
        assert_eq!(owned.said(), &saider());
        assert_eq!(payload_of(owned.schema()), Some(SCHEMA_BLOCK));
        assert_eq!(owned.registry(), Some(&AcdcField::Said(saider())));
        assert_eq!(owned.prior(), Some(&saider()));
        assert!(owned.edges().is_none());
    }
}
