//! Counter-delimited CESR attachment groups.
//!
//! One generic carrier per counting regime, mirroring how `core` models
//! primitives with [`Matter<'a, C>`](crate::core::matter::Matter):
//!
//! - [`Group<K>`] carries every **element-counted** group — `count` elements
//!   of `K`'s wire grammar backed by their raw qb64 span. The concrete group
//!   types are aliases (`ControllerIdxSigs` = `Group<ControllerIdxSig>`),
//!   the per-family wire knowledge lives in the sealed [`GroupKind`] kinds
//!   declared in [`kinds`], and all shared behavior — framing
//!   ([`Group::parse`]), lazy element iteration ([`Group::iter`]), encoding
//!   ([`CesrEncode`]) — is written once on the carrier.
//! - [`Frame<K>`] carries every **quadlet-counted** framing group — the
//!   counter tallies the enclosed material's size in quadlets (4-byte
//!   units), and the payload is nested groups parsed lazily via
//!   [`QuadletGroup`].
//!
//! [`CesrGroup`] is the version-independent sum over all group families;
//! [`dispatch_v1`]/[`dispatch_v2`] are the only places wire counter codes
//! meet kinds. Encoding version safety is type-level: every kind encodes as
//! V2, only kinds implementing [`V1GroupKind`]/[`V1FrameKind`] encode as V1.

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{format, vec, vec::Vec};
use core::fmt;
use core::marker::PhantomData;

/// The group families: sealed kinds, element grammars, and public aliases.
pub mod kinds;

use crate::core::counter::CounterCodeV1;
use crate::core::counter::CounterCodeV2;
use crate::core::version::CesrVersion;

pub use kinds::AttachmentGroup;
pub use kinds::BackerRegistrarSealCouples;
pub use kinds::BlindedStateQuadruples;
pub use kinds::BodyWithAttachmentGroup;
pub use kinds::BoundStateSextuples;
pub use kinds::ControllerIdxSigs;
pub use kinds::DatagramSegmentGroup;
pub use kinds::DigestSealSingles;
pub use kinds::ESSRPayloadGroup;
pub use kinds::ESSRWrapperGroup;
pub use kinds::FirstSeenReplayCouples;
pub use kinds::FixBodyGroup;
pub use kinds::GenericGroup;
pub use kinds::GenericListGroup;
pub use kinds::GenericMapGroup;
pub use kinds::MapBodyGroup;
pub use kinds::MerkleRootSealSingles;
pub use kinds::NonNativeBodyGroup;
pub use kinds::NonTransReceiptCouples;
pub use kinds::PathedMaterialCouples;
pub use kinds::SealSourceCouples;
pub use kinds::SealSourceLastSingles;
pub use kinds::SealSourceTriples;
pub use kinds::TransIdxSigGroups;
pub use kinds::TransLastIdxSigGroups;
pub use kinds::TransReceiptQuadruples;
pub use kinds::TypedDigestSealCouples;
pub use kinds::TypedMediaQuadruples;
pub use kinds::WitnessIdxSigs;

use crate::stream::encode::encode_counter_v1;
use crate::stream::encode::encode_counter_v2;
use crate::stream::error::ParseError;
use crate::stream::parse::parse_counter;
use crate::stream::parse::parse_counter_v2;
use crate::stream::version::CesrEncode;
use crate::stream::version::V1;
use crate::stream::version::V2;
use bytes::Bytes;
use bytes::BytesMut;

mod private {
    pub trait Sealed {}
}

// ── The element-counted carrier ──────────────────────────────────────────

/// A group family's wire knowledge: its counter code(s) and element grammar.
///
/// This trait is **sealed** — the kinds in [`kinds`] are the complete set.
/// Each kind is an uninhabited marker enum named after the KERI/CESR concept
/// its elements represent; the public group types are aliases of
/// [`Group<K>`] over these kinds.
pub trait GroupKind: private::Sealed + 'static {
    /// The typed element this group yields on iteration.
    type Element;

    /// The family's CESR V2.0 counter code (total — every family has one).
    const CODE_V2: CounterCodeV2;

    /// The family name, as printed by `Debug` (matches the public alias).
    const NAME: &'static str;

    /// Parse one element from the head of `input`, returning it and the
    /// bytes consumed. `version` selects the counter table for nested
    /// counters inside the element (only the transferable indexed-sig
    /// families have any).
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if the bytes do not form one well-typed
    /// element of this family.
    fn element(input: &[u8], version: CesrVersion) -> Result<(Self::Element, usize), ParseError>;

    /// Compute the wire size of one element without decoding it.
    ///
    /// This is the framing grammar: deliberately cheaper *and* more lenient
    /// than [`element`](Self::element) (it sizes primitives by code class
    /// without narrowing to the family's typed codes), exactly matching the
    /// per-group parsers this carrier replaced. Element typing is enforced
    /// lazily on iteration.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if the bytes do not frame one element of this
    /// family.
    fn skip(input: &[u8], version: CesrVersion) -> Result<usize, ParseError>;
}

/// Refinement for group families that also exist in the CESR V1.0 counter
/// table. V2-only families do not implement it, so encoding them with V1
/// counters is a **compile-time** error:
///
/// ```compile_fail,E0277
/// use bytes::BytesMut;
/// use cesr::stream::group::DigestSealSingles;
/// use cesr::stream::{CesrEncode, V1};
///
/// fn encode_v1(group: &DigestSealSingles, dst: &mut BytesMut) {
///     let _ = CesrEncode::<V1>::encode_cesr(group, dst); // V2-only: no impl
/// }
/// ```
pub trait V1GroupKind: GroupKind {
    /// The family's CESR V1.0 counter code.
    const CODE_V1: CounterCodeV1;
}

/// An element-counted attachment group: `count` elements of `K`'s wire
/// grammar, backed by their raw qb64 span.
///
/// The count/raw invariant is held by construction: a parsed group's span
/// was framed by [`GroupKind::skip`] over exactly `count` elements, and a
/// built group (e.g. [`ControllerIdxSigs::from_sigers`]) derives `count`
/// from its input. Elements are decoded lazily via [`iter`](Self::iter).
pub struct Group<K: GroupKind> {
    raw: Bytes,
    count: u32,
    version: CesrVersion,
    kind: PhantomData<K>,
}

impl<K: GroupKind> Group<K> {
    /// Internal constructor. `version` records the counter table this
    /// group was framed with — nested counters inside elements (e.g. the
    /// `-A`/`-K` inside a `-F` group) are read with the same table. For
    /// payloads without nested counters the value is inert; built groups
    /// use [`CesrVersion::V1`], the write path's table.
    pub(crate) const fn new(raw: Bytes, count: u32, version: CesrVersion) -> Self {
        Self {
            raw,
            count,
            version,
            kind: PhantomData,
        }
    }

    /// Frame one group of `count` elements from the head of `input`,
    /// returning the group and the unconsumed remainder as O(1) slices.
    pub(crate) fn parse(
        input: &Bytes,
        count: u32,
        version: CesrVersion,
    ) -> Result<(Self, Bytes), ParseError> {
        let mut offset = 0_usize;
        for _ in 0..count {
            let size = K::skip(&input[offset..], version)?;
            offset = offset
                .checked_add(size)
                .ok_or_else(|| ParseError::Malformed("group span overflows".into()))?;
        }
        let raw = input.slice(..offset);
        let rest = input.slice(offset..);
        Ok((Self::new(raw, count, version), rest))
    }

    /// Returns a lazy iterator over the elements in this group.
    #[must_use]
    pub fn iter(&self) -> Elements<K> {
        Elements {
            raw: self.raw.clone(),
            cursor: 0,
            remaining: self.count,
            version: self.version,
            errored: false,
            kind: PhantomData,
        }
    }

    /// Collects all elements into a `Vec`, parsing each on demand.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if any element fails to parse.
    pub fn into_vec(self) -> Result<Vec<K::Element>, ParseError> {
        self.iter().collect()
    }

    /// Returns the number of elements in this group.
    #[must_use]
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Returns the raw CESR bytes backing this group.
    #[must_use]
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }
}

impl<K: GroupKind> fmt::Debug for Group<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct(K::NAME)
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

impl<K: GroupKind> IntoIterator for &Group<K> {
    type Item = Result<K::Element, ParseError>;
    type IntoIter = Elements<K>;

    fn into_iter(self) -> Elements<K> {
        self.iter()
    }
}

/// A lazy iterator over a [`Group`]'s elements.
///
/// Backed by the group's `Bytes` span (ref-counted, `'static`). Each
/// `next()` decodes exactly one element via [`GroupKind::element`]; the
/// first parse error is yielded once, then iteration ends.
pub struct Elements<K: GroupKind> {
    raw: Bytes,
    cursor: usize,
    remaining: u32,
    version: CesrVersion,
    errored: bool,
    kind: PhantomData<K>,
}

impl<K: GroupKind> Iterator for Elements<K> {
    type Item = Result<K::Element, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 || self.errored {
            return None;
        }
        self.remaining -= 1;
        match K::element(&self.raw[self.cursor..], self.version) {
            Ok((element, consumed)) => {
                if let Some(cursor) = self.cursor.checked_add(consumed) {
                    self.cursor = cursor;
                    Some(Ok(element))
                } else {
                    self.errored = true;
                    Some(Err(ParseError::Malformed(
                        "element span overflows the group".into(),
                    )))
                }
            }
            Err(e) => {
                self.errored = true;
                Some(Err(e))
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = usize::try_from(self.remaining).unwrap_or(usize::MAX);
        (0, Some(remaining))
    }
}

// ── The quadlet-counted carrier ──────────────────────────────────────────

type GroupParser = fn(&Bytes) -> Result<(CesrGroup, Bytes), ParseError>;

/// A lazy, streaming iterator over inner groups in a quadlet-counted CESR container.
///
/// The total byte size is known upfront from the counter (`count * 4`).
/// Inner groups are parsed on-demand as the iterator is advanced.
pub struct QuadletGroup {
    input: Bytes,
    cursor: usize,
    errored: bool,
    parser: GroupParser,
}

impl QuadletGroup {
    pub(crate) fn new(input: Bytes, parser: GroupParser) -> Self {
        Self {
            input,
            cursor: 0,
            errored: false,
            parser,
        }
    }

    /// Total size of this group in quadlets (4-byte units).
    pub const fn quadlet_count(&self) -> usize {
        self.input.len() / 4
    }

    /// Returns the raw payload bytes (without any counter prefix).
    pub fn raw_bytes(&self) -> &[u8] {
        &self.input
    }

    /// Returns the group's payload as a cheap (O(1) refcount) `Bytes` handle
    /// sharing the underlying buffer.
    ///
    /// Named `to_bytes` (not `raw`) because crate-wide `raw()` returns a
    /// borrowed `&[u8]`; this returns an owned, cheaply-cloned `Bytes`.
    #[must_use]
    pub fn to_bytes(&self) -> Bytes {
        self.input.clone()
    }
}

impl fmt::Debug for QuadletGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuadletGroup")
            .field("quadlets", &self.quadlet_count())
            .field("cursor", &self.cursor)
            .field("errored", &self.errored)
            .finish_non_exhaustive()
    }
}

impl Iterator for QuadletGroup {
    type Item = Result<CesrGroup, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.input.len() || self.errored {
            return None;
        }
        let remaining = self.input.slice(self.cursor..);
        match (self.parser)(&remaining) {
            Ok((group, rest)) => {
                self.cursor = self.input.len() - rest.len();
                Some(Ok(group))
            }
            Err(e) => {
                self.errored = true;
                Some(Err(e))
            }
        }
    }
}

fn parse_quadlets(input: &Bytes, count: u32) -> Result<(QuadletGroup, Bytes), ParseError> {
    // checked_mul guards 32-bit usize targets (wasm32) where u32 * 4 can overflow.
    let total_bytes = usize::try_from(count)
        .ok()
        .and_then(|c| c.checked_mul(4))
        .ok_or_else(|| ParseError::Malformed("quadlet count overflow".into()))?;
    if input.len() < total_bytes {
        return Err(ParseError::NeedBytes(total_bytes - input.len()));
    }
    let group_bytes = input.slice(..total_bytes);
    let rest = input.slice(total_bytes..);
    Ok((QuadletGroup::new(group_bytes, parse_group_bytes), rest))
}

fn parse_quadlets_v2(input: &Bytes, count: u32) -> Result<(QuadletGroup, Bytes), ParseError> {
    // checked_mul guards 32-bit usize targets (wasm32) where u32 * 4 can overflow.
    let total_bytes = usize::try_from(count)
        .ok()
        .and_then(|c| c.checked_mul(4))
        .ok_or_else(|| ParseError::Malformed("quadlet count overflow".into()))?;
    if input.len() < total_bytes {
        return Err(ParseError::NeedBytes(total_bytes - input.len()));
    }
    let group_bytes = input.slice(..total_bytes);
    let rest = input.slice(total_bytes..);
    Ok((QuadletGroup::new(group_bytes, parse_group_bytes_v2), rest))
}

/// A framing-group family's wire knowledge: its counter code(s).
///
/// This trait is **sealed** — the kinds in [`kinds`] are the complete set.
/// Framing counters tally the enclosed material's size in quadlets; the
/// payload is opaque at framing time and parsed lazily as nested groups.
pub trait FrameKind: private::Sealed + 'static {
    /// The family's CESR V2.0 counter code (total — every family has one).
    const CODE_V2: CounterCodeV2;

    /// The family name, as printed by `Debug` (matches the public alias).
    const NAME: &'static str;
}

/// Refinement for framing-group families in the CESR V1.0 counter table.
///
/// V2-only families do not implement it, so encoding them with V1 counters
/// is a compile-time error (see [`V1GroupKind`]).
pub trait V1FrameKind: FrameKind {
    /// The family's CESR V1.0 counter code.
    const CODE_V1: CounterCodeV1;
}

/// A quadlet-counted framing group: the counter tallies the payload's size
/// in quadlets, and the payload holds nested CESR groups parsed lazily.
///
/// Iterate the frame (it is [`IntoIterator`]) to parse the nested groups
/// one at a time.
pub struct Frame<K: FrameKind> {
    quadlets: QuadletGroup,
    kind: PhantomData<K>,
}

impl<K: FrameKind> Frame<K> {
    pub(crate) const fn new(quadlets: QuadletGroup) -> Self {
        Self {
            quadlets,
            kind: PhantomData,
        }
    }

    /// Total size of this frame's payload in quadlets (4-byte units).
    #[must_use]
    pub const fn quadlet_count(&self) -> usize {
        self.quadlets.quadlet_count()
    }

    /// Returns the raw payload bytes (without the counter prefix).
    #[must_use]
    pub fn raw_bytes(&self) -> &[u8] {
        self.quadlets.raw_bytes()
    }

    /// Returns the payload as a cheap (O(1) refcount) `Bytes` handle
    /// sharing the underlying buffer.
    #[must_use]
    pub fn to_bytes(&self) -> Bytes {
        self.quadlets.to_bytes()
    }
}

impl<K: FrameKind> fmt::Debug for Frame<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple(K::NAME)
            .field(&format_args!("[{} quadlets]", self.quadlet_count()))
            .finish()
    }
}

impl<K: FrameKind> IntoIterator for Frame<K> {
    type Item = Result<CesrGroup, ParseError>;
    type IntoIter = QuadletGroup;

    fn into_iter(self) -> QuadletGroup {
        self.quadlets
    }
}

// ── The version-independent sum ──────────────────────────────────────────

/// Top-level enum over all CESR attachment group types.
///
/// These group types are version-independent — the same parsed structure
/// is produced regardless of whether V1.0 or V2.0 wire encoding was used.
#[derive(Debug)]
pub enum CesrGroup {
    /// Controller indexed signatures.
    ControllerIdxSigs(ControllerIdxSigs),
    /// Witness indexed signatures.
    WitnessIdxSigs(WitnessIdxSigs),
    /// Non-transferable receipt couples.
    NonTransReceiptCouples(NonTransReceiptCouples),
    /// Transferable receipt quadruples.
    TransReceiptQuadruples(TransReceiptQuadruples),
    /// First-seen replay couples.
    FirstSeenReplayCouples(FirstSeenReplayCouples),
    /// Transferable indexed sig groups.
    TransIdxSigGroups(TransIdxSigGroups),
    /// Seal source couples.
    SealSourceCouples(SealSourceCouples),
    /// Transferable last-event indexed sig groups.
    TransLastIdxSigGroups(TransLastIdxSigGroups),
    /// Seal source triples.
    SealSourceTriples(SealSourceTriples),
    /// Pathed material couples.
    PathedMaterialCouples(PathedMaterialCouples),
    /// Attachment group (quadlet-counted).
    AttachmentGroup(AttachmentGroup),
    /// Generic group (quadlet-counted).
    GenericGroup(GenericGroup),
    /// Body with attachment group (quadlet-counted).
    BodyWithAttachmentGroup(BodyWithAttachmentGroup),
    /// Non-native body group (quadlet-counted).
    NonNativeBodyGroup(NonNativeBodyGroup),
    /// ESSR payload group (quadlet-counted).
    ESSRPayloadGroup(ESSRPayloadGroup),
    /// Datagram segment group (V2 only, quadlet-counted).
    DatagramSegmentGroup(DatagramSegmentGroup),
    /// ESSR wrapper group (V2 only, quadlet-counted).
    ESSRWrapperGroup(ESSRWrapperGroup),
    /// Fixed body group (V2 only, quadlet-counted).
    FixBodyGroup(FixBodyGroup),
    /// Map body group (V2 only, quadlet-counted).
    MapBodyGroup(MapBodyGroup),
    /// Generic map group (V2 only, quadlet-counted).
    GenericMapGroup(GenericMapGroup),
    /// Generic list group (V2 only, quadlet-counted).
    GenericListGroup(GenericListGroup),
    /// Digest seal singles (V2 only).
    DigestSealSingles(DigestSealSingles),
    /// Merkle root seal singles (V2 only).
    MerkleRootSealSingles(MerkleRootSealSingles),
    /// Seal source last singles (V2 only).
    SealSourceLastSingles(SealSourceLastSingles),
    /// Backer registrar seal couples (V2 only).
    BackerRegistrarSealCouples(BackerRegistrarSealCouples),
    /// Typed digest seal couples (V2 only).
    TypedDigestSealCouples(TypedDigestSealCouples),
    /// Blinded state quadruples (V2 only).
    BlindedStateQuadruples(BlindedStateQuadruples),
    /// Bound state sextuples (V2 only).
    BoundStateSextuples(BoundStateSextuples),
    /// Typed media quadruples (V2 only).
    TypedMediaQuadruples(TypedMediaQuadruples),
}

// ── Parsing entry points and dispatch ────────────────────────────────────

/// Parse one CESR attachment group (counter + elements) from the input.
///
/// Uses V1.0 counter codes. All parsed primitives are fully owned
/// (`'static`), so the returned group does not borrow from the input.
///
/// # Errors
///
/// Returns [`ParseError`] on malformed data, unknown codes, or insufficient bytes.
pub fn parse_group(input: &[u8]) -> Result<(CesrGroup, &[u8]), ParseError> {
    parse_group_inner(input)
}

pub(crate) fn parse_group_inner(input: &[u8]) -> Result<(CesrGroup, &[u8]), ParseError> {
    let buf = Bytes::copy_from_slice(input);
    let (group, rest) = parse_group_bytes(&buf)?;
    let consumed = input.len() - rest.len();
    Ok((group, &input[consumed..]))
}

/// Frame `count` elements of kind `K` and wrap them in their [`CesrGroup`]
/// variant — the shared body of every element-group dispatch arm.
fn parse_kind<K: GroupKind>(
    elements: &Bytes,
    count: u32,
    version: CesrVersion,
    wrap: fn(Group<K>) -> CesrGroup,
) -> Result<(CesrGroup, Bytes), ParseError> {
    let (group, rest) = Group::parse(elements, count, version)?;
    Ok((wrap(group), rest))
}

/// Slice `count` quadlets of frame kind `K` and wrap them in their
/// [`CesrGroup`] variant — the shared body of every V1 frame dispatch arm.
fn parse_frame<K: FrameKind>(
    elements: &Bytes,
    count: u32,
    wrap: fn(Frame<K>) -> CesrGroup,
) -> Result<(CesrGroup, Bytes), ParseError> {
    let (quadlets, rest) = parse_quadlets(elements, count)?;
    Ok((wrap(Frame::new(quadlets)), rest))
}

/// V2 twin of [`parse_frame`]: nested groups parse with the V2 code table.
fn parse_frame_v2<K: FrameKind>(
    elements: &Bytes,
    count: u32,
    wrap: fn(Frame<K>) -> CesrGroup,
) -> Result<(CesrGroup, Bytes), ParseError> {
    let (quadlets, rest) = parse_quadlets_v2(elements, count)?;
    Ok((wrap(Frame::new(quadlets)), rest))
}

fn dispatch_v1(
    code: CounterCodeV1,
    count: u32,
    rest: &Bytes,
) -> Result<(CesrGroup, Bytes), ParseError> {
    let v = CesrVersion::V1;
    match code {
        CounterCodeV1::ControllerIdxSigs => {
            parse_kind(rest, count, v, CesrGroup::ControllerIdxSigs)
        }
        CounterCodeV1::WitnessIdxSigs => parse_kind(rest, count, v, CesrGroup::WitnessIdxSigs),
        CounterCodeV1::NonTransReceiptCouples => {
            parse_kind(rest, count, v, CesrGroup::NonTransReceiptCouples)
        }
        CounterCodeV1::TransReceiptQuadruples => {
            parse_kind(rest, count, v, CesrGroup::TransReceiptQuadruples)
        }
        CounterCodeV1::FirstSeenReplayCouples => {
            parse_kind(rest, count, v, CesrGroup::FirstSeenReplayCouples)
        }
        CounterCodeV1::TransIdxSigGroups => {
            parse_kind(rest, count, v, CesrGroup::TransIdxSigGroups)
        }
        CounterCodeV1::SealSourceCouples => {
            parse_kind(rest, count, v, CesrGroup::SealSourceCouples)
        }
        CounterCodeV1::TransLastIdxSigGroups => {
            parse_kind(rest, count, v, CesrGroup::TransLastIdxSigGroups)
        }
        CounterCodeV1::SealSourceTriples => {
            parse_kind(rest, count, v, CesrGroup::SealSourceTriples)
        }
        CounterCodeV1::AttachmentGroup | CounterCodeV1::BigAttachmentGroup => {
            parse_frame(rest, count, CesrGroup::AttachmentGroup)
        }
        CounterCodeV1::GenericGroup | CounterCodeV1::BigGenericGroup => {
            parse_frame(rest, count, CesrGroup::GenericGroup)
        }
        CounterCodeV1::BodyWithAttachmentGroup | CounterCodeV1::BigBodyWithAttachmentGroup => {
            parse_frame(rest, count, CesrGroup::BodyWithAttachmentGroup)
        }
        CounterCodeV1::NonNativeBodyGroup | CounterCodeV1::BigNonNativeBodyGroup => {
            parse_frame(rest, count, CesrGroup::NonNativeBodyGroup)
        }
        CounterCodeV1::ESSRPayloadGroup | CounterCodeV1::BigESSRPayloadGroup => {
            parse_frame(rest, count, CesrGroup::ESSRPayloadGroup)
        }
        CounterCodeV1::PathedMaterialCouples | CounterCodeV1::BigPathedMaterialCouples => {
            parse_frame(rest, count, CesrGroup::PathedMaterialCouples)
        }
        CounterCodeV1::KERIACDCGenusVersion => Err(ParseError::Malformed(
            "genus version codes are not attachment groups".into(),
        )),
    }
}

/// Zero-copy parsing core: slices `buf` for the counter and hands the element
/// region to the dispatch. Returns the remaining bytes as an O(1) `Bytes` slice.
pub(crate) fn parse_group_bytes(buf: &Bytes) -> Result<(CesrGroup, Bytes), ParseError> {
    let (code, count, after_counter) = parse_counter(buf)?;
    let consumed = buf.len() - after_counter.len();
    let elements = buf.slice(consumed..);
    dispatch_v1(code, count, &elements)
}

pub(crate) fn parse_group_bytes_v2(buf: &Bytes) -> Result<(CesrGroup, Bytes), ParseError> {
    let (code, count, after_counter) = parse_counter_v2(buf)?;
    let consumed = buf.len() - after_counter.len();
    let elements = buf.slice(consumed..);
    dispatch_v2(code, count, &elements)
}

/// An iterator that yields successive [`CesrGroup`]s from a byte stream.
///
/// All parsed groups are fully owned (`'static`). The attachment region is
/// copied into a shared [`Bytes`] buffer once, lazily, on the first call to
/// [`Iterator::next`]; every subsequent group is an O(1) slice of that
/// buffer rather than a fresh copy of the remaining input.
pub struct Groups<'a> {
    input: &'a [u8],
    buf: Option<Bytes>,
    cursor: usize,
}

impl Iterator for Groups<'_> {
    type Item = Result<CesrGroup, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        // Copy the attachment region into a shared Bytes exactly once; every group
        // is then an O(1) slice of it (no per-group copy). Only the per-group
        // slice bumps the refcount; the buffer itself is never re-cloned.
        let buf = self
            .buf
            .get_or_insert_with(|| Bytes::copy_from_slice(self.input));
        let buf_len = buf.len();
        if self.cursor >= buf_len {
            return None;
        }
        let slice = buf.slice(self.cursor..);
        match parse_group_bytes(&slice) {
            Ok((group, rest)) => {
                self.cursor = buf_len - rest.len();
                Some(Ok(group))
            }
            Err(e) => {
                self.cursor = buf_len;
                Some(Err(e))
            }
        }
    }
}

/// Create an iterator that parses successive CESR groups from the input.
#[must_use]
pub const fn groups(input: &[u8]) -> Groups<'_> {
    Groups {
        input,
        buf: None,
        cursor: 0,
    }
}

/// Parse one CESR attachment group using V2.0 counter codes.
///
/// V2.0 remaps wire letters but produces the same version-independent
/// `CesrGroup` variants for shared semantics.
///
/// # Errors
///
/// Returns [`ParseError`] on malformed data, unknown codes, or insufficient bytes.
pub fn parse_group_v2(input: &[u8]) -> Result<(CesrGroup, &[u8]), ParseError> {
    parse_group_inner_v2(input)
}

pub(crate) fn parse_group_inner_v2(input: &[u8]) -> Result<(CesrGroup, &[u8]), ParseError> {
    let buf = Bytes::copy_from_slice(input);
    let (group, rest) = parse_group_bytes_v2(&buf)?;
    let consumed = input.len() - rest.len();
    Ok((group, &input[consumed..]))
}

fn dispatch_v2(
    code: CounterCodeV2,
    count: u32,
    rest: &Bytes,
) -> Result<(CesrGroup, Bytes), ParseError> {
    let v = CesrVersion::V2;
    match code {
        CounterCodeV2::ControllerIdxSigs | CounterCodeV2::BigControllerIdxSigs => {
            parse_kind(rest, count, v, CesrGroup::ControllerIdxSigs)
        }
        CounterCodeV2::WitnessIdxSigs | CounterCodeV2::BigWitnessIdxSigs => {
            parse_kind(rest, count, v, CesrGroup::WitnessIdxSigs)
        }
        CounterCodeV2::NonTransReceiptCouples | CounterCodeV2::BigNonTransReceiptCouples => {
            parse_kind(rest, count, v, CesrGroup::NonTransReceiptCouples)
        }
        CounterCodeV2::TransReceiptQuadruples | CounterCodeV2::BigTransReceiptQuadruples => {
            parse_kind(rest, count, v, CesrGroup::TransReceiptQuadruples)
        }
        CounterCodeV2::FirstSeenReplayCouples | CounterCodeV2::BigFirstSeenReplayCouples => {
            parse_kind(rest, count, v, CesrGroup::FirstSeenReplayCouples)
        }
        CounterCodeV2::SealSourceCouples | CounterCodeV2::BigSealSourceCouples => {
            parse_kind(rest, count, v, CesrGroup::SealSourceCouples)
        }
        CounterCodeV2::SealSourceTriples | CounterCodeV2::BigSealSourceTriples => {
            parse_kind(rest, count, v, CesrGroup::SealSourceTriples)
        }
        CounterCodeV2::TransIdxSigGroups | CounterCodeV2::BigTransIdxSigGroups => {
            parse_kind(rest, count, v, CesrGroup::TransIdxSigGroups)
        }
        CounterCodeV2::TransLastIdxSigGroups | CounterCodeV2::BigTransLastIdxSigGroups => {
            parse_kind(rest, count, v, CesrGroup::TransLastIdxSigGroups)
        }
        _ => dispatch_v2_frames(code, count, rest),
    }
}

fn dispatch_v2_frames(
    code: CounterCodeV2,
    count: u32,
    rest: &Bytes,
) -> Result<(CesrGroup, Bytes), ParseError> {
    match code {
        CounterCodeV2::AttachmentGroup | CounterCodeV2::BigAttachmentGroup => {
            parse_frame_v2(rest, count, CesrGroup::AttachmentGroup)
        }
        CounterCodeV2::GenericGroup | CounterCodeV2::BigGenericGroup => {
            parse_frame_v2(rest, count, CesrGroup::GenericGroup)
        }
        CounterCodeV2::BodyWithAttachmentGroup | CounterCodeV2::BigBodyWithAttachmentGroup => {
            parse_frame_v2(rest, count, CesrGroup::BodyWithAttachmentGroup)
        }
        CounterCodeV2::NonNativeBodyGroup | CounterCodeV2::BigNonNativeBodyGroup => {
            parse_frame_v2(rest, count, CesrGroup::NonNativeBodyGroup)
        }
        CounterCodeV2::ESSRPayloadGroup | CounterCodeV2::BigESSRPayloadGroup => {
            parse_frame_v2(rest, count, CesrGroup::ESSRPayloadGroup)
        }
        CounterCodeV2::DatagramSegmentGroup | CounterCodeV2::BigDatagramSegmentGroup => {
            parse_frame_v2(rest, count, CesrGroup::DatagramSegmentGroup)
        }
        CounterCodeV2::ESSRWrapperGroup | CounterCodeV2::BigESSRWrapperGroup => {
            parse_frame_v2(rest, count, CesrGroup::ESSRWrapperGroup)
        }
        CounterCodeV2::FixBodyGroup | CounterCodeV2::BigFixBodyGroup => {
            parse_frame_v2(rest, count, CesrGroup::FixBodyGroup)
        }
        CounterCodeV2::MapBodyGroup | CounterCodeV2::BigMapBodyGroup => {
            parse_frame_v2(rest, count, CesrGroup::MapBodyGroup)
        }
        CounterCodeV2::GenericMapGroup | CounterCodeV2::BigGenericMapGroup => {
            parse_frame_v2(rest, count, CesrGroup::GenericMapGroup)
        }
        CounterCodeV2::GenericListGroup | CounterCodeV2::BigGenericListGroup => {
            parse_frame_v2(rest, count, CesrGroup::GenericListGroup)
        }
        CounterCodeV2::PathedMaterialCouples | CounterCodeV2::BigPathedMaterialCouples => {
            parse_frame_v2(rest, count, CesrGroup::PathedMaterialCouples)
        }
        _ => dispatch_v2_seals(code, count, rest),
    }
}

fn dispatch_v2_seals(
    code: CounterCodeV2,
    count: u32,
    rest: &Bytes,
) -> Result<(CesrGroup, Bytes), ParseError> {
    let v = CesrVersion::V2;
    match code {
        CounterCodeV2::DigestSealSingles | CounterCodeV2::BigDigestSealSingles => {
            parse_kind(rest, count, v, CesrGroup::DigestSealSingles)
        }
        CounterCodeV2::MerkleRootSealSingles | CounterCodeV2::BigMerkleRootSealSingles => {
            parse_kind(rest, count, v, CesrGroup::MerkleRootSealSingles)
        }
        CounterCodeV2::SealSourceLastSingles | CounterCodeV2::BigSealSourceLastSingles => {
            parse_kind(rest, count, v, CesrGroup::SealSourceLastSingles)
        }
        CounterCodeV2::BackerRegistrarSealCouples
        | CounterCodeV2::BigBackerRegistrarSealCouples => {
            parse_kind(rest, count, v, CesrGroup::BackerRegistrarSealCouples)
        }
        CounterCodeV2::TypedDigestSealCouples | CounterCodeV2::BigTypedDigestSealCouples => {
            parse_kind(rest, count, v, CesrGroup::TypedDigestSealCouples)
        }
        CounterCodeV2::BlindedStateQuadruples | CounterCodeV2::BigBlindedStateQuadruples => {
            parse_kind(rest, count, v, CesrGroup::BlindedStateQuadruples)
        }
        CounterCodeV2::BoundStateSextuples | CounterCodeV2::BigBoundStateSextuples => {
            parse_kind(rest, count, v, CesrGroup::BoundStateSextuples)
        }
        CounterCodeV2::TypedMediaQuadruples | CounterCodeV2::BigTypedMediaQuadruples => {
            parse_kind(rest, count, v, CesrGroup::TypedMediaQuadruples)
        }
        CounterCodeV2::KERIACDCGenusVersion => Err(ParseError::Malformed(
            "genus version codes are not attachment groups".into(),
        )),
        _ => Err(ParseError::Malformed(format!(
            "unexpected V2 counter code {}",
            code.as_str()
        ))),
    }
}

/// An iterator that yields successive [`CesrGroup`]s from a V2.0 byte stream.
///
/// The attachment region is copied into a shared [`Bytes`] buffer once,
/// lazily, on the first call to [`Iterator::next`]; every subsequent group
/// is an O(1) slice of that buffer rather than a fresh copy of the
/// remaining input.
pub struct GroupsV2<'a> {
    input: &'a [u8],
    buf: Option<Bytes>,
    cursor: usize,
}

impl Iterator for GroupsV2<'_> {
    type Item = Result<CesrGroup, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        // Copy the attachment region into a shared Bytes exactly once; every group
        // is then an O(1) slice of it (no per-group copy). Only the per-group
        // slice bumps the refcount; the buffer itself is never re-cloned.
        let buf = self
            .buf
            .get_or_insert_with(|| Bytes::copy_from_slice(self.input));
        let buf_len = buf.len();
        if self.cursor >= buf_len {
            return None;
        }
        let slice = buf.slice(self.cursor..);
        match parse_group_bytes_v2(&slice) {
            Ok((group, rest)) => {
                self.cursor = buf_len - rest.len();
                Some(Ok(group))
            }
            Err(e) => {
                self.cursor = buf_len;
                Some(Err(e))
            }
        }
    }
}

/// Create an iterator that parses successive V2.0 CESR groups from the input.
#[must_use]
pub const fn groups_v2(input: &[u8]) -> GroupsV2<'_> {
    GroupsV2 {
        input,
        buf: None,
        cursor: 0,
    }
}

// ── Encoding: one blanket impl per (carrier, version) ────────────────────

impl<K: V1GroupKind> CesrEncode<V1> for Group<K> {
    fn encode_cesr(&self, dst: &mut BytesMut) -> Result<(), ParseError> {
        let counter = encode_counter_v1(K::CODE_V1, self.count())?;
        dst.extend_from_slice(&counter);
        dst.extend_from_slice(self.raw_bytes());
        Ok(())
    }
}

impl<K: GroupKind> CesrEncode<V2> for Group<K> {
    fn encode_cesr(&self, dst: &mut BytesMut) -> Result<(), ParseError> {
        let counter = encode_counter_v2(K::CODE_V2, self.count())?;
        dst.extend_from_slice(&counter);
        dst.extend_from_slice(self.raw_bytes());
        Ok(())
    }
}

/// The quadlet tally of a frame payload, validating quadlet alignment.
fn frame_quadlet_count(payload: &[u8]) -> Result<u32, ParseError> {
    if !payload.len().is_multiple_of(4) {
        return Err(ParseError::Malformed(
            "quadlet group inner bytes must be a multiple of 4".into(),
        ));
    }
    u32::try_from(payload.len() / 4).map_err(|_| ParseError::Malformed("too many quadlets".into()))
}

impl<K: V1FrameKind> CesrEncode<V1> for Frame<K> {
    fn encode_cesr(&self, dst: &mut BytesMut) -> Result<(), ParseError> {
        let counter = encode_counter_v1(K::CODE_V1, frame_quadlet_count(self.raw_bytes())?)?;
        dst.extend_from_slice(&counter);
        dst.extend_from_slice(self.raw_bytes());
        Ok(())
    }
}

impl<K: FrameKind> CesrEncode<V2> for Frame<K> {
    fn encode_cesr(&self, dst: &mut BytesMut) -> Result<(), ParseError> {
        let counter = encode_counter_v2(K::CODE_V2, frame_quadlet_count(self.raw_bytes())?)?;
        dst.extend_from_slice(&counter);
        dst.extend_from_slice(self.raw_bytes());
        Ok(())
    }
}

// CesrGroup enum — V2 handles all variants
impl CesrEncode<V2> for CesrGroup {
    fn encode_cesr(&self, dst: &mut BytesMut) -> Result<(), ParseError> {
        match self {
            Self::ControllerIdxSigs(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::WitnessIdxSigs(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::NonTransReceiptCouples(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::TransReceiptQuadruples(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::FirstSeenReplayCouples(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::TransIdxSigGroups(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::SealSourceCouples(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::TransLastIdxSigGroups(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::SealSourceTriples(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::PathedMaterialCouples(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::AttachmentGroup(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::GenericGroup(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::BodyWithAttachmentGroup(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::NonNativeBodyGroup(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::ESSRPayloadGroup(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::DatagramSegmentGroup(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::ESSRWrapperGroup(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::FixBodyGroup(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::MapBodyGroup(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::GenericMapGroup(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::GenericListGroup(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::DigestSealSingles(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::MerkleRootSealSingles(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::SealSourceLastSingles(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::BackerRegistrarSealCouples(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::TypedDigestSealCouples(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::BlindedStateQuadruples(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::BoundStateSextuples(g) => CesrEncode::<V2>::encode_cesr(g, dst),
            Self::TypedMediaQuadruples(g) => CesrEncode::<V2>::encode_cesr(g, dst),
        }
    }
}

// CesrGroup enum — V1 returns runtime error for V2-only variants
impl CesrEncode<V1> for CesrGroup {
    fn encode_cesr(&self, dst: &mut BytesMut) -> Result<(), ParseError> {
        match self {
            Self::ControllerIdxSigs(g) => CesrEncode::<V1>::encode_cesr(g, dst),
            Self::WitnessIdxSigs(g) => CesrEncode::<V1>::encode_cesr(g, dst),
            Self::NonTransReceiptCouples(g) => CesrEncode::<V1>::encode_cesr(g, dst),
            Self::TransReceiptQuadruples(g) => CesrEncode::<V1>::encode_cesr(g, dst),
            Self::FirstSeenReplayCouples(g) => CesrEncode::<V1>::encode_cesr(g, dst),
            Self::TransIdxSigGroups(g) => CesrEncode::<V1>::encode_cesr(g, dst),
            Self::SealSourceCouples(g) => CesrEncode::<V1>::encode_cesr(g, dst),
            Self::TransLastIdxSigGroups(g) => CesrEncode::<V1>::encode_cesr(g, dst),
            Self::SealSourceTriples(g) => CesrEncode::<V1>::encode_cesr(g, dst),
            Self::PathedMaterialCouples(g) => CesrEncode::<V1>::encode_cesr(g, dst),
            Self::AttachmentGroup(g) => CesrEncode::<V1>::encode_cesr(g, dst),
            Self::GenericGroup(g) => CesrEncode::<V1>::encode_cesr(g, dst),
            Self::BodyWithAttachmentGroup(g) => CesrEncode::<V1>::encode_cesr(g, dst),
            Self::NonNativeBodyGroup(g) => CesrEncode::<V1>::encode_cesr(g, dst),
            Self::ESSRPayloadGroup(g) => CesrEncode::<V1>::encode_cesr(g, dst),
            Self::DatagramSegmentGroup(_)
            | Self::ESSRWrapperGroup(_)
            | Self::FixBodyGroup(_)
            | Self::MapBodyGroup(_)
            | Self::GenericMapGroup(_)
            | Self::GenericListGroup(_)
            | Self::DigestSealSingles(_)
            | Self::MerkleRootSealSingles(_)
            | Self::SealSourceLastSingles(_)
            | Self::BackerRegistrarSealCouples(_)
            | Self::TypedDigestSealCouples(_)
            | Self::BlindedStateQuadruples(_)
            | Self::BoundStateSextuples(_)
            | Self::TypedMediaQuadruples(_) => Err(ParseError::Malformed(
                "V2-only group type cannot be encoded with V1 counters".into(),
            )),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::needless_collect,
    reason = "test code: panics and type conversions acceptable"
)]
mod tests {
    use super::*;
    use crate::core::counter::CounterCodeV1;
    use crate::core::indexer::IndexerBuilder;
    use crate::core::indexer::code::IndexedSigCode;
    use core::num::NonZeroUsize;

    fn build_siger_qb64(index: u32) -> Vec<u8> {
        IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519)
            .with_index(index)
            .unwrap()
            .with_raw(&[0u8; 64])
            .unwrap()
            .to_qb64()
            .into_bytes()
    }

    fn build_counter_qb64(code: CounterCodeV1, count: u32) -> Vec<u8> {
        let hard = code.as_str();
        let ss = code.soft_size();
        let ss_nz = NonZeroUsize::new(ss).unwrap();
        let soft = crate::b64::encode_int(count, ss_nz);
        format!("{hard}{soft}").into_bytes()
    }

    fn encode_group_v1(group: &CesrGroup) -> Result<Vec<u8>, ParseError> {
        let mut dst = BytesMut::new();
        CesrEncode::<V1>::encode_cesr(group, &mut dst)?;
        Ok(dst.to_vec())
    }

    fn encode_group_v2(group: &CesrGroup) -> Result<Vec<u8>, ParseError> {
        let mut dst = BytesMut::new();
        CesrEncode::<V2>::encode_cesr(group, &mut dst)?;
        Ok(dst.to_vec())
    }

    #[test]
    fn dispatch_controller_idx_sigs() {
        let mut input = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        input.extend_from_slice(&build_siger_qb64(0));
        let (group, rest) = parse_group(&input).unwrap();
        assert!(matches!(group, CesrGroup::ControllerIdxSigs(_)));
        assert!(rest.is_empty());
    }

    #[test]
    fn dispatch_witness_idx_sigs() {
        let mut input = build_counter_qb64(CounterCodeV1::WitnessIdxSigs, 1);
        input.extend_from_slice(&build_siger_qb64(0));
        let (group, rest) = parse_group(&input).unwrap();
        assert!(matches!(group, CesrGroup::WitnessIdxSigs(_)));
        assert!(rest.is_empty());
    }

    #[test]
    fn dispatch_attachment_group() {
        let mut inner = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        inner.extend_from_slice(&build_siger_qb64(0));
        let quadlets = inner.len() / 4;

        let mut input = build_counter_qb64(CounterCodeV1::AttachmentGroup, quadlets as u32);
        input.extend_from_slice(&inner);
        let (group, rest) = parse_group(&input).unwrap();
        assert!(matches!(group, CesrGroup::AttachmentGroup(_)));
        assert!(rest.is_empty());
    }

    #[test]
    fn dispatch_generic_group() {
        let mut inner = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        inner.extend_from_slice(&build_siger_qb64(0));
        let quadlets = inner.len() / 4;

        let mut input = build_counter_qb64(CounterCodeV1::GenericGroup, quadlets as u32);
        input.extend_from_slice(&inner);
        let (group, rest) = parse_group(&input).unwrap();
        assert!(matches!(group, CesrGroup::GenericGroup(_)));
        assert!(rest.is_empty());
    }

    #[test]
    fn dispatch_pathed_material_quadlet_counted() {
        // Build counter `-L` with count=2 (2 quadlets = 8 bytes) + 8 bytes payload
        let counter = build_counter_qb64(CounterCodeV1::PathedMaterialCouples, 2);
        let payload = b"ABCDEFGH"; // exactly 8 bytes = 2 quadlets
        let mut input = counter;
        input.extend_from_slice(payload);
        input.extend_from_slice(b"TRAILING");
        let (group, rest) = parse_group(&input).unwrap();
        match &group {
            CesrGroup::PathedMaterialCouples(pmc) => {
                assert_eq!(pmc.quadlet_count(), 2);
                assert_eq!(pmc.raw_bytes(), b"ABCDEFGH");
            }
            other => panic!("expected PathedMaterialCouples, got {other:?}"),
        }
        assert_eq!(rest, b"TRAILING");
    }

    #[test]
    fn dispatch_empty_input() {
        let result = parse_group(b"");
        assert!(result.is_err());
    }

    #[test]
    fn groups_iterator_multiple_groups() {
        let mut input = Vec::new();
        input.extend_from_slice(&build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 2));
        input.extend_from_slice(&build_siger_qb64(0));
        input.extend_from_slice(&build_siger_qb64(1));
        input.extend_from_slice(&build_counter_qb64(CounterCodeV1::WitnessIdxSigs, 1));
        input.extend_from_slice(&build_siger_qb64(0));

        let results: Vec<_> = groups(&input).collect();
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok());
        assert!(results[1].is_ok());
        assert!(matches!(
            results[0].as_ref().unwrap(),
            CesrGroup::ControllerIdxSigs(_)
        ));
        assert!(matches!(
            results[1].as_ref().unwrap(),
            CesrGroup::WitnessIdxSigs(_)
        ));
    }

    #[test]
    fn groups_iterator_empty_input() {
        let results: Vec<_> = groups(b"").collect();
        assert!(results.is_empty());
    }

    #[test]
    fn groups_iterator_stops_on_error() {
        let input = b"INVALID";
        let results: Vec<_> = groups(input).collect();
        assert_eq!(results.len(), 1);
        assert!(results[0].is_err());
    }

    #[test]
    fn groups_iterator_copies_attachment_region_once() {
        let counter0 = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        let sig0 = build_siger_qb64(0);
        let counter1 = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        let sig1 = build_siger_qb64(1);

        let mut stream = Vec::new();
        stream.extend_from_slice(&counter0);
        stream.extend_from_slice(&sig0);
        stream.extend_from_slice(&counter1);
        stream.extend_from_slice(&sig1);

        let out: Vec<CesrGroup> = groups(&stream).collect::<Result<_, _>>().unwrap();
        assert_eq!(out.len(), 2);

        let raw0 = match &out[0] {
            CesrGroup::ControllerIdxSigs(g) => g.raw_bytes(),
            other => panic!("expected ControllerIdxSigs, got {other:?}"),
        };
        let raw1 = match &out[1] {
            CesrGroup::ControllerIdxSigs(g) => g.raw_bytes(),
            other => panic!("expected ControllerIdxSigs, got {other:?}"),
        };

        let p0 = raw0.as_ptr() as usize;
        let p1 = raw1.as_ptr() as usize;
        let g0_len = raw0.len();
        // group[1]'s own counter sits between group[0]'s payload and group[1]'s
        // payload, so the exact expected gap is that counter's length.
        let gap = counter1.len();

        // group[1]'s payload begins exactly `gap` bytes after group[0]'s payload
        // ends, within the SAME shared allocation — proving the iterator copied
        // the attachment region once and sliced it, rather than re-copying the
        // remaining input on every `next()` call.
        assert_eq!(
            p1,
            p0 + g0_len + gap,
            "groups must slice one shared buffer, not be copied separately"
        );
    }

    #[test]
    fn parse_group_trailing_bytes() {
        let mut input = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        input.extend_from_slice(&build_siger_qb64(0));
        input.extend_from_slice(b"EXTRA");
        let (group, rest) = parse_group(&input).unwrap();
        assert!(matches!(group, CesrGroup::ControllerIdxSigs(_)));
        assert_eq!(rest, b"EXTRA");
    }

    #[test]
    fn pathed_material_couples_roundtrip() {
        // Build some payload bytes (must be multiple of 4)
        let payload = b"ABCDEFGHIJKLMNOP"; // 16 bytes = 4 quadlets
        let counter = build_counter_qb64(CounterCodeV1::PathedMaterialCouples, 4);
        let mut input = counter;
        input.extend_from_slice(payload);
        let (group, rest) = parse_group(&input).unwrap();
        assert!(rest.is_empty());

        // Roundtrip: encode and re-parse
        let encoded = encode_group_v1(&group).unwrap();
        let (reparsed, rest2) = parse_group(&encoded).unwrap();
        assert!(rest2.is_empty());
        match (&group, &reparsed) {
            (CesrGroup::PathedMaterialCouples(a), CesrGroup::PathedMaterialCouples(b)) => {
                assert_eq!(a.raw_bytes(), b.raw_bytes());
            }
            _ => panic!("type mismatch after roundtrip"),
        }
    }

    // ── V2 seal group helpers ────────────────────────────────────────────

    fn build_counter_v2_qb64(code: CounterCodeV2, count: u32) -> Vec<u8> {
        let hard = code.as_str();
        let ss = code.soft_size();
        let ss_nz = NonZeroUsize::new(ss).unwrap();
        let soft = crate::b64::encode_int(count, ss_nz);
        format!("{hard}{soft}").into_bytes()
    }

    fn build_blake3_256_qb64() -> Vec<u8> {
        use base64::{Engine, engine::general_purpose as b64};
        let raw = [0xCD_u8; 32];
        let ps = 1_usize;
        let mut padded = vec![0u8; ps];
        padded.extend_from_slice(&raw);
        let payload_b64 = b64::URL_SAFE_NO_PAD.encode(&padded);
        format!("E{}", &payload_b64[ps..]).into_bytes()
    }

    fn build_ed25519_qb64() -> Vec<u8> {
        use base64::{Engine, engine::general_purpose as b64};
        let raw = [0xAB_u8; 32];
        let ps = 1_usize;
        let mut padded = vec![0u8; ps];
        padded.extend_from_slice(&raw);
        let payload_b64 = b64::URL_SAFE_NO_PAD.encode(&padded);
        format!("D{}", &payload_b64[ps..]).into_bytes()
    }

    // ── V2 seal group dispatch tests ─────────────────────────────────────

    #[test]
    fn dispatch_v2_digest_seal_singles() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::DigestSealSingles, 1);
        input.extend_from_slice(&build_blake3_256_qb64());
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(matches!(group, CesrGroup::DigestSealSingles(_)));
        assert!(rest.is_empty());
    }

    #[test]
    fn dispatch_v2_merkle_root_seal_singles() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::MerkleRootSealSingles, 1);
        input.extend_from_slice(&build_blake3_256_qb64());
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(matches!(group, CesrGroup::MerkleRootSealSingles(_)));
        assert!(rest.is_empty());
    }

    #[test]
    fn dispatch_v2_seal_source_last_singles() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::SealSourceLastSingles, 1);
        input.extend_from_slice(&build_ed25519_qb64());
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(matches!(group, CesrGroup::SealSourceLastSingles(_)));
        assert!(rest.is_empty());
    }

    #[test]
    fn dispatch_v2_backer_registrar_seal_couples() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::BackerRegistrarSealCouples, 1);
        input.extend_from_slice(&build_ed25519_qb64());
        input.extend_from_slice(&build_blake3_256_qb64());
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(matches!(group, CesrGroup::BackerRegistrarSealCouples(_)));
        assert!(rest.is_empty());
    }

    // ── V2 seal group roundtrip tests ────────────────────────────────────

    #[test]
    fn digest_seal_singles_roundtrip_v2() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::DigestSealSingles, 2);
        for _ in 0..2 {
            input.extend_from_slice(&build_blake3_256_qb64());
        }
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(rest.is_empty());

        let encoded = encode_group_v2(&group).unwrap();
        assert_eq!(encoded, input, "byte-level roundtrip identity");
        let (reparsed, rest2) = parse_group_v2(&encoded).unwrap();
        assert!(rest2.is_empty());
        match (&group, &reparsed) {
            (CesrGroup::DigestSealSingles(a), CesrGroup::DigestSealSingles(b)) => {
                assert_eq!(a.count(), b.count());
                for (da, db) in a.iter().zip(b.iter()) {
                    assert_eq!(da.unwrap().raw(), db.unwrap().raw());
                }
            }
            _ => panic!("type mismatch after roundtrip"),
        }
    }

    #[test]
    fn merkle_root_seal_singles_roundtrip_v2() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::MerkleRootSealSingles, 2);
        for _ in 0..2 {
            input.extend_from_slice(&build_blake3_256_qb64());
        }
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(rest.is_empty());

        let encoded = encode_group_v2(&group).unwrap();
        assert_eq!(encoded, input, "byte-level roundtrip identity");
        let (reparsed, rest2) = parse_group_v2(&encoded).unwrap();
        assert!(rest2.is_empty());
        match (&group, &reparsed) {
            (CesrGroup::MerkleRootSealSingles(a), CesrGroup::MerkleRootSealSingles(b)) => {
                assert_eq!(a.count(), b.count());
                for (da, db) in a.iter().zip(b.iter()) {
                    assert_eq!(da.unwrap().raw(), db.unwrap().raw());
                }
            }
            _ => panic!("type mismatch after roundtrip"),
        }
    }

    #[test]
    fn seal_source_last_singles_roundtrip_v2() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::SealSourceLastSingles, 2);
        for _ in 0..2 {
            input.extend_from_slice(&build_ed25519_qb64());
        }
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(rest.is_empty());

        let encoded = encode_group_v2(&group).unwrap();
        assert_eq!(encoded, input, "byte-level roundtrip identity");
        let (reparsed, rest2) = parse_group_v2(&encoded).unwrap();
        assert!(rest2.is_empty());
        match (&group, &reparsed) {
            (CesrGroup::SealSourceLastSingles(a), CesrGroup::SealSourceLastSingles(b)) => {
                assert_eq!(a.count(), b.count());
                for (pa, pb) in a.iter().zip(b.iter()) {
                    assert_eq!(pa.unwrap().raw(), pb.unwrap().raw());
                }
            }
            _ => panic!("type mismatch after roundtrip"),
        }
    }

    #[test]
    fn backer_registrar_seal_couples_roundtrip_v2() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::BackerRegistrarSealCouples, 2);
        for _ in 0..2 {
            input.extend_from_slice(&build_ed25519_qb64());
            input.extend_from_slice(&build_blake3_256_qb64());
        }
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(rest.is_empty());

        let encoded = encode_group_v2(&group).unwrap();
        assert_eq!(encoded, input, "byte-level roundtrip identity");
        let (reparsed, rest2) = parse_group_v2(&encoded).unwrap();
        assert!(rest2.is_empty());
        match (&group, &reparsed) {
            (
                CesrGroup::BackerRegistrarSealCouples(a),
                CesrGroup::BackerRegistrarSealCouples(b),
            ) => {
                assert_eq!(a.count(), b.count());
                for (ea, eb) in a.iter().zip(b.iter()) {
                    let (pa, da) = ea.unwrap();
                    let (pb, db) = eb.unwrap();
                    assert_eq!(pa.raw(), pb.raw());
                    assert_eq!(da.raw(), db.raw());
                }
            }
            _ => panic!("type mismatch after roundtrip"),
        }
    }

    // ── Complex V2 seal group helpers ─────────────────────────────────────

    fn build_tag7_verser_qb64() -> Vec<u8> {
        b"YAAAAAAA".to_vec()
    }

    fn build_tag3_labeler_qb64() -> Vec<u8> {
        b"XAAA".to_vec()
    }

    fn build_short_number_qb64() -> Vec<u8> {
        b"MAAF".to_vec()
    }

    fn build_texter_qb64() -> Vec<u8> {
        b"4BACW19uJT6H".to_vec()
    }

    // ── Complex V2 seal group dispatch tests ──────────────────────────────

    #[test]
    fn dispatch_v2_typed_digest_seal_couples() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::TypedDigestSealCouples, 1);
        input.extend_from_slice(&build_tag7_verser_qb64());
        input.extend_from_slice(&build_blake3_256_qb64());
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(matches!(group, CesrGroup::TypedDigestSealCouples(_)));
        assert!(rest.is_empty());
    }

    #[test]
    fn dispatch_v2_blinded_state_quadruples() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::BlindedStateQuadruples, 1);
        input.extend_from_slice(&build_blake3_256_qb64()); // diger
        input.extend_from_slice(&build_blake3_256_qb64()); // noncer1
        input.extend_from_slice(&build_blake3_256_qb64()); // noncer2
        input.extend_from_slice(&build_tag3_labeler_qb64()); // labeler
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(matches!(group, CesrGroup::BlindedStateQuadruples(_)));
        assert!(rest.is_empty());
    }

    #[test]
    fn dispatch_v2_bound_state_sextuples() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::BoundStateSextuples, 1);
        input.extend_from_slice(&build_blake3_256_qb64()); // diger
        input.extend_from_slice(&build_blake3_256_qb64()); // noncer1
        input.extend_from_slice(&build_blake3_256_qb64()); // noncer2
        input.extend_from_slice(&build_tag3_labeler_qb64()); // labeler
        input.extend_from_slice(&build_short_number_qb64()); // number
        input.extend_from_slice(&build_blake3_256_qb64()); // noncer3
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(matches!(group, CesrGroup::BoundStateSextuples(_)));
        assert!(rest.is_empty());
    }

    #[test]
    fn dispatch_v2_typed_media_quadruples() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::TypedMediaQuadruples, 1);
        input.extend_from_slice(&build_blake3_256_qb64()); // diger
        input.extend_from_slice(&build_blake3_256_qb64()); // noncer
        input.extend_from_slice(&build_tag3_labeler_qb64()); // labeler
        input.extend_from_slice(&build_texter_qb64()); // texter
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(matches!(group, CesrGroup::TypedMediaQuadruples(_)));
        assert!(rest.is_empty());
    }

    // ── Complex V2 seal group roundtrip tests ─────────────────────────────

    #[test]
    fn typed_digest_seal_couples_roundtrip_v2() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::TypedDigestSealCouples, 2);
        for _ in 0..2 {
            input.extend_from_slice(&build_tag7_verser_qb64());
            input.extend_from_slice(&build_blake3_256_qb64());
        }
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(rest.is_empty());

        let encoded = encode_group_v2(&group).unwrap();
        assert_eq!(encoded, input, "byte-level roundtrip identity");
        let (reparsed, rest2) = parse_group_v2(&encoded).unwrap();
        assert!(rest2.is_empty());
        match (&group, &reparsed) {
            (CesrGroup::TypedDigestSealCouples(a), CesrGroup::TypedDigestSealCouples(b)) => {
                assert_eq!(a.count(), b.count());
                for (ea, eb) in a.iter().zip(b.iter()) {
                    let (va, da) = ea.unwrap();
                    let (vb, db) = eb.unwrap();
                    assert_eq!(va.soft(), vb.soft());
                    assert_eq!(da.raw(), db.raw());
                }
            }
            _ => panic!("type mismatch after roundtrip"),
        }
    }

    #[test]
    fn blinded_state_quadruples_roundtrip_v2() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::BlindedStateQuadruples, 2);
        for _ in 0..2 {
            input.extend_from_slice(&build_blake3_256_qb64());
            input.extend_from_slice(&build_blake3_256_qb64());
            input.extend_from_slice(&build_blake3_256_qb64());
            input.extend_from_slice(&build_tag3_labeler_qb64());
        }
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(rest.is_empty());

        let encoded = encode_group_v2(&group).unwrap();
        assert_eq!(encoded, input, "byte-level roundtrip identity");
        let (reparsed, rest2) = parse_group_v2(&encoded).unwrap();
        assert!(rest2.is_empty());
        match (&group, &reparsed) {
            (CesrGroup::BlindedStateQuadruples(a), CesrGroup::BlindedStateQuadruples(b)) => {
                assert_eq!(a.count(), b.count());
                for (ea, eb) in a.iter().zip(b.iter()) {
                    let (da, n1a, n2a, la) = ea.unwrap();
                    let (db, n1b, n2b, lb) = eb.unwrap();
                    assert_eq!(da.raw(), db.raw());
                    assert_eq!(n1a.raw(), n1b.raw());
                    assert_eq!(n2a.raw(), n2b.raw());
                    assert_eq!(la.soft(), lb.soft());
                }
            }
            _ => panic!("type mismatch after roundtrip"),
        }
    }

    #[test]
    fn bound_state_sextuples_roundtrip_v2() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::BoundStateSextuples, 2);
        for _ in 0..2 {
            input.extend_from_slice(&build_blake3_256_qb64());
            input.extend_from_slice(&build_blake3_256_qb64());
            input.extend_from_slice(&build_blake3_256_qb64());
            input.extend_from_slice(&build_tag3_labeler_qb64());
            input.extend_from_slice(&build_short_number_qb64());
            input.extend_from_slice(&build_blake3_256_qb64());
        }
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(rest.is_empty());

        let encoded = encode_group_v2(&group).unwrap();
        assert_eq!(encoded, input, "byte-level roundtrip identity");
        let (reparsed, rest2) = parse_group_v2(&encoded).unwrap();
        assert!(rest2.is_empty());
        match (&group, &reparsed) {
            (CesrGroup::BoundStateSextuples(a), CesrGroup::BoundStateSextuples(b)) => {
                assert_eq!(a.count(), b.count());
                for (ea, eb) in a.iter().zip(b.iter()) {
                    let (da, n1a, n2a, la, num_a, n3a) = ea.unwrap();
                    let (db, n1b, n2b, lb, num_b, n3b) = eb.unwrap();
                    assert_eq!(da.raw(), db.raw());
                    assert_eq!(n1a.raw(), n1b.raw());
                    assert_eq!(n2a.raw(), n2b.raw());
                    assert_eq!(la.soft(), lb.soft());
                    assert_eq!(num_a.value(), num_b.value());
                    assert_eq!(n3a.raw(), n3b.raw());
                }
            }
            _ => panic!("type mismatch after roundtrip"),
        }
    }

    #[test]
    fn typed_media_quadruples_roundtrip_v2() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::TypedMediaQuadruples, 2);
        for _ in 0..2 {
            input.extend_from_slice(&build_blake3_256_qb64());
            input.extend_from_slice(&build_blake3_256_qb64());
            input.extend_from_slice(&build_tag3_labeler_qb64());
            input.extend_from_slice(&build_texter_qb64());
        }
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(rest.is_empty());

        let encoded = encode_group_v2(&group).unwrap();
        assert_eq!(encoded, input, "byte-level roundtrip identity");
        let (reparsed, rest2) = parse_group_v2(&encoded).unwrap();
        assert!(rest2.is_empty());
        match (&group, &reparsed) {
            (CesrGroup::TypedMediaQuadruples(a), CesrGroup::TypedMediaQuadruples(b)) => {
                assert_eq!(a.count(), b.count());
                for (ea, eb) in a.iter().zip(b.iter()) {
                    let (da, na, la, ta) = ea.unwrap();
                    let (db, nb, lb, tb) = eb.unwrap();
                    assert_eq!(da.raw(), db.raw());
                    assert_eq!(na.raw(), nb.raw());
                    assert_eq!(la.soft(), lb.soft());
                    assert_eq!(ta.raw(), tb.raw());
                }
            }
            _ => panic!("type mismatch after roundtrip"),
        }
    }

    #[test]
    fn parse_group_bytes_matches_slice_path() {
        let mut input = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        input.extend_from_slice(&build_siger_qb64(0));

        let bytes = Bytes::copy_from_slice(&input);
        let (group, rest) = parse_group_bytes(&bytes).unwrap();
        assert!(matches!(group, CesrGroup::ControllerIdxSigs(_)));
        assert!(rest.is_empty());
    }

    // ── GroupsV2 iterator tests ────────────────────────────────────────────

    #[test]
    fn groups_v2_iterator_multiple_groups() {
        let mut input = Vec::new();
        input.extend_from_slice(&build_counter_v2_qb64(CounterCodeV2::ControllerIdxSigs, 2));
        input.extend_from_slice(&build_siger_qb64(0));
        input.extend_from_slice(&build_siger_qb64(1));
        input.extend_from_slice(&build_counter_v2_qb64(CounterCodeV2::WitnessIdxSigs, 1));
        input.extend_from_slice(&build_siger_qb64(0));

        let results: Vec<_> = groups_v2(&input).collect();
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok());
        assert!(results[1].is_ok());
        assert!(matches!(
            results[0].as_ref().unwrap(),
            CesrGroup::ControllerIdxSigs(_)
        ));
        assert!(matches!(
            results[1].as_ref().unwrap(),
            CesrGroup::WitnessIdxSigs(_)
        ));
    }

    #[test]
    fn groups_v2_iterator_empty_input() {
        let results: Vec<_> = groups_v2(b"").collect();
        assert!(results.is_empty());
    }

    #[test]
    fn groups_v2_iterator_stops_on_error() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::ControllerIdxSigs, 1);
        input.extend_from_slice(&build_siger_qb64(0));
        input.extend_from_slice(b"INVALID");

        let results: Vec<_> = groups_v2(&input).collect();
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok());
        assert!(matches!(
            results[0].as_ref().unwrap(),
            CesrGroup::ControllerIdxSigs(_)
        ));
        assert!(results[1].is_err());
    }

    #[test]
    fn groups_v2_copies_attachment_region_once() {
        let counter0 = build_counter_v2_qb64(CounterCodeV2::ControllerIdxSigs, 1);
        let sig0 = build_siger_qb64(0);
        let counter1 = build_counter_v2_qb64(CounterCodeV2::ControllerIdxSigs, 1);
        let sig1 = build_siger_qb64(1);

        let mut stream = Vec::new();
        stream.extend_from_slice(&counter0);
        stream.extend_from_slice(&sig0);
        stream.extend_from_slice(&counter1);
        stream.extend_from_slice(&sig1);

        let out: Vec<CesrGroup> = groups_v2(&stream).collect::<Result<_, _>>().unwrap();
        assert_eq!(out.len(), 2);

        let raw0 = match &out[0] {
            CesrGroup::ControllerIdxSigs(g) => g.raw_bytes(),
            other => panic!("expected ControllerIdxSigs, got {other:?}"),
        };
        let raw1 = match &out[1] {
            CesrGroup::ControllerIdxSigs(g) => g.raw_bytes(),
            other => panic!("expected ControllerIdxSigs, got {other:?}"),
        };

        let p0 = raw0.as_ptr() as usize;
        let p1 = raw1.as_ptr() as usize;
        let g0_len = raw0.len();
        // group[1]'s own counter sits between group[0]'s payload and group[1]'s
        // payload, so the exact expected gap is that counter's length.
        let gap = counter1.len();

        // group[1]'s payload begins exactly `gap` bytes after group[0]'s payload
        // ends, within the SAME shared allocation — proving the iterator copied
        // the attachment region once and sliced it, rather than re-copying the
        // remaining input on every `next()` call.
        assert_eq!(
            p1,
            p0 + g0_len + gap,
            "groups_v2 must slice one shared buffer, not be copied separately"
        );
    }

    // ── V2 quadlet-group dispatch coverage (dispatch_v2_frames arms) ────────
    //
    // Quadlet-counted groups parse lazily: the payload is just `count * 4`
    // bytes, sliced without inspecting its contents. Each code must dispatch to
    // its own `CesrGroup` variant. Deleting any arm in `dispatch_v2_frames`
    // makes that code fall through to the next dispatcher and either error or
    // pick the wrong variant, so asserting the exact variant per code kills the
    // arm-deletion mutants.

    type QuadletDispatchCase = (CounterCodeV2, fn(&CesrGroup) -> bool, &'static str);

    fn quadlet_v2_dispatch_cases() -> Vec<QuadletDispatchCase> {
        vec![
            (
                CounterCodeV2::AttachmentGroup,
                (|g| matches!(g, CesrGroup::AttachmentGroup(_))) as fn(&CesrGroup) -> bool,
                "AttachmentGroup",
            ),
            (
                CounterCodeV2::GenericGroup,
                |g| matches!(g, CesrGroup::GenericGroup(_)),
                "GenericGroup",
            ),
            (
                CounterCodeV2::BodyWithAttachmentGroup,
                |g| matches!(g, CesrGroup::BodyWithAttachmentGroup(_)),
                "BodyWithAttachmentGroup",
            ),
            (
                CounterCodeV2::NonNativeBodyGroup,
                |g| matches!(g, CesrGroup::NonNativeBodyGroup(_)),
                "NonNativeBodyGroup",
            ),
            (
                CounterCodeV2::ESSRPayloadGroup,
                |g| matches!(g, CesrGroup::ESSRPayloadGroup(_)),
                "ESSRPayloadGroup",
            ),
            (
                CounterCodeV2::DatagramSegmentGroup,
                |g| matches!(g, CesrGroup::DatagramSegmentGroup(_)),
                "DatagramSegmentGroup",
            ),
            (
                CounterCodeV2::ESSRWrapperGroup,
                |g| matches!(g, CesrGroup::ESSRWrapperGroup(_)),
                "ESSRWrapperGroup",
            ),
            (
                CounterCodeV2::FixBodyGroup,
                |g| matches!(g, CesrGroup::FixBodyGroup(_)),
                "FixBodyGroup",
            ),
            (
                CounterCodeV2::MapBodyGroup,
                |g| matches!(g, CesrGroup::MapBodyGroup(_)),
                "MapBodyGroup",
            ),
            (
                CounterCodeV2::GenericMapGroup,
                |g| matches!(g, CesrGroup::GenericMapGroup(_)),
                "GenericMapGroup",
            ),
            (
                CounterCodeV2::GenericListGroup,
                |g| matches!(g, CesrGroup::GenericListGroup(_)),
                "GenericListGroup",
            ),
            (
                CounterCodeV2::PathedMaterialCouples,
                |g| matches!(g, CesrGroup::PathedMaterialCouples(_)),
                "PathedMaterialCouples",
            ),
        ]
    }

    #[test]
    fn parse_group_v2_quadlet_dispatch_maps_each_code() {
        for (code, is_variant, name) in quadlet_v2_dispatch_cases() {
            // count=1 quadlet = 4 payload bytes; quadlet parsing is lazy so any
            // 4 bytes suffice to exercise the dispatch arm.
            let mut input = build_counter_v2_qb64(code, 1);
            input.extend_from_slice(b"AAAA");
            let (group, rest) = parse_group_v2(&input)
                .unwrap_or_else(|e| panic!("{name}: parse_group_v2 failed: {e:?}"));
            assert!(
                is_variant(&group),
                "{name}: dispatched to wrong CesrGroup variant: {group:?}"
            );
            assert!(rest.is_empty(), "{name}: unexpected remainder");
        }
    }

    // ── V2 leaf-group dispatch coverage (dispatch_v2 arms) ─────────────────

    #[test]
    fn dispatch_v2_non_trans_receipt_couples() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::NonTransReceiptCouples, 1);
        input.extend_from_slice(&build_ed25519_qb64());
        input.extend_from_slice(&build_blake3_256_qb64());
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(matches!(group, CesrGroup::NonTransReceiptCouples(_)));
        assert!(rest.is_empty());
    }

    #[test]
    fn dispatch_v2_trans_receipt_quadruples() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::TransReceiptQuadruples, 1);
        input.extend_from_slice(&build_ed25519_qb64());
        input.extend_from_slice(&build_ed25519_qb64());
        input.extend_from_slice(&build_blake3_256_qb64());
        input.extend_from_slice(&build_siger_qb64(0));
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(matches!(group, CesrGroup::TransReceiptQuadruples(_)));
        assert!(rest.is_empty());
    }

    #[test]
    fn dispatch_v2_first_seen_replay_couples() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::FirstSeenReplayCouples, 1);
        input.extend_from_slice(&build_ed25519_qb64());
        input.extend_from_slice(&build_blake3_256_qb64());
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(matches!(group, CesrGroup::FirstSeenReplayCouples(_)));
        assert!(rest.is_empty());
    }

    #[test]
    fn dispatch_v2_seal_source_couples() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::SealSourceCouples, 1);
        input.extend_from_slice(&build_ed25519_qb64());
        input.extend_from_slice(&build_blake3_256_qb64());
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(matches!(group, CesrGroup::SealSourceCouples(_)));
        assert!(rest.is_empty());
    }

    #[test]
    fn dispatch_v2_seal_source_triples() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::SealSourceTriples, 1);
        input.extend_from_slice(&build_ed25519_qb64());
        input.extend_from_slice(&build_ed25519_qb64());
        input.extend_from_slice(&build_blake3_256_qb64());
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(matches!(group, CesrGroup::SealSourceTriples(_)));
        assert!(rest.is_empty());
    }

    // ── V2 special dispatch: KERIACDCGenusVersion is not an attachment group ─
    //
    // Deleting the `KERIACDCGenusVersion` arm in `dispatch_v2_seals` falls
    // through to the generic `_` arm, which returns a *different* Malformed
    // message. Asserting the exact message distinguishes the two error domains.

    #[test]
    fn dispatch_v2_genus_version_is_rejected_with_specific_message() {
        // "-_AAA" + 3 soft chars encoding major=2, minor=0.
        let input = b"-_AAACAA";
        let err = parse_group_v2(input).unwrap_err();
        match err {
            ParseError::Malformed(msg) => assert_eq!(
                &*msg, "genus version codes are not attachment groups",
                "genus-version rejection must use its own error message"
            ),
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    // ── parse_group_inner_v2 remainder slicing (line `consumed = len - rest`) ─
    //
    // The public `parse_group_v2` returns `&input[consumed..]`. If the
    // `consumed = input.len() - rest.len()` computation is corrupted (e.g.
    // `-` → `+`), the returned remainder is wrong (and out-of-range slicing
    // panics). Asserting the exact trailing bytes pins the arithmetic.

    #[test]
    fn parse_group_v2_returns_exact_trailing_remainder() {
        let mut input = build_counter_v2_qb64(CounterCodeV2::ControllerIdxSigs, 1);
        input.extend_from_slice(&build_siger_qb64(0));
        input.extend_from_slice(b"TRAILING_V2");
        let (group, rest) = parse_group_v2(&input).unwrap();
        assert!(matches!(group, CesrGroup::ControllerIdxSigs(_)));
        assert_eq!(rest, b"TRAILING_V2");
    }

    // ── Elements iterator (carrier behavior) ────────────────────────────────

    mod elements {
        use super::*;

        fn controller_group(sig_count: u32) -> ControllerIdxSigs {
            let mut raw = Vec::new();
            for i in 0..sig_count {
                raw.extend_from_slice(&build_siger_qb64(i));
            }
            let buf = Bytes::copy_from_slice(&raw);
            let (group, rest) =
                ControllerIdxSigs::parse(&buf, sig_count, crate::core::version::CesrVersion::V1)
                    .unwrap();
            assert!(rest.is_empty());
            group
        }

        #[test]
        fn iter_yields_correct_count() {
            let group = controller_group(3);
            let items: Vec<_> = group.iter().collect();
            assert_eq!(items.len(), 3);
            for (i, item) in items.into_iter().enumerate() {
                assert_eq!(item.unwrap().index(), u32::try_from(i).unwrap());
            }
        }

        #[test]
        fn iter_zero_count_yields_nothing() {
            let group = controller_group(0);
            assert_eq!(group.iter().count(), 0);
        }

        #[test]
        fn iter_stops_on_error() {
            // Count claims 2 elements but the raw span is truncated mid-second:
            // one Ok, one Err, then iteration ends.
            let mut raw = build_siger_qb64(0);
            raw.extend_from_slice(&build_siger_qb64(1)[..40]);
            let group = ControllerIdxSigs::new(
                Bytes::copy_from_slice(&raw),
                2,
                crate::core::version::CesrVersion::V1,
            );
            let items: Vec<_> = group.iter().collect();
            assert_eq!(items.len(), 2);
            assert!(items[0].is_ok());
            assert!(items[1].is_err());
        }

        #[test]
        fn ref_group_is_into_iterator() {
            let group = controller_group(2);
            let mut indices = Vec::new();
            for item in &group {
                indices.push(item.unwrap().index());
            }
            assert_eq!(indices, vec![0, 1]);
        }

        #[test]
        fn size_hint_upper_bound_is_remaining() {
            let group = controller_group(2);
            let mut iter = group.iter();
            assert_eq!(iter.size_hint(), (0, Some(2)));
            let _ = iter.next();
            assert_eq!(iter.size_hint(), (0, Some(1)));
        }
    }

    // ── Quadlet framing (carrier behavior, was quadlet_group.rs) ───────────

    mod quadlets {
        use super::*;

        fn build_controller_idx_sigs_group() -> Vec<u8> {
            let mut g = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
            g.extend_from_slice(&build_siger_qb64(0));
            g
        }

        #[test]
        fn parse_quadlets_huge_count_needs_bytes_no_panic() {
            let input = Bytes::from_static(b"AAAA");
            let err = parse_quadlets(&input, u32::MAX).unwrap_err();
            assert!(matches!(err, ParseError::NeedBytes(_)));
        }

        #[test]
        fn parse_quadlets_v2_huge_count_needs_bytes_no_panic() {
            let input = Bytes::from_static(b"AAAA");
            let err = parse_quadlets_v2(&input, u32::MAX).unwrap_err();
            assert!(matches!(err, ParseError::NeedBytes(_)));
        }

        // `NeedBytes` value = `total_bytes - input.len()`. count=2 → total 8, input
        // 4 → exactly 4 missing. `-` → `+` gives 12, `-` → `/` gives 2; the exact
        // assertion pins the shortfall arithmetic for both parse_quadlets and _v2.
        #[test]
        fn parse_quadlets_need_bytes_reports_exact_shortfall() {
            let input = Bytes::from_static(b"AAAA");
            let err = parse_quadlets(&input, 2).unwrap_err();
            assert_eq!(err, ParseError::NeedBytes(4));
        }

        #[test]
        fn parse_quadlets_v2_need_bytes_reports_exact_shortfall() {
            let input = Bytes::from_static(b"AAAA");
            let err = parse_quadlets_v2(&input, 2).unwrap_err();
            assert_eq!(err, ParseError::NeedBytes(4));
        }

        // Exact-size boundary: `input.len() == total_bytes` must SUCCEED. `<` → `<=`
        // turns the exact-fit case into `NeedBytes(0)`. count=2 → total 8, input 8.
        #[test]
        fn parse_quadlets_v2_exact_size_succeeds() {
            let input = Bytes::from_static(b"AAAABBBB");
            let (group, rest) = parse_quadlets_v2(&input, 2).unwrap();
            assert_eq!(group.quadlet_count(), 2);
            assert_eq!(group.raw_bytes(), b"AAAABBBB");
            assert!(rest.is_empty());
        }

        #[test]
        fn parse_quadlets_exact_size_succeeds() {
            let input = Bytes::from_static(b"AAAABBBB");
            let (group, rest) = parse_quadlets(&input, 2).unwrap();
            assert_eq!(group.quadlet_count(), 2);
            assert_eq!(group.raw_bytes(), b"AAAABBBB");
            assert!(rest.is_empty());
        }

        // Iterating a QuadletGroup over two inner groups must yield BOTH. The cursor
        // advance `self.input.len() - rest.len()` (`-` → `+`) overshoots past the
        // end after the first group, and the `cursor >= input.len()` guard
        // (`>=` → `<`) stops immediately; either way the count drops below 2.
        #[test]
        fn quadlet_group_iterates_all_inner_groups() {
            let mut payload = build_controller_idx_sigs_group();
            payload.extend_from_slice(&build_controller_idx_sigs_group());
            let quadlets = u32::try_from(payload.len() / 4).unwrap();

            let parent = Bytes::copy_from_slice(&payload);
            let (group, rest) = parse_quadlets(&parent, quadlets).unwrap();
            assert!(rest.is_empty());

            let inner: Vec<_> = group.collect::<Result<_, _>>().unwrap();
            assert_eq!(inner.len(), 2, "QuadletGroup must yield both inner groups");
            assert!(matches!(inner[0], CesrGroup::ControllerIdxSigs(_)));
            assert!(matches!(inner[1], CesrGroup::ControllerIdxSigs(_)));
        }

        #[test]
        fn parse_quadlets_slices_without_copying() {
            let payload = b"AAAABBBB";
            let parent = Bytes::copy_from_slice(payload);
            let parent_start = parent.as_ptr() as usize;
            let parent_end = parent_start + parent.len();

            let (group, _rest) = parse_quadlets(&parent, 2).unwrap();
            let raw_ptr = group.raw_bytes().as_ptr() as usize;

            assert!(
                raw_ptr >= parent_start && raw_ptr < parent_end,
                "QuadletGroup raw must be a slice of the parent buffer, not a copy"
            );
        }

        // ── was attachment_group.rs ─────────────────────────────────────────

        #[test]
        fn attachment_parse_zero_quadlets() {
            let (quadlets, rest) = parse_quadlets(&Bytes::new(), 0).unwrap();
            let group = AttachmentGroup::new(quadlets);
            assert_eq!(group.quadlet_count(), 0);
            assert!(rest.is_empty());
        }

        #[test]
        fn attachment_parse_single_inner_group() {
            let payload = build_controller_idx_sigs_group();
            let quadlet_count = payload.len() / 4;
            assert_eq!(payload.len() % 4, 0);

            let (quadlets, rest) = parse_quadlets(
                &Bytes::copy_from_slice(&payload),
                u32::try_from(quadlet_count).unwrap(),
            )
            .unwrap();
            let group = AttachmentGroup::new(quadlets);
            let items: Vec<_> = group.into_iter().collect();
            assert_eq!(items.len(), 1);
            assert!(items[0].is_ok());
            assert!(rest.is_empty());
        }

        #[test]
        fn attachment_trailing_bytes_preserved() {
            let mut payload = build_controller_idx_sigs_group();
            let quadlet_count = payload.len() / 4;

            payload.extend_from_slice(b"TRAILING");
            let (quadlets, rest) = parse_quadlets(
                &Bytes::copy_from_slice(&payload),
                u32::try_from(quadlet_count).unwrap(),
            )
            .unwrap();
            let group = AttachmentGroup::new(quadlets);
            let items: Vec<_> = group.into_iter().collect();
            assert_eq!(items.len(), 1);
            assert!(items[0].is_ok());
            assert_eq!(rest, Bytes::from_static(b"TRAILING"));
        }

        #[test]
        fn attachment_insufficient_data_errors() {
            let result = parse_quadlets(&Bytes::from_static(b"ABCD"), 10);
            assert!(result.is_err());
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::as_conversions,
    reason = "test code: panics and type conversions acceptable"
)]
mod encode_tests {
    use super::*;
    use crate::core::indexer::IndexerBuilder;
    use crate::core::indexer::code::IndexedSigCode;
    use crate::core::primitives::Siger;
    use crate::core::version::CesrVersion;
    use crate::stream::encode::encode_counter_v1;
    use base64::Engine as _;
    use base64::engine::general_purpose as b64;
    use core::num::NonZeroUsize;

    fn build_siger(index: u32) -> Siger<'static> {
        let indexer = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519)
            .with_index(index)
            .unwrap()
            .with_raw(&[0u8; 64])
            .unwrap();
        Siger::new(indexer)
    }

    fn build_prefixer_qb64() -> Vec<u8> {
        let raw = [0xABu8; 32];
        let ps = 1_usize;
        let mut padded = vec![0u8; ps];
        padded.extend_from_slice(&raw);
        let payload_b64 = b64::URL_SAFE_NO_PAD.encode(&padded);
        format!("D{}", &payload_b64[ps..]).into_bytes()
    }

    fn build_cigar_qb64() -> Vec<u8> {
        let raw = [0xEFu8; 64];
        let ps = 2_usize;
        let mut padded = vec![0u8; ps];
        padded.extend_from_slice(&raw);
        let payload_b64 = b64::URL_SAFE_NO_PAD.encode(&padded);
        format!("0B{}", &payload_b64[ps..]).into_bytes()
    }

    fn build_saider_qb64() -> Vec<u8> {
        let raw = [0xCDu8; 32];
        let ps = 1_usize;
        let mut padded = vec![0u8; ps];
        padded.extend_from_slice(&raw);
        let payload_b64 = b64::URL_SAFE_NO_PAD.encode(&padded);
        format!("E{}", &payload_b64[ps..]).into_bytes()
    }

    fn build_seqner_qb64() -> Vec<u8> {
        b"MAAB".to_vec()
    }

    fn build_dater_qb64() -> Vec<u8> {
        let raw = [0x11u8; 32];
        let ps = 1_usize;
        let mut padded = vec![0u8; ps];
        padded.extend_from_slice(&raw);
        let payload_b64 = b64::URL_SAFE_NO_PAD.encode(&padded);
        format!("D{}", &payload_b64[ps..]).into_bytes()
    }

    fn encode_v1<T: CesrEncode<V1>>(group: &T) -> Result<Vec<u8>, ParseError> {
        let mut dst = BytesMut::new();
        group.encode_cesr(&mut dst)?;
        Ok(dst.to_vec())
    }

    fn group_v1<K: GroupKind>(raw: Vec<u8>, count: u32) -> Group<K> {
        Group::new(Bytes::from(raw), count, CesrVersion::V1)
    }

    // ── Element-counted group encoding (was encode.rs::element_groups) ────

    #[test]
    fn encode_controller_idx_sigs_roundtrip() {
        let siger0 = build_siger(0);
        let siger1 = build_siger(1);
        let mut raw = Vec::new();
        raw.extend_from_slice(siger0.to_qb64().as_bytes());
        raw.extend_from_slice(siger1.to_qb64().as_bytes());
        let group: ControllerIdxSigs = group_v1(raw, 2);
        let encoded = encode_v1(&group).unwrap();
        let (parsed, rest) = parse_group(&encoded).unwrap();
        assert!(rest.is_empty());
        match parsed {
            CesrGroup::ControllerIdxSigs(g) => assert_eq!(g.count() as usize, 2),
            other => panic!("expected ControllerIdxSigs, got {other:?}"),
        }
    }

    #[test]
    fn encode_controller_idx_sigs_empty() {
        let group: ControllerIdxSigs = group_v1(Vec::new(), 0);
        let encoded = encode_v1(&group).unwrap();
        let (parsed, rest) = parse_group(&encoded).unwrap();
        assert!(rest.is_empty());
        match parsed {
            CesrGroup::ControllerIdxSigs(g) => assert_eq!(g.count() as usize, 0),
            other => panic!("expected ControllerIdxSigs, got {other:?}"),
        }
    }

    #[test]
    fn encode_witness_idx_sigs_roundtrip() {
        let siger0 = build_siger(0);
        let mut raw = Vec::new();
        raw.extend_from_slice(siger0.to_qb64().as_bytes());
        let group: WitnessIdxSigs = group_v1(raw, 1);
        let encoded = encode_v1(&group).unwrap();
        let (parsed, rest) = parse_group(&encoded).unwrap();
        assert!(rest.is_empty());
        match parsed {
            CesrGroup::WitnessIdxSigs(g) => assert_eq!(g.count() as usize, 1),
            other => panic!("expected WitnessIdxSigs, got {other:?}"),
        }
    }

    #[test]
    fn encode_non_trans_receipt_couples_roundtrip() {
        let mut raw = build_prefixer_qb64();
        raw.extend_from_slice(&build_cigar_qb64());
        let group: NonTransReceiptCouples = group_v1(raw, 1);
        let encoded = encode_v1(&group).unwrap();
        let (parsed, rest) = parse_group(&encoded).unwrap();
        assert!(rest.is_empty());
        match parsed {
            CesrGroup::NonTransReceiptCouples(g) => assert_eq!(g.count() as usize, 1),
            other => panic!("expected NonTransReceiptCouples, got {other:?}"),
        }
    }

    #[test]
    fn encode_trans_receipt_quadruples_roundtrip() {
        let mut raw = build_prefixer_qb64();
        raw.extend_from_slice(&build_seqner_qb64());
        raw.extend_from_slice(&build_saider_qb64());
        raw.extend_from_slice(build_siger(0).to_qb64().as_bytes());
        let group: TransReceiptQuadruples = group_v1(raw, 1);
        let encoded = encode_v1(&group).unwrap();
        let (parsed, rest) = parse_group(&encoded).unwrap();
        assert!(rest.is_empty());
        match parsed {
            CesrGroup::TransReceiptQuadruples(g) => assert_eq!(g.count() as usize, 1),
            other => panic!("expected TransReceiptQuadruples, got {other:?}"),
        }
    }

    #[test]
    fn encode_first_seen_replay_couples_roundtrip() {
        let mut raw = build_seqner_qb64();
        raw.extend_from_slice(&build_dater_qb64());
        let group: FirstSeenReplayCouples = group_v1(raw, 1);
        let encoded = encode_v1(&group).unwrap();
        let (parsed, rest) = parse_group(&encoded).unwrap();
        assert!(rest.is_empty());
        match parsed {
            CesrGroup::FirstSeenReplayCouples(g) => assert_eq!(g.count() as usize, 1),
            other => panic!("expected FirstSeenReplayCouples, got {other:?}"),
        }
    }

    #[test]
    fn encode_seal_source_couples_roundtrip() {
        let mut raw = build_seqner_qb64();
        raw.extend_from_slice(&build_saider_qb64());
        let group: SealSourceCouples = group_v1(raw, 1);
        let encoded = encode_v1(&group).unwrap();
        let (parsed, rest) = parse_group(&encoded).unwrap();
        assert!(rest.is_empty());
        match parsed {
            CesrGroup::SealSourceCouples(g) => assert_eq!(g.count() as usize, 1),
            other => panic!("expected SealSourceCouples, got {other:?}"),
        }
    }

    #[test]
    fn encode_seal_source_triples_roundtrip() {
        let mut raw = build_prefixer_qb64();
        raw.extend_from_slice(&build_seqner_qb64());
        raw.extend_from_slice(&build_saider_qb64());
        let group: SealSourceTriples = group_v1(raw, 1);
        let encoded = encode_v1(&group).unwrap();
        let (parsed, rest) = parse_group(&encoded).unwrap();
        assert!(rest.is_empty());
        match parsed {
            CesrGroup::SealSourceTriples(g) => assert_eq!(g.count() as usize, 1),
            other => panic!("expected SealSourceTriples, got {other:?}"),
        }
    }

    // ── Quadlet-counted frame encoding (was encode.rs::quadlet_groups) ────

    fn build_siger_qb64(index: u32) -> Vec<u8> {
        build_siger(index).to_qb64().into_bytes()
    }

    fn build_counter_qb64(code: CounterCodeV1, count: u32) -> Vec<u8> {
        let hard = code.as_str();
        let ss = code.soft_size();
        let ss_nz = NonZeroUsize::new(ss).unwrap();
        let soft = crate::b64::encode_int(count, ss_nz);
        format!("{hard}{soft}").into_bytes()
    }

    fn build_inner_group() -> Vec<u8> {
        let mut inner = build_counter_qb64(CounterCodeV1::ControllerIdxSigs, 1);
        inner.extend_from_slice(&build_siger_qb64(0));
        inner
    }

    fn frame_v1<K: FrameKind>(payload: Vec<u8>) -> Frame<K> {
        Frame::new(QuadletGroup::new(Bytes::from(payload), parse_group_bytes))
    }

    #[test]
    fn encode_attachment_group_roundtrip() {
        let frame: AttachmentGroup = frame_v1(build_inner_group());
        let encoded = encode_v1(&frame).unwrap();
        let (group, rest) = parse_group(&encoded).unwrap();
        assert!(rest.is_empty());
        assert!(matches!(group, CesrGroup::AttachmentGroup(_)));
    }

    #[test]
    fn encode_generic_group_roundtrip() {
        let frame: GenericGroup = frame_v1(build_inner_group());
        let encoded = encode_v1(&frame).unwrap();
        let (group, rest) = parse_group(&encoded).unwrap();
        assert!(rest.is_empty());
        assert!(matches!(group, CesrGroup::GenericGroup(_)));
    }

    #[test]
    fn encode_body_with_attachment_group_roundtrip() {
        let frame: BodyWithAttachmentGroup = frame_v1(build_inner_group());
        let encoded = encode_v1(&frame).unwrap();
        let (group, rest) = parse_group(&encoded).unwrap();
        assert!(rest.is_empty());
        assert!(matches!(group, CesrGroup::BodyWithAttachmentGroup(_)));
    }

    #[test]
    fn encode_non_native_body_group_roundtrip() {
        let frame: NonNativeBodyGroup = frame_v1(build_inner_group());
        let encoded = encode_v1(&frame).unwrap();
        let (group, rest) = parse_group(&encoded).unwrap();
        assert!(rest.is_empty());
        assert!(matches!(group, CesrGroup::NonNativeBodyGroup(_)));
    }

    #[test]
    fn encode_essr_payload_group_roundtrip() {
        let frame: ESSRPayloadGroup = frame_v1(build_inner_group());
        let encoded = encode_v1(&frame).unwrap();
        let (group, rest) = parse_group(&encoded).unwrap();
        assert!(rest.is_empty());
        assert!(matches!(group, CesrGroup::ESSRPayloadGroup(_)));
    }

    #[test]
    fn encode_quadlet_group_rejects_non_multiple_of_4() {
        let frame: AttachmentGroup = frame_v1(vec![0u8; 5]);
        let result = encode_v1(&frame);
        assert!(result.is_err());
    }

    #[test]
    fn encode_quadlet_group_empty() {
        let frame: AttachmentGroup = frame_v1(Vec::new());
        let encoded = encode_v1(&frame).unwrap();
        let (group, rest) = parse_group(&encoded).unwrap();
        assert!(rest.is_empty());
        match group {
            CesrGroup::AttachmentGroup(ag) => assert_eq!(ag.quadlet_count(), 0),
            other => panic!("expected AttachmentGroup, got {other:?}"),
        }
    }

    // ── CesrEncode trait direct tests (was encode.rs::encode_cesr) ────────

    #[test]
    fn encode_cesr_v1_element_roundtrips() {
        let raw = build_siger_qb64(0);
        let group: ControllerIdxSigs = group_v1(raw, 1);

        let mut dst = BytesMut::new();
        CesrEncode::<V1>::encode_cesr(&group, &mut dst).unwrap();

        let (parsed, rest) = parse_group(&dst).unwrap();
        assert!(rest.is_empty());
        assert!(matches!(parsed, CesrGroup::ControllerIdxSigs(g) if g.count() == 1));
    }

    #[test]
    fn encode_cesr_v2_element_roundtrips() {
        let raw = build_siger_qb64(0);
        let group: ControllerIdxSigs = group_v1(raw, 1);

        let mut dst = BytesMut::new();
        CesrEncode::<V2>::encode_cesr(&group, &mut dst).unwrap();

        let (parsed, rest) = parse_group_v2(&dst).unwrap();
        assert!(rest.is_empty());
        assert!(matches!(parsed, CesrGroup::ControllerIdxSigs(g) if g.count() == 1));
    }

    #[test]
    fn encode_cesr_v2_only_type_works() {
        let raw = build_siger_qb64(0);
        let group: DigestSealSingles = Group::new(Bytes::from(raw), 1, CesrVersion::V2);

        let mut dst = BytesMut::new();
        CesrEncode::<V2>::encode_cesr(&group, &mut dst).unwrap();
        assert!(!dst.is_empty());
    }

    #[test]
    fn encode_cesr_v1_enum_rejects_v2_only() {
        let qg = QuadletGroup::new(Bytes::from_static(b"ABCD"), parse_group_bytes_v2);
        let group = CesrGroup::DatagramSegmentGroup(DatagramSegmentGroup::new(qg));

        let mut dst = BytesMut::new();
        let result = CesrEncode::<V1>::encode_cesr(&group, &mut dst);
        assert!(result.is_err());
    }

    #[test]
    fn encode_cesr_v2_enum_accepts_all() {
        let raw = build_siger_qb64(0);
        let group = CesrGroup::ControllerIdxSigs(group_v1(raw, 1));

        let mut dst = BytesMut::new();
        CesrEncode::<V2>::encode_cesr(&group, &mut dst).unwrap();

        let (parsed, rest) = parse_group_v2(&dst).unwrap();
        assert!(rest.is_empty());
        assert!(matches!(parsed, CesrGroup::ControllerIdxSigs(g) if g.count() == 1));
    }

    #[test]
    fn encode_cesr_quadlet_v1_roundtrips() {
        let mut inner_raw = Vec::new();
        inner_raw
            .extend_from_slice(&encode_counter_v1(CounterCodeV1::ControllerIdxSigs, 1).unwrap());
        inner_raw.extend_from_slice(&build_siger_qb64(0));

        let frame: AttachmentGroup = frame_v1(inner_raw);

        let mut dst = BytesMut::new();
        CesrEncode::<V1>::encode_cesr(&frame, &mut dst).unwrap();

        let (parsed, rest) = parse_group(&dst).unwrap();
        assert!(rest.is_empty());
        assert!(matches!(parsed, CesrGroup::AttachmentGroup(_)));
    }
}
