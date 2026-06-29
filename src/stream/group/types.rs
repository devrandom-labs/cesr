#[cfg(feature = "alloc")]
#[allow(unused_imports, reason = "alloc prelude items; subset used per cfg/feature combination")]
use alloc::{vec::Vec,};
use core::fmt;

use bytes::Bytes;
use crate::core::matter::Matter;
use crate::core::matter::code::MatterCode;
use crate::core::primitives::Cigar;
use crate::core::primitives::Diger;
use crate::core::primitives::Labeler;
use crate::core::primitives::Noncer;
use crate::core::primitives::Number;
use crate::core::primitives::Prefixer;
use crate::core::primitives::Saider;
use crate::core::primitives::Siger;
use crate::core::primitives::Texter;
use crate::core::primitives::Verser;

use super::iter::GroupIter;
use super::quadlet_group::QuadletGroup;
use crate::stream::error::ParseError;
use crate::stream::parse::parse_cigar;
use crate::stream::parse::parse_counter;
use crate::stream::parse::parse_counter_v2;
use crate::stream::parse::parse_diger;
use crate::stream::parse::parse_labeler;
use crate::stream::parse::parse_matter;
use crate::stream::parse::parse_noncer;
use crate::stream::parse::parse_number;
use crate::stream::parse::parse_prefixer;
use crate::stream::parse::parse_saider;
use crate::stream::parse::parse_siger;
use crate::stream::parse::parse_texter;
use crate::stream::parse::parse_verser;
use crate::stream::parse::skip_counter;
use crate::stream::parse::skip_indexer;

/// `-A` (V1) / `-K` (V2) — Controller indexed signatures
pub struct ControllerIdxSigs {
    raw: Bytes,
    count: u32,
}

impl ControllerIdxSigs {
    pub(crate) const fn new(raw: Bytes, count: u32) -> Self {
        Self { raw, count }
    }

    /// Returns a lazy iterator over the elements in this group.
    #[allow(
        clippy::iter_without_into_iter,
        clippy::shadow_reuse,
        clippy::type_complexity,
        reason = "IntoIterator cannot be implemented for closure-based GroupIter; shadow_reuse is idiomatic for chained parsing"
    )]
    pub fn iter(
        &self,
    ) -> GroupIter<impl Fn(&[u8]) -> Result<(Siger<'static>, usize), ParseError> + '_> {
        GroupIter::new(self.raw.clone(), self.count, |input| {
            let (siger, rest) = parse_siger(input)?;
            Ok((siger, input.len() - rest.len()))
        })
    }

    /// Collects all elements into a `Vec`, parsing each on demand.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if any element fails to parse.
    pub fn into_vec(self) -> Result<Vec<Siger<'static>>, ParseError> {
        self.iter().collect()
    }

    /// Returns the number of elements in this group.
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Returns the raw CESR bytes backing this group.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }
}

impl fmt::Debug for ControllerIdxSigs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControllerIdxSigs")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

/// `-B` (V1) / `-L` (V2) — Witness indexed signatures
pub struct WitnessIdxSigs {
    raw: Bytes,
    count: u32,
}

impl WitnessIdxSigs {
    pub(crate) const fn new(raw: Bytes, count: u32) -> Self {
        Self { raw, count }
    }

    /// Returns a lazy iterator over the elements in this group.
    #[allow(
        clippy::iter_without_into_iter,
        clippy::shadow_reuse,
        clippy::type_complexity,
        reason = "IntoIterator cannot be implemented for closure-based GroupIter; shadow_reuse is idiomatic for chained parsing"
    )]
    pub fn iter(
        &self,
    ) -> GroupIter<impl Fn(&[u8]) -> Result<(Siger<'static>, usize), ParseError> + '_> {
        GroupIter::new(self.raw.clone(), self.count, |input| {
            let (siger, rest) = parse_siger(input)?;
            Ok((siger, input.len() - rest.len()))
        })
    }

    /// Collects all elements into a `Vec`, parsing each on demand.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if any element fails to parse.
    pub fn into_vec(self) -> Result<Vec<Siger<'static>>, ParseError> {
        self.iter().collect()
    }

    /// Returns the number of elements in this group.
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Returns the raw CESR bytes backing this group.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }
}

impl fmt::Debug for WitnessIdxSigs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WitnessIdxSigs")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

/// `-C` (V1) / `-M` (V2) — Non-transferable receipt couples: (prefix, non-indexed signature)
pub struct NonTransReceiptCouples {
    raw: Bytes,
    count: u32,
}

impl NonTransReceiptCouples {
    pub(crate) const fn new(raw: Bytes, count: u32) -> Self {
        Self { raw, count }
    }

    /// Returns a lazy iterator over the elements in this group.
    #[allow(
        clippy::iter_without_into_iter,
        clippy::shadow_reuse,
        clippy::type_complexity,
        reason = "IntoIterator cannot be implemented for closure-based GroupIter; shadow_reuse is idiomatic for chained parsing"
    )]
    pub fn iter(
        &self,
    ) -> GroupIter<
        impl Fn(&[u8]) -> Result<((Prefixer<'static>, Cigar<'static>), usize), ParseError> + '_,
    > {
        GroupIter::new(self.raw.clone(), self.count, |input| {
            let (prefixer, r) = parse_prefixer(input)?;
            let (cigar, r2) = parse_cigar(r)?;
            Ok(((prefixer, cigar), input.len() - r2.len()))
        })
    }

    /// Collects all elements into a `Vec`, parsing each on demand.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if any element fails to parse.
    pub fn into_vec(self) -> Result<Vec<(Prefixer<'static>, Cigar<'static>)>, ParseError> {
        self.iter().collect()
    }

    /// Returns the number of elements in this group.
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Returns the raw CESR bytes backing this group.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }
}

impl fmt::Debug for NonTransReceiptCouples {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NonTransReceiptCouples")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

/// `-D` (V1) / `-N` (V2) — Transferable receipt quadruples: (prefix, sequence number, SAID, indexed sig)
pub struct TransReceiptQuadruples {
    raw: Bytes,
    count: u32,
}

impl TransReceiptQuadruples {
    pub(crate) const fn new(raw: Bytes, count: u32) -> Self {
        Self { raw, count }
    }

    /// Returns a lazy iterator over the elements in this group.
    #[allow(
        clippy::iter_without_into_iter,
        clippy::shadow_reuse,
        clippy::type_complexity,
        reason = "IntoIterator cannot be implemented for closure-based GroupIter; shadow_reuse is idiomatic for chained parsing"
    )]
    pub fn iter(
        &self,
    ) -> GroupIter<
        impl Fn(
            &[u8],
        ) -> Result<
            (
                (
                    Prefixer<'static>,
                    Matter<'static, MatterCode>,
                    Saider<'static>,
                    Siger<'static>,
                ),
                usize,
            ),
            ParseError,
        > + '_,
    > {
        GroupIter::new(self.raw.clone(), self.count, |input| {
            let (prefixer, r) = parse_prefixer(input)?;
            let (seqner, r) = parse_matter(r)?;
            let (saider, r) = parse_saider(r)?;
            let (siger, r) = parse_siger(r)?;
            Ok(((prefixer, seqner, saider, siger), input.len() - r.len()))
        })
    }

    /// Collects all elements into a `Vec`, parsing each on demand.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if any element fails to parse.
    #[allow(
        clippy::type_complexity,
        reason = "element tuple type matches the CESR group structure"
    )]
    pub fn into_vec(
        self,
    ) -> Result<
        Vec<(
            Prefixer<'static>,
            Matter<'static, MatterCode>,
            Saider<'static>,
            Siger<'static>,
        )>,
        ParseError,
    > {
        self.iter().collect()
    }

    /// Returns the number of elements in this group.
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Returns the raw CESR bytes backing this group.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }
}

impl fmt::Debug for TransReceiptQuadruples {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransReceiptQuadruples")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

/// `-E` (V1) / `-O` (V2) — First-seen replay couples: (sequence number, datetime)
pub struct FirstSeenReplayCouples {
    raw: Bytes,
    count: u32,
}

impl FirstSeenReplayCouples {
    pub(crate) const fn new(raw: Bytes, count: u32) -> Self {
        Self { raw, count }
    }

    /// Returns a lazy iterator over the elements in this group.
    #[allow(
        clippy::iter_without_into_iter,
        clippy::shadow_reuse,
        clippy::type_complexity,
        reason = "IntoIterator cannot be implemented for closure-based GroupIter; shadow_reuse is idiomatic for chained parsing"
    )]
    pub fn iter(
        &self,
    ) -> GroupIter<
        impl Fn(
            &[u8],
        ) -> Result<
            (
                (Matter<'static, MatterCode>, Matter<'static, MatterCode>),
                usize,
            ),
            ParseError,
        > + '_,
    > {
        GroupIter::new(self.raw.clone(), self.count, |input| {
            let (seqner, r) = parse_matter(input)?;
            let (dater, r) = parse_matter(r)?;
            Ok(((seqner, dater), input.len() - r.len()))
        })
    }

    /// Collects all elements into a `Vec`, parsing each on demand.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if any element fails to parse.
    #[allow(
        clippy::type_complexity,
        reason = "element tuple type matches the CESR group structure"
    )]
    pub fn into_vec(
        self,
    ) -> Result<Vec<(Matter<'static, MatterCode>, Matter<'static, MatterCode>)>, ParseError> {
        self.iter().collect()
    }

    /// Returns the number of elements in this group.
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Returns the raw CESR bytes backing this group.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }
}

impl fmt::Debug for FirstSeenReplayCouples {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FirstSeenReplayCouples")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

/// `-F` (V1) / `-X` (V2) — Transferable indexed sig groups: (prefix, seqner, SAID, controller sigs)
pub struct TransIdxSigGroups {
    raw: Bytes,
    count: u32,
    v2: bool,
}

impl TransIdxSigGroups {
    pub(crate) const fn new(raw: Bytes, count: u32, v2: bool) -> Self {
        Self { raw, count, v2 }
    }

    /// Returns a lazy iterator over the elements in this group.
    #[allow(
        clippy::iter_without_into_iter,
        clippy::shadow_reuse,
        clippy::type_complexity,
        reason = "IntoIterator cannot be implemented for closure-based GroupIter; shadow_reuse is idiomatic for chained parsing"
    )]
    pub fn iter(
        &self,
    ) -> GroupIter<
        impl Fn(
            &[u8],
        ) -> Result<
            (
                (
                    Prefixer<'static>,
                    Matter<'static, MatterCode>,
                    Saider<'static>,
                    ControllerIdxSigs,
                ),
                usize,
            ),
            ParseError,
        > + '_,
    > {
        let v2 = self.v2;
        GroupIter::new(self.raw.clone(), self.count, move |input| {
            let mut offset = 0;
            let (prefixer, r) = parse_prefixer(input)?;
            offset += input.len() - r.len();
            let (seqner, r) = parse_matter(r)?;
            offset += input[offset..].len() - r.len();
            let (saider, r) = parse_saider(r)?;
            offset += input[offset..].len() - r.len();

            let counter_size = skip_counter(r)?;
            let sub_count = if v2 {
                let (_, cnt, _) = parse_counter_v2(r)?;
                cnt
            } else {
                let (_, cnt, _) = parse_counter(r)?;
                cnt
            };
            offset += counter_size;

            let mut sigs_len = 0;
            for _ in 0..sub_count {
                sigs_len += skip_indexer(&r[counter_size + sigs_len..])?;
            }
            let sigs_bytes = Bytes::copy_from_slice(&r[counter_size..counter_size + sigs_len]);
            let ctrl_sigs = ControllerIdxSigs::new(sigs_bytes, sub_count);
            offset += sigs_len;

            Ok(((prefixer, seqner, saider, ctrl_sigs), offset))
        })
    }

    /// Collects all elements into a `Vec`, parsing each on demand.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if any element fails to parse.
    #[allow(
        clippy::type_complexity,
        reason = "element tuple type matches the CESR group structure"
    )]
    pub fn into_vec(
        self,
    ) -> Result<
        Vec<(
            Prefixer<'static>,
            Matter<'static, MatterCode>,
            Saider<'static>,
            ControllerIdxSigs,
        )>,
        ParseError,
    > {
        self.iter().collect()
    }

    /// Returns the number of elements in this group.
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Returns the raw CESR bytes backing this group.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }
}

impl fmt::Debug for TransIdxSigGroups {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransIdxSigGroups")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

/// `-G` (V1) / `-S` (V2) — Seal source couples: (sequence number, SAID)
pub struct SealSourceCouples {
    raw: Bytes,
    count: u32,
}

impl SealSourceCouples {
    pub(crate) const fn new(raw: Bytes, count: u32) -> Self {
        Self { raw, count }
    }

    /// Returns a lazy iterator over the elements in this group.
    #[allow(
        clippy::iter_without_into_iter,
        clippy::shadow_reuse,
        clippy::type_complexity,
        reason = "IntoIterator cannot be implemented for closure-based GroupIter; shadow_reuse is idiomatic for chained parsing"
    )]
    pub fn iter(
        &self,
    ) -> GroupIter<
        impl Fn(&[u8]) -> Result<((Matter<'static, MatterCode>, Saider<'static>), usize), ParseError>
        + '_,
    > {
        GroupIter::new(self.raw.clone(), self.count, |input| {
            let (seqner, r) = parse_matter(input)?;
            let (saider, r) = parse_saider(r)?;
            Ok(((seqner, saider), input.len() - r.len()))
        })
    }

    /// Collects all elements into a `Vec`, parsing each on demand.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if any element fails to parse.
    pub fn into_vec(
        self,
    ) -> Result<Vec<(Matter<'static, MatterCode>, Saider<'static>)>, ParseError> {
        self.iter().collect()
    }

    /// Returns the number of elements in this group.
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Returns the raw CESR bytes backing this group.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }
}

impl fmt::Debug for SealSourceCouples {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealSourceCouples")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

/// `-H` (V1) / `-Y` (V2) — Transferable last-event indexed sig groups: (prefix, controller sigs)
pub struct TransLastIdxSigGroups {
    raw: Bytes,
    count: u32,
    v2: bool,
}

impl TransLastIdxSigGroups {
    pub(crate) const fn new(raw: Bytes, count: u32, v2: bool) -> Self {
        Self { raw, count, v2 }
    }

    /// Returns a lazy iterator over the elements in this group.
    #[allow(
        clippy::iter_without_into_iter,
        clippy::shadow_reuse,
        clippy::type_complexity,
        reason = "IntoIterator cannot be implemented for closure-based GroupIter; shadow_reuse is idiomatic for chained parsing"
    )]
    pub fn iter(
        &self,
    ) -> GroupIter<
        impl Fn(&[u8]) -> Result<((Prefixer<'static>, ControllerIdxSigs), usize), ParseError> + '_,
    > {
        let v2 = self.v2;
        GroupIter::new(self.raw.clone(), self.count, move |input| {
            let mut offset = 0;
            let (prefixer, r) = parse_prefixer(input)?;
            offset += input.len() - r.len();

            let counter_size = skip_counter(r)?;
            let sub_count = if v2 {
                let (_, cnt, _) = parse_counter_v2(r)?;
                cnt
            } else {
                let (_, cnt, _) = parse_counter(r)?;
                cnt
            };
            offset += counter_size;

            let mut sigs_len = 0;
            for _ in 0..sub_count {
                sigs_len += skip_indexer(&r[counter_size + sigs_len..])?;
            }
            let sigs_bytes = Bytes::copy_from_slice(&r[counter_size..counter_size + sigs_len]);
            let ctrl_sigs = ControllerIdxSigs::new(sigs_bytes, sub_count);
            offset += sigs_len;

            Ok(((prefixer, ctrl_sigs), offset))
        })
    }

    /// Collects all elements into a `Vec`, parsing each on demand.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if any element fails to parse.
    pub fn into_vec(self) -> Result<Vec<(Prefixer<'static>, ControllerIdxSigs)>, ParseError> {
        self.iter().collect()
    }

    /// Returns the number of elements in this group.
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Returns the raw CESR bytes backing this group.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }
}

impl fmt::Debug for TransLastIdxSigGroups {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransLastIdxSigGroups")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

/// `-I` (V1) / `-T` (V2) — Seal source triples: (prefix, sequence number, SAID)
pub struct SealSourceTriples {
    raw: Bytes,
    count: u32,
}

impl SealSourceTriples {
    pub(crate) const fn new(raw: Bytes, count: u32) -> Self {
        Self { raw, count }
    }

    /// Returns a lazy iterator over the elements in this group.
    #[allow(
        clippy::iter_without_into_iter,
        clippy::shadow_reuse,
        clippy::type_complexity,
        reason = "IntoIterator cannot be implemented for closure-based GroupIter; shadow_reuse is idiomatic for chained parsing"
    )]
    pub fn iter(
        &self,
    ) -> GroupIter<
        impl Fn(
            &[u8],
        ) -> Result<
            (
                (
                    Prefixer<'static>,
                    Matter<'static, MatterCode>,
                    Saider<'static>,
                ),
                usize,
            ),
            ParseError,
        > + '_,
    > {
        GroupIter::new(self.raw.clone(), self.count, |input| {
            let (prefixer, r) = parse_prefixer(input)?;
            let (seqner, r) = parse_matter(r)?;
            let (saider, r) = parse_saider(r)?;
            Ok(((prefixer, seqner, saider), input.len() - r.len()))
        })
    }

    /// Collects all elements into a `Vec`, parsing each on demand.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if any element fails to parse.
    pub fn into_vec(
        self,
    ) -> Result<
        Vec<(
            Prefixer<'static>,
            Matter<'static, MatterCode>,
            Saider<'static>,
        )>,
        ParseError,
    > {
        self.iter().collect()
    }

    /// Returns the number of elements in this group.
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Returns the raw CESR bytes backing this group.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }
}

impl fmt::Debug for SealSourceTriples {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealSourceTriples")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

/// `-L` (V1) / `-P` (V2) — Pathed material (quadlet-counted raw bytes).
///
/// keripy treats this counter code as quadlet-counted: the count specifies
/// how many 4-byte quadlets of raw data follow.  The payload contains a
/// Pather CESR primitive followed by arbitrary CESR material, but this
/// layer does not parse the individual primitives — it stores the raw bytes.
pub struct PathedMaterialCouples(pub QuadletGroup);

/// `-V` (V1) / `-C` (V2) — Attachment group (generic container for nested groups, count in quadlets)
pub struct AttachmentGroup(pub QuadletGroup);

/// `-T` (V1) / `-A` (V2) — Generic group (count in quadlets)
pub struct GenericGroup(pub QuadletGroup);

/// `-U` (V1) / `-B` (V2) — Body with attachment group (count in quadlets)
pub struct BodyWithAttachmentGroup(pub QuadletGroup);

/// `-W` (V1) / `-H` (V2) — Non-native body group (count in quadlets)
pub struct NonNativeBodyGroup(pub QuadletGroup);

/// `-Z` (V1) / `-Z` (V2) — ESSR payload group (count in quadlets)
pub struct ESSRPayloadGroup(pub QuadletGroup);

/// `-D` (V2 only) — Datagram segment group (count in quadlets)
pub struct DatagramSegmentGroup(pub QuadletGroup);

/// `-E` (V2 only) — ESSR wrapper group (count in quadlets)
pub struct ESSRWrapperGroup(pub QuadletGroup);

/// `-F` (V2 only) — Fixed body group (count in quadlets)
pub struct FixBodyGroup(pub QuadletGroup);

/// `-G` (V2 only) — Map body group (count in quadlets)
pub struct MapBodyGroup(pub QuadletGroup);

/// `-I` (V2 only) — Generic map group (count in quadlets)
pub struct GenericMapGroup(pub QuadletGroup);

/// `-J` (V2 only) — Generic list group (count in quadlets)
pub struct GenericListGroup(pub QuadletGroup);

/// `-Q` (V2 only) — Digest seal singles: (digest)
pub struct DigestSealSingles {
    raw: Bytes,
    count: u32,
}

impl DigestSealSingles {
    pub(crate) const fn new(raw: Bytes, count: u32) -> Self {
        Self { raw, count }
    }

    /// Returns a lazy iterator over the elements in this group.
    #[allow(
        clippy::iter_without_into_iter,
        clippy::shadow_reuse,
        clippy::type_complexity,
        reason = "IntoIterator cannot be implemented for closure-based GroupIter; shadow_reuse is idiomatic for chained parsing"
    )]
    pub fn iter(
        &self,
    ) -> GroupIter<impl Fn(&[u8]) -> Result<(Diger<'static>, usize), ParseError> + '_> {
        GroupIter::new(self.raw.clone(), self.count, |input| {
            let (diger, rest) = parse_diger(input)?;
            Ok((diger, input.len() - rest.len()))
        })
    }

    /// Collects all elements into a `Vec`, parsing each on demand.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if any element fails to parse.
    pub fn into_vec(self) -> Result<Vec<Diger<'static>>, ParseError> {
        self.iter().collect()
    }

    /// Returns the number of elements in this group.
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Returns the raw CESR bytes backing this group.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }
}

impl fmt::Debug for DigestSealSingles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DigestSealSingles")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

/// `-R` (V2 only) — Merkle root seal singles: (digest)
pub struct MerkleRootSealSingles {
    raw: Bytes,
    count: u32,
}

impl MerkleRootSealSingles {
    pub(crate) const fn new(raw: Bytes, count: u32) -> Self {
        Self { raw, count }
    }

    /// Returns a lazy iterator over the elements in this group.
    #[allow(
        clippy::iter_without_into_iter,
        clippy::shadow_reuse,
        clippy::type_complexity,
        reason = "IntoIterator cannot be implemented for closure-based GroupIter; shadow_reuse is idiomatic for chained parsing"
    )]
    pub fn iter(
        &self,
    ) -> GroupIter<impl Fn(&[u8]) -> Result<(Diger<'static>, usize), ParseError> + '_> {
        GroupIter::new(self.raw.clone(), self.count, |input| {
            let (diger, rest) = parse_diger(input)?;
            Ok((diger, input.len() - rest.len()))
        })
    }

    /// Collects all elements into a `Vec`, parsing each on demand.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if any element fails to parse.
    pub fn into_vec(self) -> Result<Vec<Diger<'static>>, ParseError> {
        self.iter().collect()
    }

    /// Returns the number of elements in this group.
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Returns the raw CESR bytes backing this group.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }
}

impl fmt::Debug for MerkleRootSealSingles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MerkleRootSealSingles")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

/// `-U` (V2 only) — Seal source last singles: (prefix)
pub struct SealSourceLastSingles {
    raw: Bytes,
    count: u32,
}

impl SealSourceLastSingles {
    pub(crate) const fn new(raw: Bytes, count: u32) -> Self {
        Self { raw, count }
    }

    /// Returns a lazy iterator over the elements in this group.
    #[allow(
        clippy::iter_without_into_iter,
        clippy::shadow_reuse,
        clippy::type_complexity,
        reason = "IntoIterator cannot be implemented for closure-based GroupIter; shadow_reuse is idiomatic for chained parsing"
    )]
    pub fn iter(
        &self,
    ) -> GroupIter<impl Fn(&[u8]) -> Result<(Prefixer<'static>, usize), ParseError> + '_> {
        GroupIter::new(self.raw.clone(), self.count, |input| {
            let (prefixer, rest) = parse_prefixer(input)?;
            Ok((prefixer, input.len() - rest.len()))
        })
    }

    /// Collects all elements into a `Vec`, parsing each on demand.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if any element fails to parse.
    pub fn into_vec(self) -> Result<Vec<Prefixer<'static>>, ParseError> {
        self.iter().collect()
    }

    /// Returns the number of elements in this group.
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Returns the raw CESR bytes backing this group.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }
}

impl fmt::Debug for SealSourceLastSingles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealSourceLastSingles")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

/// `-V` (V2 only) — Backer registrar seal couples: (prefix, digest)
pub struct BackerRegistrarSealCouples {
    raw: Bytes,
    count: u32,
}

impl BackerRegistrarSealCouples {
    pub(crate) const fn new(raw: Bytes, count: u32) -> Self {
        Self { raw, count }
    }

    /// Returns a lazy iterator over the elements in this group.
    #[allow(
        clippy::iter_without_into_iter,
        clippy::shadow_reuse,
        clippy::type_complexity,
        reason = "IntoIterator cannot be implemented for closure-based GroupIter; shadow_reuse is idiomatic for chained parsing"
    )]
    pub fn iter(
        &self,
    ) -> GroupIter<
        impl Fn(&[u8]) -> Result<((Prefixer<'static>, Diger<'static>), usize), ParseError> + '_,
    > {
        GroupIter::new(self.raw.clone(), self.count, |input| {
            let (prefixer, r) = parse_prefixer(input)?;
            let (diger, r) = parse_diger(r)?;
            Ok(((prefixer, diger), input.len() - r.len()))
        })
    }

    /// Collects all elements into a `Vec`, parsing each on demand.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if any element fails to parse.
    pub fn into_vec(self) -> Result<Vec<(Prefixer<'static>, Diger<'static>)>, ParseError> {
        self.iter().collect()
    }

    /// Returns the number of elements in this group.
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Returns the raw CESR bytes backing this group.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }
}

impl fmt::Debug for BackerRegistrarSealCouples {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackerRegistrarSealCouples")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

/// `-W` (V2 only) — Typed digest seal couples: (version, digest)
pub struct TypedDigestSealCouples {
    raw: Bytes,
    count: u32,
}

impl TypedDigestSealCouples {
    pub(crate) const fn new(raw: Bytes, count: u32) -> Self {
        Self { raw, count }
    }

    /// Returns a lazy iterator over the elements in this group.
    #[allow(
        clippy::iter_without_into_iter,
        clippy::shadow_reuse,
        clippy::type_complexity,
        reason = "IntoIterator cannot be implemented for closure-based GroupIter; shadow_reuse is idiomatic for chained parsing"
    )]
    pub fn iter(
        &self,
    ) -> GroupIter<
        impl Fn(&[u8]) -> Result<((Verser<'static>, Diger<'static>), usize), ParseError> + '_,
    > {
        GroupIter::new(self.raw.clone(), self.count, |input| {
            let (verser, r) = parse_verser(input)?;
            let (diger, r) = parse_diger(r)?;
            Ok(((verser, diger), input.len() - r.len()))
        })
    }

    /// Collects all elements into a `Vec`, parsing each on demand.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if any element fails to parse.
    pub fn into_vec(self) -> Result<Vec<(Verser<'static>, Diger<'static>)>, ParseError> {
        self.iter().collect()
    }

    /// Returns the number of elements in this group.
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Returns the raw CESR bytes backing this group.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }
}

impl fmt::Debug for TypedDigestSealCouples {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TypedDigestSealCouples")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

/// `-a` (V2 only) — Blinded state quadruples: (digest, nonce, nonce, label)
pub struct BlindedStateQuadruples {
    raw: Bytes,
    count: u32,
}

impl BlindedStateQuadruples {
    pub(crate) const fn new(raw: Bytes, count: u32) -> Self {
        Self { raw, count }
    }

    /// Returns a lazy iterator over the elements in this group.
    #[allow(
        clippy::iter_without_into_iter,
        clippy::shadow_reuse,
        clippy::type_complexity,
        reason = "IntoIterator cannot be implemented for closure-based GroupIter; shadow_reuse is idiomatic for chained parsing"
    )]
    pub fn iter(
        &self,
    ) -> GroupIter<
        impl Fn(
            &[u8],
        ) -> Result<
            (
                (
                    Diger<'static>,
                    Noncer<'static>,
                    Noncer<'static>,
                    Labeler<'static>,
                ),
                usize,
            ),
            ParseError,
        > + '_,
    > {
        GroupIter::new(self.raw.clone(), self.count, |input| {
            let (diger, r) = parse_diger(input)?;
            let (noncer1, r) = parse_noncer(r)?;
            let (noncer2, r) = parse_noncer(r)?;
            let (labeler, r) = parse_labeler(r)?;
            Ok(((diger, noncer1, noncer2, labeler), input.len() - r.len()))
        })
    }

    /// Collects all elements into a `Vec`, parsing each on demand.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if any element fails to parse.
    pub fn into_vec(
        self,
    ) -> Result<
        Vec<(
            Diger<'static>,
            Noncer<'static>,
            Noncer<'static>,
            Labeler<'static>,
        )>,
        ParseError,
    > {
        self.iter().collect()
    }

    /// Returns the number of elements in this group.
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Returns the raw CESR bytes backing this group.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }
}

impl fmt::Debug for BlindedStateQuadruples {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlindedStateQuadruples")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

/// `-b` (V2 only) — Bound state sextuples: (digest, nonce, nonce, label, number, nonce)
pub struct BoundStateSextuples {
    raw: Bytes,
    count: u32,
}

impl BoundStateSextuples {
    pub(crate) const fn new(raw: Bytes, count: u32) -> Self {
        Self { raw, count }
    }

    /// Returns a lazy iterator over the elements in this group.
    #[allow(
        clippy::iter_without_into_iter,
        clippy::shadow_reuse,
        clippy::type_complexity,
        reason = "IntoIterator cannot be implemented for closure-based GroupIter; shadow_reuse is idiomatic for chained parsing"
    )]
    pub fn iter(
        &self,
    ) -> GroupIter<
        impl Fn(
            &[u8],
        ) -> Result<
            (
                (
                    Diger<'static>,
                    Noncer<'static>,
                    Noncer<'static>,
                    Labeler<'static>,
                    Number,
                    Noncer<'static>,
                ),
                usize,
            ),
            ParseError,
        > + '_,
    > {
        GroupIter::new(self.raw.clone(), self.count, |input| {
            let (diger, r) = parse_diger(input)?;
            let (noncer1, r) = parse_noncer(r)?;
            let (noncer2, r) = parse_noncer(r)?;
            let (labeler, r) = parse_labeler(r)?;
            let (number, r) = parse_number(r)?;
            let (noncer3, r) = parse_noncer(r)?;
            Ok((
                (diger, noncer1, noncer2, labeler, number, noncer3),
                input.len() - r.len(),
            ))
        })
    }

    /// Collects all elements into a `Vec`, parsing each on demand.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if any element fails to parse.
    #[allow(
        clippy::type_complexity,
        reason = "element tuple type matches the CESR group structure"
    )]
    pub fn into_vec(
        self,
    ) -> Result<
        Vec<(
            Diger<'static>,
            Noncer<'static>,
            Noncer<'static>,
            Labeler<'static>,
            Number,
            Noncer<'static>,
        )>,
        ParseError,
    > {
        self.iter().collect()
    }

    /// Returns the number of elements in this group.
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Returns the raw CESR bytes backing this group.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }
}

impl fmt::Debug for BoundStateSextuples {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundStateSextuples")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

/// `-c` (V2 only) — Typed media quadruples: (digest, nonce, label, text)
pub struct TypedMediaQuadruples {
    raw: Bytes,
    count: u32,
}

impl TypedMediaQuadruples {
    pub(crate) const fn new(raw: Bytes, count: u32) -> Self {
        Self { raw, count }
    }

    /// Returns a lazy iterator over the elements in this group.
    #[allow(
        clippy::iter_without_into_iter,
        clippy::shadow_reuse,
        clippy::type_complexity,
        reason = "IntoIterator cannot be implemented for closure-based GroupIter; shadow_reuse is idiomatic for chained parsing"
    )]
    pub fn iter(
        &self,
    ) -> GroupIter<
        impl Fn(
            &[u8],
        ) -> Result<
            (
                (
                    Diger<'static>,
                    Noncer<'static>,
                    Labeler<'static>,
                    Texter<'static>,
                ),
                usize,
            ),
            ParseError,
        > + '_,
    > {
        GroupIter::new(self.raw.clone(), self.count, |input| {
            let (diger, r) = parse_diger(input)?;
            let (noncer, r) = parse_noncer(r)?;
            let (labeler, r) = parse_labeler(r)?;
            let (texter, r) = parse_texter(r)?;
            Ok(((diger, noncer, labeler, texter), input.len() - r.len()))
        })
    }

    /// Collects all elements into a `Vec`, parsing each on demand.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if any element fails to parse.
    pub fn into_vec(
        self,
    ) -> Result<
        Vec<(
            Diger<'static>,
            Noncer<'static>,
            Labeler<'static>,
            Texter<'static>,
        )>,
        ParseError,
    > {
        self.iter().collect()
    }

    /// Returns the number of elements in this group.
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Returns the raw CESR bytes backing this group.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }
}

impl fmt::Debug for TypedMediaQuadruples {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TypedMediaQuadruples")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for PathedMaterialCouples {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PathedMaterialCouples")
            .field(&format_args!("[{} quadlets]", self.0.quadlet_count()))
            .finish()
    }
}

impl fmt::Debug for AttachmentGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AttachmentGroup")
            .field(&format_args!("[{} quadlets]", self.0.quadlet_count()))
            .finish()
    }
}

impl fmt::Debug for GenericGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("GenericGroup")
            .field(&format_args!("[{} quadlets]", self.0.quadlet_count()))
            .finish()
    }
}

impl fmt::Debug for BodyWithAttachmentGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("BodyWithAttachmentGroup")
            .field(&format_args!("[{} quadlets]", self.0.quadlet_count()))
            .finish()
    }
}

impl fmt::Debug for NonNativeBodyGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("NonNativeBodyGroup")
            .field(&format_args!("[{} quadlets]", self.0.quadlet_count()))
            .finish()
    }
}

impl fmt::Debug for ESSRPayloadGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ESSRPayloadGroup")
            .field(&format_args!("[{} quadlets]", self.0.quadlet_count()))
            .finish()
    }
}

impl fmt::Debug for DatagramSegmentGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DatagramSegmentGroup")
            .field(&format_args!("[{} quadlets]", self.0.quadlet_count()))
            .finish()
    }
}

impl fmt::Debug for ESSRWrapperGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ESSRWrapperGroup")
            .field(&format_args!("[{} quadlets]", self.0.quadlet_count()))
            .finish()
    }
}

impl fmt::Debug for FixBodyGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("FixBodyGroup")
            .field(&format_args!("[{} quadlets]", self.0.quadlet_count()))
            .finish()
    }
}

impl fmt::Debug for MapBodyGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MapBodyGroup")
            .field(&format_args!("[{} quadlets]", self.0.quadlet_count()))
            .finish()
    }
}

impl fmt::Debug for GenericMapGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("GenericMapGroup")
            .field(&format_args!("[{} quadlets]", self.0.quadlet_count()))
            .finish()
    }
}

impl fmt::Debug for GenericListGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("GenericListGroup")
            .field(&format_args!("[{} quadlets]", self.0.quadlet_count()))
            .finish()
    }
}

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
