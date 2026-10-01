//! Pure V1 discovery reply authentication and replay judgment.
//!
//! The host supplies accepted historical KEL state and the previously
//! accepted reply version. This module fetches and stores nothing.

use cesr::core::primitives::{Cigar, Number, Siger};
use cesr::crypto::verify;
use keri_events::{BasicPrefix, Identifier, Said};

use crate::authority::Authority;
use crate::error::{Disposition, EvidenceKind};
use crate::state::KeyState;

/// One unverified signer attachment for a routed reply.
#[derive(Debug, Clone, Copy)]
pub enum DiscoverySigner<'a> {
    /// The prefix itself is the nontransferable verification key.
    Nontransferable {
        /// Signer's basic prefix.
        prefix: &'a BasicPrefix<'a>,
        /// Non-indexed signature over the exact routed body.
        signature: &'a Cigar<'a>,
    },
    /// A transferable signer claims a historical establishment coordinate.
    Transferable {
        /// Signer's AID.
        identifier: &'a Identifier<'a>,
        /// Historical establishment sequence.
        sn: Number,
        /// Historical establishment SAID.
        said: &'a Said<'a>,
        /// Indexed signatures over the exact routed body.
        signatures: &'a [Siger<'a>],
    },
}

/// A host-asserted association between a parsed reply, route owner and exact
/// signed body. The optional wire adapter establishes this association from
/// one `RoutedMessage` without a host assertion.
#[derive(Debug, Clone, Copy)]
pub struct DiscoveryReply<'a> {
    /// Authorizing owner named by the validated route payload.
    pub owner: &'a Identifier<'a>,
    /// Exact parsed body bytes covered by the signer attachment.
    pub body: &'a [u8],
    /// Reply timestamp text covered by its verified SAID.
    pub datetime: &'a str,
    /// One attached signer, still unverified.
    pub signer: DiscoverySigner<'a>,
}

/// Version of a previously accepted reply, persisted by the host to make
/// replay decisions restart-safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplyVersion {
    /// The accepted signer's establishment sequence (zero for a
    /// nontransferable signer).
    pub establishment_sn: u128,
    /// UTC nanoseconds of the accepted reply's timestamp.
    pub utc_nanos: i128,
}

/// The two outcomes of the selected V1 discovery route judge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryVerdict {
    /// An in-band reply is authenticated and may update host state.
    Authenticated(ReplyVersion),
    /// An OOBI URL or unsigned OOBI reply is only a fetch hint.
    UntrustedHint,
}

/// A rejected discovery reply.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DiscoveryError {
    /// A known route's selector fields are missing or inconsistent.
    #[error("malformed discovery route or payload")]
    MalformedRoute,
    /// The route is outside the selected discovery profile.
    #[error("unsupported discovery route")]
    UnsupportedRoute,
    /// An in-band reply has no signer attachment.
    #[error("discovery reply needs a signer")]
    MissingSigner,
    /// Multiple signer groups make the claimed authorizer ambiguous.
    #[error("discovery reply has ambiguous signers")]
    AmbiguousSigner,
    /// The signer AID differs from the route's authorizing owner.
    #[error("discovery signer differs from route owner")]
    WrongSigner,
    /// The host has not supplied the accepted historical signer KEL state.
    #[error("historical signer state is required")]
    MissingSignerState,
    /// Supplied signer state contradicts the claimed historical coordinate.
    #[error("historical signer state contradicts the attachment seal")]
    SignerStateMismatch,
    /// No attached signature set meets the historical authority threshold.
    #[error("discovery signature threshold did not verify")]
    BadSignature,
    /// The reply timestamp is outside supported RFC-3339 grammar.
    #[error("invalid reply timestamp")]
    InvalidTimestamp,
    /// This reply is stale or a replay under the same signer establishment.
    #[error("stale or replayed discovery reply")]
    Stale,
    /// A key-state notice needs the host's accepted subject KEL state.
    #[error("accepted key-state notice subject is required")]
    MissingSubjectState,
    /// A key-state notice disagrees with the host's accepted KEL head.
    #[error("key-state notice contradicts accepted KEL state")]
    SubjectStateMismatch,
}

impl DiscoveryError {
    /// Classify a reply error for host escrow or terminal rejection.
    #[must_use]
    pub const fn disposition(&self) -> Disposition {
        match self {
            Self::MissingSigner => Disposition::Awaiting(EvidenceKind::Signatures),
            Self::MissingSignerState => Disposition::Awaiting(EvidenceKind::DiscoverySignerState),
            Self::MissingSubjectState => Disposition::Awaiting(EvidenceKind::DiscoverySubjectState),
            Self::MalformedRoute
            | Self::UnsupportedRoute
            | Self::AmbiguousSigner
            | Self::WrongSigner
            | Self::SignerStateMismatch
            | Self::BadSignature
            | Self::InvalidTimestamp
            | Self::Stale
            | Self::SubjectStateMismatch => Disposition::Terminal,
        }
    }
}

impl DiscoveryReply<'_> {
    /// Authenticate one reply against its route owner and accepted historical
    /// signer state, then reject stale versions. The returned version is the
    /// host's durable replay marker if it accepts the reply.
    ///
    /// # Errors
    ///
    /// Missing evidence is classified as awaiting; inconsistent evidence,
    /// invalid signatures and stale replies are terminal.
    pub fn judge(
        &self,
        historical: Option<&KeyState<'_>>,
        previous: Option<ReplyVersion>,
    ) -> Result<ReplyVersion, DiscoveryError> {
        let utc_nanos = parse_reply_time(self.datetime)?;
        let establishment_sn = match self.signer {
            DiscoverySigner::Nontransferable { prefix, signature } => {
                if self.owner != &Identifier::Basic(prefix.clone()) {
                    return Err(DiscoveryError::WrongSigner);
                }
                verify(prefix.as_matter(), self.body, signature)
                    .map_err(|_| DiscoveryError::BadSignature)?;
                0
            }
            DiscoverySigner::Transferable {
                identifier,
                sn,
                said,
                signatures,
            } => {
                if identifier != self.owner {
                    return Err(DiscoveryError::WrongSigner);
                }
                let state = historical.ok_or(DiscoveryError::MissingSignerState)?;
                if state.prefix() != identifier
                    || state.sn() != sn
                    || state.last_establishment().sn != sn
                    || state.last_establishment().said != said
                {
                    return Err(DiscoveryError::SignerStateMismatch);
                }
                Authority::new(state.keys(), state.threshold())
                    .verify(self.body, signatures)
                    .map_err(|_| DiscoveryError::BadSignature)?;
                sn.value()
            }
        };
        if let Some(old) = previous
            && (establishment_sn < old.establishment_sn
                || (establishment_sn == old.establishment_sn && utc_nanos <= old.utc_nanos))
        {
            return Err(DiscoveryError::Stale);
        }
        Ok(ReplyVersion {
            establishment_sn,
            utc_nanos,
        })
    }
}

/// Parse ordinary RFC-3339 date-times with an explicit offset into UTC
/// nanoseconds. This avoids lexical ordering errors across timezone offsets.
#[allow(
    clippy::too_many_lines,
    reason = "RFC-3339 field validation and UTC normalization stay in one parser"
)]
fn parse_reply_time(value: &str) -> Result<i128, DiscoveryError> {
    let bytes = value.as_bytes();
    let digit = |start: usize, len: usize| -> Result<i128, DiscoveryError> {
        let slice = bytes
            .get(start..start + len)
            .ok_or(DiscoveryError::InvalidTimestamp)?;
        if !slice.iter().all(u8::is_ascii_digit) {
            return Err(DiscoveryError::InvalidTimestamp);
        }
        Ok(slice
            .iter()
            .fold(0i128, |n, byte| n * 10 + i128::from(byte - b'0')))
    };
    let literal = |index: usize, expected: u8| -> Result<(), DiscoveryError> {
        if bytes.get(index) == Some(&expected) {
            Ok(())
        } else {
            Err(DiscoveryError::InvalidTimestamp)
        }
    };
    let year = digit(0, 4)?;
    literal(4, b'-')?;
    let month = digit(5, 2)?;
    literal(7, b'-')?;
    let day = digit(8, 2)?;
    literal(10, b'T')?;
    let hour = digit(11, 2)?;
    literal(13, b':')?;
    let minute = digit(14, 2)?;
    literal(16, b':')?;
    let second = digit(17, 2)?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err(DiscoveryError::InvalidTimestamp),
    };
    if day < 1 || day > days_in_month || hour > 23 || minute > 59 || second > 59 {
        return Err(DiscoveryError::InvalidTimestamp);
    }
    let mut pos = 19;
    let nanos = if bytes.get(pos) == Some(&b'.') {
        pos += 1;
        let start = pos;
        while bytes.get(pos).is_some_and(u8::is_ascii_digit) {
            pos += 1;
        }
        let precision = pos - start;
        if precision == 0 || precision > 9 {
            return Err(DiscoveryError::InvalidTimestamp);
        }
        digit(start, precision)?
            * 10i128
                .pow(u32::try_from(9 - precision).map_err(|_| DiscoveryError::InvalidTimestamp)?)
    } else {
        0
    };
    let offset_seconds = match bytes.get(pos) {
        Some(b'Z') if pos + 1 == bytes.len() => 0,
        Some(sign @ (b'+' | b'-')) if pos + 6 == bytes.len() => {
            let hours = digit(pos + 1, 2)?;
            literal(pos + 3, b':')?;
            let minutes = digit(pos + 4, 2)?;
            if hours > 23 || minutes > 59 {
                return Err(DiscoveryError::InvalidTimestamp);
            }
            let magnitude = (hours * 60 + minutes) * 60;
            if *sign == b'+' { magnitude } else { -magnitude }
        }
        _ => return Err(DiscoveryError::InvalidTimestamp),
    };
    // Howard Hinnant's civil-date ordinal, offset to the Unix epoch.
    let adjusted_year = year - i128::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let shifted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let year_day = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + year_day - 719_468;
    Ok(
        ((days * 86_400 + hour * 3_600 + minute * 60 + second - offset_seconds) * 1_000_000_000)
            + nanos,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_offsets_order_as_utc_instants() {
        assert_eq!(
            parse_reply_time("2026-10-01T00:00:00.000000+00:00"),
            parse_reply_time("2026-09-30T20:00:00-04:00")
        );
        assert!(parse_reply_time("2026-02-29T00:00:00Z").is_err());
        assert!(parse_reply_time("2024-02-29T00:00:00Z").is_ok());
    }
}
