//! Key-configuration scaffolding shared by the establishment-event builders.
//!
//! Every establishment event (`icp`, `dip`, `rot`, `drt`) asserts the
//! identifier's signing authority: the current signing keys under a
//! threshold (`k`/`kt`) and the pre-rotated next-key commitment (`n`/`nt`).
//! All four builders accumulate that data identically and validate it with
//! the same keripy-parity prologue — [`KeyConfiguration`] is the accumulator
//! and [`KeyConfiguration::validate`] the single validation routine.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use super::validate_threshold;
use crate::error::SerderError;
use cesr::core::primitives::{Diger, Verfer};
use keri_events::SigningThreshold;
use keri_events::threshold_form::ThresholdForm;

/// Key configuration as accumulated by an establishment builder: explicit
/// threshold overrides are `Some`; keripy's defaults are not applied until
/// [`KeyConfiguration::validate`].
pub(super) struct KeyConfiguration {
    pub(super) keys: Vec<Verfer<'static>>,
    pub(super) threshold: Option<SigningThreshold>,
    pub(super) next_keys: Vec<Diger<'static>>,
    pub(super) next_threshold: Option<SigningThreshold>,
    pub(super) threshold_form: ThresholdForm,
}

impl KeyConfiguration {
    /// Starts a key configuration from the required signing keys, every
    /// optional field at its keripy default.
    pub(super) const fn new(keys: Vec<Verfer<'static>>) -> Self {
        Self {
            keys,
            threshold: None,
            next_keys: Vec::new(),
            next_threshold: None,
            threshold_form: ThresholdForm::HexString,
        }
    }

    /// The establishment `build()` prologue shared by `icp`, `dip`, `rot`,
    /// and `drt`: rejects an empty key list, defaults missing thresholds to
    /// keripy's simple majority (zero when no next keys are committed),
    /// rejects integer-form thresholds above keripy's `MaxIntThold`, and
    /// checks each threshold well-formed against its key list.
    ///
    /// # Errors
    ///
    /// Returns [`SerderError::EmptyKeys`] if `keys` is empty,
    /// [`SerderError::IntegerFormOverflow`] if an integer-form threshold
    /// exceeds `u32::MAX`, or [`SerderError::SigningThresholdOutOfRange`]
    /// if a threshold is malformed for its key count.
    pub(super) fn validate(self) -> Result<SigningAuthority, SerderError> {
        if self.keys.is_empty() {
            return Err(SerderError::EmptyKeys("keys"));
        }

        let threshold = match self.threshold {
            Some(explicit) => explicit,
            None => SigningThreshold::Simple(majority(self.keys.len())?),
        };

        check_integer_form_fits(&threshold, self.threshold_form)?;
        validate_threshold(&threshold, self.keys.len(), "signing")?;

        let next_threshold = match self.next_threshold {
            Some(explicit) => explicit,
            None if self.next_keys.is_empty() => SigningThreshold::Simple(0),
            None => SigningThreshold::Simple(majority(self.next_keys.len())?),
        };

        check_integer_form_fits(&next_threshold, self.threshold_form)?;
        if !self.next_keys.is_empty() {
            validate_threshold(&next_threshold, self.next_keys.len(), "next signing")?;
        }

        Ok(SigningAuthority {
            keys: self.keys,
            threshold,
            next_keys: self.next_keys,
            next_threshold,
            threshold_form: self.threshold_form,
        })
    }
}

/// The signing authority a validated establishment event asserts: the
/// current keys under their resolved threshold, the pre-rotation next-key
/// commitment under its, and the wire form the thresholds render in.
pub(super) struct SigningAuthority {
    pub(super) keys: Vec<Verfer<'static>>,
    pub(super) threshold: SigningThreshold,
    pub(super) next_keys: Vec<Diger<'static>>,
    pub(super) next_threshold: SigningThreshold,
    pub(super) threshold_form: ThresholdForm,
}

/// Default signing threshold: simple majority of `n` keys, `max(1, ceil(n / 2))`.
///
/// Port of keripy's default `sith`/`nsith` (`eventing.py:459` / `:471`,
/// keripy `de59bc7d`).
///
/// # Errors
///
/// Returns [`SerderError::MajorityOverflow`] when the majority does not fit
/// `u64` (unreachable on targets where `usize` is 64 bits or narrower).
pub(super) fn majority(n: usize) -> Result<u64, SerderError> {
    let m = 1.max(n.div_ceil(2));
    u64::try_from(m).map_err(|_| SerderError::MajorityOverflow { keys: n })
}

/// Reject a simple threshold too large for integer wire form. keripy renders
/// a numeric threshold as an integer only when `intive` is set AND the value
/// is `<= MaxIntThold = 2^32 - 1`, otherwise it silently falls back to the hex
/// string form (`eventing.py` `kt=(tholder.num if intive and ... num <=
/// MaxIntThold else tholder.sith)`, keripy pin). cesr instead models that
/// boundary as an explicit constraint: under [`ThresholdForm::Integer`], a
/// `SigningThreshold::Simple(n)` with `n > u32::MAX` is rejected rather than silently
/// re-rendered as hex. Checked independently of the key-set well-formedness
/// (keripy's form decision is a function of the value alone), and before it,
/// so a caller who opted into integer form gets this specific diagnostic.
/// Weighted thresholds and hex form are always fine (`bt` is a `Toad` = u32
/// and cannot exceed the range).
pub(super) fn check_integer_form_fits(
    threshold: &SigningThreshold,
    form: ThresholdForm,
) -> Result<(), SerderError> {
    if let (ThresholdForm::Integer, SigningThreshold::Simple(n)) = (form, threshold)
        && u32::try_from(*n).is_err()
    {
        return Err(SerderError::IntegerFormOverflow { value: *n });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::panic, reason = "panics are expected in test assertions")]
mod tests {
    use super::*;

    /// Expectations match keripy's default signing threshold
    /// `max(1, ceil(len(keys) / 2))` (`eventing.py:459`, keripy `de59bc7d`;
    /// same shape at `:471` for `nsith`).
    #[test]
    fn majority_matches_keripy_default_threshold_table() {
        let expected: [(usize, u64); 14] = [
            (0, 1),
            (1, 1),
            (2, 1),
            (3, 2),
            (4, 2),
            (5, 3),
            (6, 3),
            (7, 4),
            (8, 4),
            (9, 5),
            (10, 5),
            (11, 6),
            (12, 6),
            (13, 7),
        ];
        for (n, want) in expected {
            assert_eq!(majority(n).unwrap(), want, "majority({n})");
        }
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn majority_succeeds_at_usize_boundary() {
        assert_eq!(majority(usize::MAX).unwrap(), u64::MAX / 2 + 1);
        assert_eq!(majority(usize::MAX - 1).unwrap(), u64::MAX / 2);
    }
}
