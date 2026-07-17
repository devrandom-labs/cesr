//! Wire encoding of numeric threshold fields (keripy's `intive` flag).

/// How an establishment event's numeric threshold fields (`kt`/`nt`/`bt`)
/// are rendered on the wire.
///
/// keripy's `incept()`/`rotate()` take a single `intive` flag per event:
/// `False` (default) renders numeric thresholds as hex strings
/// (`"kt":"2"`, `"bt":"0"`); `True` renders them as JSON integers
/// (`"kt":2`, `"bt":1`) when the value fits `MaxIntThold = 2^32 - 1`.
/// Weighted thresholds are always arrays regardless of form. Mixed forms
/// are not in keripy's output language; the strict parser rejects them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum ThresholdForm {
    /// Hex-string rendering (`"kt":"2"`) — keripy `intive=False`, the default.
    #[default]
    HexString,
    /// JSON-integer rendering (`"kt":2`) — keripy `intive=True`.
    Integer,
}
