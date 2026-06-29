/// Sealed trait that prevents external crates from implementing `CesrCode`.
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — Sealed pattern restricts implementors to this crate"
)]
pub(crate) trait Sealed {}
