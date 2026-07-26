//! Binary domain (qb2) conversion — re-exported from the `cesr` primitive crate,
//! which owns all Base64-domain math. See [`cesr::b64::transcode`].

pub use cesr::b64::{Qb2, Qb64};

#[cfg(test)]
mod tests {
    use super::{Qb2, Qb64};

    #[test]
    fn reexport_paths_resolve_and_roundtrip() {
        let bin = Qb64(b"-AAB").decode().unwrap();
        assert_eq!(&Qb2(&bin).encode().unwrap(), b"-AAB");
    }
}
