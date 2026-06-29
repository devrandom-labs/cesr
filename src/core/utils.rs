/// Returns the hard (code) size in characters for a leading Base64 byte.
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — module is private but function is used across sibling modules"
)]
pub(crate) const fn get_hard_size_from_byte(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' | b'a'..=b'z' => Some(1),
        b'0' | b'4' | b'5' | b'6' => Some(2),
        b'1' | b'2' | b'3' | b'7' | b'8' | b'9' => Some(4),
        _ => None,
    }
}

/// Returns the hard (code) size in characters for a leading binary sextet.
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — module is private but function is used across sibling modules"
)]
pub(crate) const fn get_hard_size_from_sextet(b: u8) -> Option<u8> {
    match b {
        0..=51 => Some(1),
        52 | 56 | 57 | 58 => Some(2),
        53 | 54 | 55 | 59 | 60 | 61 => Some(4),
        _ => None,
    }
}
