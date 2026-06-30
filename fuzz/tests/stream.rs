//! Fuzz targets for the `stream` parse surface — counter-led groups, the
//! `groups()` iterator (broadest), and message/version-string parsers. Counter
//! decoding is exercised transitively here (no standalone counter entry point).

use cesr::stream::{
    groups, groups_v2, parse_group, parse_group_v2, parse_message, parse_version_string,
    parse_version_string_v2,
};

#[test]
fn stream_parse_group() {
    bolero::check!().for_each(|input: &[u8]| {
        let _ = parse_group(input);
    });
}

#[test]
fn stream_parse_group_v2() {
    bolero::check!().for_each(|input: &[u8]| {
        let _ = parse_group_v2(input);
    });
}

#[test]
fn stream_groups() {
    bolero::check!().for_each(|input: &[u8]| {
        // Drive the whole iterator; each item is a Result. Never panic.
        for item in groups(input) {
            let _ = item;
        }
    });
}

#[test]
fn stream_groups_v2() {
    bolero::check!().for_each(|input: &[u8]| {
        for item in groups_v2(input) {
            let _ = item;
        }
    });
}

#[test]
fn stream_parse_message() {
    bolero::check!().for_each(|input: &[u8]| {
        let _ = parse_message(input);
    });
}

#[test]
fn stream_parse_version_string() {
    bolero::check!().for_each(|input: &[u8]| {
        let _ = parse_version_string(input);
    });
}

#[test]
fn stream_parse_version_string_v2() {
    bolero::check!().for_each(|input: &[u8]| {
        let _ = parse_version_string_v2(input);
    });
}
