//! Fuzz targets for the `stream` parse surface — counter-led groups, the
//! `groups()` iterator (broadest), and message/version-string parsers.

#[test]
fn stream_parse_group() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::stream_parse_group(input));
}

#[test]
fn stream_parse_group_v2() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::stream_parse_group_v2(input));
}

#[test]
fn stream_groups() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::stream_groups(input));
}

#[test]
fn stream_groups_v2() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::stream_groups_v2(input));
}

#[test]
fn stream_parse_message() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::stream_parse_message(input));
}

#[test]
fn stream_parse_version_string() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::stream_parse_version_string(input));
}

#[test]
fn stream_parse_version_string_v2() {
    bolero::check!().for_each(|input: &[u8]| fuzz_common::stream_parse_version_string_v2(input));
}
