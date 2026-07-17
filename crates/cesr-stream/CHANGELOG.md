# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial release. Carved from `cesr-rs`'s `stream` module (#192 phase 2) with
  no wire-behavior change: `cesr::stream::X` is now `cesr_stream::X`. CESR stream
  framing — counters, groups, cold-start detection, and text/binary stream
  parsing (`CesrMessage::parse`, `CesrGroup`, the `TextStream` cursor). The
  `async` codec (`CesrCodec`) moves here from `cesr` behind the `async` feature.
  The version starts at 0.1.0 because it is a new crate; the API is under active
  redesign in #193.
