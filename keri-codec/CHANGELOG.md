# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- workspace split phase 2 (#192) — `stream` moved out of `cesr` into the new
  `cesr-stream` crate; keri-codec now depends on `cesr-stream` and reaches stream
  types as `cesr_stream::X` instead of `cesr::stream::X`. No API change to
  keri-codec's own surface.

### Added

- Initial release. Carved from `cesr-rs`'s `serder` module (#192 phase 1) with
  no API change: `cesr::serder::X` is now `keri_codec::X`. The KERI event codec —
  events to and from canonical JSON, SAID computation, and CESR message framing
  (`EventMessage::parse`, `SerializedEvent::frame_v1`). The version starts at
  0.1.0 because it is a new crate; the API is under active redesign in #193.
