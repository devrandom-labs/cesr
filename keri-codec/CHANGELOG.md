# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial release. Carved from `cesr-rs`'s `serder` module (#192 phase 1) with
  no API change: `cesr::serder::X` is now `keri_codec::X`. The KERI event codec —
  events to and from canonical JSON, SAID computation, and CESR message framing
  (`EventMessage::parse`, `SerializedEvent::frame_v1`). The version starts at
  0.1.0 because it is a new crate; the API is under active redesign in #193.
