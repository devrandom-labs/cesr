# A30 published API compatibility check

Status: comparison recorded on CESR PR #300 at `957d8bfb`; coordinated
versioning, publication and consumer adoption remain open. This compares the
current tree with the latest published versions available to
`cargo-semver-checks`. It does not test a published replacement release.

Platform: aarch64-darwin, Rust 1.95.0, cargo-semver-checks 0.48.0. Commands:

```sh
cargo semver-checks check-release --workspace --default-features
cargo semver-checks check-release --workspace --all-features
cargo semver-checks check-release -p keri-rs --all-features --release-type minor
```

All three commands exited 1 because they detected breaking changes. The
figures count failing lint *categories*, not individual affected API items.
All-feature findings include those found with default features.

| Published crate | Default / all-feature failing categories | Representative break | Version review before publication |
| --- | ---: | --- | --- |
| `cesr-rs` 0.11.1 | 0 / 1 | All-feature `VerificationError` gained `UnsupportedAlgorithm` on an exhaustive public enum. | Review a 0.12.0 minor bump under the repository's 0.x policy. |
| `cesr-stream` 0.6.0 | 3 / 4 | `CesrMessage` and its public module were removed; `CesrCodec::new` gained a limit argument; `ParseError` gained variants. | Review 0.7.0. |
| `keri-codec` 0.9.0 | 5 / 5 | Public parse methods and `Deserialize::deserialize` gained explicit limits; public error/message variants changed. | Review 0.10.0. |
| `keri-events` 0.5.0 | 4 / 4 | The `internals` feature and several constructors/getters were removed; `MessageType` changed. | Review 0.6.0. |
| `keri-rs` 0.0.15 | 0 checks / 0 checks in automatic runs; **8** failing categories with explicit minor-release check | `Signed` lost public construction/fields; `EvidenceKind` gained variants; a public method and enum variant were removed. | Decide explicitly whether to advance to 0.1.0 under the repository's minor-for-breaking policy. Do not read the automatic zero as compatibility. |

The automatic workspace runs performed **zero** checks for `keri-rs` and
skipped 253 because a no-version-change comparison of a `0.0.x` crate is
treated as an assumed major change. The explicit `--release-type minor`
comparison ran 196 checks and found eight failing categories. These are
static public-surface checks, not a complete consumer compatibility test.

The existing [release PR #294](https://github.com/devrandom-labs/cesr/pull/294)
predates PR #300 and changes only `keri-codec` 0.9.0 → 0.10.0 and
`keri-rs` 0.0.15 → 0.0.16. It neither covers all five published API breaks
nor follows the local `CLAUDE.md` rule that breaking `0.x` APIs bump the
minor component. Its `keri-rs` version requires an explicit decision before
the release PR is merged. The configured release workflow can be dispatched
to refresh the release PR after the CESR changes land; the resulting version
set and dependency requirements need review against this table before any
publish step. No version or release PR was changed by this check.

The release gate still requires the final reviewed CESR head, correct
version and changelog changes in dependency order, package/consumer builds
against the **published** crates, and the wrong-controller-key regression
running unignored in the ordinary Selo graph. Product adoption belongs to
the Selo owner after Bombay is complete.
