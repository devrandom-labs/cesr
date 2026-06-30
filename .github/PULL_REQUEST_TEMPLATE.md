<!-- Thanks for contributing to cesr! Please fill out the sections below. -->

## Summary

<!-- What does this PR change, and why? -->

## Type of change

- [ ] `feat` — new functionality (new code table, type, function, trait impl)
- [ ] `fix` — bug fix
- [ ] `docs` — documentation only
- [ ] `chore` / `ci` / `refactor` — no public behavior change

## API impact (REQUIRED)

cesr is `0.x` and under active development (see `CLAUDE.md` → Active Development).
Breaking changes are allowed, but never accidental — declare them:

- [ ] **No public API change** — purely additive or internal, or
- [ ] **Breaking change** — a signature/type/behavior/error-variant changed. It is
      intentional, scoped, noted in the `CHANGELOG`, and described below (with the
      migration for downstream consumers).

## Verification

- [ ] `nix flake check` passes locally (the single gate: clippy, fmt, taplo,
      audit, deny, nextest, doctest, wasm, no_std, actionlint).
- [ ] New behavior is covered by round-trip / boundary / property tests.

## Notes

<!-- Anything reviewers should know: trade-offs, follow-ups, security impact. -->
