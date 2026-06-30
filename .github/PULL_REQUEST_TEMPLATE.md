<!-- Thanks for contributing to cesr! Please fill out the sections below. -->

## Summary

<!-- What does this PR change, and why? -->

## Type of change

- [ ] `feat` — new functionality (new code table, type, function, trait impl)
- [ ] `fix` — bug fix
- [ ] `docs` — documentation only
- [ ] `chore` / `ci` / `refactor` — no public behavior change

## Freeze check (REQUIRED)

The public surface is **frozen** (see `CLAUDE.md` → FROZEN). Confirm:

- [ ] This PR only **adds** to the public API — it does not change the signature,
      behavior, or semantics of any existing public item.
- [ ] If it *does* alter frozen behavior (e.g. a security fix), this was approved
      and is called out explicitly below.

## Verification

- [ ] `nix flake check` passes locally (the single gate: clippy, fmt, taplo,
      audit, deny, nextest, doctest, wasm, no_std, actionlint).
- [ ] New behavior is covered by round-trip / boundary / property tests.

## Notes

<!-- Anything reviewers should know: trade-offs, follow-ups, security impact. -->
