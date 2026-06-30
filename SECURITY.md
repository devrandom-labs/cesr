# Security Policy

`cesr` provides cryptographic primitives (CESR + KERI) for Rust. We take the
security of this crate and the systems that depend on it seriously, and we
appreciate responsible disclosure of vulnerabilities.

## Supported Versions

Security fixes are provided for the latest released `0.1.x` line. Because the
public surface is intentionally frozen (see [`CLAUDE.md`](./CLAUDE.md)), a fix
that must change observable behavior is handled as a coordinated release and may
warrant a version bump beyond the normal patch cadence.

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
discussions, or pull requests.**

Report privately through GitHub's built-in advisory workflow:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability** (GitHub Private Vulnerability Reporting).
3. Provide a clear description, affected version(s), and reproduction steps.

A maintainer will receive your report privately, and you can collaborate on a
fix through the same private advisory.

Direct link: <https://github.com/devrandom-labs/cesr/security/advisories/new>

### What to include

- The module/feature affected (`core`, `crypto`, `stream`, `utils`, `keri`,
  `serder`) and the version or git commit.
- A description of the impact (e.g. memory unsafety, panic on untrusted input,
  incorrect verification, timing leak).
- A minimal reproduction (input bytes, a failing test, or a code snippet).

## Response Expectations

- **Acknowledgement:** within 3 business days.
- **Triage & severity assessment:** within 7 business days.
- **Fix & coordinated disclosure:** timeline communicated during triage, scaled
  to severity. We will credit reporters who wish to be acknowledged.

## Scope

In scope: vulnerabilities in this crate's source — including memory safety,
panics on untrusted/malformed input, incorrect cryptographic verification,
encoding/decoding correctness that affects security, and supply-chain issues in
declared dependencies.

Out of scope: vulnerabilities in downstream applications that merely depend on
`cesr`, and issues requiring a non-default, explicitly-unsafe configuration.

## Supply-Chain Hygiene

Every change is gated by `nix flake check`, which runs `cargo audit`
(RUSTSEC advisory database) and `cargo deny` (advisories, license, and source
bans) on the full dependency tree. Dependabot continuously monitors and opens
update pull requests, and CodeQL scans first-party Rust source on pull requests.
