# Security Policy

## Reporting a Vulnerability

trustless handles credentials by design, so security issues are taken seriously.

**Please do not open a public issue for security vulnerabilities.** Use one of the private channels:

1. **GitHub Private Vulnerability Reporting** (preferred)
   https://github.com/ikkun1222/trustless/security/advisories/new

2. **Email fallback**: `takahashi.iria+security@gmail.com`
   - Encrypt with GPG if possible (key fingerprint available on request).
   - If you must report without encryption, do not include real credential values — describe the vulnerability, not the secret.

## What to include

- Affected version(s) and platform
- Steps to reproduce (minimal, no real secrets)
- Impact description (what an attacker could do)
- Suggested fix, if you have one

## Scope

In scope:
- The `trustless` binary (CLI, `run` / `proxy` / `serve` / `oauth` subcommands)
- Credential handling: injection, sanitization, DLP redaction, audit logging
- Config / pass / Bitwarden backend interactions

Out of scope:
- `trustless-win` (separate product: https://github.com/ikkun1222/trustless-win)
- Third-party services (pass, Bitwarden, OAuth providers) — report to their own programs

## Response SLA

| Severity | First response | Fix target |
|---|---|---|
| Critical (credential exposure / remote code execution) | 48h | 7 days |
| High | 5 days | 30 days |
| Medium / Low | 10 days | best effort (next release) |

This is a personal, single-maintainer project. Timelines are best-effort targets, not contractual commitments. You will always receive an acknowledgment, even if a full fix takes longer.

## Supported versions

Only the latest release is supported. No LTS branches are maintained.

## Security-relevant notes for users

- Binaries are distributed via GitHub Releases with SHA256SUMS. Starting with v0.5.1, releases are additionally signed with cosign (keyless, OIDC) — verify with `cosign verify-blob`.
- The default `serve` setup runs a local HTTP proxy on `127.0.0.1` with DLP redaction (`pattern_mode: mask` recommended over `log` in production).
- Secrets are never persisted by trustless itself; the pass / Bitwarden backend remains the store of record.
