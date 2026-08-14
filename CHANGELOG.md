# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Update Go toolchain to 1.26.6 — fixes 5 standard-library vulnerabilities
  (GO-2026-6218 net/url, GO-2026-6090 crypto/tls, GO-2026-6089 + GO-2026-5026
  net/http, GO-2026-5972 encoding/asn1) that were reachable via the OAuth
  device flow, MITM proxy, DLP server, and CA loading paths. `govulncheck`
  now reports zero findings.
- Add SECURITY.md with private vulnerability reporting channels and response SLA.
- Add cosign (keyless, OIDC) signing of release artifacts.
- Add SBOM (SPDX) generation to the release pipeline.

### Changed

- `go` directive in go.mod raised to 1.26.6 (requires Go 1.26.6+ to build).
- CI now runs `govulncheck` and reports test coverage on every push.
- `trustless version` now reports the build-embedded version; release
  binaries embed the tag via ldflags (`-X main.version=vX.Y.Z`) instead of a
  hardcoded string. `go build` without ldflags reports `dev`.

## [0.5.0] - 2026-08-14

### Added

- **OAuth credential management** (`trustless oauth`): device-code flow
  (RFC 8628), refresh-grant client, google/lark provider definitions,
  entry minimization with zlib compression (works around Bitwarden's
  5000-char field limit), backend decorator with cache + CAS guard.
- **Structured audit log** (`trustless audit`): event/sink architecture
  (file, journald, off), async drop, SIGHUP reopen, wired into
  proxy/dlp/run/oauth/serve.
- **DLP pattern layer 2**: gitleaks-compatible 40-rule pattern set
  (keyword → RE2 → entropy), `rules_file` / `pattern_mode` config,
  hot-reloadable PatternSet, FP/FN test matrix.
- **Single-process egress** (`trustless serve`): unified run-injection
  proxy + DLP reverse proxy with SIGHUP and periodic hot reload.
- **`trustless dlp scrub-db` / `scrub-text`**: SQLite and text datastore
  scrubbing with pattern layer 2 support.
- **Agent Plugins 1.0.0** packaging (`plugin.json` + `skills/trustless-usage`).
- Shell completion generation (`trustless completion`: bash, fish).

### Changed

- Proxy injection unified to host-based injection (placeholder mode removed),
  query-parameter injection support added (e-Stat, Alpha Vantage).
- Bitwarden `Set` uses `-m` mode with piped input; documented 5000-char
  field limitation and mitigations.
- Config load warns on loose permissions for files containing
  `client_secret`.

### Fixed

- CONNECT routing 404 bug and MITM certificate SAN bug.
- OAuth device-poll interruption on 400 + `pending` (Lark observed).
- `invalid_grant` non-200 responses mapped to `ErrInvalidGrant`
  (Lark single-use refresh tokens).
- Empty timestamp fields tolerated; exit-code propagation fixed.
- `serve`: silent client-abort handler no longer recovered as error.

### Security

- Repo scrubbed for public release: internal paths removed, test emails
  replaced with dummy values, LICENSE (MIT) + NOTICE added, secrets-check
  gate (git diff scan) enforced via Makefile.
- CI: `go test ./... -race` + `go vet`; release automation with
  multi-arch binaries and SHA256SUMS.

[Unreleased]: https://github.com/ikkun1222/trustless/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/ikkun1222/trustless/releases/tag/v0.5.0
