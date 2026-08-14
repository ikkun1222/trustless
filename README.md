# trustless — Credential Broker CLI for AI Agents

[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/ikkun1222/trustless/actions/workflows/ci.yml/badge.svg)](https://github.com/ikkun1222/trustless/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ikkun1222/trustless)](https://goreportcard.com/report/github.com/ikkun1222/trustless)

## Overview

**trustless** is a credential broker CLI that decouples AI agents from the secrets they use. Instead of agents holding plaintext credentials in their context window (where prompt injection or leakage can expose them), trustless acts as an intermediary: agents reference credentials by name, and the broker resolves them at the transport or process layer — the agent **never holds plaintext values**.

The name reflects the architecture: you don't need to *trust* the agent with secrets because the agent structurally cannot access them.

### Why trustless?

Traditional AI agent setups give the agent direct access to credentials — either as environment variables, config files, or inline in prompts. This means a single prompt injection or overly-verbose debug output can leak secrets to an attacker or an untrusted third-party API.

trustless inverts the model: the agent says "use `GITHUB_TOKEN`", the broker resolves the value, and the agent only ever sees the API response — never the key itself.

```
Traditional:  agent → sees key → uses key → key is in context → prompt injection leaks it
              ↑  agent is a trusted principal

trustless:    agent → says "use GITHUB_TOKEN" → broker resolves → agent gets API response
              ↑  agent is an untrusted caller, broker is the authority
```

### How it compares

The "keep secrets away from AI agents" space has several tools. trustless is the
only one that combines **subprocess injection with output sanitization**,
**integrated DLP** (outbound request redaction), and **existing password-manager
backends** (pass / Bitwarden) in a single zero-dependency binary.

| | trustless | tene | vaulty | agent-secrets | secretless-ai | enject |
|---|---|---|---|---|---|---|
| Injection method | subprocess env + HTTP proxy | subprocess env | HTTP proxy + MCP | subprocess env (lease) | env + shell hook | subprocess env |
| Existing backend (pass/Bitwarden) | ✅ | ❌ own vault | ❌ own vault | ❌ own vault | ❌ keychain/1Password | ❌ own vault |
| Output sanitization | ✅ run + proxy | ❌ | ✅ | ❌ | ❌ | ❌ |
| DLP (outbound redaction) | ✅ integrated | ❌ | partial (request) | ❌ | ❌ | ❌ |
| OAuth token management | ✅ (google/lark, refresh) | ❌ | ❌ | ❌ | ❌ | ❌ |
| Audit log (structured) | ✅ | ❌ | ✅ file | ✅ append-only | ❌ | ❌ |
| Agent skills bundled | ✅ 4 | ✅ context files | MCP only | ✅ skill | ✅ rules | ❌ |
| Dependencies | **0 (single binary)** | Go static | Go static | Go static | npm/npx | Go static |
| License | MIT | MIT | MIT | MIT | Apache-2.0 | MIT |

*tene / vaulty / agent-secrets / secretless-ai / enject are compared as of Aug 2026.*

The practical difference: tools like tene or enject solve "agent shouldn't read
`.env`". trustless also solves "agent shouldn't *see* the key when it runs a
command" (output sanitization) and "secrets shouldn't leak *out* of the machine
when the agent calls an API" (DLP). If you already use pass or Bitwarden, there
is no migration — trustless reads your existing store.

## Installation

### One-liner (Linux / macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/ikkun1222/trustless/main/scripts/install.sh | sh
```

To install without the setup prompt (for CI/Docker):

```bash
curl -fsSL https://raw.githubusercontent.com/ikkun1222/trustless/main/scripts/install.sh | sh -s -- --minimal
```

To upgrade an existing installation:

```bash
curl -fsSL https://raw.githubusercontent.com/ikkun1222/trustless/main/scripts/install.sh | sh -s -- --update
```

### From source (Go 1.26+)

```bash
git clone https://github.com/ikkun1222/trustless
cd trustless && go build -o trustless .
```

Or install directly:

```bash
go install github.com/ikkun1222/trustless@latest
```

> Note: `go build` without ldflags reports `trustless dev`. Release binaries
> embed the version via `-ldflags "-X main.version=vX.Y.Z"` (the release
> pipeline and `make build VERSION=vX.Y.Z` do this automatically).

### Verifying release artifacts

Starting with v0.5.1, every release artifact (binaries, SHA256SUMS, SBOM) is
signed with **cosign keyless** (OIDC, no key management). Verify before use:

```bash
# 1. Download the artifact + its signature and certificate
gh release download v0.5.1 -p 'trustless-linux-amd64*' -p 'SHA256SUMS*'

# 2. Verify the binary matches the published checksum
sha256sum -c <(grep 'trustless-linux-amd64' SHA256SUMS)

# 3. Verify the cosign signature (keyless: identity = GitHub Actions of ikkun1222/trustless)
cosign verify-blob --certificate trustless-linux-amd64.pem \
  --signature trustless-linux-amd64.sig \
  --certificate-identity-regexp '^https://github.com/ikkun1222/trustless/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  trustless-linux-amd64
```

Each release also ships an SPDX SBOM (`trustless.sbom.spdx.json`) generated
with syft for supply-chain transparency.

### Prerequisites

- **Go 1.26+** for building from source
- **`pass`** (the standard Unix password manager) + **`gpg`** — the default credential backend
- Environment variables only (no `pass` needed) when using `backend = "env"`
- **`bw`** (Bitwarden CLI) required only when using `backend = "bitwarden"` (cloud store)

Backends are swappable via `trustless config set backend <name>`: `pass` (default), `env`, `bitwarden`. See [docs/bitwarden-backend-design.md](docs/bitwarden-backend-design.md) for the Bitwarden backend design.

## Quick Start

```bash
# First-time setup (GPG key, pass store, .env migration, agent config)
trustless setup

# Check system health
trustless doctor

# List credentials from the pass store
trustless secret list

# Run a command with a credential injected (output is sanitized)
trustless run -s iria/api/xai -- curl -s https://api.x.ai/v1/models

# Start the credential proxy
trustless proxy start --port 8080
```

## Agent Plugins 1.0.0

This repository is also packaged as an [Agent Plugins](https://agent-plugins.org) 1.0.0 plugin — the open, vendor-neutral standard for packaging Agent Skills into portable plugins. A single `plugin.json` manifest lets compatible clients discover the `trustless-usage` skill from the fixed location:

```text
trustless/
├── plugin.json               # Agent Plugins 1.0.0 manifest ($schema + name required)
├── skills/
│   └── trustless-usage/
│       └── SKILL.md          # Agent Skills spec-compliant (agentskills: true)
├── schemas/
│   └── plugin.schema.json    # Vendored official 1.0.0 plugin JSON Schema
└── scripts/validate-plugin.py  # Packaging validation (wired into make check)
```

The plugin ships the `trustless-usage` skill, which teaches agents the credential conventions (`trustless run` for injection, `trustless secret set` for registration, no plaintext persistence).

Agent Plugins–compatible clients at launch: **ChatGPT / Codex, Cursor, GitHub Copilot, Kiro, VS Code**. Install by cloning or vendoring the repo and pointing the client at the plugin root (the directory containing `plugin.json`).

Validation: `make validate-plugin` (or `make check`) verifies the manifest against the closed schema and the `skills/` discovery layout using the vendored official schema.

## Commands Reference

### `trustless secret` — Credential Store Operations

| Subcommand | Description | Example |
|------------|-------------|---------|
| `list` | List all available credential keys | `trustless secret list` |
| `get <key>` | Retrieve a credential value (JSON output) | `trustless secret get github_token` |
| `set <key> [value]` | Store a new credential (wraps `pass insert`) | `trustless secret set openai_key sk-...` |

`get` outputs JSON by default:
```json
{"key": "github_token", "value": "ghp_..."}
```

### `trustless oauth` — OAuth Credential Management

Manage OAuth credentials (RFC 8628 device flow + refresh grant) for providers like Google and Lark. `trustless oauth login` runs the device authorization flow and stores the resulting tokens as a **compact single-line JSON entry** (`type=oauth`) in the credential backend. The entry is then resolved like any other credential — `trustless run -s <key>` / `trustless proxy` return a fresh access token, with automatic refresh on expiry.

| Subcommand | Description | Example |
|------------|-------------|---------|
| `login <provider> <key>` | Device flow login; stores the OAuth entry | `trustless oauth login google api/google` |
| `refresh <key>` | Force refresh the OAuth entry (ignore cache) | `trustless oauth refresh api/google` |
| `status <key>` | Show entry status (`valid` / `expired` / `reauth_required`) | `trustless oauth status api/google` |
| `providers` | List configured providers | `trustless oauth providers` |

`login` prints the verification URL to stdout, then polls until the user approves:

```bash
$ trustless oauth login google api/google
https://oauth2.googleapis.com/device/code?user_code=ABCD-1234   # open this in a browser
{"key":"api/google","provider":"google","expires_at":"2026-08-13T12:00:00Z"}
```

`refresh` force-refreshes the access token without waiting for expiry; the access token value is never printed. `status` reports `valid` when the token is still fresh, and `reauth_required` when the refresh token is revoked (`invalid_grant`):

```bash
$ trustless oauth status api/google
{"key":"api/google","provider":"google","expires_at":"...","status":"valid"}
```

**Configuration (`[oauth.providers]`):** define a provider with its token/device endpoints and credentials. The built-in `google` and `lark` definitions ship with the endpoints below — you only need to fill in `client_id` / `client_secret` (register the app in the provider's **developer console**) and any additional scopes:

```toml
[oauth.providers.google]
client_id = "YOUR_CLIENT_ID"
client_secret = "YOUR_CLIENT_SECRET"
scopes = ["https://www.googleapis.com/auth/gmail.readonly"]

[oauth.providers.lark]
client_id = "YOUR_CLIENT_ID"
client_secret = "YOUR_CLIENT_SECRET"
# scopes 未設定時は既定の offline_access が使われる（refresh token 取得に必須）
```

| Provider | Device authorization endpoint | Token endpoint | Device auth | Token request |
|----------|-------------------------------|----------------|-------------|---------------|
| `google` | `https://oauth2.googleapis.com/device/code` | `https://oauth2.googleapis.com/token` | `body` (client_secret in form body) | `form` |
| `lark` | `https://accounts.larksuite.com/oauth/v1/device_authorization` | `https://open.larksuite.com/open-apis/authen/v2/oauth/token` | `basic` (Authorization header) | `json` (Lark code-style response) |

`client_id` / `client_secret` are registered in the provider's developer console (Google Cloud Console / Lark Open Platform) — never commit them. OAuth entries in the backend store only the tokens, never the client credentials.

### `trustless audit` — Structured Audit Log

All events (proxy injection/deny, run spawn, DLP redaction, OAuth refresh/failure/reauth) are recorded as JSONL. **No token or secret values ever appear in events** — only key names, hosts, verdicts, and small details.

| Sink | Where | Default |
|------|-------|---------|
| `journald` | serve (stdout JSONL → systemd journald) | serve |
| `file` | append-only `~/.local/state/trustless/audit.jsonl` (0600, SIGHUP-reopen for logrotate) | run / proxy / oauth |
| `off` | discard | — |

```toml
[audit]
sink = "file"        # "journald" | "file" | "off"（未設定はコマンド別デフォルト）
file = "~/.local/state/trustless/audit.jsonl"
buffer = 1024
```

```bash
$ journalctl --user -u trustless | grep '"event"'
{"ts":"...","event":"proxy.inject","key":"edinet","host":"api.edinet-fsa.go.jp","verdict":"inject","detail":"header=Ocp-Apim-Subscription-Key"}
{"ts":"...","event":"oauth.refresh","key":"iria/api/lark-oauth","verdict":"refresh","detail":"provider=lark"}
```

Events: `proxy.inject` / `proxy.deny` / `run.spawn` / `dlp.redact` / `oauth.refresh` / `oauth.fail` / `oauth.reauth_required`.

**Notes:**
- Access tokens are cached in memory (validity minus a 60s safety margin); refresh happens automatically on `Resolve` when expired.
- When a provider rotates the refresh token (Lark), the updated entry is written back with a **CAS guard** so a concurrent writer is never overwritten.
- `invalid_grant` (revoked refresh token) is not retried — re-run `trustless oauth login` to re-authenticate.

### `trustless run` — Subprocess Credential Injection (Core Command)

Run a command with one or more credentials injected as environment variables. The injected values are **never returned to the caller** — only the subprocess stdout/stderr, and any matching credential patterns are redacted.

```bash
trustless run -s iria/api/xai -- curl -s https://api.x.ai/v1/models
trustless run -s GITHUB_TOKEN -s OPENAI_KEY -- gh pr list
```

**How it works:**
1. trustless resolves each `-s` key from the backend
2. Spawns the subprocess with the credential value set as an environment variable
3. The environment variable name is derived from the last path segment of the key, converted to `UPPER_SNAKE_CASE` (e.g. `iria/api/xai` → `XAI`)
4. Forwards stdin to the subprocess and streams stdout/stderr
5. Scans output (line by line) for credential patterns and **redacts** matches with `[REDACTED]`
6. Returns sanitized output to the caller

**Security features:**

- **`--scan-args`** (default: `true`): Before spawning the subprocess, all command arguments are scanned for credential patterns and injected values. If detected, execution is blocked with exit code 3 (fail closed). This prevents the agent from accidentally exposing credential values in CLI arguments like `curl -H "Authorization: Bearer ***"`.
- **`--sanitize`** (default: `true`): Scans and redacts credential patterns from subprocess output.
- **Policy engine**: Command-level access control (see configuration section).

**stdio protocols (ACP / MCP / LSP):** stdin is always forwarded to the child (fixed 2026-07-31), and output is sanitized **line-by-line in real time** so long-running processes (ACP servers, gateways) flush output instead of buffering until exit. For interactive JSON-RPC stdio servers, sanitizing the stream can corrupt protocol messages — pass `--sanitize=false` for those (e.g. `hermes acp`).

| Flag | Description |
|------|-------------|
| `-s, --secret <key>` | Credential key to inject (repeatable, format: `KEY` or `KEY:ENVNAME`) |
| `--sanitize` | Enable output scanning/redaction (default: on) |
| `--sanitize-policy <file>` | Custom redaction patterns file |
| `--scan-args` | Scan command arguments for credential patterns before spawning (default: on) |
| `--json` | Output as JSON `{"exit_code": N, "stdout": "...", "stderr": "..."}` |
| `--timeout <duration>` | Subprocess timeout (default: 5m) |

### `trustless proxy` — HTTP Forward Proxy with Credential Injection

Start a local HTTP forward proxy that injects credentials into requests based on the destination host. The agent sends plain requests — no placeholder syntax, no knowledge of the key.

```bash
trustless proxy start --port 8080
trustless proxy start --port 8080 --mitm  # HTTPS interception mode
```

Configure your agent to use the proxy:

```bash
export HTTPS_PROXY=http://127.0.0.1:8080
```

**Injection rules (config `[proxy.rules]`):** map a host to a credential injected as a header or query parameter. The header/parameter is injected only when absent; unresolved keys fail open (no injection).

```toml
[proxy.rules]
# Header injection (e.g. LLM APIs, EDINET)
"api.x.ai" = { header = "Authorization", key = "xai", prefix = "Bearer " }
"api.edinet-fsa.go.jp" = { header = "Ocp-Apim-Subscription-Key", key = "edinet" }
# Query parameter injection (e.g. e-Stat, Alpha Vantage)
"statdb.nstac.go.jp" = { query = "appid", key = "estat" }
"www.alphavantage.co" = { query = "apikey", key = "alphavantage/mcp-key" }
```

- `header` / `query`: injection target (exactly one per rule)
- `key`: credential key (resolution: lowercase → pass, fallback `iria/api/<key>`)
- `prefix` / `suffix`: header value wrapping (e.g. `Bearer ` prefix)

**Egress allowlist (config `proxy.allowlist`):** when set, only listed hosts are permitted through the proxy; all other requests are rejected with `403 Forbidden`. Empty/absent = all hosts allowed.

```toml
[proxy]
allowlist = ["api.x.ai", "api.edinet-fsa.go.jp"]
```

**Hot reload (SIGHUP):** rule/allowlist changes and credential rotations take effect without a restart.

```bash
systemctl --user reload trustless-proxy   # systemd: sends SIGHUP
# or manually:
# kill -HUP $(pgrep -f "trustless proxy start")
```

Reload re-reads `config.toml` (rules/allowlist) and refreshes the backend cache (bitwarden), so newly rotated keys are visible immediately instead of waiting for the 24h cache TTL.

**MITM mode (`--mitm`):**
- Enables HTTPS interception for credential injection into encrypted requests
- Auto-generates a root CA certificate at `~/.config/trustless/trustless-ca.{crt,key}` on first use
- Leaf certificates are generated per-hostname (24h validity, ECDSA P-256)
- Install the CA certificate system-wide for seamless HTTPS interception:

  ```bash
  sudo cp ~/.config/trustless/trustless-ca.crt /usr/local/share/ca-certificates/
  sudo update-ca-certificates
  ```

| Flag | Description |
|------|-------------|
| `--port <n>` | Listen port (default: 8080) |
| `--unix-socket <path>` | Listen on Unix socket (file permission control) |
| `--mitm` | Enable MITM mode (intercept HTTPS for credential injection) |

HTTPS CONNECT tunneling is supported. Without `--mitm`, CONNECT requests pass through without modification. With `--mitm`, the connection is intercepted and host-based credential injection applies.

### `trustless dlp` — Outbound DLP Reverse Proxy (former dlp-proxy)

`trustless dlp` is the successor subcommand for the former `github.com/ikkun1222/dlp-proxy`: an outbound DLP reverse proxy that masks known secrets in LLM API request bodies with `<redacted>` before they leave the host.

```bash
trustless dlp start -config ~/.config/dlp-proxy/config.json   # start DLP reverse proxy (default 127.0.0.1:8787)
trustless dlp scrub-db  <db-path> [--apply] [--backup]        # scan / scrub secrets in a SQLite DB
trustless dlp scrub-text <path>   [--apply]                   # scan / scrub secrets in text files / dirs
```

- **Config schema is the same JSON as dlp-proxy**: `listen` / `min_secret_len` / `secrets_source` (`pass` | `bitwarden`, default pass) / `secrets_refresh_interval` (**required**, e.g. `"10m"`) / `routes` (prefix → upstream URL)
- **Secrets load through the shared backend** (`backend.Values`); the former bitwardenloader/passstore are gone
- **fail-closed**: startup aborts if secrets cannot be loaded; a failed reload keeps the previous set and logs a warning (fail-safe)
- **Hot reload**: periodic refresh per `secrets_refresh_interval` + immediate reload on SIGHUP
- **Two-layer redaction** (2026-08-14): Layer 1 = known-value substring scan (zero false positives); Layer 2 = gitleaks-compatible pattern rules (API key formats, JWT, private keys, etc.) with keyword pre-filter → RE2 regex → Shannon entropy threshold (default 3.5, per-rule override). Pattern rules are bundled in `internal/dlp/redact/rules.toml` (40 rules, `//go:embed`), derived from [gitleaks](https://github.com/gitleaks/gitleaks) (MIT, Copyright (c) 2019 Zachary Rice — see `LICENSE.gitleaks` / `NOTICE`)
- **New config fields**: `rules_file` (path to an external gitleaks-compatible rules TOML; empty = bundled rules) / `pattern_mode` (`"mask"` = redact pattern matches, `"log"` = detect only, body unchanged, audit event with `detail="patterns=hit&mode=log"`) / `pattern_disabled` (list of rule IDs to disable, e.g. `["generic-api-key"]` to silence a false-positive rule)
- **Hot reload (serve)**: `trustless serve` re-applies `pattern_mode` / `pattern_disabled` / `rules_file` on every reload (SIGHUP via `kill -HUP $(pgrep -f 'trustless serve')` or the 10-minute periodic refresh) — config is re-read, the pattern set is atomically swapped (`PatternSet.Replace`), failures keep the previous state (fail-safe). Standalone `trustless dlp start` reads them at startup only
- The former dlp-proxy repository is frozen (2026-08-13); `trustless dlp` is its replacement

### `trustless setup` — First-Time Setup Wizard

Interactive wizard that automates the full first-time setup:

```bash
trustless setup
```

**4-step flow:**

| Step | Action | Auto-detection |
|------|--------|----------------|
| [1/4] GPG Key | Detect existing key or batch-create RSA 3072 (no passphrase, 5y expiry) | Scans `gpg --list-secret-keys` |
| [2/4] pass Store | Initialize pass store, git init | Checks `pass` availability |
| [3/4] .env Import | Scan directories for .env files, parse KEY=VALUE, import to pass, backup originals | Walks `--import-dir` paths (default: `.`) |
| [4/4] Agent Integration | Detect AI coding agents and **install trustless-usage SKILL.md** into their skill directory (upon confirmation) | Config file existence + grep for trustless references |

**Skill installation paths per agent:**

| Agent | Skill directory |
|-------|----------------|
| OpenCode | `~/.config/opencode/skills/trustless-usage/` |
| Claude Code | `~/.claude/skills/trustless-usage/` |
| Codex | `~/.codex/skills/trustless-usage/` |
| Hermes | `~/.hermes/skills/credential-management/trustless-usage/` |

The installed skill teaches the AI agent the credential conventions: use `trustless run` for injection, `trustless secret set` for registration, and never store plaintext credentials.

**Options:**

| Flag | Description |
|------|-------------|
| `--non-interactive` | Run in non-interactive mode (safe defaults, no prompts, no file removal) |
| `--import-dir <dir>` | Directory to scan for .env files (repeatable, default: `.`) |

**Agent detection currently supports:** OpenCode, Claude Code, Codex, Hermes.

### `trustless doctor` — System Health Check

Diagnostic tool that validates the entire trustless setup:

```bash
trustless doctor           # Human-readable output
trustless doctor --json    # Structured JSON for cron/SIEM
trustless doctor --fix     # Auto-resolve detected issues (stub)
```

**Health checks performed:** GPG key validity, pass store health, gpg-agent status, .env file security scan, agent integration status, MITM CA certificate installation.

### `trustless config` — Tool Configuration

| Subcommand | Description |
|------------|-------------|
| `init` | Create default config at `~/.config/trustless/config.toml` |
| `show` | Print current configuration |
| `set <key> <value>` | Update a configuration value |

**Config keys:**

| Key | Description | Default |
|-----|-------------|---------|
| `backend` | Credential backend (`pass`, `env`, `bitwarden`) | `pass` |
| `output` | Default output mode | `json` |
| `run_defaults.sanitize` | Enable sanitization by default | `true` |
| `run_defaults.timeout` | Default subprocess timeout | `5m` |
| `proxy.port` | Default proxy port | `8080` |
| `policy.default.denied_commands` | Commands blocked globally (e.g., `sh,bash`) | (empty) |

**Config file location:** `~/.config/trustless/config.toml` (overridable via `TRUSTLESS_CONFIG` env var)

```toml
backend = "pass"
output = "json"

run_defaults = { sanitize = true, timeout = "5m" }

[proxy]
port = 8080

[sanitize]
patterns = [
  "(sk_live|sk_test)_[A-Za-z0-9]+",
  "(ghp|gho|ghu|ghs)_[A-Za-z0-9_]+",
  "Bearer [A-Za-z0-9._-]+",
]

[policy.default]
denied_commands = ["sh", "bash", "zsh"]

[[policy.overrides]]
secret_key = "iria/api/xai"
denied_commands = ["curl"]
```

### `trustless completion` — Shell Completion

Generate shell completion scripts for bash, zsh, or fish:

```bash
trustless completion bash > /etc/bash_completion.d/trustless
trustless completion zsh > /usr/local/share/zsh/site-functions/_trustless
trustless completion fish > ~/.config/fish/completions/trustless.fish
```

### `trustless version` — Version Information

```bash
trustless version
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   AI Agent (Hermes / LLM)                │
│  "run psql with DATABASE_URL"                            │
└────────────────────┬────────────────────────────────────┘
                     │ CLI / HTTP
                     ▼
┌─────────────────────────────────────────────────────────┐
│                   trustless CLI                          │
│                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │ secret   │  │ run      │  │ proxy    │              │
│  │ (list/   │  │ (subproc │  │ (HTTP    │              │
│  │  get/set)│  │  inject) │  │  proxy + │              │
│  └────┬─────┘  └────┬─────┘  │  MITM)   │              │
│       │             │        └─────┬─────┘              │
│       │             │              │                    │
│  ┌────┴─────────────┴──────────────┴─────┐              │
│  │            Backend Interface          │              │
│  │  (pass / env / bitwarden — swappable) │              │
│  └─────────────────────┬──────────────────┘             │
└────────────────────────┼────────────────────────────────┘
                          │
            ┌─────────────┴─────────────┐
            │                           │
            ▼                           ▼
     ┌──────────────┐          ┌──────────────┐
     │  pass store   │          │  Target API   │
     │  (GPG + pass) │          │  / Service    │
     └──────────────┘          └──────────────┘
```

### Backend Abstraction

The credential resolver is abstracted behind a simple interface:

```go
type Backend interface {
    Resolve(ctx context.Context, key string) (string, error)
    List(ctx context.Context) ([]Entry, error)
}
```

Implemented backends:
- **`pass`** (default) — wraps `pass show <key>`, reads first line as secret
- **`env`** — reads from environment variables via `os.Getenv()` (for CI/CD, containers)
- **`bitwarden`** — wraps the `bw` CLI (`bw list items`), resolves secureNote `fields[value]` / login passwords / notes first line. Session key is passed via `BW_SESSION` env (never argv). Unlock via `trustless bw-unlock` (session key saved to `~/.config/trustless/bw-session`, 0600). Fails closed on invalid session. Details: [docs/bitwarden-backend-design.md](docs/bitwarden-backend-design.md)

Configure via `trustless config set backend <name>`.

## Security Model

### What trustless guarantees

1. **Credential values never enter the LLM context window**
   - `run`: credentials are set on the subprocess environment, output is scanned and redacted before being returned
   - `proxy`: credentials are substituted inside the proxy process; the agent sees only the API response
   - Direct `get` outputs the value but requires explicit invocation (not available to the agent in normal workflows)

2. **Command argument scanning** (`--scan-args`)
   - Before spawning a subprocess, all command arguments are scanned for credential patterns and injected values
   - If detected, execution is blocked with exit code 3 (fail closed)
   - Prevents the agent from accidentally exposing credential values in CLI arguments

3. **Policy engine** — command-level access control
   - `policy.default.denied_commands`: block dangerous commands globally (e.g., `sh`, `bash`)
   - `policy.<key>.denied_commands`: block specific commands per credential
   - Fail-closed: policy violation blocks execution with exit code 3

4. **Subprocess output sanitization**
   - Default patterns match common credential formats: GitHub tokens, OpenAI keys, xAI keys, AWS keys, Bearer tokens, and generic patterns
   - **Injected values are themselves pattern-scanned**: if the subprocess echoes the credential, that value is redacted
   - Custom patterns via config file or `--sanitize-policy`

5. **Minimal attack surface**
   - Proxy listens on `127.0.0.1` by default (not exposed to the network)
   - Unix socket mode available for file permission control
   - MITM proxy generates per-hostname ephemeral certificates (24h validity)
   - Single binary with zero runtime dependencies beyond `pass` + `gpg` (the `bitwarden` backend additionally requires the `bw` CLI)

6. **No credential persistence in the broker process**
   - Credentials are resolved on-demand and released after the subprocess exits
   - HTTP proxy holds credentials in memory only during active request processing

### What trustless does NOT solve (v1 scope)

- **Dynamic/rotating credentials** — the pass store is static; rotation is handled externally
- **Full audit trail** — basic logging only; SIEM export is future work
- **Hardware-backed key storage** — relies on GPG keyring security
- **HTTPS MITM CA trust management** — the MITM proxy generates a CA cert; the user must install it in the OS trust store

## Configuration

Configuration is stored at `~/.config/trustless/config.toml`. Use `trustless config init` to create the default file, or create it manually.

The config file path can be overridden with the `TRUSTLESS_CONFIG` environment variable.

For full configuration options, see the [design document](docs/design.md).

## Development

### Prerequisites

- Go 1.26+
- `pass` CLI + `gpg` (for testing with a real backend)

### Building

```bash
git clone https://github.com/ikkun1222/trustless
cd trustless
go build -o trustless .
```

### Testing

```bash
go test ./...
```

### Project Structure

```
├── main.go                          # CLI entry point & subcommand dispatch
├── plugin.json                      # Agent Plugins 1.0.0 manifest
├── skills/
│   └── trustless-usage/             # Agent Skills spec-compliant SKILL.md
├── schemas/
│   └── plugin.schema.json           # Vendored official Agent Plugins schema
├── internal/
│   ├── backend/
│   │   ├── backend.go               # Backend interface + types
│   │   ├── env.go                   # Environment variable backend
│   │   └── pass.go                  # Pass CLI backend implementation
│   ├── config/
│   │   └── config.go                # TOML config loading/saving (+ policy types)
│   ├── proxy/
│   │   ├── ca.go                    # MITM CA certificate generation
│   │   ├── command.go               # HTTP forward proxy with credential substitution
│   │   └── mitm.go                  # MITM CONNECT handler (HTTPS interception)
│   ├── run/
│   │   └── command.go               # Subprocess credential injection (+ policy check)
│   ├── scanner/
│   │   ├── scanner.go               # Pattern-based credential redaction
│   │   └── scanner_test.go          # Scanner tests
│   └── secret/
│       └── command.go               # Credential store operations
├── scripts/
│   └── validate-plugin.py           # Agent Plugins packaging validation
└── docs/
    └── design.md                    # Architecture & design document
```

### Dependencies

trustless has a single external dependency — the rest is all Go standard library:

- `github.com/pelletier/go-toml/v2` — TOML config file parsing

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Credential not found / invalid args |
| 3 | Subprocess error / policy violation / credential in args |
| 4 | Config error |

## License

MIT
