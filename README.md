# trustless — Credential Broker CLI for AI Agents

[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

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

# Start MCP server for AI agent integration
trustless mcp
```

## Agent Plugins 1.0.0

This repository is also packaged as an [Agent Plugins](https://agent-plugins.org) 1.0.0 plugin — the open, vendor-neutral standard for packaging Agent Skills and MCP servers into portable plugins. A single `plugin.json` manifest lets compatible clients discover the `trustless-usage` skill and the stdio MCP server from the fixed locations:

```text
trustless/
├── plugin.json               # Agent Plugins 1.0.0 manifest ($schema + name required)
├── skills/
│   └── trustless-usage/
│       └── SKILL.md          # Agent Skills spec-compliant (agentskills: true)
├── mcp.json                  # stdio MCP server: `trustless mcp`
├── schemas/                  # Vendored official 1.0.0 JSON Schemas (plugin + mcp)
└── scripts/validate-plugin.py  # Packaging validation (wired into make check)
```

Both v1 component types are provided: the `trustless-usage` skill from `skills/`, and a stdio MCP server (`mcp.json`) exposing `resolve_credential`, `inject_run`, and `list_credentials` via `trustless mcp`.

Agent Plugins–compatible clients at launch: **ChatGPT / Codex, Cursor, GitHub Copilot, Kiro, VS Code**. Install by cloning or vendoring the repo and pointing the client at the plugin root (the directory containing `plugin.json`).

Validation: `make validate-plugin` (or `make check`) verifies the manifest against the closed schema, the `skills/` discovery layout, and `mcp.json` semantics using the vendored official schemas.

**PATH requirement:** the MCP `command` is a bare executable name — `trustless` must be on `PATH` for clients that launch the stdio server.

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

Start a local HTTP forward proxy that substitutes `__KEY_NAME__` placeholders in requests with real credentials.

```bash
trustless proxy start --port 8080
trustless proxy start --port 8080 --mitm  # HTTPS interception mode
```

Configure your agent to use the proxy:

```bash
export HTTPS_PROXY=http://127.0.0.1:8080
```

**Placeholder format:** `__<KEY_NAME>__` — double underscores surrounding an uppercase key name. Resolution tries the lowercase key as a pass entry first, then falls back to `iria/api/<lowercase_key>`.

**MITM mode (`--mitm`):**
- Enables HTTPS interception for placeholder substitution in encrypted requests
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
| `--mitm` | Enable MITM mode (intercept HTTPS for placeholder substitution) |

HTTPS CONNECT tunneling is supported. Without `--mitm`, CONNECT requests pass through without modification. With `--mitm`, the connection is intercepted and placeholder substitution applies.

### `trustless mcp` — MCP Server Mode

Start a stdio-based MCP (Model Context Protocol) server for AI agents to resolve credentials directly.

```bash
trustless mcp
```

The server implements [JSON-RPC 2.0](https://www.jsonrpc.org/specification) over stdin/stdout with these tools:

| Tool | Description | Input |
|------|-------------|-------|
| `resolve_credential` | Resolve and return a credential value | `{"key": "..."}` |
| `inject_run` | Run a command with credential injection | `{"secrets": [...], "command": [...], "sanitize": true}` |
| `list_credentials` | List all credential keys | `{}` |

**Protocol:** MCP 2024-11-05. Compatible with any MCP-compatible AI agent (Hermes, Claude Code, Codex, Cursor, etc.).

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
                     │ CLI / HTTP / MCP
                     ▼
┌─────────────────────────────────────────────────────────┐
│                   trustless CLI                          │
│                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐ │
│  │ secret   │  │ run      │  │ proxy    │  │ mcp    │ │
│  │ (list/   │  │ (subproc │  │ (HTTP    │  │ (MCP   │ │
│  │  get/set)│  │  inject) │  │  proxy + │  │  stdio │ │
│  └────┬─────┘  └────┬─────┘  │  MITM)   │  │ server)│ │
│       │             │        └─────┬─────┘  └────┬───┘ │
│       │             │              │              │     │
│  ┌────┴─────────────┴──────────────┴──────────────┴──┐  │
│  │              Backend Interface                     │  │
│  │  (pass / env / bitwarden — swappable)            │  │
│  └──────────────────────┬───────────────────────────-┘  │
└─────────────────────────┼──────────────────────────────┘
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
├── mcp.json                         # stdio MCP server config (`trustless mcp`)
├── skills/
│   └── trustless-usage/             # Agent Skills spec-compliant SKILL.md
├── schemas/
│   ├── plugin.schema.json           # Vendored official Agent Plugins schema
│   └── mcp.schema.json              # Vendored official MCP config schema
├── internal/
│   ├── backend/
│   │   ├── backend.go               # Backend interface + types
│   │   ├── env.go                   # Environment variable backend
│   │   └── pass.go                  # Pass CLI backend implementation
│   ├── config/
│   │   └── config.go                # TOML config loading/saving (+ policy types)
│   ├── mcp/
│   │   └── server.go                # MCP server (JSON-RPC 2.0 over stdio)
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
