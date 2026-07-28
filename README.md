# trustless — Credential Broker CLI for AI Agents

[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/ikkun1222/trustless.svg)](https://pkg.go.dev/github.com/ikkun1222/trustless)

## Overview

**trustless** is a credential broker CLI that decouples AI agents from the secrets they use. Instead of agents holding plaintext credentials in their context window (where prompt injection or leakage can expose them), trustless acts as an intermediary: agents reference credentials by name, and the broker resolves them at the transport or process layer.

The name reflects the architecture — you don't need to *trust* the agent with secrets because the agent structurally cannot access them.

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
- **`pass`** (the standard Unix password manager) + **`gpg`** — the credential backend

## Quick Start

```bash
# List credentials from the pass store
trustless secret list

# Run a command with a credential injected (output is sanitized)
trustless run -s iria/api/xai -- curl -s https://api.x.ai/v1/models

# Start the credential proxy on port 8080
trustless proxy start --port 8080
```

## Commands Reference

### `trustless secret` — Credential Store Operations

| Subcommand | Description | Example |
|---|---|---|
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
1. trustless resolves each `-s` key from the pass backend
2. Spawns the subprocess with the credential value set as an environment variable
3. The environment variable name is derived from the last path segment of the key, converted to `UPPER_SNAKE_CASE` (e.g. `iria/api/xai` → `XAI`, `github_token` → `GITHUB_TOKEN`)
4. Captures stdout/stderr
5. Scans output for credential patterns and **redacts** matches with `[REDACTED]`
6. Returns sanitized output to the caller

| Flag | Description |
|---|---|
| `-s, --secret <key>` | Credential key to inject (repeatable) |
| `--sanitize` | Enable output scanning/redaction (default: on) |
| `--sanitize-policy <file>` | Custom redaction patterns file |
| `--json` | Output as JSON `{"exit_code": N, "stdout": "...", "stderr": "..."}` |
| `--timeout <duration>` | Subprocess timeout (default: 5m) |

### `trustless proxy` — HTTP Forward Proxy with Credential Injection

Start a local HTTP forward proxy that substitutes `__KEY_NAME__` placeholders in requests with real credentials.

```bash
trustless proxy start --port 8080
```

Configure your agent to use the proxy:

```bash
export HTTPS_PROXY=http://127.0.0.1:8080
```

**Request flow:**
1. Agent makes a request: `curl -H "Authorization: Bearer __GITHUB_TOKEN__" https://api.github.com/repos/owner/repo`
2. Proxy intercepts the request, substitutes `__GITHUB_TOKEN__` with the resolved value
3. Forwards to the target API, returns the response to the agent

**Placeholder format:** `__<KEY_NAME>__` — double underscores surrounding an uppercase key name. Resolution tries the lowercase key as a pass entry first, then falls back to `iria/api/<lowercase_key>`.

| Flag | Description |
|---|---|
| `--port <n>` | Listen port (default: 8080) |
| `--unix-socket <path>` | Listen on Unix socket (more secure, file permission control) |

HTTPS CONNECT tunneling is supported, but placeholder substitution only applies to HTTP requests (CONNECT tunnels are passed through without modification).

### `trustless config` — Tool Configuration

| Subcommand | Description |
|---|---|
| `init` | Create default config at `~/.config/trustless/config.toml` |
| `show` | Print current configuration |
| `set <key> <value>` | Update a configuration value |

**Config keys:**

| Key | Description | Default |
|---|---|---|
| `backend` | Credential backend | `pass` |
| `output` | Default output mode | `json` |
| `run_defaults.sanitize` | Enable sanitization by default | `true` |
| `run_defaults.timeout` | Default subprocess timeout | `5m` |
| `proxy.port` | Default proxy port | `8080` |

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
```

### `trustless completion` — Shell Completion

Generate shell completion scripts for bash, zsh, or fish:

```bash
trustless completion bash > /etc/bash_completion.d/trustless
trustless completion zsh > /usr/local/share/zsh/site-functions/_trustless
trustless completion fish > ~/.config/fish/completions/trustless.fish
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
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐  │
│  │ secret   │  │ run      │  │ proxy                │  │
│  │ (list/   │  │ (subproc │  │ (HTTP forward proxy  │  │
│  │  get/set)│  │  inject) │  │  with placeholder    │  │
│  └────┬─────┘  └────┬─────┘  │  substitution)       │  │
│       │             │        └──────────┬───────────┘  │
│       │             │                   │              │
│  ┌────┴─────────────┴───────────────────┴──────────┐   │
│  │              Backend Interface                   │   │
│  │  (resolve credential by key name)                │   │
│  └────────────────────┬────────────────────────────┘   │
└───────────────────────┼────────────────────────────────┘
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

The credential resolver is abstracted behind a simple interface, making backends swappable:

```go
type Backend interface {
    Resolve(ctx context.Context, key string) (string, error)
    List(ctx context.Context) ([]Entry, error)
}
```

The only implemented backend is `pass` — it wraps `pass show <key>`, reading the first line as the secret value. The interface is designed to accommodate future backends (e.g., HashiCorp Vault, 1Password CLI, environment variables).

## Security Model

### What trustless guarantees

1. **Credential values never enter the LLM context window**
   - `run`: credentials are set on the subprocess environment, output is scanned and redacted before being returned
   - `proxy`: credentials are substituted inside the proxy process; the agent sees only the API response
   - Direct `get` outputs the value but requires explicit invocation (not available to the agent in normal workflows)

2. **Subprocess output sanitization**
   - Default patterns match common credential formats: GitHub tokens (`ghp_*`, `gho_*`), OpenAI keys (`sk-*`), xAI keys (`xai-*`), AWS keys (`AKIA*`), Bearer tokens, and generic `key=value` patterns
   - **Injected values are themselves pattern-scanned**: if the subprocess echoes the credential, that value is redacted
   - Custom patterns can be added via the config file or a policy file (`--sanitize-policy`)

3. **Minimal attack surface**
   - Proxy listens on `127.0.0.1` by default (not exposed to the network)
   - Unix socket mode available for file permission control
   - Single binary with zero runtime dependencies beyond `pass` + `gpg`

4. **No credential persistence in the broker process**
   - Credentials are resolved on-demand and released after the subprocess exits
   - HTTP proxy holds credentials in memory only during active request processing

### What trustless does NOT solve (v1 scope)

- **Dynamic/rotating credentials** — the pass store is static; rotation is handled externally
- **Full audit trail** — basic logging only; SIEM export is future work
- **Hardware-backed key storage** — relies on GPG keyring security

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
├── internal/
│   ├── backend/
│   │   ├── backend.go               # Backend interface + types
│   │   └── pass.go                  # Pass CLI backend implementation
│   ├── config/
│   │   └── config.go                # TOML config loading/saving
│   ├── proxy/
│   │   └── command.go               # HTTP forward proxy with credential substitution
│   ├── run/
│   │   └── command.go               # Subprocess credential injection
│   ├── scanner/
│   │   ├── scanner.go               # Pattern-based credential redaction
│   │   └── scanner_test.go          # Scanner tests
│   └── secret/
│       └── command.go               # Credential store operations
└── docs/
    └── design.md                    # Architecture & design document
```

### Dependencies

trustless has a single external dependency — the rest is all Go standard library:

- `github.com/pelletier/go-toml/v2` — TOML config file parsing

### Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | General error |
| 2 | Credential not found / invalid args |
| 3 | Subprocess error |
| 4 | Config error |

## License

MIT
