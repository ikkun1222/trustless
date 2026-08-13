# trustless — Credential Broker CLI for AI Agents

## Overview

**trustless** is a credential broker CLI that decouples AI agents from the secrets they use.  
Agents reference credentials by name; the broker resolves them at the transport/process layer — the agent **never holds plaintext values**.

The name reflects the architecture: you don't need to *trust* the agent with secrets because the agent structurally cannot access them.

### Core Principle

```
Traditional:  agent → sees key → uses key → key is in context → prompt injection leaks it
              ↑  agent is a trusted principal

trustless:    agent → says "use GITHUB_TOKEN" → broker resolves → agent gets API response
              ↑  agent is an untrusted caller, broker is the authority
```

## Technology Stack

**Language:** Go (1.26+)
- Single binary cross-compilation (`GOOS`/`GOARCH`)
- All required capabilities in stdlib: `net/http`, `os/exec`, `crypto/*`, `encoding/json`, `net` (Unix sockets)
- CLI argument parsing uses `std flag` — subcommand dispatch is hand-written (manageable at this scale)
- Only external dependency: TOML parsing (for config file)

**External runtime dependency:** `pass` CLI + `gpg` (for the `pass` backend)

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
│  │  get/set)│  │  inject) │  │  host-based inject)  │  │
│  └────┬─────┘  └────┬─────┘  └──────────┬───────────┘  │
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

The credential resolver is abstracted behind an interface, so backends are swappable:

```go
type Backend interface {
    Resolve(ctx context.Context, key string) (string, error)
    List(ctx context.Context) ([]Entry, error)
}
```

Initial backend: `pass` — wraps `pass show <key>`, reads first line as secret value.

## Command Reference

### `trustless secret` — Credential Store Operations

| Subcommand | Description | Example |
|---|---|---|
| `list` | List all available credential keys | `trustless secret list` |
| `get <key>` | Retrieve a credential value (direct, for scripts) | `trustless get github_token` |
| `set <key> [value]` | Add/update credential (wraps `pass insert`) | `trustless set openai_key sk-...` |

`get` outputs JSON by default:
```json
{"key": "github_token", "value": "ghp_...", "backend": "pass"}
```

Use `--quiet` or pipe to suppress value output (for the agent case).

### `trustless run` — Subprocess Credential Injection (Core Command)

Run a command with one or more credentials injected as environment variables.  
The injected values are **never returned to the caller** — only the subprocess stdout/stderr.

```bash
trustless run -s DATABASE_URL -- psql -c "SELECT count(*) FROM users"
trustless run -s GITHUB_TOKEN -s OPENAI_KEY -- gh pr list
```

**Data flow:**
1. trustless resolves `DATABASE_URL` from pass backend
2. Spawns `psql` subprocess with `DATABASE_URL` in its environment
3. Captures stdout/stderr
4. **Scans output** for any pattern matching known credential formats or the injected value itself
5. Redacts any matches with `[REDACTED]`
6. Returns sanitized output to caller

**Options:**

| Flag | Description |
|---|---|
| `-s, --secret <key>` | Credential key to inject (repeatable) |
| `--sanitize` | Enable output scanning/redaction (default: on) |
| `--sanitize-policy <file>` | Custom redaction patterns file |
| `--json` | Output as JSON `{"exit_code": N, "stdout": "...", "stderr": "..."}` |
| `--timeout <duration>` | Subprocess timeout (default: 5m) |

### `trustless proxy` — HTTP Forward Proxy with Credential Injection

Start a local HTTP forward proxy that injects credentials into requests based on the destination host.

```bash
trustless proxy start --port 8080
```

**Agent config:**
```bash
export HTTPS_PROXY=http://127.0.0.1:8080
```

**Request flow:**
1. Agent makes a plain request: `curl https://api.x.ai/v1/models`
2. Proxy matches the host against `[proxy.rules]` and injects the credential (header or query parameter)
3. Forwards to the API, returns response to agent

**Injection rules (config `[proxy.rules]`):** host → `{header|query, key, prefix?, suffix?}`. Key resolution: lowercase → pass, fallback `iria/api/<key>`. Existing header/parameter values are never overwritten; unresolved keys fail open.

```toml
[proxy.rules]
"api.x.ai" = { header = "Authorization", key = "xai", prefix = "Bearer " }
"statdb.nstac.go.jp" = { query = "appid", key = "estat" }
```

**Options:**

| Flag | Description |
|---|---|
| `--port <n>` | Listen port (default: 8080) |
| `--unix-socket <path>` | Listen on Unix socket instead (more secure) |
| `--allowlist <domain>` | Only proxy requests to these domains (repeatable) |

### `trustless config` — Tool Configuration

| Subcommand | Description |
|---|---|
| `init` | Create default config at `~/.config/trustless/config.toml` |
| `show` | Print current config |
| `set <key> <value>` | Update a config value |

**Config file location:** `~/.config/trustless/config.toml`

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
| [4/4] Agent Integration | Detect and suggest wrapping credentials for AI coding agents | Checks agent config files |

**Options:**

| Flag | Description |
|------|-------------|
| `--non-interactive` | Run in non-interactive mode (safe defaults, no prompts, no file removal) |
| `--import-dir <dir>` | Directory to scan for .env files (repeatable, default: `.`) |

**Agent detection currently supports:**
- **OpenCode** — `~/.config/opencode/providers.yaml` / `opencode.json`
- **Claude Code** — `~/.claude/claude_dotfiles/claude.env` / `~/.claude/.claude.env`
- **Codex** — `~/.codex/config.toml`
- **Hermes** — `~/.hermes/config.yaml`

### `trustless doctor` — System Health Check

Diagnostic tool that validates the entire trustless setup:

```bash
trustless doctor           # Human-readable output
trustless doctor --json    # Structured JSON for cron/SIEM
trustless doctor --fix     # Auto-resolve detected issues (stub)
```

**Health checks performed:**

| Check | What it validates |
|-------|-------------------|
| GPG Key | Key exists, not expired, not expiring within 30 days |
| pass Store | Store initialized, accessible, credential count |
| gpg-agent | Agent process responding |
| .env Security | Scans for plaintext .env files with credential patterns |
| Agent Integration | OpenCode/Claude Code/Codex/Hermes trustless configuration status |
| MITM CA | trustless CA certificate installation for `--mitm` proxy support |


```toml
# Backend selection
backend = "pass"

# Default output mode
output = "json"

# Run defaults
run_defaults = { sanitize = true, timeout = "5m" }

# Proxy defaults
[proxy]
port = 8080
# allowlist = ["api.github.com", "api.openai.com"]

# Sanitization patterns (extended regex)
[sanitize]
patterns = [
  "(sk_live|sk_test)_[A-Za-z0-9]+",
  "(ghp|gho|ghu|ghs)_[A-Za-z0-9_]+",
  "Bearer [A-Za-z0-9._-]+",
]
```

## Security Model

### What trustless guarantees

1. **Credential values never enter the LLM context window**
   - `run`: credential set on subprocess env, subprocess output scanned before return
   - `proxy`: credential substituted inside the proxy process, agent sees only the API response
   - Direct `get` outputs to TTY with a warning, and JSON mode can be piped with `--quiet`

2. **Subprocess output sanitization**
   - Default patterns match common credential formats (GitHub tokens, OpenAI keys, AWS keys, Bearer tokens, etc.)
   - **Injected values are themselves pattern-scanned**: if the subprocess echoes `DATABASE_URL=postgres://...`, that line is redacted
   - Custom patterns via config file

2. **Command argument scanning** (`--scan-args`)
   - Before spawning a subprocess, all command arguments are scanned for credential patterns and injected values
   - If detected, execution is blocked with exit code 3 (fail closed)
   - Prevents the agent from accidentally exposing credential values in CLI arguments

3. **Policy engine** — command-level access control
   - `policy.default.denied_commands`: block dangerous commands globally (e.g., `sh`, `bash`)
   - `policy.<key>.denied_commands`: block specific commands per credential
   - Fail-closed: policy violation blocks execution with exit code 3

4. **Minimal attack surface**
   - Proxy listens on `127.0.0.1` by default (not exposed)
   - Unix socket mode available (file permission control)
   - Single binary, no runtime dependencies beyond `pass`+`gpg`

4. **No credential persistence in the broker process**
   - Credentials are resolved on-demand, released after subprocess exits
   - HTTP proxy holds credentials in memory only during active requests

### What trustless does NOT solve (out of scope for v1)

- **Dynamic/rotating credentials** — pass store is static; rotation is handled externally
- **Full audit trail** — basic logging only; SIEM export is future work
- **Hardware-backed key storage** — relies on GPG keyring security

## OpenCode Implementation Steps

Each phase is decomposed into atomic steps executed via `opencode run`.

### Step A — `trustless run` skeleton + subprocess execution

**Files to create:** `internal/run/command.go`
**Files to modify:** `main.go`

Implements:
- `trustless run -s KEY1 -s KEY2 -- cmd [args...]` subcommand dispatch in main.go
- Flag parsing with `flag`: `-s` (repeatable string slice), `--json`, `--timeout` (duration string)
- Subprocess execution: resolve credentials from backend → set on `Cmd.Env` → spawn → capture stdout/stderr
- `-s` injects credential value as env var named by the last path segment (`iria/api/xai` → `XAI`)
- `--json` outputs `{"exit_code": N, "stdout": "...", "stderr": "..."}`
- `--timeout` sets context deadline
- **No sanitization yet** — raw output returned
- Default output: raw stdout/stderr to terminal, preserving subprocess behavior

**Acceptance:** `trustless run -s iria/api/xai -- curl -s -H "Authorization: Bearer *** XAI)" https://api.x.ai/...` (エコーはされるがcredentialがsubprocessで使える)

### Step B — Output scanner (`internal/scanner/`)

**Files to create:** `internal/scanner/scanner.go`

Implements:
- `scanner.Scanner` struct with `AddPattern(re)` and `Scan(input []byte) []byte`
- Default patterns: GitHub tokens (`ghp_`), OpenAI keys (`sk-`), Bearer tokens, AWS keys, generic `key=value` patterns
- `ScanKnown(input []byte) []byte` — applies all default patterns
- Also detects and redacts exact injected values (passed at scan time)
- Redaction replaces matched content with `[REDACTED]`
- Thread-safe (patterns are read-only after init)

**Acceptance:** `scanner.ScanKnown([]byte("***"))` returns `[REDACTED]`

### Step C — Integrate scanner into `trustless run`

**Files to modify:** `internal/run/command.go`

Implements:
- Scanner initialization with default patterns + config patterns
- After subprocess output capture, run scanner on stdout + stderr
- `--sanitize` flag (default: true, from config)
- Also redact the exact injected credential values if they appear in output
- `--sanitize-policy <file>` for custom pattern file

**Acceptance:** `trustless run -s iria/api/xai -- sh -c 'echo $XAI'` outputs `[REDACTED]` instead of the actual key

### Step D — `trustless proxy`

**Files to create:** `internal/proxy/proxy.go`
**Files to modify:** `main.go`

Implements:
- `trustless proxy start` subcommand
- Local HTTP forward proxy using `httputil.ReverseProxy`
- Host-based credential injection: `[proxy.rules]` maps host → {header|query, key}
- Egress allowlisting (from config)
- Unix socket support (`--unix-socket <path>`)
- `--port` flag (default: 8080)
- Graceful shutdown on SIGINT/SIGTERM

**Acceptance:** `HTTPS_PROXY=http://127.0.0.1:8080` curl with `__GITHUB_TOKEN__` header gets proxied

### Step E — Completion

Implements:
- Shell completion script generation
- `trustless config set <key> <value>` subcommand
- `--help` enrichment on all commands
- Error message polish (consistent exit codes)
- README.md

### Step F1 — `-s KEY:ENVNAME` override + `version`

**Files to modify:** `internal/run/command.go`, `main.go`

Implements:
- `-s iria/api/xai:MY_XAI_KEY` syntax for explicit env var naming
- Backward-compatible: `-s iria/api/xai` still auto-derives `XAI`
- `trustless version` subcommand
- Passthrough mode now sets `cmd.Stdin = os.Stdin` (fixes MCP server compatibility where stdio transport requires stdin forwarding)

**Acceptance:** `trustless run -s iria/api/xai:MY_XAI_KEY -- sh -c 'echo $MY_XAI_KEY'` outputs `[REDACTED]`

### Implementation Principles for Each Step

1. Every step starts with `go build` to verify compilation
2. Test manually with the acceptance criteria shown
3. Commit after each step with a descriptive message
4. If opencode produces broken code, fix manually and retry

## Implementation Phases

### Phase 1: Project Skeleton + `pass` Backend + `secret` Commands

- `go mod init github.com/ikkun1222/trustless` (or appropriate module path)
- Directory structure: `cmd/trustless/`, `internal/backend/`, `internal/cli/`, `internal/config/`
- Backend interface + `pass` backend implementation
- `trustless secret list`, `trustless secret get <key>`, `trustless secret set <key>`
- Config file parsing (TOML)
- Test with real `pass` store (or mock backend)

**Deliverable:** `trustless secret list` works against the user's pass store.

### Phase 2: `trustless run` — Subprocess Injection

- `internal/run/` package
- Credential resolution → `os/exec` subprocess with `Cmd.Env`
- Stdout/stderr capture
- `--sanitize` output scanning with default patterns
- `--json` output mode
- Subprocess timeout via context

**Deliverable:** `trustless run -s OPENAI_KEY -- curl -s https://api.openai.com/v1/models` works without the key appearing in output.

### Phase 3: Output Sanitization Engine

- `internal/scanner/` package
- Pattern-based redaction engine
- Injected-value-aware scanner (also redacts the exact value that was injected)
- Custom pattern loading from config
- Confidence: centralize pattern definitions

**Deliverable:** Robust redaction that catches `echo $API_KEY`, `env | grep TOKEN`, etc.

### Phase 4: `trustless proxy` — HTTP Forward Proxy

- `internal/proxy/` package
- Forward proxy with host-based credential injection (`[proxy.rules]`: header/query)
- Egress allowlisting
- Unix socket support
- Graceful shutdown

**Deliverable:** Agent can `export HTTPS_PROXY=http://127.0.0.1:8080` and send plain requests; credentials are injected by host-based rules transparently.

### Phase 5: Completion + Integration

- Shell completion (cobra built-in)
- `trustless config init` with interactive setup
- `--help` enrichment with examples
- Hermes tool wrapper (`~/.hermes/tools/trustless.yaml`)
- README with architecture diagram, quickstart, and security rationale
- Homebrew tap setup (optional)

**Deliverable:** Production-ready tool usable as daily driver for AI agent workflows.

## Development Principles

1. **Dependencies**: Zero external dependencies for the core credential path. CLI framework (`cobra`) and TOML lib are the only allowed runtime deps.
2. **Testing**: All redaction patterns tested against known credential formats. Backend operations tested with mock GPG/pass.
3. **Error handling**: Structured errors with exit codes (0=success, 1=general error, 2=credential not found, 3=subprocess error, 4=config error).
4. **Security**: Failing closed — if credential resolution fails, the subprocess is not started. If scanning fails, output is blocked.
5. **Logging**: Structured JSON logs to stderr only (stdout is reserved for tool output).