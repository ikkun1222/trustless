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

## OAuth

OAuth 資格情報（Google / Lark など）を backend に保存し、`backend.Backend` のデコレータとして access token を解決する。

### エントリ型（`internal/oauth/entry.go`）

OAuth エントリは pass の 1 行制約を満たすため **compact 単一行 JSON** で保存する。`type` フィールドが固定値 `oauth` で、通常の静的エントリ（プレーンテキスト値）と区別する。

```json
{"type":"oauth","provider":"google","access":"...","refresh":"...","expires_at":"...","refresh_expires_at":"...","scopes":["..."]}
```

- `IsOAuthEntry` が JSON かつ `type=="oauth"` のときだけ OAuth エントリと判定する（型検出は backend デコレータが行う）
- `MarshalJSON` / `UnmarshalJSON` で `type` の付与と検証を一元化する

### デコレータ（`internal/oauth/backend.go`）

`NewBackend(inner, providers)` は `backend.Backend` をラップする `*OAuthBackend` を返す。

- **素通し**：`Resolve` は OAuth エントリでなければ内側の値をそのまま返す（静的エントリ混在）
- **OAuth 解決**：OAuth エントリなら access token を返す。`Refreshable` が false のプロバイダはキャッシュも HTTP も使わず保存済み access を返す
- **キャッシュ**：未失効の access token はインメモリキャッシュ（`map[key]cacheEntry`）から返し、HTTP refresh を避ける。有効期限は `expires_at` の **60 秒手前**（`cacheSkew`）で切る。`ExpiresAt` がゼロ（応答に `expires_in` が無い）のエントリはキャッシュを使わない
- **自動 refresh**：失効済みなら `Refresh`（refresh grant）で更新してから返す。`invalid_grant` は自動リトライせず `ErrInvalidGrant`（`ErrReauthRequired` でラップ）を返す
- **CAS ガード**：refresh 成功時のエントリ書き戻しは、読み直した現在値の `refresh` token が refresh 実行前の値と一致する場合のみ行う。他プロセスが先に書き換えていた場合は上書きしない（二重 refresh 競合の解決）。書き戻しは最良努力で、失敗しても呼び出し元の返却値・キャッシュには影響しない
- **List / Set / Values**：`Set` は書き換え後に該当キーのキャッシュを破棄し、`Values` は各キーを OAuth 処理込みで解決した fresh な値を返す（dedup + 昇順ソート）

### refresh_token のローテーションと失効（Lark）

Lark は refresh token を **7 日で失効**させる（`refresh_token_expires_in` = 604800）。このため:

- `login` 時に `refresh_expires_at` を保存し、`status` コマンドが残り有効期間を報告できるようにする
- refresh grant の応答に新しい `refresh_token` が含まれる場合は **ローテーション**し、CAS ガード付きで書き戻す。これにより失効 7 日以内に一度でも refresh されれば連続利用できる
- `invalid_grant`（refresh token 失効）は自動リトライせず、`trustless oauth login` での再認証が必要

### device code フロー（RFC 8628）

`DeviceStart`（認可開始）→ ユーザーに認可 URL を提示 → `DevicePoll`（`authorization_pending` は待機継続、`slow_down` は interval +5s 上限 60s）→ トークン取得、を `trustless oauth login` が実行する。

- Google は `device_auth_style = "body"`（form ボディに `client_secret`）、Lark は `"basic"`（`Authorization: Basic` ヘッダ）で資格情報を送る
- token リクエストは Google が `form`（`application/x-www-form-urlencoded`）、Lark が `json`（`application/json` ボディ + `code` フィールドで成功/失敗判定）

### 既知の制約（実測 2026-08-13）

- **Bitwarden バックエンドは暗号化値の上限 5000 文字**。Lark の access/refresh token は JWT で各 5.7KB 級のため素のエントリは格納不可（`The field Value exceeds the maximum encrypted value length of 5000 characters`）。
  → **エントリ最小化 + zlib 圧縮で解消**: access/scopes/expires_at は永続化しない（ランタイム専用・resolve 時に refresh で取得）・永続フィールドが閾値 3500B 超なら zlib+base64 の `{"type":"oauth","z":true,"data":...}` にラップ。実測: Lark エントリ 3595B で bitwarden に格納成功・Google は非圧縮のまま収まる
- エントリの時刻フィールド（`expires_at` / `refresh_expires_at`）は空文字をゼロ値として許容する（旧形式・手動編集エントリ対策）
- **Lark の refresh token は single-use**（`invalid_grant: ... can only be used once`）: refresh ごとにローテーションされ旧トークンは即無効化。CAS ガード（書き戻し時の refresh 値比較）が二重 refresh 競合で古い値を残さないことを保証する。消費済みトークンは `oauth status` が `reauth_required` を返し、`oauth login` で再認可が必要
- **OAuth 統合は run / proxy / serve がデコレータ経由**（main.go の dispatch・serve の backend 構築で `oauth.NewBackend` を適用）。`secret get` は生エントリ（圧縮ラップ含む）を返すため、OAuth エントリの確認は `oauth status` / `oauth refresh` を使う

## 構造化監査ログ（Phase 0・2026-08-14）

全イベントを構造化 JSONL で記録する `internal/audit` パッケージ。**依存ゼロ（stdlib のみ）・ホットパス非破壊（非同期・満杯 drop・エラーは握りつぶし）・秘密混入禁止**が設計原則。

### スキーマ

```json
{"ts":"2026-08-14T00:00:00.000Z","event":"proxy.inject","key":"iria/api/xai","host":"api.x.ai","verdict":"inject","detail":"header=Authorization"}
```

- `ts`: UTC RFC3339Nano・`key`/`host`/`verdict`/`detail` は空なら omitempty
- **記録されるのはキー名・ホスト・verdict・小さな detail のみ。トークン値・シークレット値・生の argv は絶対に含めない**（run.spawn は `cmd=<名> args=<数>` のみ）

### イベント一覧（実機検証済み 2026-08-14）

| event | 発火点 | 備考 |
|---|---|---|
| `proxy.inject` | 注入ルール適用時（header/query） | serve/proxy 単体 |
| `proxy.deny` | allowlist 違反 403 | 実機確認（allowlist config で gmail 拒否） |
| `run.spawn` | 子プロセス起動 | 値は含めない |
| `dlp.redact` | ボディのシークレット/パターン置換時 | detail=`redacted=true` / `patterns=hit&mode=log`（log モードのパターン検出時） |
| `oauth.refresh` | refresh 成功 | detail=`provider=<name>` |
| `oauth.fail` | refresh 失敗（invalid_grant 以外） | |
| `oauth.reauth_required` | invalid_grant → 再認可必要 | `oauth status` の reauth_required と一致 |

※ `dlp.deny` は計画段階で想定したが**不採用**（dlp に allowlist/deny 点が存在しないため。YAGNI）

### Sink とデフォルト

- `[audit] sink = "journald" | "file" | "off"` / `audit.file = <path>` / `audit.buffer = 1024`
- **デフォルト**: serve = `journald`（stdout JSONL → systemd journald）・run/proxy/oauth 単体 = `file`（`~/.local/state/trustless/audit.jsonl`・0600）
- file sink: 非同期 worker・満杯 drop（`Dropped()` で確認可）・**SIGHUP/定期リロードで Reopen**（logrotate 対応・reloadAll に組み込み）
- 未設定（sink 空）は呼び出し側デフォルト適用。`off` は明示無効

### 運用

```bash
# serve の監査ログ（journald）
journalctl --user -u trustless | grep '"event"'
# 単体コマンドの監査ログ（file）
tail -f ~/.local/state/trustless/audit.jsonl
# logrotate: リネーム後 SIGHUP で reopen
mv audit.jsonl audit.jsonl.1 && kill -HUP $(pgrep -f 'trustless serve')
```

## DLP パターン第2層（gitleaks 互換・2026-08-14）

`internal/dlp/redact` は 2 層でリクエスト本文をマスクする（`redact.ScanAll`）:

1. **第1層・既知値**: backend（pass/bitwarden）からロードした秘密リストの substring スキャン（従来の `ScanAndRedact`・FP ゼロ）
2. **第2層・パターン**: gitleaks 互換ルール（`internal/dlp/redact/rules.toml`・40 ルール・`//go:embed` 同梱）。ルールごとに **keyword プリフィルタ → RE2 regex → Shannon entropy 閾値**（デフォルト 3.5・ルールの `entropy` で上書き）の 3 段で FP を抑制。`secret_group` 指定時は該当キャプチャのみ置換、entropy は指定グループの値で計測（S2 実装時の改善・gitleaks セマンティクス準拠）

### ライセンス

ルールは [gitleaks](https://github.com/gitleaks/gitleaks)（MIT・Copyright (c) 2019 Zachary Rice）由来。`LICENSE.gitleaks`（MIT 全文）・`NOTICE`・rules.toml ヘッダで帰属。**llm-prism は LICENSE 無しのため非採用**（2026-08-14 調査）。抽出は `scripts/extract_dlp_rules.py`（tomllib・再現可能）。

### config（dlp config JSON・追加フィールド）

| フィールド | 型 | 意味 |
|---|---|---|
| `rules_file` | string | 外部 gitleaks 互換 rules TOML のパス。空 = 同梱。`~` 展開対応。存在しない/不正は**起動失敗**（fail-closed） |
| `pattern_mode` | string | `"mask"`（デフォルト・置換）/ `"log"`（検出のみ・本文不変・audit `patterns=hit&mode=log`）。第1層は常にマスク |
| `pattern_disabled` | string[] | 無効化するルール id 一覧（例: `["generic-api-key"]`）。未知 id は**起動/リロード失敗**（fail-closed・タイポ検出）。空 = 全ルール有効 |

- 配線は `dlp.BuildPatternSet(cfg)` → `BuildHandler(cfg, secrets, patterns, patternMode, logger, sink)` の 1 点。`trustless dlp start` と `trustless serve` の両方が同じ経路（serve.go 実測 2026-08-14）
- **ホットリロード（serve・2026-08-14）**: `trustless serve` は SIGHUP / 定期リロードのたびに config を再読込し、`PatternSet.Replace` + `PatternMode.Set` で原子的に反映（`reloaded patterns (N rules, mode=...)` ログ）。失敗時は WARN + 旧状態維持（fail-safe）。**スタンドアロン `trustless dlp start` は起動時読込のまま**（検証用）
- `scrub-db` / `scrub-text` もパターン第2層対応（2026-08-14）: config の `rules_file` / `pattern_disabled` / `pattern_mode` を尊重。`--apply` なし = dry-run（パターン検出のレポート）。`pattern_mode: "log"` なら `--apply` でもパターンは置換しない（既知値は常に置換）。DB は行単位 ScanAll 経路（patterns == nil の時のみ従来の SQL 経路）

### 実測知見（2026-08-14・スモーク + 本番 log 投入）

- mask モード: OpenAI 新形式 / GitHub PAT / JWT を実リクエストで `<redacted>` 化確認
- log モード: 本文不変 + `scan: pattern detected (mode=log)` + audit イベント発行を確認
- **JWT 検出には終端デリミタが必要**（gitleaks の regex 仕様: 空白/引用符/改行/`$`。`.` や `,` 直後は非検出）— 実運用の JSON 本文では通常クォート/空白で終端されるため実害なし
- generic-api-key ルールは高エントロピーな env 変数名（`process.env.API_KEY` 等）を検出し得る → コード多めの本文で FP が出る可能性。**log モード先行投入の理由**（FP 観察後に mask 切替）

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