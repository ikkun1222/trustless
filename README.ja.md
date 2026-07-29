# trustless — AIエージェント向けCredential Broker CLI

[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## 概要

**trustless** は、AIエージェントとシークレット（APIキー・認証情報）を構造的に分離するCredential Broker CLIです。
エージェントは「この認証情報を使って」と名前で指示するだけで、実際の値は broker がトランスポート/プロセス層で解決します。
エージェントは**平文の認証情報を決して保持しません**。

名前の由来は「エージェントを信頼する必要がない」＝ agent を trusted principal と見なさず、broker が権限の源泉になる設計思想から来ています。

```
従来:      agent → キーを見る → キーを使う → キーがコンテキストに残る → 漏洩
           ↑  agent を信頼する前提

trustless: agent → 「GITHUB_TOKENを使って」→ broker が解決 → agent はAPI応答のみ
           ↑  agent は信頼しない caller、broker が権限の源泉
```

## インストール

### ワンライナー（Linux / macOS）

```bash
curl -fsSL https://trustless.sh/install.sh | sh
```

最小インストール（CI/Docker用）:

```bash
curl -fsSL https://trustless.sh/install.sh | sh -s -- --minimal
```

アップグレード:

```bash
curl -fsSL https://trustless.sh/install.sh | sh -s -- --update
```

### Go 1.26+ からビルド

```bash
git clone https://github.com/ikkun1222/trustless
cd trustless && go build -o trustless .
```

または直接インストール:

```bash
go install github.com/ikkun1222/trustless@latest
```

### 前提条件

- **Go 1.26+**（ビルド用）
- **`pass`**（Unixパスワードマネージャー）+ **`gpg`** — デフォルトのcredentialバックエンド
- 環境変数のみを使う場合は `backend = "env"` で pass 不要

## クイックスタート

```bash
# 初回セットアップ（GPG鍵、passストア、.env移行、agent設定）
trustless setup

# システムヘルスチェック
trustless doctor

# pass store の認証情報一覧
trustless secret list

# 認証情報を注入してコマンド実行（出力は自動サニタイズ）
trustless run -s iria/api/xai -- curl -s https://api.x.ai/v1/models

# 認証情報プロキシ起動
trustless proxy start --port 8080

# MCPサーバー起動（AIエージェント統合用）
trustless mcp
```

## コマンドリファレンス

### `trustless secret` — 認証情報ストア操作

| サブコマンド | 説明 | 例 |
|-------------|------|-----|
| `list` | 利用可能な認証情報キー一覧 | `trustless secret list` |
| `get <key>` | 認証情報の値を取得（JSON出力） | `trustless secret get github_token` |
| `set <key> [value]` | 認証情報を保存（`pass insert` のラッパー） | `trustless secret set openai_key sk-...` |

`get` の出力（デフォルトJSON）:
```json
{"key": "github_token", "value": "ghp_..."}
```

### `trustless run` — サブプロセス認証情報注入（中核機能）

1つ以上の認証情報を環境変数としてサブプロセスに注入して実行します。
注入された値は**呼び出し元に一切返らず**、サブプロセスの stdout/stderr だけが返ります。出力に含まれる認証情報パターンは自動的に `[REDACTED]` に置換されます。

```bash
trustless run -s iria/api/xai -- curl -s https://api.x.ai/v1/models
trustless run -s GITHUB_TOKEN -s OPENAI_KEY -- gh pr list
```

**セキュリティ機能:**

- **`--scan-args`**（デフォルト: `true`）: サブプロセス起動前に全コマンド引数をスキャンし、認証情報パターンや注入値を検出したら exit code 3 でブロック（fail closed）。`curl -H "Authorization: Bearer sk-..."` のような引数経由の露出を防止。
- **`--sanitize`**（デフォルト: `true`）: サブプロセス出力の認証情報パターンをスキャン・Redact。
- **ポリシーエンジン**: コマンド単位のアクセス制御（設定セクション参照）。

| フラグ | 説明 |
|--------|------|
| `-s, --secret <key>` | 注入する認証情報キー（複数指定可、形式: `KEY` または `KEY:ENVNAME`） |
| `--sanitize` | 出力スキャン/Redact (デフォルト: on) |
| `--sanitize-policy <file>` | カスタムRedactパターンファイル |
| `--scan-args` | コマンド引数の認証情報スキャン (デフォルト: on) |
| `--json` | JSON形式で出力: `{"exit_code": N, "stdout": "...", "stderr": "..."}` |
| `--timeout <duration>` | サブプロセスタイムアウト (デフォルト: 5m) |

### `trustless proxy` — HTTPフォワードプロキシ（認証情報置換）

`__KEY_NAME__` 形式のプレースホルダーを実際の認証情報に置換するローカルHTTPフォワードプロキシを起動します。

```bash
trustless proxy start --port 8080
trustless proxy start --port 8080 --mitm  # HTTPSインターセプションモード
```

エージェントのプロキシ設定:

```bash
export HTTPS_PROXY=http://127.0.0.1:8080
```

**プレースホルダー形式:** `__KEY_NAME__`（大文字アンダースコア区切り）。
解決順: 小文字キーで pass 検索 → フォールバック: `iria/api/小文字キー`

**MITMモード（`--mitm`）:**

- HTTPS通信をインターセプトし、暗号化されたリクエスト内のプレースホルダーも置換
- 初回起動時にルートCA証明書を自動生成（`~/.config/trustless/trustless-ca.{crt,key}`）
- ホスト名ごとにエフェメラル証明書を生成（24時間有効、ECDSA P-256）
- システム全体で証明書を有効にするには:

  ```bash
  sudo cp ~/.config/trustless/trustless-ca.crt /usr/local/share/ca-certificates/
  sudo update-ca-certificates
  ```

| フラグ | 説明 |
|--------|------|
| `--port <n>` | 待受ポート (デフォルト: 8080) |
| `--unix-socket <path>` | Unixソケットで待受（ファイルパーミッション制御） |
| `--mitm` | MITMモード有効化（HTTPSインターセプション） |

### `trustless mcp` — MCPサーバーモード

AIエージェントが直接認証情報を解決するための stdio ベース MCP (Model Context Protocol) サーバー。

```bash
trustless mcp
```

[JSON-RPC 2.0](https://www.jsonrpc.org/specification) over stdin/stdout で動作し、以下のツールを提供:

| ツール | 説明 | 入力 |
|--------|------|------|
| `resolve_credential` | 認証情報を解決して値を返す | `{"key": "..."}` |
| `inject_run` | 認証情報注入してコマンド実行 | `{"secrets": [...], "command": [...], "sanitize": true}` |
| `list_credentials` | 認証情報キー一覧 | `{}` |

**プロトコル:** MCP 2024-11-05。Hermes、Claude Code、Codex、Cursor など MCP 対応のAIエージェントと互換性あり。

### `trustless setup` — 初回セットアップウィザード

初回セットアップを自動化する対話型ウィザード:

```bash
trustless setup
```

**4ステップの流れ:**

| ステップ | 内容 | 自動検出 |
|----------|------|----------|
| [1/4] GPG鍵 | 既存鍵を検出、なければRSA 3072を生成（パスフレーズなし、5年期限） | `gpg --list-secret-keys` をスキャン |
| [2/4] passストア | passストアを初期化、git initを実行 | `pass` コマンドの有無を確認 |
| [3/4] .envインポート | .envファイルをスキャン、passに一括インポート、元ファイルをバックアップ | `--import-dir` で指定されたディレクトリを検索 |
| [4/4] AIエージェント連携 | AIコーディングエージェントの設定を検出し、trustless連携を提案 | 各agentの設定ファイルを確認 |

**オプション:**

| フラグ | 説明 |
|--------|------|
| `--non-interactive` | 非対話モード（安全なデフォルト値を使用、ファイル削除なし） |
| `--import-dir <dir>` | .envファイルをスキャンするディレクトリ（複数指定可、デフォルト: `.`） |

**対応エージェント:** OpenCode、Claude Code、Codex、Hermes。

### `trustless doctor` — システムヘルスチェック

trustlessのセットアップ全体を検証する診断ツール:

```bash
trustless doctor           # 人間が読める形式で出力
trustless doctor --json    # JSON出力（cron/SIEM連携用）
trustless doctor --fix     # 検出された問題を自動修復（スタブ）
```

**チェック項目:** GPG鍵の有効性、passストアの状態、gpg-agentの応答、.envファイルのセキュリティ、エージェント連携状況、MITM CA証明書のインストール状態。

### `trustless config` — 設定管理

| サブコマンド | 説明 |
|-------------|------|
| `init` | `~/.config/trustless/config.toml` にデフォルト設定を作成 |
| `show` | 現在の設定を表示 |
| `set <key> <value>` | 設定値を更新 |

**設定キー:**

| キー | 説明 | デフォルト |
|------|------|-----------|
| `backend` | Credentialバックエンド（`pass` または `env`） | `pass` |
| `output` | デフォルト出力モード | `json` |
| `run_defaults.sanitize` | サニタイズ有効/無効 | `true` |
| `run_defaults.timeout` | サブプロセスタイムアウト | `5m` |
| `proxy.port` | プロキシ待受ポート | `8080` |
| `policy.default.denied_commands` | グローバル拒否コマンド一覧（例: `sh,bash`） | (空) |

**設定ファイル:** `~/.config/trustless/config.toml`（`TRUSTLESS_CONFIG` 環境変数で上書き可能）

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

### `trustless completion` — シェル補完

bash、zsh、fish の補完スクリプトを生成:

```bash
trustless completion bash > /etc/bash_completion.d/trustless
trustless completion zsh > /usr/local/share/zsh/site-functions/_trustless
trustless completion fish > ~/.config/fish/completions/trustless.fish
```

### `trustless version` — バージョン情報

```bash
trustless version
```

## アーキテクチャ

```
┌─────────────────────────────────────────────────────────┐
│                   AI Agent (Hermes / LLM)                │
│  "DATABASE_URL を使って psql 実行"                       │
└────────────────────┬────────────────────────────────────┘
                     │ CLI / HTTP / MCP
                     ▼
┌─────────────────────────────────────────────────────────┐
│                   trustless CLI                          │
│                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐ │
│  │ secret   │  │ run      │  │ proxy    │  │ mcp    │ │
│  │ (一覧/   │  │ (サブプ  │  │ (HTTP    │  │ (MCP   │ │
│  │  取得/   │  │  ロセス  │  │  プロキ  │  │  stdio │ │
│  │  保存)   │  │  注入)   │  │  シ+     │  │ サーバ│ │
│  └────┬─────┘  └────┬─────┘  │  MITM)   │  │ ー)   │ │
│       │             │        └─────┬─────┘  └────┬───┘ │
│       │             │              │              │     │
│  ┌────┴─────────────┴──────────────┴──────────────┴──┐  │
│  │              Backend Interface                     │  │
│  │  (pass / env — 切り替え可能)                       │  │
│  └──────────────────────┬────────────────────────────-┘  │
└─────────────────────────┼──────────────────────────────┘
                          │
            ┌─────────────┴─────────────┐
            │                           │
            ▼                           ▼
     ┌──────────────┐          ┌──────────────┐
     │  pass store   │          │  対象API     │
     │  (GPG + pass) │          │  / サービス  │
     └──────────────┘          └──────────────┘
```

### Backend 抽象化

認証情報の解決はシンプルなインターフェースで抽象化されています:

```go
type Backend interface {
    Resolve(ctx context.Context, key string) (string, error)
    List(ctx context.Context) ([]Entry, error)
}
```

実装済みバックエンド:
- **`pass`**（デフォルト）— `pass show <key>` をラップ
- **`env`** — CI/CD・コンテナ環境向け、環境変数から読み取り

`trustless config set backend <name>` で切り替え。

## セキュリティモデル

### trustless が保証すること

1. **認証情報の値がLLMコンテキストに入らない**
   - `run`: 環境変数としてサブプロセスにのみ注入、出力はスキャン・Redact
   - `proxy`: プロキシプロセス内部で置換、agent はAPI応答のみ見える
   - `secret get`: 値を出力するが明示的な呼び出しが必要（通常ワークフローでは使われない）

2. **コマンド引数スキャン（`--scan-args`）**
   - サブプロセス起動前に全コマンド引数をスキャン
   - 認証情報パターンや注入値を検出したら exit code 3 でブロック（fail closed）
   - エージェントが `curl -H "Authorization: Bearer sk-..."` のように引数に認証情報を埋め込むのを防止

3. **ポリシーエンジン** — コマンド単位のアクセス制御
   - `policy.default.denied_commands`: 危険なコマンドをグローバルに禁止（例: `sh`, `bash`）
   - `policy.<key>.denied_commands`: 認証情報ごとに特定コマンドを禁止
   - Fail-closed: ポリシー違反は exit code 3 でブロック

4. **サブプロセス出力サニタイズ**
   - デフォルトパターン: GitHub tokens, OpenAI keys, xAI keys, AWS keys, Bearer tokens 他
   - **注入値自体もパターンスキャン**: サブプロセスが認証情報をエコーしても Redact
   - カスタムパターンは設定ファイルまたは `--sanitize-policy` で追加

5. **最小攻撃表面**
   - プロキシはデフォルトで `127.0.0.1` のみ待受
   - Unixソケットモード対応（ファイルパーミッション制御）
   - MITMプロキシはホスト名ごとにエフェメラル証明書（24時間有効）
   - 単一バイナリ、`pass`+`gpg` 以外のランタイム依存無し

6. **ブローカープロセス内に認証情報を永続化しない**
   - 認証情報はオンデマンド解決、サブプロセス終了後に解放
   - HTTPプロキシはアクティブなリクエスト処理中のみメモリに保持

### v1 で対応していないこと

- **動的/ローテーション認証情報** — pass store は静的。ローテーションは外部で
- **完全な監査証跡** — 基本ログのみ。SIEM連携は将来対応
- **ハードウェアバックアップ鍵** — GPGキーリングのセキュリティに依存
- **HTTPS MITM CA管理** — MITMプロキシはCA証明書を生成するが、OSのトラストストアへのインストールはユーザー作業

## 開発

### 前提

- Go 1.26+
- `pass` CLI + `gpg`（実バックエンドでのテスト用）

### ビルド

```bash
git clone https://github.com/ikkun1222/trustless
cd trustless
go build -o trustless .
```

### テスト

```bash
go test ./...
```

### プロジェクト構造

```
├── main.go                          # CLIエントリポイント & サブコマンドディスパッチ
├── internal/
│   ├── backend/
│   │   ├── backend.go               # Backend インターフェース + 型定義
│   │   ├── env.go                   # 環境変数バックエンド
│   │   └── pass.go                  # Pass CLI バックエンド実装
│   ├── config/
│   │   └── config.go                # TOML 設定読み込み/保存 (+ ポリシー型)
│   ├── mcp/
│   │   └── server.go                # MCPサーバー (JSON-RPC 2.0 over stdio)
│   ├── proxy/
│   │   ├── ca.go                    # MITM CA 証明書生成
│   │   ├── command.go               # HTTPフォワードプロキシ (認証情報置換)
│   │   └── mitm.go                  # MITM CONNECT ハンドラ (HTTPSインターセプト)
│   ├── run/
│   │   └── command.go               # サブプロセス認証情報注入 (+ ポリシーチェック)
│   ├── scanner/
│   │   ├── scanner.go               # パターンベース認証情報Redact
│   │   └── scanner_test.go          # Scanner テスト
│   └── secret/
│       └── command.go               # 認証情報ストア操作
└── docs/
    └── design.md                    # アーキテクチャ & 設計書
```

### 依存関係

trustless の外部依存は1つだけ。残りはすべて Go 標準ライブラリ:

- `github.com/pelletier/go-toml/v2` — TOML設定ファイルパース

### 終了コード

| コード | 意味 |
|--------|------|
| 0 | 成功 |
| 1 | 一般エラー |
| 2 | 認証情報が見つからない / 不正な引数 |
| 3 | サブプロセスエラー / ポリシー違反 / 引数に認証情報検出 |
| 4 | 設定エラー |

## ライセンス

MIT
