# trustless — AIエージェント向けCredential Broker CLI

[English](README.md) | **日本語** | [简体中文](README.zh.md)

[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/ikkun1222/trustless/actions/workflows/ci.yml/badge.svg)](https://github.com/ikkun1222/trustless/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ikkun1222/trustless)](https://goreportcard.com/report/github.com/ikkun1222/trustless)

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

### 競合比較

「AIエージェントからシークレットを遠ざける」領域には複数のツールがあります。trustless は
**サブプロセス注入と出力サニタイズ**・**統合DLP（送信リクエストの秘匿化）**・
**既存パスワードマネージャバックエンド（pass / Bitwarden）** を、単一静的バイナリ（外部モジュールは go-toml/v2 の1つのみ・ランタイム不要）に
組み合わせた唯一のツールです。

| | trustless | tene | vaulty | agent-secrets | secretless-ai | enject |
|---|---|---|---|---|---|---|
| 注入方式 | サブプロセス env + HTTP proxy | サブプロセス env | HTTP proxy + MCP | サブプロセス env（lease） | env + shell hook | サブプロセス env |
| 既存バックエンド（pass/Bitwarden） | ✅ | ❌ 独自 vault | ❌ 独自 vault | ❌ 独自 vault | ❌ keychain/1Password | ❌ 独自 vault |
| 出力サニタイズ | ✅ run + proxy | ❌ | ✅ | ❌ | ❌ | ❌ |
| DLP（送信秘匿化） | ✅ 統合 | ❌ | 一部（request） | ❌ | ❌ | ❌ |
| OAuth トークン管理 | ✅（google/lark, refresh） | ❌ | ❌ | ❌ | ❌ | ❌ |
| 監査ログ（構造化） | ✅ | ❌ | ✅ file | ✅ append-only | ❌ | ❌ |
| Agent スキル同梱 | ✅ 4種 | ✅ context files | MCP のみ | ✅ skill | ✅ rules | ❌ |
| 依存関係 | **1（go-toml/v2, pure Go）** | Go static | Go static | Go static | npm/npx | Go static |
| ライセンス | MIT | MIT | MIT | MIT | Apache-2.0 | MIT |

*tene / vaulty / agent-secrets / secretless-ai / enject は 2026年8月時点の比較。*

実務上の違い: tene や enject は「エージェントが `.env` を読めない」ことを解決します。
trustless はさらに「コマンド実行時にキーを**見せない**」（出力サニタイズ）と
「エージェントが API を呼ぶときにマシン外へキーが漏れない」（DLP）も解決します。
すでに pass や Bitwarden を使っているなら移行は不要 — trustless は既存ストアを読みます。

## インストール

### ワンライナー（Linux / macOS）

```bash
curl -fsSL https://raw.githubusercontent.com/ikkun1222/trustless/main/scripts/install.sh | sh
```

最小インストール（CI/Docker用）:

```bash
curl -fsSL https://raw.githubusercontent.com/ikkun1222/trustless/main/scripts/install.sh | sh -s -- --minimal
```

アップグレード:

```bash
curl -fsSL https://raw.githubusercontent.com/ikkun1222/trustless/main/scripts/install.sh | sh -s -- --update
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

> 注: `go build` を ldflags 無しで実行すると `trustless dev` と表示されます。
> リリースバイナリは `-ldflags "-X main.version=vX.Y.Z"` でバージョンを埋め込みます
> （リリースパイプラインと `make build VERSION=vX.Y.Z` は自動で行います）。

### リリース成果物の検証

v0.5.1 以降、すべてのリリース成果物（バイナリ・SHA256SUMS・SBOM）は
**cosign keyless**（OIDC・鍵管理不要）で署名されています。使用前に検証してください:

```bash
# 1. 成果物 + 署名・証明書をダウンロード
gh release download v0.5.1 -p 'trustless-linux-amd64*' -p 'SHA256SUMS*'

# 2. バイナリが公開チェックサムと一致するか確認
sha256sum -c <(grep 'trustless-linux-amd64' SHA256SUMS)

# 3. cosign 署名を検証（keyless: 署名者 = ikkun1222/trustless の GitHub Actions）
cosign verify-blob --certificate trustless-linux-amd64.pem \
  --signature trustless-linux-amd64.sig \
  --certificate-identity-regexp '^https://github.com/ikkun1222/trustless/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  trustless-linux-amd64
```

各リリースには syft 生成の SPDX SBOM（`trustless.sbom.spdx.json`）も同梱され、
サプライチェーン透過性を担保します。

### 前提条件

- **Go 1.26+**（ビルド用）
- **`pass`**（Unixパスワードマネージャー）+ **`gpg`** — デフォルトのcredentialバックエンド
- 環境変数のみを使う場合は `backend = "env"` で pass 不要
- **`bw`**（Bitwarden CLI）は `backend = "bitwarden"`（クラウドストア）を使う場合のみ必要

バックエンドは `trustless config set backend <name>` で切り替え可能: `pass`（デフォルト）/ `env` / `bitwarden`。Bitwarden バックエンドの設計は [docs/bitwarden-backend-design.md](docs/bitwarden-backend-design.md) 参照。

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
```

## Agent Plugins 1.0.0

このリポジトリは [Agent Plugins](https://agent-plugins.org) 1.0.0 プラグインとしても配布可能です — Agent Skills をポータブルなプラグインにパッケージングする、オープンでベンダーニュートラルな標準規格。ルートの `plugin.json` 1枚で、対応クライアントが固定位置から `trustless-usage` スキルを発見できます：

```text
trustless/
├── plugin.json               # Agent Plugins 1.0.0 マニフェスト ($schema + name 必須)
├── skills/
│   └── trustless-usage/
│       └── SKILL.md          # Agent Skills 仕様準拠 (agentskills: true)
├── schemas/
│   └── plugin.schema.json    # 公式 1.0.0 プラグイン JSON Schema (vendored)
└── scripts/validate-plugin.py  # パッケージング検証（make check に組み込み）
```

プラグインは `trustless-usage` スキルを同梱し、エージェントにcredential管理のルール（`trustless run` で注入、`trustless secret set` で登録、平文保存禁止）を教えます。

ローンチ時対応クライアント: **ChatGPT / Codex、Cursor、GitHub Copilot、Kiro、VS Code**。リポジトリを clone / vendor し、クライアントにプラグインルート（`plugin.json` を含むディレクトリ）を指定するだけです。

検証: `make validate-plugin`（または `make check`）で、クローズドスキーマへの準拠と `skills/` ディスカバリレイアウトを vendored 公式スキーマでチェックします。

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

### `trustless oauth` — OAuth 認証情報管理

Google / Lark などのプロバイダ向けに OAuth 認証情報（RFC 8628 デバイスフロー + refresh grant）を管理します。`trustless oauth login` はデバイス認可フローを実行し、得られたトークンを**コンパクトな単一行 JSON エントリ**（`type=oauth`）として認証情報バックエンドに保存します。このエントリは他の認証情報と同じように解決され — `trustless run -s <key>` / `trustless proxy` は有効なアクセストークンを返し、期限切れ時は自動でリフレッシュします。

| サブコマンド | 説明 | 例 |
|------------|-------------|---------|
| `login <provider> <key>` | デバイスフローログイン。OAuth エントリを保存 | `trustless oauth login google api/google` |
| `refresh <key>` | OAuth エントリを強制リフレッシュ（キャッシュ無視） | `trustless oauth refresh api/google` |
| `status <key>` | エントリの状態を表示（`valid` / `expired` / `reauth_required`） | `trustless oauth status api/google` |
| `providers` | 設定済みプロバイダ一覧 | `trustless oauth providers` |

`login` は確認 URL を stdout に出力し、ユーザーの承認をポーリングします:

```bash
$ trustless oauth login google api/google
https://oauth2.googleapis.com/device/code?user_code=ABCD-1234   # ブラウザで開く
{"key":"api/google","provider":"google","expires_at":"2026-08-13T12:00:00Z"}
```

`refresh` は期限切れを待たずにアクセストークンを強制リフレッシュします。アクセストークンの値が出力されることはありません。`status` はトークンが有効な間 `valid`、リフレッシュトークンが失効している場合（`invalid_grant`）`reauth_required` を報告します:

```bash
$ trustless oauth status api/google
{"key":"api/google","provider":"google","expires_at":"...","status":"valid"}
```

**設定（`[oauth.providers]`）:** プロバイダのトークン/デバイスエンドポイントと認証情報を定義します。組み込みの `google` と `lark` 定義は以下のエンドポイントが同梱されており、`client_id` / `client_secret`（プロバイダの**開発者コンソール**でアプリ登録）と追加スコープを埋めるだけで使えます:

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

| プロバイダ | デバイス認可エンドポイント | トークンエンドポイント | デバイス認証 | トークンリクエスト |
|----------|-------------------------------|----------------|-------------|---------------|
| `google` | `https://oauth2.googleapis.com/device/code` | `https://oauth2.googleapis.com/token` | `body`（form body に client_secret） | `form` |
| `lark` | `https://accounts.larksuite.com/oauth/v1/device_authorization` | `https://open.larksuite.com/open-apis/authen/v2/oauth/token` | `basic`（Authorization header） | `json`（Lark code-style 応答） |

`client_id` / `client_secret` はプロバイダの開発者コンソール（Google Cloud Console / Lark Open Platform）で登録したものを使います — 絶対にコミットしないでください。バックエンドに保存されるのはトークンのみで、クライアント認証情報は保存されません。

### `trustless audit` — 構造化監査ログ

すべてのイベント（proxy 注入/拒否、run 起動、DLP 秘匿化、OAuth リフレッシュ/失敗/再認証）が JSONL で記録されます。**イベントにトークンやシークレットの値が現れることはありません** — キー名・ホスト・判定・最小限の詳細のみです。

| シンク | 場所 | デフォルト |
|------|-------|---------|
| `journald` | serve（stdout JSONL → systemd journald） | serve |
| `file` | append-only `~/.local/state/trustless/audit.jsonl`（0600、logrotate 用に SIGHUP で再オープン） | run / proxy / oauth |
| `off` | 破棄 | — |

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

イベント: `proxy.inject` / `proxy.deny` / `run.spawn` / `dlp.redact` / `oauth.refresh` / `oauth.fail` / `oauth.reauth_required`。

**注意:**
- アクセストークンはメモリにキャッシュされます（有効期限から60秒の安全マージンを引いた期間）。期限切れ時は `Resolve` で自動リフレッシュされます。
- プロバイダがリフレッシュトークンをローテーションする場合（Lark）、更新エントリは **CAS ガード**付きで書き戻されるため、並行書き込みで上書きされることはありません。
- `invalid_grant`（リフレッシュトークン失効）はリトライされません — 再認証するには `trustless oauth login` を再実行してください。

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

### `trustless dlp` — 送信DLPリバースプロキシ（旧 dlp-proxy 統合）

`trustless dlp` は旧 `github.com/ikkun1222/dlp-proxy` の後継サブコマンド。LLM API へのリクエスト本文を既知秘密（bitwarden / pass）と照合し `<redacted>` に置換する送信 DLP を提供する。

```bash
trustless dlp start -config ~/.config/dlp-proxy/config.json   # リバースプロキシ起動（既定 127.0.0.1:8787）
trustless dlp scrub-db  <db-path> [--apply] [--backup]        # SQLite DB の秘密スキャン / スクラブ
trustless dlp scrub-text <path>   [--apply]                   # テキスト / ディレクトリのスキャン / スクラブ
```

- **config スキーマは旧 dlp-proxy と同一（JSON）**: `listen` / `min_secret_len` / `secrets_source`（`pass` | `bitwarden`・既定 pass）/ `secrets_refresh_interval`（**必須**・例 `"10m"`）/ `routes`（prefix → upstream URL）
- **秘密ロードは共通 backend 経由**（`backend.Values`）— 旧 bitwardenloader/passstore は廃止
- **fail-closed**: 起動時の秘密ロード失敗は即終了（無防備で走らない）。リロード失敗時は既存セット維持 + WARN（fail-safe）
- **ホットリロード**: `secrets_refresh_interval` の定期リロード + SIGHUP で即時リロード
- 旧 dlp-proxy リポジトリは凍結（2026-08-13・`trustless dlp` に統合）

**Scrub コマンド** — すでにディスクに残ってしまったシークレット（エージェントのセッションDB・ログ・ダンプ）を、稼働中のプロキシと同じ二層脱敏で掃除します:

```bash
trustless dlp scrub-db  ~/.local/state/hermes/sessions.db            # dry-run: スキャンのみ
trustless dlp scrub-db  ~/.local/state/hermes/sessions.db --apply    # 変更を書き込む
trustless dlp scrub-db  ~/.local/state/hermes/sessions.db --apply --backup  # 先に .bak コピーを残す
trustless dlp scrub-text ~/.hermes/sessions --apply                  # テキストファイル/ディレクトリを掃除
```

- **デフォルトは dry-run**: どちらのコマンドもテーブル/ファイルごとのヒット数を表示するだけで書き込みません。実際に掃除するには `--apply` を追加。`scrub-db` はさらに `--backup`（書き込み前に `<db>.bak` へコピー）と `--min-len`（最小シークレット長、デフォルト8）を受け付けます。
- **`scrub-db`** は SQLite データベースを対象に: Layer 1 の既知値置換 + Layer 2 のパターンマスクを行い、その後 **FTS 仮想テーブルを再構築**し `VACUUM` を実行するため、ファイルに物理的な残骸が残りません（テストで検証済み）。
- **`scrub-text`** はファイル/ディレクトリツリー（エージェントの `sessions/`・ログ・ダンプ）を同じ二層脱敏で走査します。
- どちらも DLP 設定の `secrets_source`（pass / bitwarden）からシークレットを読み込み、`pattern_mode` を尊重します — `"log"` はマスクせずヒット数だけ数え、`"mask"` はその場で秘匿化します。

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
| [4/4] AIエージェント連携 | AIコーディングエージェントの設定を検出し、**trustless-usage SKILL.md を各エージェントのスキルディレクトリにインストール**（確認後） | 各agentの設定ファイルの存在 + trustless参照の有無をgrep |

**スキルインストール先:**

| エージェント | スキルディレクトリ |
|-------------|-------------------|
| OpenCode | `~/.config/opencode/skills/trustless-usage/` |
| Claude Code | `~/.claude/skills/trustless-usage/` |
| Codex | `~/.codex/skills/trustless-usage/` |
| Hermes | `~/.hermes/skills/credential-management/trustless-usage/` |

インストールされるスキルは、AIエージェントにcredential管理のルール（`trustless run` で注入、`trustless secret set` で登録、平文保存禁止）を教えます。

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
| `backend` | Credentialバックエンド（`pass` / `env` / `bitwarden`） | `pass` |
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
                     │ CLI / HTTP
                     ▼
┌─────────────────────────────────────────────────────────┐
│                   trustless CLI                          │
│                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │ secret   │  │ run      │  │ proxy    │              │
│  │ (一覧/   │  │ (サブプ  │  │ (HTTP    │              │
│  │  取得/   │  │  ロセス  │  │  プロキ  │              │
│  │  保存)   │  │  注入)   │  │  シ+     │              │
│  └────┬─────┘  └────┬─────┘  │  MITM)   │              │
│       │             │        └─────┬─────┘              │
│       │             │              │                    │
│  ┌────┴─────────────┴──────────────┴─────┐              │
│  │            Backend Interface          │              │
│  │  (pass / env / bitwarden — 切り替え可能) │            │
│  └─────────────────────┬──────────────────┘             │
└────────────────────────┼────────────────────────────────┘
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
- **`bitwarden`** — `bw` CLI（`bw list items`）をラップ。secureNote の fields[name="value", type=1 hidden] / login.password / notes 1行目を解決。セッションキーは **BW_SESSION 環境変数のみ**で渡す（argv 禁止）。unlock は `trustless bw-unlock`（セッションキーは `~/.config/trustless/bw-session` に 0600 で保存）。セッション無効時は fail-closed。詳細: [docs/bitwarden-backend-design.md](docs/bitwarden-backend-design.md)

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
   - 単一静的バイナリ、ランタイム依存無し（既存の `pass`+`gpg` ストアを読む。`bitwarden` バックエンドは追加で `bw` CLI が必要）

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
├── plugin.json                      # Agent Plugins 1.0.0 マニフェスト
├── skills/
│   └── trustless-usage/             # Agent Skills 仕様準拠の SKILL.md
├── schemas/
│   └── plugin.schema.json           # 公式 Agent Plugins スキーマ (vendored)
├── internal/
│   ├── backend/
│   │   ├── backend.go               # Backend インターフェース + 型定義
│   │   ├── env.go                   # 環境変数バックエンド
│   │   └── pass.go                  # Pass CLI バックエンド実装
│   ├── config/
│   │   └── config.go                # TOML 設定読み込み/保存 (+ ポリシー型)
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
├── scripts/
│   └── validate-plugin.py           # Agent Plugins パッケージング検証
└── docs/
    └── design.md                    # アーキテクチャ & 設計書
```

### 依存関係

trustless は実行時依存ゼロの単一静的バイナリとしてビルドされます。Go 標準ライブラリでほぼ全てを賄えますが、唯一 TOML パースだけは標準ライブラリに無いため、[`github.com/pelletier/go-toml/v2`](https://github.com/pelletier/go-toml/v2) — プロジェクト唯一の外部モジュール — を使用しています。手書きパーサ（未検証コード）を抱えるより、検証済みモジュール1つの方が supply chain リスクが小さいためです。pure Go（cgo 不使用）でバイナリ本体と同様に静的リンクされ、積極的にメンテナンスされ、fuzz テスト済みです。バージョンは `go.sum` で固定され、Dependabot と `govulncheck` で監視されています。

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
