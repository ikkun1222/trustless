# trustless Integration & Security Automation — Design

## 1. 現状のCredentialフロー

```
.env.pass (pass show ...)
     │ 起動時にpass-env.shが解決
     ▼
.env (平文の環境変数)
     │ Hermes起動時に読み込み
     ▼
Hermesプロセス (環境変数経由でAPIキー保持)
     │
     ├─ model.provider: opencode-go → OPENCODE_GO_API_KEY
     ├─ custom_providers.sakura     → SAKURA_API_KEY (key_env)
     ├─ fallback_providers          → OPENROUTER_API_KEY (任意)
     ├─ mcp_servers.brightdata      → BRIGHTDATA_TOKEN
     ├─ mcp_servers.estat-mcp       → ESTAT_APP_ID
     ├─ mcp_servers.edinetdb        → EDINETDB_TOKEN
     └─ mcp_servers.mlit-dpf        → MLIT_API_KEY (直書き)
```

**問題**: 起動後、全APIキーが環境変数としてプロセスに露出している。prompt injectionから `env` を見られると漏洩する。

## 2. trustless統合 — ロードマップ

### Phase 1: Hermes起動ラッパー (今すぐ)

`trustless run` でHermesをラップし、環境変数を安全に注入する。

```
trustless run -s KEY1 -s KEY2 -- python -m hermes_cli.main
     │ 各KEYをpassからresolve → サブプロセスの環境変数に注入
     ▼
Hermesプロセス (従来と同じ環境変数経由)
     ↓ 出力はscannerがRedact
信頼できないチャネル (stdout, ログ)
```

**ラッパースクリプト** `~/.hermes/scripts/trustless-gateway.sh`:

```bash
#!/bin/bash
# Launch Hermes Gateway with credentials injected via trustless
exec /home/ubuntu/projects/trustless/trustless run \
  -s iria/api/opencode-go \
  -s iria/api/sakura \
  -s iria/api/opencode-zen \
  -s iria/api/brightdata \
  -s iria/api/tavily \
  -s iria/api/estat \
  -s iria/api/edinetdb/mcp \
  -- /home/ubuntu/.hermes/hermes-agent/venv/bin/python \
     -m hermes_cli.main gateway run
```

**systemd service 変更**:

```ini
ExecStart=/home/ubuntu/.hermes/scripts/trustless-gateway.sh
```

この変更により:
- `.env.pass` → `.env` の解決が不要になる
- `OPENCODE_GO_API_KEY` の平文例外が解消される（全キーがtrustless経由に）
- 環境変数はサブプロセスにのみ注入され、親シェルには露出しない

**注意点**:
- `trustless run` のpassthroughモードで動作（stdout/stderrはそのままjournalへ）
- sanitizeは有効のままで問題なし（Hermesのログにcredentialパターンが出ることは稀）
- `trustless` バイナリのパスは固定（更新時に注意）

### Phase 2: MCP直書きクレデンシャルの解決

現在、一部のMCPサーバー設定にAPIキーが直書きされている:

| MCP | 現状 | 対策 |
|---|---|---|
| `mlit-dpf` | `env.MLIT_API_KEY` に平文 | `env` を `MLIT_API_KEY=$(trustless secret get ...)` に置換…できない（固定値のみ） |
| `brightdata` | URLにトークン直書き | 変更不要（専用トークン、漏洩リスク低い） |
| `alpha-vantage` | URLにAPIキー直書き | 同上 |

mlit-dpfだけはラッパースクリプトで起動する必要がある。MCPサーバー起動用ラッパー `~/.hermes/scripts/mcp-mlit.sh`:

```bash
#!/bin/bash
export MLIT_API_KEY=$(/home/ubuntu/projects/trustless/trustless secret get iria/api/mlit/dpf-mcp --quiet)
exec /home/ubuntu/mlit-dpf-mcp/.venv/bin/python /home/ubuntu/mlit-dpf-mcp/src/server.py "$@"
```

config.yamlのmlit-dpfエントリをcommandラッパーに変更。

### Phase 3: trustless export コマンド (将来)

systemdの `EnvironmentFile=` と組み合わせるための `trustless export` コマンドを追加:

```bash
trustless export iria/api/opencode-go iria/api/sakura > /run/hermes-env.conf
```

```
OPENCODE_GO_API_KEY=sk-...
SAKURA_API_KEY=sk-...
```

これを `ExecStartPre` で生成し、`EnvironmentFile=/run/hermes-env.conf` で読み込む。`/run/` はtmpfsなので再起動時に消える。

ただし現状のsystemd serviceは `EnvironmentFile` を使っていない。Hermesが内部で `.env` を読む仕組みを変更する必要があるため、Phase 3は優先度低。

## 3. セキュリティ自動更新

### 3.1 GitHub Dependabot (リポジトリ公開時)

toukibo-cliと同じ設定。Goモジュールの自動更新 + PR自動作成 + CI通過後auto-merge。

`.github/dependabot.yml`:
```yaml
version: 2
updates:
  - package-ecosystem: gomod
    directory: /
    schedule:
      interval: weekly
      day: monday
      time: "09:00"
      timezone: Asia/Tokyo
    labels:
      - security
```

### 3.2 ローカルcron — trustless自身の更新

毎週月曜04:00 JSTに最新版をインストール（toukiboのパターンと統一）。

cron job:
```bash
#!/bin/bash
# ~/.hermes/automation/cron/update-trustless.sh
go install github.com/ikkun1222/trustless@latest 2>&1
systemctl --user daemon-reload
systemctl --user restart hermes-gateway.service
```

cron定義:
```yaml
name: update-trustless
schedule: "0 4 * * 1"
command: /home/ubuntu/.hermes/automation/cron/update-trustless.sh
timezone: Asia/Tokyo
```

### 3.3 定期Credential Audit

pass storeの状態を定期的にチェックし、レポートをメール送信。

```bash
# ~/.hermes/automation/cron/trustless-audit.sh
# 1. GPG鍵の有効期限チェック
gpg --list-keys --with-colons | grep '^pub:' | awk -F: '{print $7,$10}'
# 2. pass storeのエントリ数・最終更新日
find ~/.password-store -name '*.gpg' -type f | while read f; do
  echo "$(stat -c '%Y' "$f") $(basename "$f" .gpg)"
done
# 3. trustless自身のバージョン
~/projects/trustless/trustless version
```

既存の `system-health-check` cron（日次00:00 JST）に統合しても良い。

## 4. まとめ

| 項目 | 優先度 | 工数 | 効果 |
|---|---|---|---|
| Phase 1: 起動ラッパー | **高** | 30分 | 全APIキーの平文露出を排除、.env不要に |
| Phase 2: MCP直書き解決 | 中 | 15分 | mlit-dpfのキー露出を解消 |
| Dependabot | 中 | 10分 | Go依存関係の自動セキュリティ更新 |
| ローカルcron | 中 | 15分 | trustlessの自動アップデート |
| Credential Audit | 低 | 30分 | 鍵の有効期限管理 |
| Phase 3: export コマンド | 低 | 2h | systemd統合の最適化 |

## 5. 判断してほしいこと

1. **Phase 1を今すぐやるか？** — systemdのExecStartをラッパースクリプトに変更するだけ。ロールバックも容易。
2. **`.env` はどうするか？** — ラッパー導入後は空にする or 削除。万が一のフォールバックとして残すなら中身をクリア。
3. **GitHub公開のタイミング** — Dependabotは公開後でないと設定できない。今はローカルcronのみ。
