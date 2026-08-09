---
type: Design
title: trustless Bitwarden backend — ストア外部化設計（構成 A）
description: trustless に Bitwarden クラウド backend を追加し、pass から移行する設計。マスターパスワード非保存 + セッションキー 600 + 監査で流出体制を確保。muse spark レビュー（2026-08-09）反映。
tags: [trustless, design, bitwarden, credential-broker, security]
timestamp: 2026-08-09
---

# trustless Bitwarden backend 設計書（構成 A）

## 1. 背景と目的

### 1.1 問題

現行構成では credential ストア（pass + GPG 鍵）が agent 実行マシン（development VM）に存在する。

- マシン乗っ取り → ストア全漏洩（パスフレーズなし GPG 鍵が同梱）
- バックアップ・ログからの漏洩リスク（スクラブで軽減しているが構造的ではない）
- credential がモバイル・他デバイスから閲覧・編集できない

### 1.2 目的

1. **ストアを Bitwarden クラウド（無料）へ外部化** — マシン乗っ取り・バックアップ漏洩で credential が漏れない
2. **マスターパスワードを平文保存しない** — 全 vault の復号鍵（最強の秘密）がディスクに存在しない
3. 既存機能（run / scan-args / sanitize / proxy / MCP）はローカル実行のまま維持
4. モバイル・他デバイスからの credential アクセス（付随価値）

### 1.3 不採用とした方式（決定済み）

| 方式 | 理由 |
|---|---|
| リモート run（値が broker から出ない） | broker 側に agent と同じ実行環境が必要になり非現実的（環境同一性問題） |
| リモート resolve + pass serve（構成 B） | broker VM 運用が必要。Bitwarden 直（構成 A）で同じ目的を達成できるため保留 |
| コマンドブラックリスト（denied_commands 拡張） | 任意コード実行（python3 -c 等）を防げず「完璧でない」割に複雑化。不採用（2026-08-09 ユーザー決定） |

### 1.4 前提（実測済み 2026-08-09）

- Bitwarden 個人 Free プラン: アイテム無制限・API キー使用可・2段階ログイン可
- Personal API Key は**認証のみ**（復号不可）。`bw unlock` にマスターパスワード必須
- セッションキー（88 chars）は lock/logout/ローテーションまで有効・プロセス間共有可
- bw CLI **2026.2.0 で動作確認済み**。2026.3.0+ は kdfType null バグ（clients#20720）→ 2026.4.2 の修正を Phase 0 で再実測
- vault データは暗号文で API 直叩きでは復号不可 → **backend は bw CLI exec ラッパーに確定**

## 2. アーキテクチャ

```
┌─ development VM（agent 実行マシン）────────────────────────────┐
│  trustless（backend = "bitwarden"）                            │
│    ├─ run     : resolve → env 注入 → ローカル実行（既存）       │
│    ├─ proxy   : プレースホルダー置換（既存）                    │
│    ├─ mcp     : resolve を bitwarden 経由（既存）               │
│    └─ dlp-proxy: 起動時全アイテム取得 → メモリ照合（変更）       │
│  bw CLI 2026.2.0（mise）                                        │
│  ~/.config/trustless/bw-session（chmod 600・セッションキー）    │
│  ~/.config/Bitwarden CLI/（暗号化 vault キャッシュ・bw 管理）   │
└─────────────────────────────────────────────────────────────────┘
        │ HTTPS（bw CLI 経由・公式クライアント）
┌─ Bitwarden クラウド（vault.bitwarden.com・Free プラン）─────────┐
│  全 credential（暗号文・ゼロ知識）                              │
│  マスターパスワード由来の復号鍵はクライアント側のみ             │
└─────────────────────────────────────────────────────────────────┘
```

- **ストアの実体は Bitwarden クラウドのみ**。development VM には暗号化 vault キャッシュ（bw 管理）とセッションキーのみ
- pass / GPG 鍵は移行後に read-only アーカイブ化（§5）

## 3. コンポーネント設計

### 3.1 bitwarden backend（新規・`internal/backend/bitwarden.go`）

```go
// bw CLI exec ラッパー（serve 不使用）
// 実行方式: bw list items を exec（復号は実行時のみ・常時 API なし）
//   ⚠️ セッションキーは argv で渡さない（ps -ef / /proc/<pid>/cmdline で漏洩）
//   → BW_SESSION 環境変数経由（公式推奨・H-1）
// キャッシュポリシー（H-3 確定）:
//   起動時に list を1回実行 → メモリ保持（Resolve はメモリ参照・ゼロコスト）
//   bw 不達時: メモリキャッシュで Resolve 成功（audit.log に WARN）— 可用性優先
//   ただしキャッシュ TTL 24h 超 + bw 不達 → fail-closed（exit 非0）
//   セッション失効時は常に fail-closed（キャッシュ不使用）
//   再取得は明示的 refresh（cron 定期 sync と連動）
// セッション状態キャッシュ（2026-08-09 追加）:
//   sessionAlive の bw status 実行を TTL（デフォルト 60s）でキャッシュし、
//   Resolve ごとの subprocess 呼び出しを排除。1プロセスで複数秘密を解決する
//   ケース（例: hermes acp が 19 秘密を順次解決）で bw status を 1 回に削減。
//   失効検知は最大 TTL 分遅延するが fail-closed は維持（SessionCheckTTL で調整可、
//   ゼロ指定で毎回チェックの後方互換）。並行 Resolve は sessionMu で保護。
```

#### アイテムマッピング（fields hidden 方式）

| pass の構造 | Bitwarden アイテム（secureNote 型） |
|---|---|
| キー名 `iria/api/openrouter` | アイテム名 `iria/api/openrouter` |
| 1行目 = 値 | fields[0]: name=`value`, type=`1`（hidden）, value=`<値>` |
| 2行目以降 = メタデータ | notes にそのまま |

- **`notes` の1行目には値を置かない**（notes は検索対象・履歴に残るため。hidden フィールドは復号時のみ表示）
- login 型アイテムは `login.password` を値として扱う（後方互換・移行元が login 型の場合）

#### セッション管理

```
~/.config/trustless/bw-session（chmod 600）: セッションキーのみ保存
~/.config/trustless/bw-unlock-required（フラグ）: 失効検知用

起動時: bw-session 読込 → 有効なら即動作
        └─ 無効（401/エラー）→ エラーメール通知 + 手動 unlock 待ち
unlock: trustless bw-unlock（新コマンド）
        └─ マスターパスワードをプロンプト or --passwordenv で受領（メモリのみ）
        └─ bw unlock --raw → セッションキーを 600 で保存
```

- **マスターパスワードはファイル・環境変数・ログに一切保存しない**（unlock 時のメモリのみ）
- **パスワードの受け渡しは stdin のみ**（`bw unlock --passwordenv` は env 継承で `ps e` に残るリスクがあるため使用しない。プロンプト入力 or stdin パイプ・M-3）
- セッションキーはローテーション可能（`bw lock` で即失効）— 漏洩時の無効化手段
- 再起動（unattended-upgrades 含む）後はセッションキー読込で自動復帰（手動介入なし）

#### エラー処理（fail-closed）

| 状況 | 挙動 |
|---|---|
| bw-session 不存在 or 失効 | Resolve はエラー。run は exit 非0 + 通知。**静かなフォールバックなし** |
| アイテム欠落（key 未登録） | ErrNotFound（pass backend と同型） |
| bw 不達（ネットワーク/障害） | エラー + exit 非0。既存キャッシュで応答しない（キャッシュは読み取り専用参照） |

### 3.2 設定（config.toml）

```toml
backend = "bitwarden"        # "pass"（従来・rollback 用）| "bitwarden"
```

- pass backend は残す（rollback・移行検証用）。切替は config 1行
- **ブートストラップ認証の分離（H-2）**: Bitwarden の client_id / client_secret は**移行対象から除外**し、`~/.config/trustless/bitwarden-credentials.env`（chmod 600）に置く。`bw login` はこのファイルからのみ行う
  - ⚠️ pass に登録したままにすると、backend=bitwarden 切替後に「bw login に必要な秘密の解決自体が bitwarden 経由」になる循環が発生し、セッション失効時に永久復旧不能になる
  - pass 側の `iria/api/bitwarden/*` は削除 or アーカイブ（正は credentials ファイル）

### 3.3 dlp-proxy 連携

- 現行: 起動時に pass 全エントリを復号 → メモリ保持
- 変更後: 起動時に `bw list items` → fields value をメモリ保持（**ディスクに書かない**）
- 照合ロジックは無変更（照合ソースの取得先が変わるだけ）
- セッションキー・マスターパスワードも照合対象に追加（会話への貼り付け・混入を検知）

## 4. セキュリティモデル

### 4.1 保証

1. credential の**永続ストアは Bitwarden クラウドのみ**（暗号文・ゼロ知識）
2. **マスターパスワードがディスクに存在しない**（unlock 時のメモリのみ）— 最強の秘密の非保存
3. セッションキーは 600 ファイル + `bw lock`/client_secret ローテーションで即無効化可能
4. 全 vault アクセスは **trustless 側の resolve ログ（journald + audit.log）**に記録（Bitwarden イベントログは **Free プランでは取得不可** — Organization 限定のため。有料移行時は追加で有効化・L-1）
5. 事故的混入は dlp-proxy が遮断（照合ソース = Bitwarden 全アイテム）
6. バックアップ・ログ・ファイルシステムに平文 credential が構造的に存在しない

### 4.2 範囲外（正直な限界・muse spark レビュー C4 への回答）

1. **agent はセッションキーファイルを読める**（root 相当のため）→ 意図的に `cat bw-session` + bw 実行で vault を復号できる。「agent が読めない」の完全達成は**実行環境の分離（サンドボックス化）が必要**で、本設計の対象外。本設計の価値は「**事故的混入の遮断**（dlp-proxy）+ **流出時の影響抑制**（マスパス非保存・セッションキー即失効）+ **ストアの外部化**（マシン喪失・バックアップ漏洩耐性）」
2. Bitwarden クラウドの可用性・セキュリティはベンダー依存（ゼロ知識設計のため内容漏洩リスクは低い）
3. マスターパスワード紛失 = vault 喪失（Bitwarden 仕様）。保管はユーザー責任（記憶 or 紙/USB）

### 4.3 脅威モデル

| 脅威 | 対応 |
|---|---|
| development VM 乗っ取り | ストアは外部（暗号文）。ローカルにはセッションキーのみ → `bw lock` で無効化可能。マスパスはローカルに存在しない |
| バックアップ / ログ漏洩 | 構造的に平文 credential なし（スクラブ不要の設計）。セッションキーの 600 は**この脅威（バックアップ・他ユーザー）対策であり、同一 UID の agent からの隔離ではない**（M-1。agent からは読める前提で §4.2 の範囲外に含む） |
| 事故的コンテキスト混入 | dlp-proxy（照合ソース = Bitwarden 全アイテム + セッションキー + マスパス） |
| Bitwarden クラウド侵害 | ゼロ知識暗号化（マスパス由来鍵・サーバー側に復号手段なし） |
| セッションキー漏洩 | **`bw lock` 即失効 + client_secret ローテーション**（600 は agent からの隔離ではない・上記） |
| client_secret 漏洩 | ローテーション（全セッション無効化） |
| マスターパスワード漏洩 | ユーザー責任領域（非保存・記憶/紙保管）+ 2FA 推奨（API キーは 2FA バイパスするためマスパス強度が最重要） |

## 5. 移行設計（pass → Bitwarden）

### 5.1 原則

- **Bitwarden を正（source of truth）とする**。移行後の値の更新は Bitwarden 側でのみ行う
- **pass は read-only アーカイブ**（更新停止・GPG 暗号化のまま保持）
- rollback（backend=pass 切替）は「**pass の最終同期時点の値**」にしか戻せないことを明記し、rollback 時は手動値検証を必須化（muse spark レビュー M3 への対応）

### 5.2 移行スクリプト（技術確認済み 2026-08-09）

```
pass 全エントリ（40+）:
  pass show <key> → 1行目 = 値 / 2行目以降 = メタ
  → Bitwarden secureNote アイテム作成（bw create item・技術確認済み）:
     アイテム名 = <key> / fields[value, hidden] = 値 / notes = メタ
     JSON は Base64 エンコード必須（bw create item <encodedJson>・stdin 可）
```

- **冪等**: 同名アイテムが既にあればスキップ（--dry-run で作成予定を先に確認）
- 既存アイテム（test-api-key 等）は事前に確認してスキップ or 削除
- 検証用比較スクリプト: pass と Bitwarden の全キー値を照合（差分ゼロが出口条件）

### 5.3 検証

- **全キー値一致検証**: pass と Bitwarden の値を比較スクリプトで照合（差分ゼロが出口条件）
- 検証後: `bw sync` + サンプルキーで `trustless run` 実動確認

## 6. 実装フェーズ

| Phase | 内容 | 出口条件 |
|---|---|---|
| **0** | 設計確定（本設計書）+ Backend 抽象のコードリーディング + pass 依存ジョブの洗い出し（cron 26本・gateway・dlp-proxy）+ **bw 2026.4.2 再実測**（kdfType バグ修正確認 → 採用判断） | 見積もり確定・依存ジョブ一覧・bw バージョン確定 |
| **1** | **bitwarden backend 実装**: bw CLI exec・fields マッピング・セッションキー 600 管理・`bw-unlock` コマンド・メモリキャッシュ + **性能再実測**（list キャッシュ後の resolve 速度） | ローカル E2E 合格: `trustless run -s test-note:TEST_KEY -- env` が Bitwarden 経由で動作・`secret list` が Bitwarden アイテム列挙 |
| **2** | **移行**: 移行スクリプト + 40+ キー移行 + 全キー値一致検証 | 差分ゼロ |
| **3** | **切替**: config → backend=bitwarden → gateway / CLI ラッパー / cron ジョブ / dlp-proxy を Bitwarden 経由に | 全 cron 正常動作・dlp-proxy マスク実測（実キー送信テスト） |
| **4** | **旧ストア整理**: pass を read-only アーカイブ化（更新停止）→ 平文例外3種を Bitwarden 注入に置換 → セッション失効検知 cron + 定期 `bw sync` cron → セッションキー検知ルール（detect-secrets 拡張） | detect-secrets ヒット 0・例外解消 |
| **5** | **復旧・文書化**: 復旧ドリル（Bitwarden 障害時は backend=pass 切替 + 手動検証 / 新マシン復旧は bw 導入 + unlock のみ）→ OKF 更新（trust-boundary / credential-management / connectivity / overview）→ bitwarden スキル・trustless スキル更新 | ドリル成功・OKF 準拠チェック合格 |

### ロールバック（安全網）

- Phase 1〜4 のどの時点でも `backend = "pass"` に戻すだけで従来動作に復帰
- pass は Phase 4 まで無傷で保持（read-only 化は Phase 4）
- rollback 時は pass が「最終同期時点」の値であることを認識し、手動値検証を必須化（§5.1）

## 7. 検証計画

### 7.1 正常系（Phase 1 出口）

```bash
# backend=bitwarden で:
trustless run -s test-note:TEST_KEY -- env | grep TEST_KEY   # Bitwarden 経由で注入
trustless run -s test-api-key:API_KEY -- curl -s https://example.com  # fields 値の解決
trustless secret list                                          # Bitwarden アイテム列挙
# 性能: キャッシュ後の resolve レイテンシ（初回 vs 2回目以降）
```

### 7.2 異常系（muse spark レビュー反映）

| ケース | 期待挙動 |
|---|---|
| bw-session 不存在 | エラー + exit 非0 + 通知（fail-closed） |
| bw-session 失効（lock 後） | 同左（**キャッシュ不使用**・常に fail-closed） |
| bw 不達（オフライン） | **メモリキャッシュで Resolve 成功**（audit.log に WARN）— ただしキャッシュ TTL 24h 超で fail-closed（H-3） |
| アイテム欠落 | ErrNotFound（明確なエラーメッセージ） |
| 同時実行（複数 run） | 競合なし（キャッシュは読み取り専用・exec は独立プロセス） |
| レート制限（bw sync 連打） | エラー伝播（リトライは cron 側の設計で吸収） |

### 7.3 移行検証（Phase 2 出口）

- 全キー値一致（比較スクリプト・差分ゼロ）
- **Tier1 キー全数で `trustless run` 実動確認**（課金キー・起動クリティカルキーはランダム抽出に含めない・L-2）
- **dlp-proxy マスク確認**: 実キー文字列を echo して `<redacted>` に置換されるか実測（照合ソースが Bitwarden に切り替わっていることの確認）

## 8. 監視・運用

| 項目 | 内容 |
|---|---|
| セッション失効検知 | cron（日次）: `bw status` が locked/unauthenticated ならエラーメール。**検知後は `bw sync` も失敗し続けるため、リトライは指数バックオフ + 3回失敗で通知を1回に抑制**（M-2） |
| 定期 sync | cron（日次）: `bw sync`（vault キャッシュ更新・アイテム追加反映）。失効中は失敗継続 → 上記のアラート抑制と連動 |
| resolve 監査ログ | **journald を正**（改竄検知あり）+ `~/.local/share/trustless/audit.log`（600・追記のみの設計。`chattr +a` は root 必要のため使用しない・M-4） |
| 検知ルール | detect-secrets 拡張: Bitwarden セッションキー（88 chars base64）・client_secret パターン |
| バージョン管理 | bw CLI は mise で固定 + **更新フロー定義**（Phase 0 で 2026.4.2 判定後、mise の Renovate/Dependabot 的更新 + E2E を組み込み・L-3） |

## 9. 開発原則

- **依存ゼロ**: backend は Go stdlib のみ（bw CLI は外部プロセスとして exec・go.mod 増やさない）
- **fail-closed**: セッション失効・アイテム欠落はエラー（exit 非0）。bw 不達はキャッシュ TTL 24h までは可用性優先（§3.1 H-3）。静かなフォールバック禁止
- **値の永続化禁止**: 解決した値をファイル・ログ・キャッシュ（trustless 側）に書かない。メモリのみ
- **マスターパスワード非保存**: プロンプト or stdin パイプ経由のみ・argv と環境変数の永続化禁止（M-3）
- **セッションキーは BW_SESSION 環境変数でのみ渡す**: argv 禁止（`ps -ef` / `/proc/<pid>/cmdline` 漏洩防止・H-1）。コードレビュー観点に「ps 漏洩チェック」を入れる
- **make check 準拠**: gofmt + go vet + gocyclo（CCN 15）+ go test -race + pre-commit + secrets-check
- **テスト**: httptest 不使用（実 bw CLI 依存の E2E はスキップ可能な統合テストとして分離）

## 10. 関連

- [trustless README](https://github.com/ikkun1222/trustless)
- bitwarden スキル（Personal API Key・トークン取得・落とし穴）
- credential-broker スキル（三層成熟度モデル・Backend 抽象パターン）
- OKF: security-operations（/credential-management/trustless.md / /platform/trust-boundary.md）
