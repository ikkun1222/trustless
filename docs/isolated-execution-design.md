# 機密情報実行の隔離 — 設計検討メモ

> 更新: 2026-08-12
> 状態: 検討中（実装は承認後）

## 1. 背景と目的

trustless の `run`（サブプロセス注入）は、エージェントと同じ環境で子プロセスを実行する。
検討課題: 「機密情報を使うコード実行を、エージェントから隔離された環境で実行し、
エージェントに機密情報を渡さない」ことはできないか。

過去の結論: 実行環境側（注入される側）がエージェントと同じ環境（ファイル・ランタイム・OS）を
保つ必要があり、隔離と環境パリティのトレードオフが解消できず断念。

本メモは、技術の進展（microVMスナップショット・プロキシ注入）と本環境の実測制約を
踏まえて再検討した結果。

## 2. 脅威モデル

- エージェント（Hermes / opencode / commandcode）は **sudo 付き** で動作
- 保護対象: APIキー・トークン（pass/bitwarden 管理、53キー）
- 攻撃シナリオ: エージェントが自プロセスツリー配下の子プロセスの
  `/proc/<pid>/environ` や ptrace 経由で注入値を読む
- 重要: **sudo 持ちエージェントには namespace 分離（bwrap/コンテナ）は無効**
  （nsenter で境界を抜けられる）

## 3. 環境制約（実測 2026-08-12）

| 項目 | 結果 | 影響 |
|---|---|---|
| /dev/kvm | **なし**（Oracle Cloud VM・ネスト仮想化なし） | Firecracker / Kata / 任意のmicroVMは**このホストでは不可** |
| bwrap / systemd-nspawn | なし | namespace分離は unshare で代替可能だが脅威モデル上無意味 |
| cgroup v2 | あり | コンテナランタイムは動く |
| trustless proxy | 実装済み（MITM可）・**実利用実績なし**・allowlist未実装・テストなし | プロキシ注入は拡張前提 |

## 4. ユースケース分類（53キーの棚卸し）

### A. HTTP APIキー（プロキシ注入で解決可能）— 約45キー

ヘッダー注入（Authorization / Ocp-Apim-Subscription-Key / X-API-Key）で対応可能:
- LLM: xai, openrouter, sakura, sakura-2, merge-gateway, merge-gateway-org, kilocode,
  commandcode, opencode-go, opencode-zen, meta-model-api, google-gemini, vercel-ai-gateway
- 検索: exa, tavily, octen, anysearch, brightdata, brightdata/gproxy, gproxy
- 統計/企業: estat, edinet, edinetdb/mcp, irbank, speeda-gas, monid/live-key,
  alphavantage/mcp-key, houjin-bangou, mlit/dpf-mcp, ebook-knowledge
- インフラ: slack-bot/app (x2), telegram-bot/channel, stripe, kintone, turso/token,
  cloudflare/api-token, oci/api-key, oci/auth-token, google, google-places, houjin-suite/client-token

### B. プロセス注入が必須（env/ファイルで直接読む）— 約8キー

- 接続文字列: turso/url（URL形式・SDKがenv直読）
- JSONトークンファイル: google-cloud/google-token-json, xiaomi/token-json
- OAuth: clasp/oauth, google-cloud/oauth-credentials, google-cloud/config-default
- その他: xiaomi/credentials, vercel-ai-gateway(429フォールバック用)

## 5. 設計判断

### 結論: 「プロキシ注入」を主軸にする（Docker Sandboxes / agent-sandbox / Islo と同じ方式）

- 鍵をエージェント環境に**一切存在させない**（プロセス・ファイル・env のどこにも無い）
- 環境パリティ問題が**構造的に消える**（コードは普通のHTTP呼び出しをするだけ）
- オーバーヘッド ≈ 0（ローカルプロキシ経由のみ）
- エージェントが sudo を持っていても鍵は読めない（読む対象が存在しない）

### 却下した案

| 案 | 却下理由 |
|---|---|
| コンテナ/bwrap 隔離実行 | sudoエージェントに nsenter で突破される。パリティも bind でしか解決できない |
| microVM（Firecracker等） | 本ホストに /dev/kvm なし。実行不可 |
| gVisor | ホストrootから runsc プロセスを ptrace 可能。sudoエージェントには不十分 |

### プロセス注入必須ケース（B群）の扱い

- 現状の `trustless run` を維持（サブプロセス注入+出力サニタイズ）
- これらはエージェント実行の都度ではなく、**cron/スクリプト（エージェント外）** で使う
  ケースが多い → 脅威は低い
- エージェント経由でどうしても必要な場合のみ、短期トークン化（STS等）を別途検討

## 6. trustless proxy の設計（2026-08-12 更新・後方互換なし方針）

**実装済み（feature/trustless-proxy-hostrules）:**
- `[proxy.rules]`: host → {header|query, key, prefix?, suffix?}
  - header注入（Authorization / Ocp-Apim-Subscription-Key 等）
  - query注入（e-Stat の appid、Alpha Vantage の apikey 等）
  - 既存ヘッダー/パラメータは上書きしない・未解決キーはfail-open
- `proxy.allowlist`: 設定時のみ許可ホスト限定、違反は403（HTTP/CONNECT/MITM全経路）
- プレースホルダ方式（`__KEY__`）は**廃止**（デッドコード回避・後方互換なし方針）
- テスト11件・実機E2E（header/query注入・403）検証済み

**dlp-proxy との連携（役割分担）:**

| 経路 | 担当 | 役割 |
|---|---|---|
| LLM API（merge/openrouter/sakura/google/vercel等） | dlp-proxy (127.0.0.1:8787) | 送信DLP（リクエストボディのシークレットマスク） |
| 一般API（EDINET/e-Stat/xai等） | trustless proxy (127.0.0.1:8080) | 認証注入（ホストベース） |

- 両者とも secrets_source=bitwarden・systemd常駐で統一
- trustless proxy はフォワードプロキシ（HTTPS_PROXY設定）、dlp-proxy はリバースプロキシ
  （base_url差し替え）なので経路が重ならない
- エージェント（Hermes/opencode）の設定: LLM系はdlp-proxy経由、それ以外のAPIは
  HTTPS_PROXY=trustless経由で素のリクエストを送る

## 7. PoC実証結果（2026-08-12）

現行 `trustless proxy start` の実機検証:

- ✅ `go build` + `proxy start --port 18080` で起動
- ✅ HTTPリクエストのヘッダー置換が動作:
  `curl -x http://127.0.0.1:18080 -H "Authorization: Bearer __XAI__" http://<echo>/`
  → echoサーバーが受信したヘッダーは `Authorization: Bearer xai-8R...`（実キーに解決済み）
- ✅ 未登録キーは置換されず残る（fail-openでプレースホルダ残置）
- ✅ バイナリは単体で `go build` 可能（依存はpass/gpg/bitwardenのみ）

確認事項:
- MITMなし（プレーンHTTP）なら追加設定不要で注入可能
- HTTPSは `--mitm` + CA証明書インストールが必要（現状の実装はCONNECTトンネル時も
  substituteRequestを通す設計だが、実機では`--mitm`フラグ必須）

## 8. 実装ステップ（承認後）

1. ~~PoC~~ ✅ **完了**（上記 §7。プレースホルダ注入は現行実装で動作確認済み）
2. ~~ホストベース注入ルール~~ ✅ **完了**（2026-08-12, feature/trustless-proxy-hostrules）
   - config `[proxy.rules]`: host → {header|query, key, prefix?, suffix?}
   - 素のリクエストに自動注入（既存ヘッダー/パラメータは上書きしない・未解決キーはfail-open）
   - allowlist（設定時のみ許可ホスト限定、違反は403）
   - テスト11件追加・実機E2E（header/query注入・403）検証済み
3. ~~allowlist~~ ✅ **完了**（上記2に含む・実機403確認済み）
4. ~~テスト追加~~ ✅ **完了**（proxy回帰テスト11件・make check 72 passed）
5. ~~プレースホルダ方式廃止~~ ✅ **完了**（ホストベース注入に一本化・デッドコード排除）
6. **systemd 常駐化 + エージェント環境（HTTPS_PROXY）への適用** — 未着手
7. **dlp-proxy との連携**（役割分担の運用化・LLM系はdlp/一般APIはtrustless） — 未着手
8. 実運用: A群キーのエージェント利用を run → proxy に移行 — 未着手

## 9. 参考（既存ソリューション）

- Docker Sandboxes: microVM + ワークスペースpassthrough + クレデンシャルプロキシ
- mattsolson/agent-sandbox (OSS): コンテナ + sidecarプロキシ + iptables + プロキシ側シークレット注入
- Islo: 使い捨てmicroVM + egressゲートウェイでトークン注入
- E2B: Firecracker microVM（鍵はenv渡しなので今回の設計とは異なる）
- ForgeVM (OSS): Firecrackerスナップショットで28ms起動（KVM必須・本ホストでは不可）
