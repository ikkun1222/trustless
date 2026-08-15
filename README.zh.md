# trustless — 面向 AI 代理的凭据代理 CLI（Credential Broker CLI）

[English](README.md) | [日本語](README.ja.md) | **简体中文**

[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/ikkun1222/trustless/actions/workflows/ci.yml/badge.svg)](https://github.com/ikkun1222/trustless/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ikkun1222/trustless)](https://goreportcard.com/report/github.com/ikkun1222/trustless)

## 概述

**trustless** 是一个凭据代理 CLI，将 AI 代理与其使用的密钥解耦。传统方案中，代理会在上下文窗口里持有明文凭据（可能因提示注入或泄露而暴露）；而 trustless 作为中间层：代理只按名称引用凭据，由 broker 在传输层/进程层解析实际值——代理**永远不会持有明文值**。

名称体现了架构思想：你不需要*信任*代理来保管密钥，因为代理在结构上就无法接触它们。

### 为什么用 trustless？

传统的 AI 代理配置会让代理直接访问凭据——无论是环境变量、配置文件，还是内联在提示词中。这意味着一次提示注入或过于冗长的调试输出就可能把密钥泄露给攻击者或不受信任的第三方 API。

trustless 反转了这一模型：代理说「使用 `GITHUB_TOKEN`」，broker 解析出值，代理只看到 API 响应——永远看不到密钥本身。

```
传统方式:   agent → 看到密钥 → 使用密钥 → 密钥进入上下文 → 提示注入泄露
            ↑  代理是受信任主体

trustless:  agent → 说「使用 GITHUB_TOKEN」 → broker 解析 → agent 拿到 API 响应
            ↑  代理是不可信调用方，broker 才是权威
```

### 竞品对比

「让密钥远离 AI 代理」这个领域已有多个工具。trustless 是唯一一个把**子进程注入 + 输出脱敏**、**集成 DLP（出站请求脱敏）**、**现有密码管理器后端（pass / Bitwarden）** 组合进单一零依赖二进制的工具。

| | trustless | tene | vaulty | agent-secrets | secretless-ai | enject |
|---|---|---|---|---|---|---|
| 注入方式 | 子进程 env + HTTP 代理 | 子进程 env | HTTP 代理 + MCP | 子进程 env（lease） | env + shell hook | 子进程 env |
| 现有后端（pass/Bitwarden） | ✅ | ❌ 自带 vault | ❌ 自带 vault | ❌ 自带 vault | ❌ keychain/1Password | ❌ 自带 vault |
| 输出脱敏 | ✅ run + proxy | ❌ | ✅ | ❌ | ❌ | ❌ |
| DLP（出站脱敏） | ✅ 集成 | ❌ | 部分（request） | ❌ | ❌ | ❌ |
| OAuth 令牌管理 | ✅（google/lark, refresh） | ❌ | ❌ | ❌ | ❌ | ❌ |
| 审计日志（结构化） | ✅ | ❌ | ✅ file | ✅ append-only | ❌ | ❌ |
| 随附 Agent 技能 | ✅ 4 种 | ✅ context files | 仅 MCP | ✅ skill | ✅ rules | ❌ |
| 依赖 | **0（单一二进制）** | Go static | Go static | Go static | npm/npx | Go static |
| 许可证 | MIT | MIT | MIT | MIT | Apache-2.0 | MIT |

*tene / vaulty / agent-secrets / secretless-ai / enject 按 2026 年 8 月状态对比。*

实际差异：tene 或 enject 解决的是「代理读不到 `.env`」。trustless 还解决「代理运行命令时*看不到*密钥」（输出脱敏）和「代理调用 API 时密钥不会从机器*外泄*」（DLP）。如果你已经在用 pass 或 Bitwarden，无需迁移——trustless 直接读取你现有的存储。

## 安装

### 一行命令（Linux / macOS）

```bash
curl -fsSL https://raw.githubusercontent.com/ikkun1222/trustless/main/scripts/install.sh | sh
```

免交互安装（用于 CI/Docker）：

```bash
curl -fsSL https://raw.githubusercontent.com/ikkun1222/trustless/main/scripts/install.sh | sh -s -- --minimal
```

升级已有安装：

```bash
curl -fsSL https://raw.githubusercontent.com/ikkun1222/trustless/main/scripts/install.sh | sh -s -- --update
```

### 从源码构建（Go 1.26+）

```bash
git clone https://github.com/ikkun1222/trustless
cd trustless && go build -o trustless .
```

或直接安装：

```bash
go install github.com/ikkun1222/trustless@latest
```

> 注意：不带 ldflags 的 `go build` 会显示 `trustless dev`。发布二进制通过 `-ldflags "-X main.version=vX.Y.Z"` 嵌入版本号（发布流水线和 `make build VERSION=vX.Y.Z` 会自动完成）。

### 校验发布产物

从 v0.5.1 开始，每个发布产物（二进制、SHA256SUMS、SBOM）都使用 **cosign keyless**（OIDC，无需密钥管理）签名。使用前请校验：

```bash
# 1. 下载产物 + 签名与证书
gh release download v0.5.1 -p 'trustless-linux-amd64*' -p 'SHA256SUMS*'

# 2. 校验二进制与发布校验和一致
sha256sum -c <(grep 'trustless-linux-amd64' SHA256SUMS)

# 3. 校验 cosign 签名（keyless：身份 = ikkun1222/trustless 的 GitHub Actions）
cosign verify-blob --certificate trustless-linux-amd64.pem \
  --signature trustless-linux-amd64.sig \
  --certificate-identity-regexp '^https://github.com/ikkun1222/trustless/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  trustless-linux-amd64
```

每个版本还附带 syft 生成的 SPDX SBOM（`trustless.sbom.spdx.json`），用于供应链透明。

### 前置条件

- **Go 1.26+**（从源码构建时）
- **`pass`**（标准 Unix 密码管理器）+ **`gpg`** —— 默认凭据后端
- 使用 `backend = "env"` 时只需环境变量（不需要 `pass`）
- **`bw`**（Bitwarden CLI）仅在 `backend = "bitwarden"`（云存储）时需要

后端可通过 `trustless config set backend <name>` 切换：`pass`（默认）、`env`、`bitwarden`。Bitwarden 后端设计见 [docs/bitwarden-backend-design.md](docs/bitwarden-backend-design.md)。

## 快速上手

```bash
# 首次设置（GPG 密钥、pass 存储、.env 迁移、代理配置）
trustless setup

# 检查系统健康
trustless doctor

# 列出 pass 存储中的凭据
trustless secret list

# 注入凭据运行命令（输出自动脱敏）
trustless run -s iria/api/xai -- curl -s https://api.x.ai/v1/models

# 启动凭据代理
trustless proxy start --port 8080
```

## Agent Plugins 1.0.0

本仓库同时打包为 [Agent Plugins](https://agent-plugins.org) 1.0.0 插件——面向 Agent Skills 的可移植插件打包开放标准。单个 `plugin.json` 清单让兼容客户端可以从固定位置发现 `trustless-usage` 技能：

```text
trustless/
├── plugin.json               # Agent Plugins 1.0.0 清单（$schema + name 必填）
├── skills/
│   └── trustless-usage/
│       └── SKILL.md          # 符合 Agent Skills 规范（agentskills: true）
├── schemas/
│   └── plugin.schema.json    # 内置官方 1.0.0 插件 JSON Schema
└── scripts/validate-plugin.py  # 打包校验（已接入 make check）
```

插件自带 `trustless-usage` 技能，教会代理凭据使用约定（`trustless run` 注入、`trustless secret set` 注册、不持久化明文）。

启动时支持 Agent Plugins 的客户端：**ChatGPT / Codex, Cursor, GitHub Copilot, Kiro, VS Code**。安装方式：克隆或 vendoring 仓库后，让客户端指向插件根目录（包含 `plugin.json` 的目录）。

校验：`make validate-plugin`（或 `make check`）会使用内置的官方 schema 校验清单结构和 `skills/` 发现布局。

## 命令参考

### `trustless secret` — 凭据存储操作

| 子命令 | 说明 | 示例 |
|------------|-------------|---------|
| `list` | 列出所有可用凭据键 | `trustless secret list` |
| `get <key>` | 读取凭据值（JSON 输出） | `trustless secret get github_token` |
| `set <key> [value]` | 存储新凭据（封装 `pass insert`） | `trustless secret set openai_key sk-...` |

`get` 默认输出 JSON：
```json
{"key": "github_token", "value": "ghp_..."}
```

### `trustless oauth` — OAuth 凭据管理

管理 Google、Lark 等提供方的 OAuth 凭据（RFC 8628 设备流 + refresh grant）。`trustless oauth login` 运行设备授权流程，并把得到的令牌以**紧凑单行 JSON 条目**（`type=oauth`）存入凭据后端。该条目像其他凭据一样被解析——`trustless run -s <key>` / `trustless proxy` 会返回有效访问令牌，过期时自动刷新。

| 子命令 | 说明 | 示例 |
|------------|-------------|---------|
| `login <provider> <key>` | 设备流登录；保存 OAuth 条目 | `trustless oauth login google api/google` |
| `refresh <key>` | 强制刷新 OAuth 条目（忽略缓存） | `trustless oauth refresh api/google` |
| `status <key>` | 显示条目状态（`valid` / `expired` / `reauth_required`） | `trustless oauth status api/google` |
| `providers` | 列出已配置的提供方 | `trustless oauth providers` |

`login` 把验证 URL 打印到 stdout，然后轮询直到用户批准：

```bash
$ trustless oauth login google api/google
https://oauth2.googleapis.com/device/code?user_code=ABCD-1234   # 在浏览器中打开
{"key":"api/google","provider":"google","expires_at":"2026-08-13T12:00:00Z"}
```

`refresh` 不等待过期即强制刷新访问令牌；访问令牌的值永远不会被打印。`status` 在令牌仍有效时报告 `valid`，在刷新令牌被吊销（`invalid_grant`）时报告 `reauth_required`：

```bash
$ trustless oauth status api/google
{"key":"api/google","provider":"google","expires_at":"...","status":"valid"}
```

**配置（`[oauth.providers]`）：** 为提供方定义令牌/设备端点与凭据。内置的 `google` 和 `lark` 定义已附带下面的端点——你只需填写 `client_id` / `client_secret`（在提供方的**开发者控制台**注册应用）以及任何附加 scope：

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

| 提供方 | 设备授权端点 | 令牌端点 | 设备认证 | 令牌请求 |
|----------|-------------------------------|----------------|-------------|---------------|
| `google` | `https://oauth2.googleapis.com/device/code` | `https://oauth2.googleapis.com/token` | `body`（表单体中携带 client_secret） | `form` |
| `lark` | `https://accounts.larksuite.com/oauth/v1/device_authorization` | `https://open.larksuite.com/open-apis/authen/v2/oauth/token` | `basic`（Authorization 头） | `json`（Lark code 风格响应） |

`client_id` / `client_secret` 在提供方的开发者控制台（Google Cloud Console / Lark Open Platform）注册——切勿提交到仓库。后端存储的 OAuth 条目只有令牌，从不包含客户端凭据。

### `trustless audit` — 结构化审计日志

所有事件（代理注入/拒绝、run 启动、DLP 脱敏、OAuth 刷新/失败/重新认证）都以 JSONL 记录。**事件中永远不会出现令牌或密钥值**——只有键名、主机、判定和少量细节。

| Sink | 位置 | 默认 |
|------|-------|---------|
| `journald` | serve（stdout JSONL → systemd journald） | serve |
| `file` | append-only `~/.local/state/trustless/audit.jsonl`（0600，SIGHUP 重开以配合 logrotate） | run / proxy / oauth |
| `off` | 丢弃 | — |

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

事件类型：`proxy.inject` / `proxy.deny` / `run.spawn` / `dlp.redact` / `oauth.refresh` / `oauth.fail` / `oauth.reauth_required`。

**注意事项：**
- 访问令牌缓存在内存中（有效期减去 60 秒安全余量）；过期时在 `Resolve` 中自动刷新。
- 当提供方轮换刷新令牌（Lark）时，更新条目通过 **CAS 守卫**写回，并发写入者不会被覆盖。
- `invalid_grant`（刷新令牌被吊销）不会重试——请重新运行 `trustless oauth login` 重新认证。

### `trustless run` — 子进程凭据注入（核心命令）

将一个或多个凭据作为环境变量注入后运行命令。注入的值**永远不会返回给调用方**——只有子进程的 stdout/stderr 会返回，且匹配的凭据模式会被脱敏。

```bash
trustless run -s iria/api/xai -- curl -s https://api.x.ai/v1/models
trustless run -s GITHUB_TOKEN -s OPENAI_KEY -- gh pr list
```

**工作原理：**
1. trustless 从后端解析每个 `-s` 键
2. 以环境变量形式把凭据值注入子进程并启动
3. 环境变量名由键的最后一段路径转换而来，转为 `UPPER_SNAKE_CASE`（例如 `iria/api/xai` → `XAI`）
4. 把 stdin 转发给子进程并流式输出 stdout/stderr
5. 逐行扫描输出中的凭据模式，命中处替换为 `[REDACTED]`
6. 把脱敏后的输出返回给调用方

**安全特性：**

- **`--scan-args`**（默认：`true`）：启动子进程前，扫描所有命令参数中是否包含凭据模式或注入值。若检测到，以退出码 3 阻止执行（fail closed）。这防止代理在 CLI 参数中意外暴露凭据值，例如 `curl -H "Authorization: Bearer ***"`。
- **`--sanitize`**（默认：`true`）：扫描并从子进程输出中脱敏凭据模式。
- **策略引擎**：命令级访问控制（见配置章节）。

**stdio 协议（ACP / MCP / LSP）：** stdin 始终转发给子进程（2026-07-31 修复），输出**逐行实时**脱敏，因此长驻进程（ACP 服务器、网关）会刷新输出而不是缓冲到退出。对于交互式 JSON-RPC stdio 服务器，脱敏流可能破坏协议消息——请为这类场景传 `--sanitize=false`（例如 `hermes acp`）。

| 标志 | 说明 |
|------|-------------|
| `-s, --secret <key>` | 要注入的凭据键（可重复，格式：`KEY` 或 `KEY:ENVNAME`） |
| `--sanitize` | 启用输出扫描/脱敏（默认开启） |
| `--sanitize-policy <file>` | 自定义脱敏模式文件 |
| `--scan-args` | 启动前扫描命令参数中的凭据模式（默认开启） |
| `--json` | 以 JSON 输出 `{"exit_code": N, "stdout": "...", "stderr": "..."}` |
| `--timeout <duration>` | 子进程超时（默认：5m） |

### `trustless proxy` — 带凭据注入的 HTTP 转发代理

启动本地 HTTP 转发代理，根据目标主机把凭据注入请求。代理发送普通请求——无需占位符语法，无需知道密钥。

```bash
trustless proxy start --port 8080
trustless proxy start --port 8080 --mitm  # HTTPS 拦截模式
```

让代理使用该代理：

```bash
export HTTPS_PROXY=http://127.0.0.1:8080
```

**注入规则（配置 `[proxy.rules]`）：** 把主机映射到以请求头或查询参数形式注入的凭据。请求头/参数仅在缺失时注入；无法解析的键 fail open（不注入）。

```toml
[proxy.rules]
# Header injection (e.g. LLM APIs, EDINET)
"api.x.ai" = { header = "Authorization", key = "xai", prefix = "Bearer " }
"api.edinet-fsa.go.jp" = { header = "Ocp-Apim-Subscription-Key", key = "edinet" }
# Query parameter injection (e.g. e-Stat, Alpha Vantage)
"statdb.nstac.go.jp" = { query = "appid", key = "estat" }
"www.alphavantage.co" = { query = "apikey", key = "alphavantage/mcp-key" }
```

- `header` / `query`：注入目标（每条规则二选一）
- `key`：凭据键（解析顺序：小写 → pass，回退 `iria/api/<key>`）
- `prefix` / `suffix`：请求头值包装（例如 `Bearer ` 前缀）

**出站白名单（配置 `proxy.allowlist`）：** 设置后，只有列出的主机允许通过代理；其余请求以 `403 Forbidden` 拒绝。空/缺省 = 允许所有主机。

```toml
[proxy]
allowlist = ["api.x.ai", "api.edinet-fsa.go.jp"]
```

**热重载（SIGHUP）：** 规则/白名单变更与凭据轮换无需重启即可生效。

```bash
systemctl --user reload trustless-proxy   # systemd：发送 SIGHUP
# 或手动：
# kill -HUP $(pgrep -f "trustless proxy start")
```

重载会重新读取 `config.toml`（规则/白名单）并刷新后端缓存（bitwarden），因此新轮换的密钥立即可见，无需等待 24h 缓存 TTL。

**MITM 模式（`--mitm`）：**
- 启用 HTTPS 拦截，向加密请求注入凭据
- 首次使用自动生成根 CA 证书 `~/.config/trustless/trustless-ca.{crt,key}`
- 按主机名生成叶子证书（24h 有效期，ECDSA P-256）
- 系统级安装 CA 证书以无缝拦截 HTTPS：

  ```bash
  sudo cp ~/.config/trustless/trustless-ca.crt /usr/local/share/ca-certificates/
  sudo update-ca-certificates
  ```

| 标志 | 说明 |
|------|-------------|
| `--port <n>` | 监听端口（默认：8080） |
| `--unix-socket <path>` | 监听 Unix socket（文件权限控制） |
| `--mitm` | 启用 MITM 模式（拦截 HTTPS 以注入凭据） |

支持 HTTPS CONNECT 隧道。不带 `--mitm` 时，CONNECT 请求原样放行；带 `--mitm` 时拦截连接并应用基于主机的凭据注入。

### `trustless dlp` — 出站 DLP 反向代理（原 dlp-proxy）

`trustless dlp` 是原 `github.com/ikkun1222/dlp-proxy` 的继任子命令：一个出站 DLP 反向代理，在 LLM API 请求体离开主机前，用 `<redacted>` 掩蔽已知密钥。

```bash
trustless dlp start -config ~/.config/dlp-proxy/config.json   # 启动 DLP 反向代理（默认 127.0.0.1:8787）
trustless dlp scrub-db  <db-path> [--apply] [--backup]        # 扫描/清洗 SQLite 数据库中的密钥
trustless dlp scrub-text <path>   [--apply]                   # 扫描/清洗文本文件/目录中的密钥
```

- **配置 schema 与 dlp-proxy 相同（JSON）**：`listen` / `min_secret_len` / `secrets_source`（`pass` | `bitwarden`，默认 pass） / `secrets_refresh_interval`（**必填**，如 `"10m"`） / `routes`（前缀 → 上游 URL）
- **密钥通过共享后端加载**（`backend.Values`）；原 bitwardenloader/passstore 已移除
- **fail-closed**：密钥加载失败则启动中止；重载失败时保留上一组并记录警告（fail-safe）
- **热重载**：按 `secrets_refresh_interval` 周期刷新 + SIGHUP 立即重载
- **双层脱敏**（2026-08-14）：第 1 层 = 已知值子串扫描（零误报）；第 2 层 = 兼容 gitleaks 的模式规则（API 密钥格式、JWT、私钥等），带关键词预过滤 → RE2 正则 → Shannon 熵阈值（默认 3.5，可按规则覆盖）。模式规则打包在 `internal/dlp/redact/rules.toml`（40 条规则，`//go:embed`），源自 [gitleaks](https://github.com/gitleaks/gitleaks)（MIT，Copyright (c) 2019 Zachary Rice——见 `LICENSE.gitleaks` / `NOTICE`）
- **新增配置字段**：`rules_file`（外部 gitleaks 兼容规则 TOML 路径；空 = 内置规则） / `pattern_mode`（`"mask"` = 脱敏模式命中，`"log"` = 仅检测、请求体不变、审计事件带 `detail="patterns=hit&mode=log"`） / `pattern_disabled`（要禁用的规则 ID 列表，如 `["generic-api-key"]` 用于屏蔽误报规则）
- **热重载（serve）**：`trustless serve` 在每次重载时重新应用 `pattern_mode` / `pattern_disabled` / `rules_file`（通过 `kill -HUP $(pgrep -f 'trustless serve')` 或 10 分钟周期刷新）——配置被重新读取，模式集原子替换（`PatternSet.Replace`），失败时保留上一状态（fail-safe）。独立 `trustless dlp start` 仅在启动时读取
- 原 dlp-proxy 仓库已冻结（2026-08-13）；`trustless dlp` 是其替代品

**Scrub 命令** —— 清理已经残留在磁盘上的密钥（代理会话数据库、日志、转储），使用与在线代理相同的双层脱敏：

```bash
trustless dlp scrub-db  ~/.local/state/hermes/sessions.db            # dry-run：仅扫描
trustless dlp scrub-db  ~/.local/state/hermes/sessions.db --apply    # 写入更改
trustless dlp scrub-db  ~/.local/state/hermes/sessions.db --apply --backup  # 先保留 .bak 副本
trustless dlp scrub-text ~/.hermes/sessions --apply                  # 清理文本文件/目录
```

- **默认是 dry-run**：两个命令都只打印每个表/文件的命中数而不写入。实际清理需加 `--apply`；`scrub-db` 还支持 `--backup`（写入前复制到 `<db>.bak`）和 `--min-len`（最小密钥长度，默认 8）。
- **`scrub-db`** 针对 SQLite 数据库：第 1 层已知值替换 + 第 2 层模式掩蔽，随后**重建 FTS 虚拟表**并执行 `VACUUM`，确保文件中不残留物理痕迹（已由测试验证）。
- **`scrub-text`** 以相同的双层脱敏遍历文件或目录树（代理的 `sessions/`、日志、转储）。
- 两者都通过 DLP 配置的 `secrets_source`（pass / bitwarden）加载密钥，并遵循 `pattern_mode` —— `"log"` 只计数不掩蔽，`"mask"` 就地脱敏。

### `trustless setup` — 首次设置向导

自动化完整首次设置的交互式向导：

```bash
trustless setup
```

**4 步流程：**

| 步骤 | 动作 | 自动检测 |
|------|--------|----------------|
| [1/4] GPG 密钥 | 检测现有密钥或批量创建 RSA 3072（无口令，5 年有效期） | 扫描 `gpg --list-secret-keys` |
| [2/4] pass 存储 | 初始化 pass 存储、git init | 检查 `pass` 可用性 |
| [3/4] .env 导入 | 扫描目录中的 .env 文件，解析 KEY=VALUE，导入 pass，备份原件 | 遍历 `--import-dir` 路径（默认：`.`） |
| [4/4] 代理集成 | 检测 AI 编码代理并**安装 trustless-usage SKILL.md** 到其技能目录（确认后） | 配置文件存在性 + grep trustless 引用 |

**各代理的技能安装路径：**

| 代理 | 技能目录 |
|-------|----------------|
| OpenCode | `~/.config/opencode/skills/trustless-usage/` |
| Claude Code | `~/.claude/skills/trustless-usage/` |
| Codex | `~/.codex/skills/trustless-usage/` |
| Hermes | `~/.hermes/skills/credential-management/trustless-usage/` |

安装的技能会教会 AI 代理凭据约定：用 `trustless run` 注入、用 `trustless secret set` 注册、绝不存储明文凭据。

**选项：**

| 标志 | 说明 |
|------|-------------|
| `--non-interactive` | 非交互模式运行（安全默认值，无提示，不删除文件） |
| `--import-dir <dir>` | 扫描 .env 文件的目录（可重复，默认：`.`） |

**当前支持检测的代理：** OpenCode, Claude Code, Codex, Hermes。

### `trustless doctor` — 系统健康检查

校验整个 trustless 环境的诊断工具：

```bash
trustless doctor           # 人类可读输出
trustless doctor --json    # 供 cron/SIEM 使用的结构化 JSON
trustless doctor --fix     # 自动解决检测到的问题（stub）
```

**执行的健康检查：** GPG 密钥有效性、pass 存储健康、gpg-agent 状态、.env 文件安全扫描、代理集成状态、MITM CA 证书安装。

### `trustless config` — 工具配置

| 子命令 | 说明 |
|------------|-------------|
| `init` | 在 `~/.config/trustless/config.toml` 创建默认配置 |
| `show` | 打印当前配置 |
| `set <key> <value>` | 更新配置值 |

**配置键：**

| 键 | 说明 | 默认 |
|-----|-------------|---------|
| `backend` | 凭据后端（`pass`、`env`、`bitwarden`） | `pass` |
| `output` | 默认输出模式 | `json` |
| `run_defaults.sanitize` | 默认启用脱敏 | `true` |
| `run_defaults.timeout` | 默认子进程超时 | `5m` |
| `proxy.port` | 默认代理端口 | `8080` |
| `policy.default.denied_commands` | 全局禁用的命令（如 `sh,bash`） | （空） |

**配置文件位置：** `~/.config/trustless/config.toml`（可通过 `TRUSTLESS_CONFIG` 环境变量覆盖）

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

### `trustless completion` — Shell 补全

为 bash、zsh 或 fish 生成 shell 补全脚本：

```bash
trustless completion bash > /etc/bash_completion.d/trustless
trustless completion zsh > /usr/local/share/zsh/site-functions/_trustless
trustless completion fish > ~/.config/fish/completions/trustless.fish
```

### `trustless version` — 版本信息

```bash
trustless version
```

## 架构

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

### 后端抽象

凭据解析器被抽象为简单接口：

```go
type Backend interface {
    Resolve(ctx context.Context, key string) (string, error)
    List(ctx context.Context) ([]Entry, error)
}
```

已实现的后端：
- **`pass`**（默认）—— 封装 `pass show <key>`，读取第一行作为密钥
- **`env`** —— 通过 `os.Getenv()` 从环境变量读取（用于 CI/CD、容器）
- **`bitwarden`** —— 封装 `bw` CLI（`bw list items`），解析 secureNote `fields[value]` / 登录密码 / notes 首行。会话密钥通过 `BW_SESSION` 环境变量传递（绝不经过 argv）。通过 `trustless bw-unlock` 解锁（会话密钥保存到 `~/.config/trustless/bw-session`，0600）。会话无效时 fail closed。详见 [docs/bitwarden-backend-design.md](docs/bitwarden-backend-design.md)

通过 `trustless config set backend <name>` 配置。

## 安全模型

### trustless 保证什么

1. **凭据值永远不会进入 LLM 上下文窗口**
   - `run`：凭据设置在子进程环境上，输出在返回前被扫描并脱敏
   - `proxy`：凭据在代理进程内部替换；代理只看到 API 响应
   - 直接 `get` 会输出值，但需要显式调用（正常流程中代理不可用）

2. **命令参数扫描**（`--scan-args`）
   - 启动子进程前，扫描所有命令参数中的凭据模式和注入值
   - 若检测到，以退出码 3 阻止执行（fail closed）
   - 防止代理在 CLI 参数中意外暴露凭据值

3. **策略引擎** —— 命令级访问控制
   - `policy.default.denied_commands`：全局阻止危险命令（如 `sh`、`bash`）
   - `policy.<key>.denied_commands`：按凭据阻止特定命令
   - Fail-closed：策略违规以退出码 3 阻止执行

4. **子进程输出脱敏**
   - 默认模式匹配常见凭据格式：GitHub 令牌、OpenAI 密钥、xAI 密钥、AWS 密钥、Bearer 令牌和通用模式
   - **注入值本身也会被模式扫描**：如果子进程回显了凭据，该值会被脱敏
   - 可通过配置文件或 `--sanitize-policy` 自定义模式

5. **最小攻击面**
   - 代理默认监听 `127.0.0.1`（不暴露到网络）
   - 提供 Unix socket 模式以进行文件权限控制
   - MITM 代理按主机名生成临时证书（24h 有效期）
   - 单一二进制，除 `pass` + `gpg` 外零运行时依赖（`bitwarden` 后端额外需要 `bw` CLI）

6. **broker 进程不持久化凭据**
   - 凭据按需解析，子进程退出后释放
   - HTTP 代理仅在活跃请求处理期间在内存中持有凭据

### trustless 不解决什么（v1 范围）

- **动态/轮换凭据** —— pass 存储是静态的；轮换由外部处理
- **完整审计追踪** —— 仅基础日志；SIEM 导出是未来工作
- **硬件密钥存储** —— 依赖 GPG 密钥环安全
- **HTTPS MITM CA 信任管理** —— MITM 代理生成 CA 证书；用户必须将其安装到操作系统信任库

## 配置

配置存储在 `~/.config/trustless/config.toml`。使用 `trustless config init` 创建默认文件，或手动创建。

配置文件路径可通过 `TRUSTLESS_CONFIG` 环境变量覆盖。

完整配置选项见[设计文档](docs/design.md)。

## 开发

### 前置条件

- Go 1.26+
- `pass` CLI + `gpg`（用真实后端测试时）

### 构建

```bash
git clone https://github.com/ikkun1222/trustless
cd trustless
go build -o trustless .
```

### 测试

```bash
go test ./...
```

### 项目结构

```
├── main.go                          # CLI 入口点与子命令分发
├── plugin.json                      # Agent Plugins 1.0.0 清单
├── skills/
│   └── trustless-usage/             # 符合 Agent Skills 规范的 SKILL.md
├── schemas/
│   └── plugin.schema.json           # 内置官方 Agent Plugins schema
├── internal/
│   ├── backend/
│   │   ├── backend.go               # Backend 接口 + 类型
│   │   ├── env.go                   # 环境变量后端
│   │   └── pass.go                  # Pass CLI 后端实现
│   ├── config/
│   │   └── config.go                # TOML 配置加载/保存（+ 策略类型）
│   ├── proxy/
│   │   ├── ca.go                    # MITM CA 证书生成
│   │   ├── command.go               # 带凭据替换的 HTTP 转发代理
│   │   └── mitm.go                  # MITM CONNECT 处理器（HTTPS 拦截）
│   ├── run/
│   │   └── command.go               # 子进程凭据注入（+ 策略检查）
│   ├── scanner/
│   │   ├── scanner.go               # 基于模式的凭据脱敏
│   │   └── scanner_test.go          # Scanner 测试
│   └── secret/
│       └── command.go               # 凭据存储操作
├── scripts/
│   └── validate-plugin.py           # Agent Plugins 打包校验
└── docs/
    └── design.md                    # 架构与设计文档
```

### 依赖

trustless 只有一个外部依赖——其余全部是 Go 标准库：

- `github.com/pelletier/go-toml/v2` —— TOML 配置文件解析

### 退出码

| 代码 | 含义 |
|------|---------|
| 0 | 成功 |
| 1 | 一般错误 |
| 2 | 凭据未找到 / 参数无效 |
| 3 | 子进程错误 / 策略违规 / 参数中含凭据 |
| 4 | 配置错误 |

## 许可证

MIT
