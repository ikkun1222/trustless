---
name: trustless-usage
description: >-
  Use trustless CLI for credential management. All credentials are stored in
  the pass password store (GPG-encrypted). The agent injects secrets into
  subprocess memory only — never sees plaintext values. Run commands with
  `trustless run -s <key> -- <command>`. Register new credentials with
  `trustless secret set <key>`.
version: 0.1.0
agentskills: true
tags:
  - credentials
  - security
  - linux
  - pass
  - ai-agents
  - secrets
install:
  hermes: hermes skills install ikkun1222/trustless/skills/trustless-usage
  opencode: npx add-skill https://github.com/ikkun1222/trustless/tree/main/skills/trustless-usage
---

# trustless-usage

This machine uses [trustless](https://github.com/ikkun1222/trustless) CLI for credential management across all AI agent sessions.

## Core Rules

- **Never use plaintext .env files or hardcoded API keys.** All credentials are stored in the `pass` password store (GPG-encrypted) via trustless.
- **The agent NEVER sees plaintext credential values.** trustless injects secrets into subprocess memory only.
- **All output is automatically sanitized.** Credential patterns in stdout/stderr are REDACTED by default.
- **Command arguments are scanned for credentials** (`--scan-args` is on by default). If detected, execution is blocked.

## OAuth Credentials

Some credentials are OAuth entries (stored as `type=oauth` JSON). They resolve like any other key via `trustless run -s <key>`, and trustless auto-refreshes the access token when it expires. If resolution fails with a reauth error (refresh token revoked), re-authenticate with `trustless oauth login <provider> <key>` — or run `trustless oauth refresh <key>` to force a refresh ahead of expiry. Check state with `trustless oauth status <key>` and list configured providers with `trustless oauth providers`.

## Audit Logs

trustless records structured audit events as JSONL — `proxy.inject` / `proxy.deny` / `run.spawn` / `dlp.redact` / `oauth.refresh` / `oauth.fail` / `oauth.reauth_required`. **Events never contain token or secret values** — only key names, hosts, and verdicts. The serve process writes to journald (or stdout JSONL); standalone commands append to `~/.local/state/trustless/audit.jsonl` (0600). View with `journalctl --user -u trustless | grep '"event"'` or `tail -f ~/.local/state/trustless/audit.jsonl`.

## DLP Pattern Layer (gitleaks-compatible, 2026-08-14)

The outbound DLP (`trustless dlp start` / `trustless serve`) redacts in two layers:

1. **Layer 1 — known values**: substring scan of the secret list loaded from the backend (pass/bitwarden). Zero false positives.
2. **Layer 2 — patterns**: gitleaks-compatible rules (40 bundled in `internal/dlp/redact/rules.toml` via `//go:embed`; MIT attribution to gitleaks, see `LICENSE.gitleaks` / `NOTICE`). Each rule: keyword pre-filter → RE2 regex → Shannon entropy threshold (default 3.5, per-rule override via the `entropy` field). Detects unregistered secrets (OpenAI/Anthropic/GitHub/AWS/GCP/Slack/Stripe keys, JWT, private keys, ...).

Config (dlp config JSON):
- `rules_file`: external gitleaks-compatible rules TOML path (empty = bundled). `~` is expanded. Startup fails if missing/invalid (fail-closed).
- `pattern_mode`: `"mask"` (default, redacts pattern matches) or `"log"` (detects only — body unchanged, audit event `dlp.redact` with `detail="patterns=hit&mode=log"`). Layer 1 always masks regardless of mode.
- `pattern_disabled`: list of rule IDs to disable (e.g. `["generic-api-key"]`); unknown IDs fail the reload (fail-closed).

Both `trustless dlp start` and `trustless serve` build the pattern set from the same config (`dlp.BuildPatternSet`). In `trustless serve`, `pattern_mode` / `pattern_disabled` / `rules_file` changes are applied on every reload — SIGHUP (`kill -HUP $(pgrep -f 'trustless serve')`) or the periodic refresh — with atomic `PatternSet.Replace` and fail-safe semantics (failed reload keeps the previous state + WARN). Standalone `trustless dlp start` reads them at startup only. The `scrub-db` / `scrub-text` commands also support the pattern layer from the same config: dry-run (no `--apply`) reports pattern hits, and `pattern_mode: "log"` never replaces pattern matches even with `--apply`.

## Running Commands with Credentials

To run a command with credential injection:

```
trustless run -s <key> -- <command>
```

Example:
```
trustless run -s iria/api/openai -- curl -s https://api.openai.com/v1/models
```

Multiple credentials:
```
trustless run -s GITHUB_TOKEN -s OPENAI_KEY -- gh pr list
```

Override environment variable name:
```
trustless run -s iria/api/openai:MY_OPENAI_KEY -- python train.py
```

## Registering a New Credential

```
trustless secret set <key>
```

You will be prompted to enter the value. The credential is stored GPG-encrypted in `pass` immediately.

List all stored credentials:
```
trustless secret list
```

Retrieve a credential (direct access, for scripting):
```
trustless secret get <key>
```

## Proxy Mode (for HTTP-based tools)

Start a local HTTP proxy that automatically substitutes credential placeholders:

```
trustless proxy start --port 8080
```

Then configure your tool to use the proxy:
```
export HTTPS_PROXY=http://127.0.0.1:8080
```

Placeholder format: `__KEY_NAME__` in request headers/body gets replaced with the real credential value.

For HTTPS interception (MITM):
```
trustless proxy start --port 8080 --mitm
```

## First-Time Setup

```
trustless setup
```

Interactive wizard that:
1. Verifies the `pass` store and GPG key are accessible
2. Creates configuration
3. Imports existing .env files
4. Installs this skill for detected AI coding agents

## Health Check

```
trustless doctor           # Human-readable
trustless doctor --json    # Structured JSON output
trustless doctor --fix     # Auto-resolve issues
```

## Security Notes

- trustless runs on `127.0.0.1` only (proxy mode) — no network exposure
- Failed credential resolution blocks execution (fail closed)
- Policy engine can restrict which commands can use which credentials
- Never pipe credential values through stdin manually
- Never echo or print credential values — trustless handles masking automatically
