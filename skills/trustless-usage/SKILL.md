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
