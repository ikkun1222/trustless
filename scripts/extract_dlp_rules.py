#!/usr/bin/env python3
"""Extract the 40 approved gitleaks rules into internal/dlp/redact/rules.toml.

Derives the DLP pattern-rule asset from gitleaks' config/gitleaks.toml
(MIT License, Copyright (c) 2019 Zachary Rice). Only the schema fields
id/description/regex/keywords/entropy/secret_group are carried over.
"""
import sys
import tomllib

SRC = "/tmp/gitleaks.toml"
OUT = "internal/dlp/redact/rules.toml"

TARGET_IDS = [
    "aws-access-token",
    "aws-amazon-bedrock-api-key-long-lived",
    "aws-amazon-bedrock-api-key-short-lived",
    "github-pat",
    "github-fine-grained-pat",
    "github-oauth",
    "gitlab-pat",
    "gitlab-cicd-job-token",
    "gitlab-oauth-app-secret",
    "openai-api-key",
    "anthropic-api-key",
    "gcp-api-key",
    "slack-bot-token",
    "slack-user-token",
    "slack-webhook-url",
    "stripe-access-token",
    "twilio-api-key",
    "sendgrid-api-token",
    "npm-access-token",
    "pypi-upload-token",
    "rubygems-api-token",
    "heroku-api-key",
    "azure-ad-client-secret",
    "jwt",
    "private-key",
    "generic-api-key",
    "telegram-bot-api-token",
    "discord-api-token",
    "dropbox-api-token",
    "shopify-access-token",
    "square-access-token",
    "datadog-access-token",
    "digitalocean-pat",
    "fastly-api-token",
    "grafana-api-key",
    "huggingface-access-token",
    "age-secret-key",
    "mailchimp-api-key",
    "mailgun-pub-key",
    "microsoft-teams-webhook",
]

HEADER = """\
# DLP pattern rules for trustless.
# Derived from gitleaks config/gitleaks.toml — MIT License,
# Copyright (c) 2019 Zachary Rice. See LICENSE.gitleaks / NOTICE.
# Schema is gitleaks-compatible: id/description/regex/keywords/entropy/secret_group.
"""

ALLOWED_FIELDS = ("id", "description", "regex", "keywords", "entropy", "secret_group")


def toml_scalar(v):
    if isinstance(v, str):
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, list):
        return "[" + ", ".join(toml_scalar(x) for x in v) + "]"
    raise TypeError(f"unsupported TOML value: {v!r}")


def main():
    with open(SRC, "rb") as f:
        data = tomllib.load(f)

    source_rules = {r["id"]: r for r in data["rules"]}
    missing = [i for i in TARGET_IDS if i not in source_rules]
    if missing:
        sys.exit(f"error: {len(missing)} target rule(s) missing from {SRC}: {missing}")
    if len(set(TARGET_IDS)) != len(TARGET_IDS):
        sys.exit("error: duplicate ids in TARGET_IDS")

    lines = [HEADER.rstrip("\n")]
    for rid in TARGET_IDS:
        rule = source_rules[rid]
        lines.append("[[rules]]")
        for field in ALLOWED_FIELDS:
            if field in rule:
                if field == "regex":
                    lines.append("regex = '''" + rule["regex"] + "'''")
                else:
                    lines.append(f"{field} = {toml_scalar(rule[field])}")
        lines.append("")

    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"wrote {len(TARGET_IDS)} rules to {OUT}")


if __name__ == "__main__":
    main()
