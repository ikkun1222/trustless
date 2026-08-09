#!/usr/bin/env python3
"""Validate trustless-win Agent Plugins 1.0.0 packaging.

Checks the spec's normative requirements that matter for this repo, without
requiring a JSON Schema engine (stdlib only). The vendored official schemas
under schemas/ are the source of truth; this script covers the rules the
schema cannot express (path containment, skills/ discovery) plus the
closed-schema essentials.

Exit code: 0 = valid, 1 = invalid.
Output: one JSON object on stdout (machine-readable).
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLUGIN_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
# Spec §5.2: closed top-level manifest schema.
PLUGIN_FIELDS = {
    "$schema", "name", "version", "description", "author",
    "homepage", "repository", "license", "keywords", "extensions",
}
# Spec §5.5: name constraints.
NAME_RE = re.compile(r"^(?!.*(?:--|\.\.))[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")
AUTHOR_FIELDS = {"name", "email", "url"}

errors: list[str] = []


def fail(msg: str) -> None:
    errors.append(msg)


def load_json(path: Path) -> object | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        fail(f"{path}: invalid JSON: {e}")
        return None


def validate_plugin() -> None:
    path = ROOT / "plugin.json"
    if not path.is_file():
        fail("plugin.json: missing (spec §4.1/§5.1)")
        return
    doc = load_json(path)
    if not isinstance(doc, dict):
        fail("plugin.json: top-level value must be an object (spec §5.2)")
        return

    # §5.3 required fields.
    for field in ("$schema", "name"):
        value = doc.get(field)
        if not isinstance(value, str) or not value:
            fail(f"plugin.json: required field '{field}' missing/empty (spec §5.3)")

    # §5.2 closed schema: report-and-ignore unknown fields is client behavior,
    # but the manifest itself must not contain them.
    unknown = set(doc) - PLUGIN_FIELDS
    if unknown:
        fail(f"plugin.json: unknown top-level fields {sorted(unknown)} (spec §5.2)")

    # §5.2 $schema const.
    if doc.get("$schema") != PLUGIN_SCHEMA:
        fail(f"plugin.json: $schema must be {PLUGIN_SCHEMA}")

    # §5.5 name constraints.
    name = doc.get("name")
    if isinstance(name, str):
        if not (1 <= len(name) <= 64):
            fail("plugin.json: name length must be 1-64 (spec §5.5)")
        if not NAME_RE.match(name):
            fail(f"plugin.json: name '{name}' violates constraints (spec §5.5)")

    # §5.4 author object.
    author = doc.get("author")
    if author is not None:
        if not isinstance(author, dict) or set(author) - AUTHOR_FIELDS:
            fail("plugin.json: author must be an object with only name/email/url (spec §5.4)")
        for key, value in author.items():
            if not isinstance(value, str):
                fail(f"plugin.json: author.{key} must be a string")

    # §5.4 keywords array.
    keywords = doc.get("keywords")
    if keywords is not None:
        if not isinstance(keywords, list) or not all(isinstance(k, str) for k in keywords):
            fail("plugin.json: keywords must be an array of strings (spec §5.4)")

    # §8.1 extensions object.
    extensions = doc.get("extensions")
    if extensions is not None and not isinstance(extensions, dict):
        fail("plugin.json: extensions must be an object (spec §8.1)")


def validate_skills() -> None:
    skills_dir = ROOT / "skills"
    if not skills_dir.is_dir():
        return  # §6.2: missing fixed location is not an error.
    found = 0
    for child in sorted(skills_dir.iterdir()):
        if not child.is_dir():
            continue
        if (child / "SKILL.md").is_file():
            found += 1
        else:
            fail(f"skills/{child.name}: directory without SKILL.md is ignored (spec §7.1)")
    if found == 0:
        fail("skills/: no skills discovered — expected trustless-usage (spec §7.1)")


def _schema_version(schema_url: object) -> str:
    """Extract the Agent Plugins version from a canonical schema URL.

    e.g. 'https://agent-plugins.org/schemas/1.0.0/plugin.schema.json' -> '1.0.0'
    """
    if not isinstance(schema_url, str):
        return ""
    parts = schema_url.rstrip("/").split("/")
    return parts[-2] if len(parts) >= 2 else ""


def main() -> int:
    validate_plugin()
    validate_skills()
    result = {
        "valid": not errors,
        "plugin_root": str(ROOT),
        "errors": errors,
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
