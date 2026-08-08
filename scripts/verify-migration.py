#!/usr/bin/env python3
"""Verify pass → Bitwarden migration: compare every key's value on both sides.

For each pass entry (filesystem walk of ~/.password-store, same key set and
exclusions as migrate-pass-to-bitwarden.py), the value is fetched with
`pass show <key>` and from Bitwarden with `bw list items` (fields[0].value,
design §3.1 mapping). Only key names and a match/mismatch verdict are printed
— values are never displayed.

Exit code: 0 = all compared keys match, 1 = any mismatch (mismatches listed).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

PASSWORD_STORE = Path(os.environ.get("PASSWORD_STORE_DIR", "~/.password-store")).expanduser()
EXCLUDE_PREFIXES = ("iria/api/bitwarden/",)
FIELD_VALUE = "value"


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def pass_keys() -> list[str]:
    if not PASSWORD_STORE.is_dir():
        sys.exit(f"error: pass store not found: {PASSWORD_STORE}")
    keys = []
    for gpg in sorted(PASSWORD_STORE.rglob("*.gpg")):
        key = gpg.relative_to(PASSWORD_STORE).with_suffix("").as_posix()
        if key.startswith(EXCLUDE_PREFIXES):
            continue
        keys.append(key)
    return keys


def pass_value(key: str) -> str | None:
    result = run(["pass", "show", key])
    if result.returncode != 0:
        return None
    lines = result.stdout.splitlines()
    return lines[0] if lines else ""


def parse_item_list(raw: str) -> list[dict]:
    items: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, list):
            items.extend(o for o in obj if isinstance(o, dict))
        elif isinstance(obj, dict):
            items.append(obj)
    return items


def bw_items() -> list[dict]:
    result = run(["bw", "list", "items"])
    if result.returncode != 0:
        sys.exit(
            "error: `bw list items` failed"
            f" ({result.returncode}): {result.stderr.strip() or 'is BW_SESSION set?'}"
        )
    return parse_item_list(result.stdout)


def bw_value(item: dict) -> str | None:
    """Value as stored by the migration (fields[0] named 'value', hidden)."""
    for field in item.get("fields", []) or []:
        if field.get("name") == FIELD_VALUE:
            return field.get("value", "")
    return None


def verify(compare_excluded: bool, quiet: bool) -> int:
    keys = pass_keys()
    items = {item.get("name", ""): item for item in bw_items() if item.get("name")}

    mismatches: list[tuple[str, str]] = []
    missing_bw: list[str] = []
    missing_pass: list[str] = []
    compared = 0

    for key in keys:
        if not compare_excluded and key.startswith(EXCLUDE_PREFIXES):
            continue
        pass_val = pass_value(key)
        item = items.get(key)
        if item is None:
            if pass_val is None:
                continue  # broken on both sides; nothing meaningful to say
            missing_bw.append(key)
            mismatches.append((key, "missing in Bitwarden"))
            continue
        bw_val = bw_value(item)
        if pass_val is None:
            missing_pass.append(key)
            mismatches.append((key, "missing in pass"))
            continue
        compared += 1
        if pass_val == bw_val:
            if not quiet:
                print(f"ok    {key}")
        else:
            mismatches.append((key, "value mismatch"))
            if not quiet:
                print(f"FAIL  {key}  value mismatch")

    print(f"\ncompared: {compared} keys"
          f"{', mismatches: ' + str(len(mismatches)) if mismatches else ''}")
    if mismatches:
        for key, reason in mismatches:
            print(f"  FAIL {key} — {reason}")
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "The Bitwarden session key is read from the BW_SESSION environment "
            "variable. Values are never printed — only key names and verdicts."
        ),
    )
    parser.add_argument(
        "--compare-excluded",
        action="store_true",
        help="also compare iria/api/bitwarden/* keys (excluded from migration)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="print only the summary and any mismatches",
    )
    args = parser.parse_args()
    return verify(compare_excluded=args.compare_excluded, quiet=args.quiet)


if __name__ == "__main__":
    sys.exit(main())
