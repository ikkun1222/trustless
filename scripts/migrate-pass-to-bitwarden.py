#!/usr/bin/env python3
"""Migrate pass store entries to Bitwarden as secureNote items.

Reads every .gpg entry under ~/.password-store (filesystem walk), maps each
entry to a Bitwarden secureNote item per docs/bitwarden-backend-design.md §5.2:

    name        = <key>                        (e.g. "iria/api/openrouter")
    fields[0]   = {"name": "value", "value": <1st line>, "type": 1 (hidden)}
    notes       = remaining lines (metadata)

Item JSON is Base64-encoded and piped to `bw create item <encoded>` on stdin;
the session key is taken from the BW_SESSION environment variable only (never
argv, see design §9 H-1).

Idempotent: an item whose name already exists in the vault is skipped. Keys
under iria/api/bitwarden/* are excluded (bootstrap auth is split out to
credentials.env, design §3.2 H-2).

Values are never printed or logged: --dry-run prints keys with the value
masked; the full run prints key names only.

Exit code: 0 = all entries migrated (or skipped), 1 = any failure. A single
failed entry does not stop the run, but failures are aggregated and reported.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
from pathlib import Path

PASSWORD_STORE = Path(os.environ.get("PASSWORD_STORE_DIR", "~/.password-store")).expanduser()
EXCLUDE_PREFIXES = ("iria/api/bitwarden/",)
FIELD_VALUE = "value"


def run(cmd: list[str], *, check: bool = False) -> subprocess.CompletedProcess:
    """Run a subprocess with secrets never passed via argv."""
    return subprocess.run(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=check,
    )


def pass_keys() -> list[str]:
    """Enumerate all pass entry keys (relative to the store root)."""
    if not PASSWORD_STORE.is_dir():
        sys.exit(f"error: pass store not found: {PASSWORD_STORE}")
    keys = []
    for gpg in sorted(PASSWORD_STORE.rglob("*.gpg")):
        key = gpg.relative_to(PASSWORD_STORE).with_suffix("").as_posix()
        if key.startswith(EXCLUDE_PREFIXES):
            continue
        keys.append(key)
    return keys


def pass_show(key: str) -> str:
    """Return the decrypted pass entry content for key."""
    result = run(["pass", "show", key])
    if result.returncode != 0:
        raise RuntimeError(
            f"pass show {key} failed ({result.returncode}): {result.stderr.strip()}"
        )
    return result.stdout


def item_from_entry(key: str, content: str) -> dict:
    """Build the Bitwarden secureNote item JSON for a pass entry."""
    lines = content.splitlines()
    value = lines[0] if lines else ""
    notes = "\n".join(lines[1:])
    return {
        "type": 2,  # secureNote
        "name": key,
        "secureNote": {"type": 0},
        "fields": [{"name": FIELD_VALUE, "value": value, "type": 1}],  # type 1 = hidden
        "notes": notes,
    }


def mask(value: str) -> str:
    """Mask a secret for display: keep nothing of the value itself."""
    if not value:
        return "(empty)"
    return f"<{len(value)} chars>"


def parse_item_list(raw: str) -> list[dict]:
    """Parse `bw list items` output, tolerating bws-style NDJSON lines."""
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


def existing_item_names() -> set[str]:
    """Names of all items currently in the Bitwarden vault."""
    result = run(["bw", "list", "items"])
    if result.returncode != 0:
        sys.exit(
            "error: `bw list items` failed"
            f" ({result.returncode}): {result.stderr.strip() or 'is BW_SESSION set?'}"
        )
    names = {item.get("name", "") for item in parse_item_list(result.stdout)}
    return {name for name in names if name}


def field_value(item: dict) -> str | None:
    """Extract the hidden 'value' field from a Bitwarden item (design §3.1)."""
    for field in item.get("fields", []) or []:
        if field.get("name") == FIELD_VALUE:
            return field.get("value", "")
    return None


def create_item(item: dict) -> None:
    """Create one Bitwarden item via `bw create item` (Base64 JSON on stdin)."""
    encoded = base64.b64encode(json.dumps(item, ensure_ascii=False).encode("utf-8")).decode(
        "ascii"
    )
    result = subprocess.run(
        ["bw", "create", "item", encoded],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"bw create item {item['name']} failed ({result.returncode}): {result.stderr.strip()}"
        )


def migrate(dry_run: bool, show_meta: bool) -> int:
    keys = pass_keys()
    existing = existing_item_names()

    errors: list[str] = []
    created = 0
    skipped = 0
    for key in keys:
        if key in existing:
            print(f"skip  {key} (already exists)")
            skipped += 1
            continue
        try:
            content = pass_show(key)
        except RuntimeError as e:
            errors.append(str(e))
            continue
        item = item_from_entry(key, content)
        if dry_run:
            prefix = "plan  "
            line = f"{prefix}{key}  value={mask(item['fields'][0]['value'])}"
            if show_meta and item["notes"]:
                line += f"  notes={len(item['notes'])} chars"
            print(line)
            continue
        try:
            create_item(item)
        except RuntimeError as e:
            errors.append(str(e))
            continue
        print(f"create {key}")
        created += 1

    print(f"\ntotal: {len(keys)} keys ({created} created, {skipped} skipped"
          f"{', ' + str(len(errors)) + ' failed' if errors else ''})")
    if errors:
        print("\nerrors:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "The Bitwarden session key is read from the BW_SESSION environment "
            "variable. Values are never printed or logged."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="list keys that would be created (values masked); do not create anything",
    )
    parser.add_argument(
        "--show-meta",
        action="store_true",
        help="in --dry-run, also show the length of each entry's metadata (notes)",
    )
    args = parser.parse_args()
    return migrate(dry_run=args.dry_run, show_meta=args.show_meta)


if __name__ == "__main__":
    sys.exit(main())
