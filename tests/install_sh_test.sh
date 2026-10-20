#!/usr/bin/env bash
# Verifies scripts/install.sh against a loopback HTTP release fixture.
# Run with: make test-install-sh
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
INSTALLER="$ROOT/scripts/install.sh"
WORK=$(mktemp -d)
SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

PASS=0
pass() { printf 'PASS: %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

# Build a deterministic PATH without cosign so the "cosign absent" branch is
# exercised regardless of the host machine.
BIN="$WORK/bin"
mkdir -p "$BIN"
for tool in uname tr mkdir mktemp rm install curl wget sha256sum awk sh; do
    src=$(command -v "$tool" 2>/dev/null || true)
    [ -n "$src" ] && ln -s "$src" "$BIN/$tool"
done

SERVER="$WORK/server"
mkdir -p "$SERVER"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
esac
ASSET="trustless-${OS}-${ARCH}"

# Fake release binary: prints the version marker the test asserts on.
cat > "$SERVER/$ASSET" <<'EOF'
#!/bin/sh
case "${1:-}" in
    version) echo v0.0.0-test ;;
    *) echo "trustless v0.0.0-test" ;;
esac
EOF
chmod 755 "$SERVER/$ASSET"

write_sums() {
    (cd "$SERVER" && sha256sum "$ASSET" > SHA256SUMS)
}
write_sums

PORT=$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)
python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$SERVER" \
    >"$WORK/http.log" 2>&1 &
SERVER_PID=$!

BASE="http://127.0.0.1:${PORT}"
for _ in $(seq 1 50); do
    if curl -fsS "$BASE/SHA256SUMS" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done
curl -fsS "$BASE/SHA256SUMS" >/dev/null 2>&1 || fail "fixture HTTP server did not start"

run_installer() {
    local dir="$1"
    shift
    PATH="$BIN" \
        TRUSTLESS_INSTALL_DIR="$dir" \
        TRUSTLESS_RELEASE_BASE="$BASE" \
        "$BIN/sh" "$INSTALLER" --minimal "$@"
}

echo "== case 1: normal install from loopback fixture =="
OUT_OK="$WORK/install-ok"
if ! run_installer "$OUT_OK" >"$WORK/ok.log" 2>&1; then
    cat "$WORK/ok.log"
    fail "normal install exited non-zero"
fi
cat "$WORK/ok.log"
[ -x "$OUT_OK/trustless" ] || fail "installed binary is missing or not executable"
GOT=$(PATH="$BIN" "$OUT_OK/trustless" version)
[ "$GOT" = "v0.0.0-test" ] || fail "unexpected version output: $GOT"
pass "normal install placed an executable binary (version: $GOT)"

echo
echo "== case 2: tampered SHA256SUMS =="
printf '%064d  %s\n' 0 "$ASSET" > "$SERVER/SHA256SUMS"
OUT_BAD="$WORK/install-bad"
if run_installer "$OUT_BAD" >"$WORK/bad.log" 2>&1; then
    cat "$WORK/bad.log"
    fail "installer accepted a tampered checksum"
fi
cat "$WORK/bad.log"
[ ! -e "$OUT_BAD/trustless" ] || fail "binary was installed despite checksum mismatch"
pass "tampered checksum caused a non-zero exit and no installation"

echo
echo "== case 3: SHA256SUMS has no entry for the asset =="
HASH=$(sha256sum "$SERVER/$ASSET" | awk '{print $1}')
printf '%s  not-our-asset\n' "$HASH" > "$SERVER/SHA256SUMS"
OUT_MISSING="$WORK/install-missing"
if run_installer "$OUT_MISSING" >"$WORK/missing.log" 2>&1; then
    cat "$WORK/missing.log"
    fail "installer accepted SHA256SUMS without an entry for $ASSET"
fi
cat "$WORK/missing.log"
[ ! -e "$OUT_MISSING/trustless" ] || fail "binary was installed without a checksum entry"
pass "missing checksum entry caused a non-zero exit and no installation"
write_sums

echo
echo "== case 4: POSIX shell compatibility (--help) =="
if command -v dash >/dev/null 2>&1; then
    if ! dash "$INSTALLER" --help >"$WORK/help.log" 2>&1; then
        cat "$WORK/help.log"
        fail "dash --help exited non-zero"
    fi
    cat "$WORK/help.log"
    pass "dash scripts/install.sh --help exited 0"
else
    if ! sh -c 'set -e; exec "$1" --help' sh "$INSTALLER" >"$WORK/help.log" 2>&1; then
        cat "$WORK/help.log"
        fail "sh --help exited non-zero"
    fi
    cat "$WORK/help.log"
    pass "sh scripts/install.sh --help exited 0"
fi

echo
printf 'All %d install.sh checks passed.\n' "$PASS"
