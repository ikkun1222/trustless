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
# Signature artifacts are only downloaded when a cosign stub is on PATH; their
# contents are irrelevant to the stub.
: > "$SERVER/SHA256SUMS.sig"
: > "$SERVER/SHA256SUMS.pem"

# make_cosign_stub creates a fake cosign that records its argv and exits with
# the requested status.
make_cosign_stub() {
    stub_dir="$1"
    stub_log="$2"
    stub_rc="$3"
    mkdir -p "$stub_dir"
    cat > "$stub_dir/cosign" <<EOF
#!/bin/sh
printf '%s\n' "\$@" > "$stub_log"
exit $stub_rc
EOF
    chmod 755 "$stub_dir/cosign"
}

COSIGN_OK_DIR="$WORK/cosign-ok"
COSIGN_FAIL_DIR="$WORK/cosign-fail"
COSIGN_LOG="$WORK/cosign-argv.log"
make_cosign_stub "$COSIGN_OK_DIR" "$COSIGN_LOG" 0
make_cosign_stub "$COSIGN_FAIL_DIR" "$WORK/cosign-fail-argv.log" 1

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

RUN_PATH="$BIN"
run_installer() {
    local dir="$1"
    shift
    PATH="$RUN_PATH" \
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
echo "== case 5: cosign is pinned to the release workflow tag identity =="
rm -f "$COSIGN_LOG"
RUN_PATH="$COSIGN_OK_DIR:$BIN"
OUT_COSIGN="$WORK/install-cosign"
if ! run_installer "$OUT_COSIGN" >"$WORK/cosign-ok.log" 2>&1; then
    cat "$WORK/cosign-ok.log"
    fail "installer failed with a successful cosign stub"
fi
cat "$WORK/cosign-ok.log"
[ -f "$COSIGN_LOG" ] || fail "cosign stub was not invoked"
cat "$COSIGN_LOG"
grep -Fxq -- '--certificate-identity-regexp' "$COSIGN_LOG" \
    || fail "cosign argv is missing --certificate-identity-regexp"
grep -Fxq -- '^https://github\.com/ikkun1222/trustless/\.github/workflows/release\.yml@refs/tags/v' "$COSIGN_LOG" \
    || fail "cosign identity is not limited to release.yml on a v tag"
grep -Fxq -- '--certificate-oidc-issuer' "$COSIGN_LOG" \
    || fail "cosign argv is missing --certificate-oidc-issuer"
grep -Fxq -- 'https://token.actions.githubusercontent.com' "$COSIGN_LOG" \
    || fail "cosign issuer is not GitHub Actions OIDC"
[ -x "$OUT_COSIGN/trustless" ] || fail "install with cosign stub did not place the binary"
pass "cosign was invoked with the release workflow identity and GitHub OIDC issuer"

echo
echo "== case 6: cosign verification failure aborts installation =="
RUN_PATH="$COSIGN_FAIL_DIR:$BIN"
OUT_COSIGN_FAIL="$WORK/install-cosign-fail"
if run_installer "$OUT_COSIGN_FAIL" >"$WORK/cosign-fail.log" 2>&1; then
    cat "$WORK/cosign-fail.log"
    fail "installer accepted a failed cosign verification"
fi
cat "$WORK/cosign-fail.log"
[ ! -e "$OUT_COSIGN_FAIL/trustless" ] || fail "binary was installed despite cosign failure"
pass "failed cosign verification caused a non-zero exit and no installation"

echo
printf 'All %d install.sh checks passed.\n' "$PASS"
