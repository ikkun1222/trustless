#!/bin/sh
# trustless — credential broker for AI agents
# Install script: https://github.com/ikkun1222/trustless
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/ikkun1222/trustless/main/scripts/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/ikkun1222/trustless/main/scripts/install.sh | sh -s -- --update
#   curl -fsSL https://raw.githubusercontent.com/ikkun1222/trustless/main/scripts/install.sh | sh -s -- --minimal
#
# Options:
#   --minimal    Install binary only, skip setup prompt
#   --update     Update existing installation
#   --force      Reinstall even if already installed
#   --version    Print version and exit
#   --help       Print usage
#
# This script must run under POSIX sh (dash, ash, bash --posix); do not use
# bash-only features such as `pipefail`.

set -eu

INSTALLER_VERSION="1"
REPO="ikkun1222/trustless"
INSTALL_DIR="${TRUSTLESS_INSTALL_DIR:-$HOME/.local/bin}"
DEFAULT_RELEASE_BASE="https://github.com/${REPO}/releases/latest/download"
# TRUSTLESS_RELEASE_BASE exists for tests: it may point at a loopback HTTP
# fixture. When it is unset the base is always HTTPS.
GITHUB="${TRUSTLESS_RELEASE_BASE:-$DEFAULT_RELEASE_BASE}"

# Set by do_install; the EXIT trap reads this global so cleanup stays safe
# after function scope ends under `set -u`.
TEMP_DIR=""
cleanup() {
    if [ -n "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
}
trap cleanup EXIT

# Colors (if terminal supports)
if [ -t 1 ]; then
    GREEN='\033[0;32m'
    CYAN='\033[0;36m'
    RED='\033[0;31m'
    YELLOW='\033[1;33m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    GREEN=''; CYAN=''; RED=''; YELLOW=''; BOLD=''; RESET=''
fi

# Print helpers
info()  { printf "${GREEN}  ✓${RESET} %s\\n" "$1"; }
warn()  { printf "${YELLOW}  ⚠${RESET} %s\\n" "$1"; }
error() { printf "${RED}  ✗${RESET} %s\\n" "$1"; }
header(){ printf "\\n${BOLD}%s${RESET}\\n" "$1"; }
action(){ printf "${CYAN}  →${RESET} %s\\n" "$1"; }

# Detect OS and architecture
detect_platform() {
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"

    case "$ARCH" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) error "Unsupported architecture: $ARCH"; exit 1 ;;
    esac

    case "$OS" in
        linux) ;;
        darwin) OS="darwin" ;;
        *) error "Unsupported OS: $OS (trustless requires Linux or macOS)"; exit 1 ;;
    esac

    # Release assets are bare binaries named trustless-<os>-<arch>.
    ASSET="trustless-${OS}-${ARCH}"
    CHECKSUMS="SHA256SUMS"
}

# Check prerequisites
check_prereqs() {
    missing=""
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
        missing="$missing curl-or-wget"
    fi
    if ! command -v install >/dev/null 2>&1; then
        missing="$missing install"
    fi
    if [ -n "$missing" ]; then
        error "Missing required tools:$missing"
        info "Install them with your package manager, e.g.:"
        info "  apt install curl coreutils   (Debian/Ubuntu)"
        info "  yum install curl coreutils   (RHEL/CentOS)"
        info "  apk add curl coreutils       (Alpine)"
        exit 1
    fi
}

# Download a file from the release base
download() {
    url="$1"
    out="$2"
    desc="$3"

    action "Downloading ${desc}..."
    if command -v curl >/dev/null 2>&1; then
        case "$url" in
            https://*)
                curl -fsSL --retry 3 --tlsv1.2 --proto '=https' -o "$out" "$url"
                ;;
            *)
                # Only reachable when TRUSTLESS_RELEASE_BASE overrides the base.
                curl -fsSL --retry 3 -o "$out" "$url"
                ;;
        esac
    else
        wget -q -t 3 -O "$out" "$url"
    fi
}

# Verify the SHA256SUMS signature when cosign is available.
# Missing cosign is a warning; a failed verification is fatal.
verify_signature() {
    checksum_file="$1"

    if ! command -v cosign >/dev/null 2>&1; then
        warn "cosign not found — release signature not verified"
        return 0
    fi

    sig_file="${checksum_file}.sig"
    pem_file="${checksum_file}.pem"

    download "${GITHUB}/${CHECKSUMS}.sig" "$sig_file" "checksum signature"
    download "${GITHUB}/${CHECKSUMS}.pem" "$pem_file" "checksum certificate"

    action "Verifying signature with cosign..."
    if ! cosign verify-blob \
        --certificate "$pem_file" \
        --signature "$sig_file" \
        --certificate-identity-regexp '^https://github\.com/ikkun1222/trustless/\.github/workflows/release\.yml@refs/tags/v' \
        --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
        "$checksum_file"; then
        error "Signature verification failed — aborting"
        exit 1
    fi
    info "Signature verified"
}

# Verify SHA256 checksum. Every missing piece (tool, entry, match) is fatal.
verify_checksum() {
    binary="$1"
    checksum_file="$2"
    asset_name="$3"

    action "Verifying checksum..."

    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$binary" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "$binary" | awk '{print $1}')
    else
        error "Neither sha256sum nor shasum is available — cannot verify checksum"
        exit 1
    fi

    # Match the exact filename; accept the `*filename` binary-mode form.
    expected=$(awk -v name="$asset_name" '
        $2 == name || $2 == "*" name { print $1; found = 1; exit }
        END { if (!found) exit 1 }
    ' "$checksum_file") || {
        error "No checksum entry for ${asset_name} in ${CHECKSUMS}"
        exit 1
    }

    if [ -z "$expected" ]; then
        error "Empty checksum entry for ${asset_name} in ${CHECKSUMS}"
        exit 1
    fi
    if [ "$actual" != "$expected" ]; then
        error "Checksum mismatch!"
        error "  Expected: $expected"
        error "  Got:      $actual"
        exit 1
    fi
    info "Checksum verified"
}

# Main installation
do_install() {
    minimal="${1:-false}"
    TEMP_DIR=$(mktemp -d) || { error "Could not create temporary directory"; exit 1; }

    detect_platform

    echo ""
    header "trustless installer v${INSTALLER_VERSION}"
    echo ""

    # Ensure install dir exists
    mkdir -p "$INSTALL_DIR"

    # Check if already installed
    current_version=""
    if [ -f "$INSTALL_DIR/trustless" ]; then
        current_version=$("$INSTALL_DIR/trustless" version 2>/dev/null || echo "unknown")
    fi

    if [ -n "$current_version" ] && [ "$current_version" != "unknown" ] \
        && [ "${UPDATE:-false}" != "true" ] && [ "${FORCE:-false}" != "true" ]; then
        info "trustless already installed at ${INSTALL_DIR}/trustless (${current_version})"
        action "Run with --update to upgrade, or --force to reinstall"
        echo ""
        return 0
    fi

    # Download bare binary and checksum manifest
    info "Detected: ${OS} (${ARCH})"
    download "${GITHUB}/${ASSET}" "${TEMP_DIR}/${ASSET}" "trustless binary"
    download "${GITHUB}/${CHECKSUMS}" "${TEMP_DIR}/${CHECKSUMS}" "checksum file"

    # Verify signature (when cosign exists), then the binary checksum
    verify_signature "${TEMP_DIR}/${CHECKSUMS}"
    verify_checksum "${TEMP_DIR}/${ASSET}" "${TEMP_DIR}/${CHECKSUMS}" "$ASSET"

    # Install
    install -m 755 "${TEMP_DIR}/${ASSET}" "$INSTALL_DIR/trustless"
    info "Installed to ${INSTALL_DIR}/trustless"

    # Check PATH
    case ":$PATH:" in
        *:"$INSTALL_DIR":*) ;;
        *) warn "${INSTALL_DIR} is not in your PATH"
           action "Add to ~/.bashrc:  export PATH=\"\$PATH:${INSTALL_DIR}\""
           action "Add to ~/.zshrc:   export PATH=\"\$PATH:${INSTALL_DIR}\"" ;;
    esac

    # Completion (optional)
    if command -v "$INSTALL_DIR/trustless" >/dev/null 2>&1; then
        if [ -d /etc/bash_completion.d ] && [ -w /etc/bash_completion.d ] 2>/dev/null; then
            "$INSTALL_DIR/trustless" completion bash > /etc/bash_completion.d/trustless 2>/dev/null || true
        fi
    fi

    # Verify
    installed_version=$("$INSTALL_DIR/trustless" version 2>/dev/null || echo "unknown")
    info "Installed: ${installed_version}"
    echo ""

    # Post-install: offer setup
    if [ "$minimal" != "true" ]; then
        if command -v gpg >/dev/null 2>&1 || [ ! -f "$HOME/.password-store/.gpg-id" ]; then
            action "Run 'trustless setup' to configure GPG and initialize pass store."
            action "Or 'trustless doctor' to check system health."
        fi
        echo ""
        printf "${CYAN}  →${RESET} Run %btrustless setup%b now? [Y/n] " "${BOLD}" "${RESET}"
        read -r answer </dev/tty 2>/dev/null || answer="y"
        case "$answer" in
            n|N|no|NO) echo "   OK, run it anytime." ;;
            *) "$INSTALL_DIR/trustless" setup ;;
        esac
    fi

    echo ""
    header "trustless ${installed_version} installed successfully"
    echo ""
}

# Print version
if [ "${1:-}" = "--version" ]; then
    echo "trustless installer v${INSTALLER_VERSION}"
    exit 0
fi

# Print help
if [ "${1:-}" = "--help" ]; then
    echo "trustless — credential broker for AI agents"
    echo "Install script v${INSTALLER_VERSION}"
    echo ""
    echo "Usage:"
    echo "  curl -fsSL https://raw.githubusercontent.com/ikkun1222/trustless/main/scripts/install.sh | sh"
    echo "  curl -fsSL https://raw.githubusercontent.com/ikkun1222/trustless/main/scripts/install.sh | sh -s -- --minimal"
    echo "  curl -fsSL https://raw.githubusercontent.com/ikkun1222/trustless/main/scripts/install.sh | sh -s -- --update"
    echo ""
    echo "Options:"
    echo "  --minimal    Install binary only, skip setup prompt"
    echo "  --update     Upgrade existing installation"
    echo "  --force      Reinstall even if already installed"
    echo "  --version    Print version and exit"
    echo "  --help       Print this help"
    echo ""
    echo "Environment:"
    echo "  TRUSTLESS_INSTALL_DIR    Install directory (default: ~/.local/bin)"
    echo "  TRUSTLESS_RELEASE_BASE   Release base URL override (testing only)"
    exit 0
fi

# Main
check_prereqs

UPDATE=false
MINIMAL=false
FORCE=false

for arg in "$@"; do
    case "$arg" in
        --update) UPDATE=true ;;
        --minimal) MINIMAL=true ;;
        --force) FORCE=true ;;
    esac
done

do_install "$MINIMAL"
