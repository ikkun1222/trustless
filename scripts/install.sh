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
#   --version    Print version and exit
#   --help       Print usage

set -euo pipefail

VERSION="0.1.0"
REPO="ikkun1222/trustless"
INSTALL_DIR="${TRUSTLESS_INSTALL_DIR:-$HOME/.local/bin}"
GITHUB="https://github.com/${REPO}/releases/latest/download"

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

    BINARY="trustless_${OS}_${ARCH}.tar.gz"
    CHECKSUM="trustless_${OS}_${ARCH}.sha256"
}

# Check prerequisites
check_prereqs() {
    local missing=""
    for cmd in curl tar; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing="$missing $cmd"
        fi
    done
    if [ -n "$missing" ]; then
        error "Missing required tools:$missing"
        info "Install them with your package manager, e.g.:"
        info "  apt install curl tar   (Debian/Ubuntu)"
        info "  yum install curl tar   (RHEL/CentOS)"
        info "  apk add curl tar       (Alpine)"
        exit 1
    fi
}

# Download a file from GitHub Releases
download() {
    local url="$1"
    local out="$2"
    local desc="$3"

    action "Downloading ${desc}..."
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 --tlsv1.2 --proto "=https" -o "$out" "$url"
    else
        wget -q -t 3 -O "$out" "$url"
    fi
}

# Verify SHA256 checksum
verify_checksum() {
    local archive="$1"
    local checksum_file="$2"

    action "Verifying checksum..."
    local expected=""
    if command -v sha256sum >/dev/null 2>&1; then
        expected=$(sha256sum "$archive" | cut -d' ' -f1)
    elif command -v shasum >/dev/null 2>&1; then
        expected=$(shasum -a 256 "$archive" | cut -d' ' -f1)
    else
        warn "No sha256sum or shasum found — skipping verification"
        return 0
    fi

    local actual=$(grep "$(basename "$archive")" "$checksum_file" | cut -d' ' -f1 2>/dev/null || echo "")
    if [ -z "$actual" ]; then
        warn "Checksum file has no entry for this archive — skipping verification"
        return 0
    fi
    if [ "$expected" != "$actual" ]; then
        error "Checksum mismatch!"
        error "  Expected: $actual"
        error "  Got:      $expected"
        exit 1
    fi
    info "Checksum verified"
}

# Main installation
do_install() {
    local minimal="${1:-false}"
    local temp_dir
    temp_dir=$(mktemp -d)
    trap 'rm -rf "$temp_dir"' EXIT

    detect_platform

    echo ""
    header "trustless installer v${VERSION}"
    echo ""

    # Ensure install dir exists
    mkdir -p "$INSTALL_DIR"

    # Check if already installed
    local current_version=""
    if [ -f "$INSTALL_DIR/trustless" ]; then
        current_version=$("$INSTALL_DIR/trustless" version 2>/dev/null || echo "unknown")
    fi

    if [ -n "$current_version" ] && [ "$current_version" != "unknown" ] && [ "${UPDATE:-false}" != "true" ]; then
        info "trustless already installed at ${INSTALL_DIR}/trustless (${current_version})"
        action "Run with --update to upgrade, or --force to reinstall"
        echo ""
        return 0
    fi

    # Download
    info "Detected: ${OS} (${ARCH})"
    download "${GITHUB}/${BINARY}" "${temp_dir}/${BINARY}" "trustless binary"
    download "${GITHUB}/${CHECKSUM}" "${temp_dir}/${CHECKSUM}" "checksum"

    # Verify
    verify_checksum "${temp_dir}/${BINARY}" "${temp_dir}/${CHECKSUM}"

    # Extract
    action "Extracting..."
    tar -xzf "${temp_dir}/${BINARY}" -C "$temp_dir"

    # Find the binary (might be nested or named differently)
    local binary_path
    binary_path=$(find "$temp_dir" -name "trustless" -type f 2>/dev/null | head -1)
    if [ -z "$binary_path" ]; then
        binary_path="$temp_dir/trustless"
        if [ ! -f "$binary_path" ]; then
            binary_path="$temp_dir/trustless_${OS}_${ARCH}/trustless"
        fi
    fi

    if [ ! -f "$binary_path" ]; then
        error "Could not find trustless binary in archive"
        ls -la "$temp_dir"
        exit 1
    fi

    # Install
    install -m 755 "$binary_path" "$INSTALL_DIR/trustless"
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
    local installed_version
    installed_version=$("$INSTALL_DIR/trustless" version 2>/dev/null || echo "v${VERSION}")
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
    echo "trustless installer v${VERSION}"
    exit 0
fi

# Print help
if [ "${1:-}" = "--help" ]; then
    echo "trustless — credential broker for AI agents"
    echo "Install script v${VERSION}"
    echo ""
    echo "Usage:"
    echo "  curl -fsSL https://raw.githubusercontent.com/ikkun1222/trustless/main/scripts/install.sh | sh"
    echo "  curl -fsSL https://raw.githubusercontent.com/ikkun1222/trustless/main/scripts/install.sh | sh -s -- --minimal"
    echo "  curl -fsSL https://raw.githubusercontent.com/ikkun1222/trustless/main/scripts/install.sh | sh -s -- --update"
    echo ""
    echo "Options:"
    echo "  --minimal    Install binary only, skip setup prompt"
    echo "  --update     Upgrade existing installation"
    echo "  --version    Print version and exit"
    echo "  --help       Print this help"
    echo ""
    echo "Environment:"
    echo "  TRUSTLESS_INSTALL_DIR    Install directory (default: ~/.local/bin)"
    exit 0
fi

# Main
check_prereqs

UPDATE=false
MINIMAL=false

for arg in "$@"; do
    case "$arg" in
        --update) UPDATE=true ;;
        --minimal) MINIMAL=true ;;
    esac
done

do_install "$MINIMAL"
