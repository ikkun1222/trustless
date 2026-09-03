package doctor

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ikkun1222/trustless/internal/envscan"
)

type CheckStatus int

const (
	StatusOK      CheckStatus = iota
	StatusWarning CheckStatus = iota
	StatusError   CheckStatus = iota
	StatusInfo    CheckStatus = iota
)

type CheckResult struct {
	Name    string
	Status  CheckStatus
	Message string
	Fixable bool
	Fix     func() error `json:"-"` // excluded: func types are not JSON-serializable (silent Encode failure otherwise)
}

type AgentCheckFn func(data []byte) bool

func CheckGPG() CheckResult {
	out, err := exec.Command("gpg", "--list-secret-keys", "--keyid-format=long").Output()
	if err != nil {
		return CheckResult{
			Name:    "GPG Key",
			Status:  StatusError,
			Message: "No GPG secret key found — run 'trustless setup' to create one",
		}
	}

	var keyID string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "sec") {
			parts := strings.Split(line, "/")
			if len(parts) >= 2 {
				fields := strings.Fields(parts[1])
				if len(fields) > 0 {
					keyID = fields[0]
					break
				}
			}
		}
	}

	if keyID == "" {
		return CheckResult{
			Name:    "GPG Key",
			Status:  StatusError,
			Message: "No GPG secret key found",
		}
	}

	out, err = exec.Command("gpg", "--fixed-list-mode", "--with-colons", "--list-secret-keys").Output()
	if err != nil {
		return CheckResult{
			Name:    "GPG Key",
			Status:  StatusWarning,
			Message: fmt.Sprintf("Key %s found but expiry check failed: %v", keyID, err),
		}
	}

	for _, line := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(line, "sec:") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		expiryStr := fields[6]
		if expiryStr == "" {
			return CheckResult{
				Name:    "GPG Key",
				Status:  StatusOK,
				Message: fmt.Sprintf("GPG key %s valid (no expiry)", keyID),
			}
		}
		expiryUnix, err := strconv.ParseUint(expiryStr, 10, 64)
		if err != nil {
			return CheckResult{
				Name:    "GPG Key",
				Status:  StatusOK,
				Message: fmt.Sprintf("GPG key %s valid", keyID),
			}
		}
		expiryTime := time.Unix(int64(expiryUnix), 0)
		daysLeft := time.Until(expiryTime).Hours() / 24

		if daysLeft < 0 {
			return CheckResult{
				Name:    "GPG Key",
				Status:  StatusError,
				Message: fmt.Sprintf("GPG key %s expired on %s", keyID, expiryTime.Format("2006-01-02")),
			}
		}
		if daysLeft < 30 {
			return CheckResult{
				Name:    "GPG Key",
				Status:  StatusWarning,
				Message: fmt.Sprintf("GPG key %s expires %s (%d days)", keyID, expiryTime.Format("2006-01-02"), int(daysLeft)),
			}
		}
		return CheckResult{
			Name:    "GPG Key",
			Status:  StatusOK,
			Message: fmt.Sprintf("GPG key %s valid (expires %s)", keyID, expiryTime.Format("2006-01-02")),
		}
	}

	return CheckResult{
		Name:    "GPG Key",
		Status:  StatusOK,
		Message: fmt.Sprintf("GPG key %s valid", keyID),
	}
}

func CheckPassStore() CheckResult {
	home, err := os.UserHomeDir()
	if err != nil {
		return CheckResult{
			Name:    "pass store",
			Status:  StatusError,
			Message: "Cannot determine home directory",
		}
	}

	passDir := filepath.Join(home, ".password-store")
	info, err := os.Stat(passDir)
	if err != nil || !info.IsDir() {
		return CheckResult{
			Name:    "pass store",
			Status:  StatusError,
			Message: "pass store not found at ~/.password-store — run 'trustless setup'",
		}
	}

	if _, err := exec.LookPath("pass"); err != nil {
		return CheckResult{
			Name:    "pass store",
			Status:  StatusError,
			Message: "'pass' command not found in PATH",
		}
	}

	if err := exec.Command("pass", "ls").Run(); err != nil {
		return CheckResult{
			Name:    "pass store",
			Status:  StatusError,
			Message: fmt.Sprintf("pass ls failed: %v", err),
		}
	}

	var count int
	filepath.WalkDir(passDir, func(path string, d os.DirEntry, _ error) error {
		if d != nil && !d.IsDir() && strings.HasSuffix(d.Name(), ".gpg") {
			count++
		}
		return nil
	})

	return CheckResult{
		Name:    "pass store",
		Status:  StatusOK,
		Message: fmt.Sprintf("pass store initialized, %d credentials", count),
	}
}

// CheckBitwardenCLI verifies the bw CLI is installed and reachable.
func CheckBitwardenCLI() CheckResult {
	if _, err := exec.LookPath("bw"); err != nil {
		return CheckResult{
			Name:    "Bitwarden CLI",
			Status:  StatusError,
			Message: "'bw' command not found in PATH — install bitwarden-cli",
		}
	}
	return CheckResult{
		Name:    "Bitwarden CLI",
		Status:  StatusOK,
		Message: "bw CLI found",
	}
}

// CheckBitwardenSession verifies a valid unlocked bw session exists.
// The session key file (default ~/.config/trustless/bw-session, chmod 600)
// must exist and `bw status` must report "unlocked".
func CheckBitwardenSession() CheckResult {
	home, err := os.UserHomeDir()
	if err != nil {
		return CheckResult{
			Name:    "Bitwarden session",
			Status:  StatusError,
			Message: "Cannot determine home directory",
		}
	}
	sessionPath := filepath.Join(home, ".config", "trustless", "bw-session")
	data, err := os.ReadFile(sessionPath)
	if err != nil {
		return CheckResult{
			Name:    "Bitwarden session",
			Status:  StatusError,
			Message: "No bw session file at ~/.config/trustless/bw-session — run 'trustless bw-unlock'",
		}
	}
	session := strings.TrimSpace(string(data))
	if session == "" {
		return CheckResult{
			Name:    "Bitwarden session",
			Status:  StatusError,
			Message: "bw-session file is empty — run 'trustless bw-unlock'",
		}
	}
	cmd := exec.Command("bw", "status", "--session", session)
	out, err := cmd.Output()
	if err != nil {
		return CheckResult{
			Name:    "Bitwarden session",
			Status:  StatusError,
			Message: fmt.Sprintf("bw status failed: %v — run 'trustless bw-unlock'", err),
		}
	}
	if strings.Contains(string(out), `"unlocked"`) {
		return CheckResult{
			Name:    "Bitwarden session",
			Status:  StatusOK,
			Message: "bw session unlocked",
		}
	}
	return CheckResult{
		Name:    "Bitwarden session",
		Status:  StatusWarning,
		Message: "bw session exists but vault is locked — run 'trustless bw-unlock'",
	}
}

func CheckEnvFiles() CheckResult {
	home, err := os.UserHomeDir()
	if err != nil {
		return CheckResult{
			Name:    ".env scan",
			Status:  StatusError,
			Message: "Cannot determine home directory",
		}
	}

	patterns := []string{"API_KEY", "TOKEN", "SECRET", "PASSWORD"}
	// home 走査が home/projects を既に含むため重複排除（二重走査防止）。
	searchDirs := dedupeSearchDirs([]string{home, filepath.Join(home, "projects")})
	var found []string
	var walkErrs int
	for _, dir := range searchDirs {
		walkErrs += scanEnvDir(dir, patterns, &found)
	}
	if walkErrs > 0 {
		fmt.Fprintf(os.Stderr, "doctor: .env scan skipped %d unreadable path(s)\n", walkErrs)
	}

	if len(found) > 0 {
		// 自動修復はしない（ヒント文だけの Fix を謳わない）: Fixable は false
		// のままにし、移行手順をメッセージに含める。
		return CheckResult{
			Name:    ".env scan",
			Status:  StatusWarning,
			Message: fmt.Sprintf("%d .env file(s) with plaintext credentials — run 'trustless setup --import-dir <directory>' to import them into pass", len(found)),
		}
	}

	return CheckResult{
		Name:    ".env scan",
		Status:  StatusOK,
		Message: "No .env files with plaintext credentials found",
	}
}

// dedupeSearchDirs drops dirs nested under an earlier dir (e.g. ~/projects
// under ~, or exact duplicates) so WalkDir never scans the same tree twice.
func dedupeSearchDirs(dirs []string) []string {
	var out []string
	for _, d := range dirs {
		nested := false
		for _, kept := range out {
			if isNestedPath(kept, d) {
				nested = true
				break
			}
		}
		if !nested {
			out = append(out, d)
		}
	}
	return out
}

// isNestedPath reports whether child resolves inside parent (or equals it).
func isNestedPath(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// scanEnvDir walks dir for ".env" files containing credential patterns,
// appending matches to found. Unreadable paths are counted and skipped so a
// single bad dir cannot fail the whole scan (the caller warns with the count).
func scanEnvDir(dir string, patterns []string, found *[]string) (walkErrs int) {
	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil {
			if err != nil {
				walkErrs++
			}
			return nil
		}
		if d.IsDir() {
			// 除外ルールは setup と共有 (envscan.SkipDir)。
			if envscan.SkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !envscan.IsEnvFile(d.Name()) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			walkErrs++
			return nil
		}
		if envDataHasSecrets(data, patterns) {
			*found = append(*found, path)
		}
		return nil
	})
	return walkErrs
}

// envDataHasSecrets は setup と同一の判定 (envscan.ContainsSecret) への薄い
// 別名。呼び出し側のシグネチャを変えずに共有実装を使う。
func envDataHasSecrets(data []byte, patterns []string) bool {
	return envscan.ContainsSecret(data, patterns)
}

// CheckAgentIntegration walks every candidate path: any existing file that
// is not trustless-configured makes the agent need a fix (a single
// configured file no longer masks a raw sibling, e.g. opencode.json vs
// providers.yaml).
func CheckAgentIntegration(name string, configPaths []string, fn AgentCheckFn) CheckResult {
	var found, unconfigured string
	for _, p := range configPaths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if found == "" {
			found = p
		}
		if !fn(data) && unconfigured == "" {
			unconfigured = p
		}
	}
	if found == "" {
		return CheckResult{
			Name:    name,
			Status:  StatusInfo,
			Message: fmt.Sprintf("%s not detected", name),
		}
	}
	if unconfigured != "" {
		return CheckResult{
			Name:    name,
			Status:  StatusWarning,
			Message: fmt.Sprintf("%s not configured for trustless (%s)", name, filepath.Base(unconfigured)),
			Fixable: true,
		}
	}
	return CheckResult{
		Name:    name,
		Status:  StatusOK,
		Message: fmt.Sprintf("%s configured (%s)", name, filepath.Base(found)),
	}
}

func agentConfigPaths(paths ...string) []string { return paths }

func opencodeConfigPaths() []string {
	home, _ := os.UserHomeDir()
	return agentConfigPaths(
		filepath.Join(home, ".config", "opencode", "opencode.json"),
		filepath.Join(home, ".config", "opencode", "providers.yaml"),
	)
}

func opencodeDetectFn(data []byte) bool {
	return bytes.Contains(data, []byte("trustless")) ||
		bytes.Contains(data, []byte("127.0.0.1:8787")) ||
		bytes.Contains(data, []byte("127.0.0.1:8080"))
}

func claudeConfigPaths() []string {
	home, _ := os.UserHomeDir()
	return agentConfigPaths(
		filepath.Join(home, ".claude", "claude_dotfiles", "claude.env"),
		filepath.Join(home, ".claude", ".claude.env"),
	)
}

func claudeDetectFn(data []byte) bool {
	return bytes.Contains(data, []byte("trustless")) || bytes.Contains(data, []byte("TRUSTLESS_"))
}

func codexConfigPaths() []string {
	home, _ := os.UserHomeDir()
	return agentConfigPaths(filepath.Join(home, ".codex", "config.toml"))
}

func codexDetectFn(data []byte) bool {
	return bytes.Contains(data, []byte("trustless")) ||
		bytes.Contains(data, []byte("127.0.0.1:8787")) ||
		bytes.Contains(data, []byte("127.0.0.1:8080"))
}

func hermesConfigPaths() []string {
	home, _ := os.UserHomeDir()
	return agentConfigPaths(filepath.Join(home, ".hermes", "config.yaml"))
}

func hermesDetectFn(data []byte) bool {
	return bytes.Contains(data, []byte("trustless")) ||
		bytes.Contains(data, []byte("127.0.0.1:8787")) ||
		bytes.Contains(data, []byte("127.0.0.1:8080"))
}

func CheckMITMCA() CheckResult {
	paths := []string{
		"/usr/local/share/ca-certificates/trustless-ca.crt",
		"/etc/ssl/certs/trustless-ca.pem",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return CheckResult{
				Name:    "MITM CA",
				Status:  StatusInfo,
				Message: fmt.Sprintf("trustless CA installed at %s", p),
			}
		}
	}
	return CheckResult{
		Name:    "MITM CA",
		Status:  StatusInfo,
		Message: "trustless CA not installed (--mitm won't work for HTTPS)",
	}
}

func CheckGPGAgent() CheckResult {
	if _, err := exec.LookPath("gpg"); err != nil {
		return CheckResult{
			Name:    "gpg-agent",
			Status:  StatusError,
			Message: "gpg not found in PATH",
		}
	}

	if err := exec.Command("gpg-connect-agent", "/bye").Run(); err != nil {
		return CheckResult{
			Name:    "gpg-agent",
			Status:  StatusError,
			Message: "gpg-agent not running or not responding",
		}
	}

	return CheckResult{
		Name:    "gpg-agent",
		Status:  StatusOK,
		Message: "gpg-agent responding",
	}
}
