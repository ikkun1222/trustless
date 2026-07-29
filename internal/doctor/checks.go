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
	Fix     func() error
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
	searchDirs := []string{home, filepath.Join(home, "projects")}
	var found []string

	for _, dir := range searchDirs {
		filepath.WalkDir(dir, func(path string, d os.DirEntry, _ error) error {
			if d != nil && d.IsDir() {
				base := d.Name()
				if base == ".git" || base == ".config" || base == "node_modules" || base == ".cache" || base == ".password-store" || base == ".gnupg" {
					return filepath.SkipDir
				}
				return nil
			}
			if d == nil || d.Name() != ".env" {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				for _, p := range patterns {
					if strings.Contains(line, p) {
						found = append(found, path)
						return nil
					}
				}
			}
			return nil
		})
	}

	if len(found) > 0 {
		return CheckResult{
			Name:    ".env scan",
			Status:  StatusWarning,
			Message: fmt.Sprintf("%d .env file(s) with plaintext credentials", len(found)),
			Fixable: true,
			Fix: func() error {
				fmt.Fprintf(os.Stderr, "  Run: trustless setup --import-dir ~/projects\n")
				return nil
			},
		}
	}

	return CheckResult{
		Name:    ".env scan",
		Status:  StatusOK,
		Message: "No .env files with plaintext credentials found",
	}
}

func CheckAgentIntegration(name string, configPaths []string, fn AgentCheckFn) CheckResult {
	for _, p := range configPaths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		configured := fn(data)
		if configured {
			return CheckResult{
				Name:    name,
				Status:  StatusOK,
				Message: fmt.Sprintf("%s configured (%s)", name, filepath.Base(p)),
			}
		}
		return CheckResult{
			Name:    name,
			Status:  StatusWarning,
			Message: fmt.Sprintf("%s not configured for trustless (%s)", name, filepath.Base(p)),
			Fixable: true,
		}
	}
	return CheckResult{
		Name:    name,
		Status:  StatusInfo,
		Message: fmt.Sprintf("%s not detected", name),
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
	return bytes.Contains(data, []byte("trustless"))
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
	return bytes.Contains(data, []byte("trustless"))
}

func hermesConfigPaths() []string {
	home, _ := os.UserHomeDir()
	return agentConfigPaths(filepath.Join(home, ".hermes", "config.yaml"))
}

func hermesDetectFn(data []byte) bool {
	return bytes.Contains(data, []byte("trustless"))
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
