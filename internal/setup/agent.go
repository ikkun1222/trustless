package setup

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// apiKeyPattern は API キー設定の表記揺れ (apiKey / api_key / APIKEY /
// api-key / apikey) を正規表現で正規化する。リテラル一致では変種を見逃す。
var apiKeyPattern = regexp.MustCompile(`(?i)api[-_]?key`)

// trustlessEnvAssign は TRUSTLESS_* 環境変数の実代入にマッチする
// (export 付き・引用符付きを含む)。値が空なら未設定扱い。行単位で適用する
// こと（\s は改行を跨ぐため (?m) 一括マッチでは空値判定が漏れる）。
var trustlessEnvAssign = regexp.MustCompile(`^(?:export\s+)?TRUSTLESS_[A-Za-z0-9_]+\s*=\s*(.+?)\s*$`)

// isCommentLine はコメント専用行を報告する。コメント内の言及は設定の証拠に
// ならない（trustless ラッパーが有効な場合のみ clean 扱いのため）。
func isCommentLine(trimmed string) bool {
	return strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, ";")
}

// hasTrustlessWrapper は非コメント行に trustless への実参照があるか報告する。
// コメント・説明文だけの言及は clean 扱いにしない。
func hasTrustlessWrapper(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || isCommentLine(trimmed) {
			continue
		}
		if strings.Contains(trimmed, "trustless") {
			return true
		}
	}
	return false
}

// isRawCredentialLine は api_key:/token: 行に空でない非 trustless 値があるか
// 報告する（空・引用符のみ・trustless ラッパーは raw に数えない）。
func isRawCredentialLine(trimmed string) bool {
	if !strings.Contains(trimmed, "api_key:") && !strings.Contains(trimmed, "token:") {
		return false
	}
	parts := strings.SplitN(trimmed, ":", 2)
	if len(parts) != 2 {
		return false
	}
	val := strings.TrimSpace(parts[1])
	return val != "" && val != `""` && val != "''" && !strings.Contains(val, "trustless")
}

// hasTrustlessEnvValue は TRUSTLESS_* に非空値が代入されているか報告する。
func hasTrustlessEnvValue(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || isCommentLine(trimmed) {
			continue
		}
		m := trustlessEnvAssign.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}
		if strings.Trim(m[1], `"'`) != "" {
			return true
		}
	}
	return false
}

type AgentDetectResult struct {
	Name        string
	ConfigPath  string
	Detected    bool
	NeedsChange bool
	Description string
	ChangeFunc  func() error
}

func homeDir() (string, error) {
	return os.UserHomeDir()
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

const trustlessSkillMD = "# trustless-usage\n\n" +
	"This machine uses [trustless](https://github.com/ikkun1222/trustless) CLI for credential management across all AI agent sessions.\n\n" +
	"## Core Rules\n\n" +
	"- **Never use plaintext .env files or hardcoded API keys.** All credentials are stored in the pass password store managed by trustless.\n" +
	"- **The agent NEVER sees plaintext credential values.** trustless injects secrets into subprocess memory only.\n" +
	"- **All output is automatically sanitized.** Credential patterns in stdout/stderr are REDACTED by default.\n\n" +
	"## Running Commands with Credentials\n\n" +
	"To run a command with credential injection:\n\n" +
	"```\ntrustless run -s <key> -- <command>\n```\n\n" +
	"Example:\n```\ntrustless run -s OPENAI_API_KEY -- opencode --model \"gpt-4o\" \"implement feature X\"\n```\n\n" +
	"## Registering a New Credential\n\n" +
	"To add a new credential to the store:\n\n" +
	"```\ntrustless secret set <key>\n```\n\n" +
	"You will be prompted to enter the value. The credential is encrypted immediately.\n\n" +
	"## Security Notes\n\n" +
	"- Use `--scan-args` (default: on) to prevent credential leakage in CLI arguments.\n" +
	"- Never pipe credential values through stdin manually.\n" +
	"- Never echo or print credential values — trustless handles masking automatically.\n"

func findSkillDir(agentName string) (string, error) {
	home, err := homeDir()
	if err != nil {
		return "", err
	}

	switch agentName {
	case "opencode":
		return filepath.Join(home, ".config", "opencode", "skills", "trustless-usage"), nil
	case "claude-code":
		return filepath.Join(home, ".claude", "skills", "trustless-usage"), nil
	case "codex":
		return filepath.Join(home, ".codex", "skills", "trustless-usage"), nil
	case "hermes":
		return filepath.Join(home, ".hermes", "skills", "credential-management", "trustless-usage"), nil
	default:
		return "", fmt.Errorf("unknown agent: %s", agentName)
	}
}

func InstallTrustlessSkill(agentName string) error {
	dir, err := findSkillDir(agentName)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create skill directory: %w", err)
	}
	skillPath := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(skillPath, []byte(trustlessSkillMD), 0644); err != nil {
		return fmt.Errorf("failed to write SKILL.md: %w", err)
	}
	fmt.Printf("  %s\u2713%s trustless-usage skill installed for %s\n", green, reset, agentName)
	return nil
}

func DetectOpenCode() (*AgentDetectResult, error) {
	home, err := homeDir()
	if err != nil {
		return nil, err
	}

	candidates := []string{
		filepath.Join(home, ".config", "opencode", "providers.yaml"),
		filepath.Join(home, ".config", "opencode", "opencode.json"),
	}

	if configDir := os.Getenv("OPENCODE_CONFIG_DIR"); configDir != "" {
		candidates = append([]string{
			filepath.Join(configDir, "opencode.json"),
			filepath.Join(configDir, "providers.yaml"),
		}, candidates...)
	}

	var configPath string
	for _, c := range candidates {
		if fileExists(c) {
			configPath = c
			break
		}
	}

	if configPath == "" {
		return nil, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", configPath, err)
	}

	lines := strings.Split(string(data), "\n")
	var rawKeys int
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || isCommentLine(trimmed) {
			continue
		}
		if apiKeyPattern.MatchString(trimmed) && !strings.Contains(trimmed, "trustless") {
			rawKeys++
		}
	}

	alreadySetup := hasTrustlessWrapper(string(data))
	needsChange := rawKeys > 0
	description := ""
	if needsChange {
		description = fmt.Sprintf("OpenCode config has %d apiKey(s) not wrapped with trustless", rawKeys)
	} else if alreadySetup {
		description = "OpenCode is already configured with trustless"
	} else {
		description = "OpenCode config found but no raw apiKey references detected"
	}

	return &AgentDetectResult{
		Name:        "opencode",
		ConfigPath:  configPath,
		Detected:    true,
		NeedsChange: needsChange,
		Description: description,
		ChangeFunc: func() error {
			return InstallTrustlessSkill("opencode")
		},
	}, nil
}

func DetectClaudeCode() (*AgentDetectResult, error) {
	home, err := homeDir()
	if err != nil {
		return nil, err
	}

	candidates := []string{
		filepath.Join(home, ".claude", "claude_dotfiles", "claude.env"),
		filepath.Join(home, ".claude", ".claude.env"),
	}

	var configPath string
	for _, c := range candidates {
		if fileExists(c) {
			configPath = c
			break
		}
	}

	if configPath == "" {
		return nil, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", configPath, err)
	}

	content := string(data)
	// 実設定として trustless ラッパーが有効な場合のみ clean: コメント言及や
	// 空値の TRUSTLESS_* 代入は未設定扱い。
	alreadyTrustless := hasTrustlessWrapper(content) || hasTrustlessEnvValue(content)

	needsChange := !alreadyTrustless
	description := ""
	if needsChange {
		description = "Claude Code environment file found. Consider wrapping credential exports with trustless"
	} else {
		description = "Claude Code is already configured with trustless"
	}

	return &AgentDetectResult{
		Name:        "claude-code",
		ConfigPath:  configPath,
		Detected:    true,
		NeedsChange: needsChange,
		Description: description,
		ChangeFunc: func() error {
			return InstallTrustlessSkill("claude-code")
		},
	}, nil
}

func DetectCodex() (*AgentDetectResult, error) {
	home, err := homeDir()
	if err != nil {
		return nil, err
	}

	configPath := filepath.Join(home, ".codex", "config.toml")
	if !fileExists(configPath) {
		return nil, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", configPath, err)
	}

	alreadyTrustless := hasTrustlessWrapper(string(data))
	hasCredentials := bytes.Contains(data, []byte("api_key")) || bytes.Contains(data, []byte("token")) || bytes.Contains(data, []byte("secret"))

	needsChange := !alreadyTrustless && hasCredentials
	description := ""
	if needsChange {
		description = "Codex config contains credential references. Consider wrapping with trustless"
	} else if alreadyTrustless {
		description = "Codex is already configured with trustless"
	} else {
		description = "Codex config found but no credential references detected"
	}

	return &AgentDetectResult{
		Name:        "codex",
		ConfigPath:  configPath,
		Detected:    true,
		NeedsChange: needsChange,
		Description: description,
		ChangeFunc: func() error {
			return InstallTrustlessSkill("codex")
		},
	}, nil
}

func DetectHermes() (*AgentDetectResult, error) {
	home, err := homeDir()
	if err != nil {
		return nil, err
	}

	configPath := filepath.Join(home, ".hermes", "config.yaml")
	if !fileExists(configPath) {
		return nil, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", configPath, err)
	}

	lines := strings.Split(string(data), "\n")
	var rawKeys int
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || isCommentLine(trimmed) {
			continue
		}
		if isRawCredentialLine(trimmed) {
			rawKeys++
		}
	}

	alreadySetup := hasTrustlessWrapper(string(data))
	needsChange := rawKeys > 0
	description := ""
	if needsChange {
		description = fmt.Sprintf("Hermes config has %d api_key/token field(s) with raw values not wrapped with trustless", rawKeys)
	} else if alreadySetup {
		description = "Hermes is already configured with trustless"
	} else {
		description = "Hermes config found but no raw api_key/token references detected"
	}

	return &AgentDetectResult{
		Name:        "hermes",
		ConfigPath:  configPath,
		Detected:    true,
		NeedsChange: needsChange,
		Description: description,
		ChangeFunc: func() error {
			return InstallTrustlessSkill("hermes")
		},
	}, nil
}

func DetectAllAgents() []AgentDetectResult {
	var results []AgentDetectResult

	detectors := []func() (*AgentDetectResult, error){
		DetectOpenCode,
		DetectClaudeCode,
		DetectCodex,
		DetectHermes,
	}

	for _, detect := range detectors {
		result, err := detect()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: agent detection error: %v\n", err)
			continue
		}
		if result != nil {
			results = append(results, *result)
		}
	}

	return results
}
