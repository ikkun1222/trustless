package setup

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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
	"This project uses [trustless](https://github.com/ikkun1222/trustless) CLI for credential management.\n\n" +
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
		if strings.Contains(trimmed, "apiKey:") && !strings.Contains(trimmed, "trustless") {
			rawKeys++
		}
	}

	alreadySetup := bytes.Contains(data, []byte("trustless"))
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
	alreadyTrustless := strings.Contains(content, "trustless") || strings.Contains(content, "TRUSTLESS_")

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

	alreadyTrustless := bytes.Contains(data, []byte("trustless"))
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
		if strings.Contains(trimmed, "api_key:") || strings.Contains(trimmed, "token:") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				if val != "" && val != `""` && val != "''" && !strings.Contains(val, "trustless") {
					rawKeys++
				}
			}
		}
	}

	alreadySetup := bytes.Contains(data, []byte("trustless"))
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
