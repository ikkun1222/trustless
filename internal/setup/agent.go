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
