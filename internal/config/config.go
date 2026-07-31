package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"
)

// Config represents the trustless configuration.
type Config struct {
	Backend     string         `toml:"backend"`
	Output      string         `toml:"output"`
	RunDefaults RunDefaults    `toml:"run_defaults"`
	Proxy       ProxyConfig    `toml:"proxy"`
	Sanitize    SanitizeConfig `toml:"sanitize"`
	Policy      PolicyConfig   `toml:"policy"`
}

type RunDefaults struct {
	Sanitize bool   `toml:"sanitize"`
	Timeout  string `toml:"timeout"`
}

type ProxyConfig struct {
	Port int `toml:"port"`
}

type SanitizeConfig struct {
	Patterns []string `toml:"patterns"`
}

type PolicyRule struct {
	DeniedCommands []string `toml:"denied_commands"`
}

type PolicyOverride struct {
	SecretKey string `toml:"secret_key"`
	PolicyRule
}

type PolicyConfig struct {
	Default   PolicyRule       `toml:"default"`
	Overrides []PolicyOverride `toml:"overrides"`
}

// Default config values.
var defaultPatterns = []string{
	`(sk_live|sk_test)_[A-Za-z0-9]+`,
	`(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{8,}`,
	`Bearer [A-Za-z0-9._-]{8,}`,
	`(?:api|secret|key)\s*[:=]\s*['"]?[A-Za-z0-9_\-]{16,}['"]?`,
}

func DefaultConfigPath() string {
	if p := os.Getenv("TRUSTLESS_CONFIG"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "trustless", "config.toml")
}

func Default() *Config {
	return &Config{
		Backend: "pass",
		Output:  "json",
		RunDefaults: RunDefaults{
			Sanitize: true,
			Timeout:  "5m",
		},
		Proxy: ProxyConfig{
			Port: 8080,
		},
		Sanitize: SanitizeConfig{
			Patterns: defaultPatterns,
		},
		Policy: PolicyConfig{},
	}
}

// Load reads and parses the config file at path, falling back to defaults for missing fields.
func Load(path string) (*Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil // no config file, use defaults
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return cfg, nil
}

// Save writes the config to the given path.
func Save(path string, cfg *Config) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir config dir: %w", err)
	}

	data, err := toml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	return nil
}
