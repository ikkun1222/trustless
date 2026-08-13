// Package config loads and validates the dlp-proxy configuration file.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// DefaultListen is the bind address used when config omits "listen".
const DefaultListen = "127.0.0.1:8787"

// DefaultMinSecretLen is the minimum secret length scanned when config
// omits "min_secret_len". Shorter values are dropped to avoid
// false-positive masking of ordinary prose.
const DefaultMinSecretLen = 8

// SecretsSource identifies where the proxy loads known secrets from.
type SecretsSource string

const (
	// SecretsPass loads secrets from the pass store.
	SecretsPass SecretsSource = "pass"
	// SecretsBitwarden loads secrets from a Bitwarden vault via the bw CLI.
	SecretsBitwarden SecretsSource = "bitwarden"
)

// DefaultSecretsSource is used when config omits "secrets_source".
// trustless と同じく pass がデフォルト（バックエンド選択可能な仕様）。
const DefaultSecretsSource = SecretsPass

// Route maps a local URL prefix to an upstream base URL. The request path
// is forwarded unchanged, so the prefix and the upstream path must align
// (e.g. prefix "/v1/openai" → "https://host/v1/openai").
type Route struct {
	Prefix string `json:"prefix"`
	URL    string `json:"url"`
}

// Config is the dlp-proxy configuration.
type Config struct {
	Listen        string        `json:"listen"`
	MinSecretLen  int           `json:"min_secret_len"`
	SecretsSource SecretsSource `json:"secrets_source"`
	// SecretsRefreshInterval is a Go duration string (e.g. "10m") that
	// enables periodic secret hot-reload from the configured source.
	// REQUIRED — 後方互換なし（2026-08-09: 常時ホットリロード必須）。
	SecretsRefreshInterval string        `json:"secrets_refresh_interval"`
	SecretsRefresh         time.Duration `json:"-"`
	Routes                 []Route       `json:"routes"`
}

// Load reads and validates the config file at path.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := &Config{}
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if cfg.Listen == "" {
		cfg.Listen = DefaultListen
	}
	if cfg.MinSecretLen == 0 {
		cfg.MinSecretLen = DefaultMinSecretLen
	}
	switch cfg.SecretsSource {
	case "", SecretsPass:
		cfg.SecretsSource = DefaultSecretsSource
	case SecretsBitwarden:
		// ok
	default:
		return nil, fmt.Errorf("config: unknown secrets_source %q (want %q or %q)", cfg.SecretsSource, SecretsPass, SecretsBitwarden)
	}
	if len(cfg.Routes) == 0 {
		return nil, fmt.Errorf("config: at least one route required")
	}

	seen := make(map[string]bool, len(cfg.Routes))
	for _, r := range cfg.Routes {
		if r.Prefix == "" {
			return nil, fmt.Errorf("config: route prefix required")
		}
		if r.URL == "" {
			return nil, fmt.Errorf("config: route %q missing url", r.Prefix)
		}
		if seen[r.Prefix] {
			return nil, fmt.Errorf("config: duplicate route prefix %q", r.Prefix)
		}
		seen[r.Prefix] = true
	}

	if cfg.SecretsRefreshInterval == "" {
		return nil, fmt.Errorf("config: secrets_refresh_interval is required (e.g. \"10m\")")
	}
	d, err := time.ParseDuration(cfg.SecretsRefreshInterval)
	if err != nil {
		return nil, fmt.Errorf("config: invalid secrets_refresh_interval %q: %w", cfg.SecretsRefreshInterval, err)
	}
	if d <= 0 {
		return nil, fmt.Errorf("config: secrets_refresh_interval must be positive (e.g. \"10m\")")
	}
	cfg.SecretsRefresh = d
	return cfg, nil
}
