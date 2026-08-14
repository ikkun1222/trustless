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

// PatternMode はパターン第2層の動作モード。
type PatternMode string

const (
	// PatternModeMask はパターン一致を置換する（デフォルト）。
	PatternModeMask PatternMode = "mask"
	// PatternModeLog は検出のみ・本文は不変（段階ロールアウト用）。
	PatternModeLog PatternMode = "log"
)

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
	// RulesFile は外部 gitleaks 互換ルールファイルのパス。空 = 同梱 rules.toml（go:embed）。
	// パース時は検証しない（存在チェックは BuildPatternSet 側）。反映はプロセス再起動で行う。
	RulesFile string `json:"rules_file"`
	// PatternDisabled は無効化するパターンルールの id 一覧（ホットリロード対象）。
	// 未知の id は BuildPatternSet で error（fail-closed）。空 = 全ルール有効。
	PatternDisabled []string `json:"pattern_disabled"`
	// PatternMode はパターン第2層の動作: "mask"（置換・デフォルト）/ "log"（検出のみ・本文不変）。
	PatternMode PatternMode `json:"pattern_mode"`
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
	if err := validateSecretsSource(cfg); err != nil {
		return nil, err
	}
	if err := validateRoutes(cfg); err != nil {
		return nil, err
	}
	if err := validateRefreshInterval(cfg); err != nil {
		return nil, err
	}
	if err := validatePatternMode(cfg); err != nil {
		return nil, err
	}
	if err := validatePatternDisabled(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func validateSecretsSource(cfg *Config) error {
	switch cfg.SecretsSource {
	case "", SecretsPass:
		cfg.SecretsSource = DefaultSecretsSource
	case SecretsBitwarden:
		// ok
	default:
		return fmt.Errorf("config: unknown secrets_source %q (want %q or %q)", cfg.SecretsSource, SecretsPass, SecretsBitwarden)
	}
	return nil
}

func validateRoutes(cfg *Config) error {
	if len(cfg.Routes) == 0 {
		return fmt.Errorf("config: at least one route required")
	}
	seen := make(map[string]bool, len(cfg.Routes))
	for _, r := range cfg.Routes {
		if r.Prefix == "" {
			return fmt.Errorf("config: route prefix required")
		}
		if r.URL == "" {
			return fmt.Errorf("config: route %q missing url", r.Prefix)
		}
		if seen[r.Prefix] {
			return fmt.Errorf("config: duplicate route prefix %q", r.Prefix)
		}
		seen[r.Prefix] = true
	}
	return nil
}

func validateRefreshInterval(cfg *Config) error {
	if cfg.SecretsRefreshInterval == "" {
		return fmt.Errorf("config: secrets_refresh_interval is required (e.g. \"10m\")")
	}
	d, err := time.ParseDuration(cfg.SecretsRefreshInterval)
	if err != nil {
		return fmt.Errorf("config: invalid secrets_refresh_interval %q: %w", cfg.SecretsRefreshInterval, err)
	}
	if d <= 0 {
		return fmt.Errorf("config: secrets_refresh_interval must be positive (e.g. \"10m\")")
	}
	cfg.SecretsRefresh = d
	return nil
}

// validatePatternMode は PatternMode を正規化・検証する。空は "mask" に正規化。
func validatePatternMode(cfg *Config) error {
	switch cfg.PatternMode {
	case "", PatternModeMask:
		cfg.PatternMode = PatternModeMask
	case PatternModeLog:
		// ok
	default:
		return fmt.Errorf("config: unknown pattern_mode %q (want %q or %q)", cfg.PatternMode, PatternModeMask, PatternModeLog)
	}
	return nil
}

// validatePatternDisabled は pattern_disabled を正規化・検証する。
// 空文字エントリは error、重複は排除する。未知 id の存在チェックは
// BuildPatternSet（Filter）側で行う（fail-closed: タイポを検出）。
func validatePatternDisabled(cfg *Config) error {
	if len(cfg.PatternDisabled) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(cfg.PatternDisabled))
	out := cfg.PatternDisabled[:0]
	for _, id := range cfg.PatternDisabled {
		if id == "" {
			return fmt.Errorf("config: pattern_disabled contains empty rule id")
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	cfg.PatternDisabled = out
	return nil
}
