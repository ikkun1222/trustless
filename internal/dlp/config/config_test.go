package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestLoad_Valid(t *testing.T) {
	path := writeConfig(t, `{
  "listen": "127.0.0.1:8787",
  "min_secret_len": 10,
  "secrets_refresh_interval": "10m",
  "routes": [
    {"prefix": "/v1/openai", "url": "https://api-gateway.merge.dev/v1/openai"}
  ]
}`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != "127.0.0.1:8787" {
		t.Fatalf("Listen = %q", cfg.Listen)
	}
	if cfg.MinSecretLen != 10 {
		t.Fatalf("MinSecretLen = %d", cfg.MinSecretLen)
	}
	if len(cfg.Routes) != 1 || cfg.Routes[0].Prefix != "/v1/openai" {
		t.Fatalf("Routes = %+v", cfg.Routes)
	}
}

func TestLoad_Defaults(t *testing.T) {
	path := writeConfig(t, `{
  "secrets_refresh_interval": "10m",
  "routes": [
    {"prefix": "/v1", "url": "https://example.com/v1"}
  ]
}`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != "127.0.0.1:8787" {
		t.Fatalf("default Listen = %q, want 127.0.0.1:8787", cfg.Listen)
	}
	if cfg.MinSecretLen != 8 {
		t.Fatalf("default MinSecretLen = %d, want 8", cfg.MinSecretLen)
	}
	if cfg.SecretsSource != SecretsPass {
		t.Fatalf("default SecretsSource = %q, want %q", cfg.SecretsSource, SecretsPass)
	}
}

func TestLoad_SecretsSourceBitwarden(t *testing.T) {
	path := writeConfig(t, `{
  "secrets_source": "bitwarden",
  "secrets_refresh_interval": "10m",
  "routes": [
    {"prefix": "/v1", "url": "https://example.com/v1"}
  ]
}`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SecretsSource != SecretsBitwarden {
		t.Fatalf("SecretsSource = %q, want %q", cfg.SecretsSource, SecretsBitwarden)
	}
}

func TestLoad_UnknownSecretsSource(t *testing.T) {
	path := writeConfig(t, `{
  "secrets_source": "1password",
  "routes": [
    {"prefix": "/v1", "url": "https://example.com/v1"}
  ]
}`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for unknown secrets_source")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_InvalidJSON(t *testing.T) {
	path := writeConfig(t, `{not json`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoad_EmptyRoutes(t *testing.T) {
	path := writeConfig(t, `{"routes": []}`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for empty routes")
	}
}

func TestLoad_DuplicatePrefix(t *testing.T) {
	path := writeConfig(t, `{
  "routes": [
    {"prefix": "/v1", "url": "https://a.example.com"},
    {"prefix": "/v1", "url": "https://b.example.com"}
  ]
}`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for duplicate prefix")
	}
}

func TestLoad_MissingRouteURL(t *testing.T) {
	path := writeConfig(t, `{"routes": [{"prefix": "/v1"}]}`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for route without url")
	}
}

func TestLoad_ValidRefreshInterval(t *testing.T) {
	path := writeConfig(t, `{"routes": [{"prefix": "/v1", "url": "http://x"}], "secrets_refresh_interval": "10m"}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.SecretsRefresh != 10*time.Minute {
		t.Fatalf("SecretsRefresh = %v, want 10m", cfg.SecretsRefresh)
	}
}

func TestLoad_SecretsSourcePass(t *testing.T) {
	path := writeConfig(t, `{
  "secrets_source": "pass",
  "secrets_refresh_interval": "10m",
  "routes": [
    {"prefix": "/v1", "url": "https://example.com/v1"}
  ]
}`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SecretsSource != SecretsPass {
		t.Fatalf("SecretsSource = %q, want %q", cfg.SecretsSource, SecretsPass)
	}
}

func TestLoad_MissingRefreshInterval(t *testing.T) {
	path := writeConfig(t, `{"routes": [{"prefix": "/v1", "url": "http://x"}]}`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for missing secrets_refresh_interval")
	}
}

func TestLoad_InvalidRefreshInterval(t *testing.T) {
	path := writeConfig(t, `{"routes": [{"prefix": "/v1", "url": "http://x"}], "secrets_refresh_interval": "abc"}`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for invalid duration")
	}
}

func TestLoad_ZeroRefreshInterval(t *testing.T) {
	path := writeConfig(t, `{"routes": [{"prefix": "/v1", "url": "http://x"}], "secrets_refresh_interval": "0s"}`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for zero duration")
	}
}
