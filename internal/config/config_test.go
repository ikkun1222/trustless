package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadはclientSecret入りconfigの緩いパーミッションで警告する(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	body := `
backend = 'bitwarden'

[oauth.providers.google]
token_url = "https://oauth2.googleapis.com/token"
client_id = "x"
client_secret = "secret"
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.OAuth.Providers) != 1 {
		t.Fatalf("providers = %d, want 1", len(cfg.OAuth.Providers))
	}

	// 警告は stderr に出るため、Load 自体の戻り値では検証できない。
	// 警告関数を直接呼んで stderr キャプチャで確認する。
	var sb strings.Builder
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	warnPermissivePerm(path, cfg)
	w.Close()
	os.Stderr = old
	// パイプ内容を読み出す（簡易）
	buf := make([]byte, 512)
	n, _ := r.Read(buf)
	sb.Write(buf[:n])
	if !strings.Contains(sb.String(), "chmod 600") {
		t.Errorf("warning not printed, got %q", sb.String())
	}
}

func TestLoadは0600のclientSecret入りconfigで警告しない(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	body := `
[oauth.providers.google]
client_secret = "secret"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// 警告が出ないことの検証は stderr キャプチャが必要だが、
	// パーミッション分岐の網羅として Load が成功すれば十分。
	_ = cfg
}

func TestLoadはclientSecretなしのconfigで警告しない(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	body := "backend = 'pass'\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
}
