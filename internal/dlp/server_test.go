package dlp

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	"github.com/ikkun1222/trustless/internal/audit"
	"github.com/ikkun1222/trustless/internal/dlp/redact"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ikkun1222/trustless/internal/dlp/config"
	"github.com/ikkun1222/trustless/internal/dlp/proxy"
)

// loadTestPatterns returns the bundled pattern set, failing the test if the
// embedded rules.toml cannot be loaded.
func loadTestPatterns(t *testing.T) *redact.PatternSet {
	t.Helper()
	ps, err := redact.DefaultPatterns()
	if err != nil {
		t.Fatalf("DefaultPatterns: %v", err)
	}
	return ps
}

// TestBuildHandler_E2E wires a config with a route through buildHandler and
// verifies end-to-end: prefix stripping, upstream path joining, secret
// masking, and response propagation.
func TestBuildHandler_E2E(t *testing.T) {
	const secret = "sk-e2e-secret-value-1234567890"

	var mu sync.Mutex
	var gotPath string
	var gotBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		gotPath = r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"resp_1","choices":[]}`))
	}))
	t.Cleanup(upstream.Close)

	cfg := &config.Config{
		Listen:       "127.0.0.1:0",
		MinSecretLen: 8,
		Routes: []config.Route{
			{Prefix: "/v1/openai", URL: upstream.URL + "/v1/openai"},
		},
	}
	handler := buildHandler(cfg, proxy.NewSecrets([]string{secret}), loadTestPatterns(t), "", log.New(io.Discard, "", 0), audit.Off())
	proxyServer := httptest.NewServer(handler)
	t.Cleanup(proxyServer.Close)

	body := `{"model":"m","messages":[{"role":"user","content":"key is ` + secret + ` now"}]}`
	resp, err := http.Post(proxyServer.URL+"/v1/openai/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotPath != "/v1/openai/chat/completions" {
		t.Fatalf("upstream path = %q", gotPath)
	}
	got := string(gotBody)
	if strings.Contains(got, secret) {
		t.Fatalf("secret reached upstream: %s", got)
	}
	if !strings.Contains(got, "<redacted>") {
		t.Fatalf("expected <redacted>: %s", got)
	}
}

// TestBuildHandler_RouteSelection verifies the multiplexer routes by prefix.
func TestBuildHandler_RouteSelection(t *testing.T) {
	var gotA, gotB int
	upA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotA++
		io.Copy(io.Discard, r.Body)
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(upA.Close)
	upB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotB++
		io.Copy(io.Discard, r.Body)
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(upB.Close)

	cfg := &config.Config{
		MinSecretLen: 8,
		Routes: []config.Route{
			{Prefix: "/v1/a", URL: upA.URL + "/v1/a"},
			{Prefix: "/v1/b", URL: upB.URL + "/v1/b"},
		},
	}
	handler := buildHandler(cfg, proxy.NewSecrets(nil), loadTestPatterns(t), "", log.New(io.Discard, "", 0), audit.Off())
	proxyServer := httptest.NewServer(handler)
	t.Cleanup(proxyServer.Close)

	for _, path := range []string{"/v1/a/chat/completions", "/v1/a/models", "/v1/b/chat/completions"} {
		resp, err := http.Post(proxyServer.URL+path, "application/json", strings.NewReader(`{"x":1}`))
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		resp.Body.Close()
	}
	if gotA != 2 || gotB != 1 {
		t.Fatalf("route selection wrong: gotA=%d gotB=%d", gotA, gotB)
	}
}

// TestRefreshLoop verifies the hot-reload loop semantics: a successful
// reload replaces the shared set, a failed reload keeps the previous set
// (proxy stays armed) and logs a warning, and a later success recovers.
func TestRefreshLoop(t *testing.T) {
	secret1 := "«redacted:sk-1…»"
	secret2 := "«redacted:sk-2…»"

	var calls atomic.Int32
	load := func(*config.Config) ([]string, error) {
		switch calls.Add(1) {
		case 1:
			return []string{secret1}, nil
		case 2:
			return nil, fmt.Errorf("bw session expired (simulated)")
		default:
			return []string{secret2}, nil
		}
	}

	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	set := proxy.NewSecrets(nil)
	cfg := &config.Config{SecretsRefresh: 5 * time.Millisecond}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		refreshLoop(cfg, set, load, logger, stop, nil)
	}()

	deadline := time.Now().Add(3 * time.Second)
	for calls.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	close(stop)
	<-done // refreshLoop の全ログ書き込み完了を待つ（バッファ競合防止）

	if calls.Load() < 3 {
		t.Fatalf("refreshLoop did not run 3 loads (calls=%d)", calls.Load())
	}
	// After call 1: secret1 loaded. Call 2 failed (kept secret1).
	// Call 3: replaced with secret2.
	snap := set.Snapshot()
	if len(snap) != 1 || snap[0] != secret2 {
		t.Fatalf("final set = %v, want [%s]", snap, secret2)
	}
	gotLog := buf.String()
	if !strings.Contains(gotLog, "WARN: secret reload failed") {
		t.Fatalf("expected failure warning in log, got: %s", gotLog)
	}
	if !strings.Contains(gotLog, "reloaded 1 secrets") {
		t.Fatalf("expected reload log, got: %s", gotLog)
	}
}

// TestRefreshLoop_ManualReload verifies that a signal on the manual channel
// triggers an immediate reload even when the periodic ticker is far away
// (simulates SIGHUP right after storing a new secret).
func TestRefreshLoop_ManualReload(t *testing.T) {
	var calls atomic.Int32
	load := func(*config.Config) ([]string, error) {
		n := calls.Add(1)
		if n == 1 {
			return []string{"«redacted:sk-first…»"}, nil
		}
		return []string{"«redacted:sk-new…»"}, nil
	}
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	set := proxy.NewSecrets(nil)
	cfg := &config.Config{SecretsRefresh: 10 * time.Minute, SecretsSource: "bitwarden"} // ticker は遠い

	stop := make(chan struct{})
	manual := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		refreshLoop(cfg, set, load, logger, stop, manual)
	}()

	// 手動リロード要求 → ticker を待たずに即時リロードされる
	manual <- struct{}{}
	deadline := time.Now().Add(2 * time.Second)
	for calls.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	close(stop)
	<-done

	if calls.Load() < 1 {
		t.Fatalf("manual reload did not trigger (calls=%d)", calls.Load())
	}
	got := set.Snapshot()
	if len(got) != 1 || got[0] != "«redacted:sk-first…»" {
		t.Fatalf("secrets not replaced by manual reload: %v", got)
	}
	if !strings.Contains(buf.String(), "manual reload requested") {
		t.Fatalf("expected manual reload log, got: %s", buf.String())
	}
}

// TestBuildPatternSet_Bundled verifies that an empty rules_file selects the
// bundled rules.toml (40 gitleaks-compatible rules).
func TestBuildPatternSet_Bundled(t *testing.T) {
	ps, err := BuildPatternSet(&config.Config{})
	if err != nil {
		t.Fatalf("BuildPatternSet: %v", err)
	}
	if ps == nil {
		t.Fatal("expected non-nil pattern set")
	}
	// The bundled set detects an OpenAI project key (sk-proj-…).
	seg := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" +
		"abcdefghijkl" // 62 + 12 = 74
	dummy := "sk-proj-" + seg + "T3BlbkFJ" + seg
	if out, changed := ps.Scan("key " + dummy + " end"); !changed || strings.Contains(out, dummy) {
		t.Fatalf("bundled set must detect pattern, got changed=%v out=%q", changed, out)
	}
}

// TestBuildPatternSet_ExternalFile verifies that a rules_file pointing at a
// gitleaks-compatible TOML (written under t.TempDir) is loaded.
func TestBuildPatternSet_ExternalFile(t *testing.T) {
	rules := `
[[rules]]
id = "test-openai"
description = "test rule"
regex = '''sk-proj-[A-Za-z0-9]{40}'''
keywords = ["sk-proj-"]
entropy = 3.0
`
	path := filepath.Join(t.TempDir(), "rules.toml")
	if err := os.WriteFile(path, []byte(rules), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	ps, err := BuildPatternSet(&config.Config{RulesFile: path})
	if err != nil {
		t.Fatalf("BuildPatternSet: %v", err)
	}
	seg := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" +
		"abcdefghijkl" // 62 + 12 = 74
	dummy := "sk-proj-" + seg[:40]
	if out, changed := ps.Scan("key " + dummy + " end"); !changed || strings.Contains(out, dummy) {
		t.Fatalf("external set must detect pattern, got changed=%v out=%q", changed, out)
	}
}

// TestBuildPatternSet_MissingFile verifies that a nonexistent rules_file is
// an error (fail-closed).
func TestBuildPatternSet_MissingFile(t *testing.T) {
	cfg := &config.Config{RulesFile: filepath.Join(t.TempDir(), "nope.toml")}
	if _, err := BuildPatternSet(cfg); err == nil {
		t.Fatal("expected error for missing rules_file")
	}
}
