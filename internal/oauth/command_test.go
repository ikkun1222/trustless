package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ikkun1222/trustless/internal/backend"
	"github.com/ikkun1222/trustless/internal/config"
)

// cmdMemBackend は command テスト用のインメモリ backend.Backend 実装。
type cmdMemBackend struct {
	mu  sync.Mutex
	m   map[string]string
	set map[string]int
}

func newCmdMemBackend() *cmdMemBackend {
	return &cmdMemBackend{m: make(map[string]string), set: make(map[string]int)}
}

func (mb *cmdMemBackend) Resolve(ctx context.Context, key string) (string, error) {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	v, ok := mb.m[key]
	if !ok {
		return "", &backend.ErrNotFound{Key: key, Reason: "not in cmdMemBackend"}
	}
	return v, nil
}

func (mb *cmdMemBackend) List(ctx context.Context) ([]backend.Entry, error) {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	out := make([]backend.Entry, 0, len(mb.m))
	for k := range mb.m {
		out = append(out, backend.Entry{Key: k, Value: mb.m[k]})
	}
	return out, nil
}

func (mb *cmdMemBackend) Set(ctx context.Context, key, value string) error {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	mb.m[key] = value
	mb.set[key]++
	return nil
}

func (mb *cmdMemBackend) Values(ctx context.Context, minLen int) ([]string, error) {
	return nil, nil
}

func (mb *cmdMemBackend) putRaw(key, value string) {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	mb.m[key] = value
}

func (mb *cmdMemBackend) getRaw(key string) string {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	return mb.m[key]
}

// cmdCapturer は stdout / stderr を捕捉する。
type cmdCapturer struct {
	stdout, stderr *bytes.Buffer
}

// captureStdoutStderr は後続の Run 呼び出しの出力を捕捉して返す。
func captureStdoutStderr(t *testing.T) *cmdCapturer {
	t.Helper()
	c := &cmdCapturer{stdout: new(bytes.Buffer), stderr: new(bytes.Buffer)}
	origOut, origErr := stdout, stderr
	stdout, stderr = c.stdout, c.stderr
	t.Cleanup(func() { stdout, stderr = origOut, origErr })
	return c
}

// deviceFlowServer は疑似 device 認可開始 + token endpoint を立てる。
func deviceFlowServer(t *testing.T, tokenBody string) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	polled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/device") {
			fmt.Fprint(w, `{"device_code":"dc-1","user_code":"ABCD-1234","verification_uri":"https://example.test/verify","verification_uri_complete":"https://example.test/verify?user_code=ABCD-1234","expires_in":240,"interval":5}`)
			return
		}
		if !polled { // 1 回目は authorization_pending、2 回目で成功
			polled = true
			fmt.Fprint(w, `{"error":"authorization_pending"}`)
			return
		}
		fmt.Fprint(w, tokenBody)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// cmdConfig は httptest サーバを指す Provider 定義を持つ config を組み立てる。
func cmdConfig(srv *httptest.Server) *config.Config {
	return &config.Config{
		OAuth: config.OAuthConfig{
			Providers: map[string]config.OAuthProvider{
				"google": {
					TokenURL:     srv.URL + "/token",
					DeviceURL:    srv.URL + "/device",
					ClientID:     "client-1",
					ClientSecret: "secret-1",
					Scopes:       []string{"a", "b"},
					Refreshable:  true,
				},
			},
		},
	}
}

// cmdEntry は config.Provider に変換するヘルパー。
func cmdEntry(t *testing.T, e *OAuthEntry) string {
	t.Helper()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}
	return string(b)
}

// captureOutput は Run の戻り値と stdout をまとめて返す。
func runCmd(t *testing.T, args []string, be backend.Backend, cfg *config.Config) (int, string) {
	t.Helper()
	c := captureStdoutStderr(t)
	code := Run(args, be, cfg)
	return code, c.stdout.String()
}

// runLogin は疑似 device フロー（1 回 pending → 成功）で login を実行する。
func runLogin(t *testing.T, tokenBody string) (int, string, *cmdMemBackend) {
	t.Helper()
	fakeDeviceWait(t) // 実時間待ちを差し替え、poll を即時実行する
	srv := deviceFlowServer(t, tokenBody)
	mb := newCmdMemBackend()
	cfg := cmdConfig(srv)
	code, out := runCmd(t, []string{"login", "google", "key-1"}, NewBackend(mb, ProvidersFromConfig(cfg)), cfg)
	return code, out, mb
}

func TestCommandのloginは疑似deviceフローでエントリを保存しJSONを出力する(t *testing.T) {
	code, out, mb := runLogin(t, `{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600,"scope":"a b"}`)
	if code != 0 {
		t.Fatalf("login exit code = %d, want 0 (stdout: %s)", code, out)
	}
	if !strings.Contains(out, "https://example.test/verify?user_code=ABCD-1234") {
		t.Errorf("stdout = %q, want verification_uri_complete", out)
	}
	raw := mb.getRaw("key-1")
	if raw == "" {
		t.Fatal("stored entry is empty")
	}
	if strings.Count(raw, "\n") != 0 {
		t.Errorf("stored entry = %q, want single-line JSON", raw)
	}
	var stored OAuthEntry
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		t.Fatalf("unmarshal stored entry: %v", err)
	}
	if stored.Provider != "google" || stored.Access != "access-1" || stored.Refresh != "refresh-1" {
		t.Errorf("stored entry = %+v, want provider=google access=access-1 refresh=refresh-1", stored)
	}
	if !strings.Contains(out, `"key":"key-1"`) || !strings.Contains(out, `"provider":"google"`) {
		t.Errorf("stdout = %q, want key/provider fields", out)
	}
}

func TestCommandのloginは未定義プロバイダでエラーを返す(t *testing.T) {
	mb := newCmdMemBackend()
	c := captureStdoutStderr(t)
	code := Run([]string{"login", "nonexistent", "key-1"}, NewBackend(mb, ProvidersFromConfig(&config.Config{})), &config.Config{})
	if code == 0 {
		t.Fatalf("login exit code = %d, want non-zero", code)
	}
	if mb.getRaw("key-1") != "" {
		t.Errorf("stored entry = %q, want empty", mb.getRaw("key-1"))
	}
	if !strings.Contains(c.stderr.String(), "not defined") {
		t.Errorf("stderr = %q, want provider-not-defined error", c.stderr.String())
	}
}

func TestCommandのrefreshはForceRefreshで新トークンを保存し出力にトークン値が含まれない(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"access-2","refresh_token":"refresh-2","expires_in":3600}`)
	}))
	t.Cleanup(srv.Close)
	cfg := cmdConfig(srv)
	mb := newCmdMemBackend()
	mb.putRaw("key-1", cmdEntry(t, &OAuthEntry{Provider: "google", Access: "access-1", Refresh: "refresh-1", ExpiresAt: time.Now().Add(-1 * time.Minute)}))
	ob := NewBackend(mb, ProvidersFromConfig(cfg)).(*OAuthBackend)
	code, out := runCmd(t, []string{"refresh", "key-1"}, ob, cfg)
	if code != 0 {
		t.Fatalf("refresh exit code = %d, want 0 (stdout: %s)", code, out)
	}
	if strings.Contains(out, "access-2") || strings.Contains(out, "refresh-2") {
		t.Errorf("stdout = %q, must not contain token values", out)
	}
	if !strings.Contains(out, `"status":"ok"`) {
		t.Errorf("stdout = %q, want status ok", out)
	}
	var stored OAuthEntry
	if err := json.Unmarshal([]byte(mb.getRaw("key-1")), &stored); err != nil {
		t.Fatalf("unmarshal stored entry: %v", err)
	}
	if stored.Access != "access-2" || stored.Refresh != "refresh-2" {
		t.Errorf("stored = %+v, want refreshed access-2/refresh-2", stored)
	}
}

func TestCommandのstatusは未失効エントリをvalidと判定する(t *testing.T) {
	mb := newCmdMemBackend()
	mb.putRaw("key-1", cmdEntry(t, &OAuthEntry{Provider: "google", Access: "access-1", Refresh: "refresh-1", ExpiresAt: time.Now().Add(10 * time.Minute), Scopes: []string{"a", "b"}}))
	code, out := runCmd(t, []string{"status", "key-1"}, NewBackend(mb, ProvidersFromConfig(&config.Config{})), &config.Config{})
	if code != 0 {
		t.Fatalf("status exit code = %d, want 0", code)
	}
	if !strings.Contains(out, `"status":"valid"`) {
		t.Errorf("stdout = %q, want status valid", out)
	}
	if !strings.Contains(out, `"scopes":["a","b"]`) {
		t.Errorf("stdout = %q, want scopes", out)
	}
	if strings.Contains(out, "access-1") || strings.Contains(out, "refresh-1") {
		t.Errorf("stdout = %q, must not contain token values", out)
	}
}

func TestCommandのstatusは失効エントリをrefreshしてvalidと判定する(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"access-2","refresh_token":"refresh-2","expires_in":3600}`)
	}))
	t.Cleanup(srv.Close)
	cfg := cmdConfig(srv)
	mb := newCmdMemBackend()
	mb.putRaw("key-1", cmdEntry(t, &OAuthEntry{Provider: "google", Access: "access-1", Refresh: "refresh-1", ExpiresAt: time.Now().Add(-1 * time.Minute)}))
	ob := NewBackend(mb, ProvidersFromConfig(cfg)).(*OAuthBackend)
	code, out := runCmd(t, []string{"status", "key-1"}, ob, cfg)
	if code != 0 {
		t.Fatalf("status exit code = %d, want 0 (stdout: %s)", code, out)
	}
	if !strings.Contains(out, `"status":"valid"`) {
		t.Errorf("stdout = %q, want status valid after refresh", out)
	}
	if strings.Contains(out, "access-2") || strings.Contains(out, "refresh-2") {
		t.Errorf("stdout = %q, must not contain token values", out)
	}
	// refresh 成功で新しい access/refresh token が保存されている
	var stored OAuthEntry
	if err := json.Unmarshal([]byte(mb.getRaw("key-1")), &stored); err != nil {
		t.Fatalf("unmarshal stored entry: %v", err)
	}
	if stored.Access != "access-2" || stored.Refresh != "refresh-2" {
		t.Errorf("stored = %+v, want refreshed access-2/refresh-2", stored)
	}
}

func TestCommandのstatusはinvalidGrantでreauthRequiredを返す(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"error":"invalid_grant","error_description":"bad refresh token"}`)
	}))
	t.Cleanup(srv.Close)
	cfg := cmdConfig(srv)
	mb := newCmdMemBackend()
	mb.putRaw("key-1", cmdEntry(t, &OAuthEntry{Provider: "google", Access: "access-1", Refresh: "refresh-1", ExpiresAt: time.Now().Add(-1 * time.Minute)}))
	ob := NewBackend(mb, ProvidersFromConfig(cfg)).(*OAuthBackend)
	code, out := runCmd(t, []string{"status", "key-1"}, ob, cfg)
	if code != 0 {
		t.Fatalf("status exit code = %d, want 0 (stdout: %s)", code, out)
	}
	if !strings.Contains(out, `"status":"reauth_required"`) {
		t.Errorf("stdout = %q, want status reauth_required", out)
	}
	if strings.Contains(out, "access-1") || strings.Contains(out, "refresh-1") {
		t.Errorf("stdout = %q, must not contain token values", out)
	}
}

func TestCommandのprovidersは名称とtokenUrlを出力しclientSecretが含まれない(t *testing.T) {
	cfg := &config.Config{
		OAuth: config.OAuthConfig{
			Providers: map[string]config.OAuthProvider{
				"google": {TokenURL: "https://example.test/token", ClientID: "client-1", ClientSecret: "top-secret"},
				"lark":   {TokenURL: "https://lark.example/token", ClientSecret: "lark-secret"},
			},
		},
	}
	code, out := runCmd(t, []string{"providers"}, NewBackend(newCmdMemBackend(), ProvidersFromConfig(cfg)), cfg)
	if code != 0 {
		t.Fatalf("providers exit code = %d, want 0", code)
	}
	if !strings.Contains(out, `"name":"google"`) || !strings.Contains(out, "https://example.test/token") {
		t.Errorf("stdout = %q, want google name/token_url", out)
	}
	if !strings.Contains(out, `"name":"lark"`) || !strings.Contains(out, "https://lark.example/token") {
		t.Errorf("stdout = %q, want lark name/token_url", out)
	}
	if strings.Contains(out, "top-secret") || strings.Contains(out, "lark-secret") || strings.Contains(out, "client-1") {
		t.Errorf("stdout = %q, must not contain client_id/client_secret", out)
	}
}

func TestCommandはサブコマンド無しでusageを返しexit1する(t *testing.T) {
	c := captureStdoutStderr(t)
	code := Run(nil, NewBackend(newCmdMemBackend(), nil), &config.Config{})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(c.stderr.String(), "Usage:") {
		t.Errorf("stderr = %q, want usage", c.stderr.String())
	}
}

func TestCommandは不明なサブコマンドでusageを返しexit1する(t *testing.T) {
	c := captureStdoutStderr(t)
	code := Run([]string{"frobnicate"}, NewBackend(newCmdMemBackend(), nil), &config.Config{})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(c.stderr.String(), "Usage:") {
		t.Errorf("stderr = %q, want usage", c.stderr.String())
	}
}
