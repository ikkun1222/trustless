package serve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ikkun1222/trustless/internal/backend"
	"github.com/ikkun1222/trustless/internal/config"
	dlpconfig "github.com/ikkun1222/trustless/internal/dlp/config"
	dlpproxy "github.com/ikkun1222/trustless/internal/dlp/proxy"
	"github.com/ikkun1222/trustless/internal/proxy"
)

// fakeBackend is a controllable in-memory Backend for serve tests. Values
// returns the configured values (or error); Reload returns the configured
// error, so reload failure paths are testable without any real vault.
type fakeBackend struct {
	mu     sync.Mutex
	values []string
	err    error
	reload error

	valuesCalls atomic.Int32
}

func (f *fakeBackend) Resolve(context.Context, string) (string, error) { return "", nil }
func (f *fakeBackend) List(context.Context) ([]backend.Entry, error)   { return nil, nil }
func (f *fakeBackend) Set(context.Context, string, string) error       { return nil }

func (f *fakeBackend) Values(_ context.Context, _ int) ([]string, error) {
	f.valuesCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.values, nil
}

func (f *fakeBackend) Reload(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reload
}

func (f *fakeBackend) setValues(v []string) { f.mu.Lock(); defer f.mu.Unlock(); f.values = v }
func (f *fakeBackend) setErr(e error)       { f.mu.Lock(); defer f.mu.Unlock(); f.err = e }
func (f *fakeBackend) setReload(e error)    { f.mu.Lock(); defer f.mu.Unlock(); f.reload = e }

// freePort reserves an ephemeral TCP port and releases it, so the test can
// hand a concrete port to serveCore without knowing the OS assignment.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// writeTempDlpConfig writes a minimal valid dlp-proxy config.json.
func writeTempDlpConfig(t *testing.T) string {
	t.Helper()
	cfg := map[string]any{
		"listen":                   "127.0.0.1:0",
		"min_secret_len":           8,
		"secrets_source":           "pass",
		"secrets_refresh_interval": "10m",
		"routes": []map[string]string{
			{"prefix": "/v1/openai", "url": "http://127.0.0.1:1/v1/openai"},
		},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal dlp config: %v", err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write dlp config: %v", err)
	}
	return path
}

// isolateTrustlessConfig points the trustless config loader at a temp file
// so reloadAll never reads the real ~/.config/trustless/config.toml.
func isolateTrustlessConfig(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("backend = \"pass\"\n"), 0o600); err != nil {
		t.Fatalf("write trustless config: %v", err)
	}
	t.Setenv("TRUSTLESS_CONFIG", path)
}

// waitDial polls a TCP listener until it accepts connections.
func waitDial(t *testing.T, port int) {
	t.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("listener %s not reachable", addr)
}

func TestServeは注入とDLPの両リスナーを同時に起動する(t *testing.T) {
	injectPort := freePort(t)
	scrubPort := freePort(t)
	scrubListen := fmt.Sprintf("127.0.0.1:%d", scrubPort)

	be := &fakeBackend{}
	be.setValues([]string{"sk-serve-test-1234567890"})

	trustlessCfg := &config.Config{
		Proxy: config.ProxyConfig{
			Port: injectPort,
			Rules: map[string]config.ProxyRule{
				"api.x.ai": {Header: "Authorization", Key: "xai", Prefix: "Bearer "},
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- serveCore(ctx, injectPort, scrubListen, writeTempDlpConfig(t), false, trustlessCfg, be, log.New(io.Discard, "", 0))
	}()

	waitDial(t, injectPort)
	waitDial(t, scrubPort)

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("serveCore returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveCore did not stop after context cancel")
	}
}

func TestServeはdlp設定が壊れていると起動に失敗する(t *testing.T) {
	be := &fakeBackend{}
	err := serveCore(context.Background(), 18080, "127.0.0.1:18788",
		filepath.Join(t.TempDir(), "missing.json"), false, &config.Config{}, be, log.New(io.Discard, "", 0))
	if err == nil {
		t.Fatal("expected error for broken dlp config")
	}
}

func TestServeは秘密ロード失敗で起動に失敗する(t *testing.T) {
	be := &fakeBackend{}
	be.setErr(errors.New("bw session expired (simulated)"))

	err := serveCore(context.Background(), freePort(t), fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		writeTempDlpConfig(t), false, &config.Config{}, be, log.New(io.Discard, "", 0))
	if err == nil {
		t.Fatal("expected error when secret load fails")
	}
}

func TestServeは定期リロードで秘密セットを置き換える(t *testing.T) {
	isolateTrustlessConfig(t)
	dlpCfgPath := writeTempDlpConfig(t)

	be := &fakeBackend{}
	be.setValues([]string{"old-secret-1234567890"})
	set := dlpproxy.NewSecrets([]string{"old-secret-1234567890"})
	fwd := &proxy.Proxy{}
	dlpCfg := &dlpconfig.Config{MinSecretLen: 8}

	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)

	reloadAll(dlpCfgPath, dlpCfg, set, be, fwd, logger)
	if got := set.Snapshot(); len(got) != 1 || got[0] != "old-secret-1234567890" {
		t.Fatalf("set after first reload = %v", got)
	}

	be.setValues([]string{"new-secret-1234567890"})
	reloadAll(dlpCfgPath, dlpCfg, set, be, fwd, logger)

	if got := set.Snapshot(); len(got) != 1 || got[0] != "new-secret-1234567890" {
		t.Fatalf("set after second reload = %v, want new secret", got)
	}
	if n := be.valuesCalls.Load(); n < 2 {
		t.Fatalf("Values calls = %d, want >= 2 (reload must re-read the backend)", n)
	}
}

func TestServeはリロード失敗時に既存秘密を維持する(t *testing.T) {
	isolateTrustlessConfig(t)
	dlpCfgPath := writeTempDlpConfig(t)

	be := &fakeBackend{}
	be.setValues([]string{"old-secret-1234567890"})
	set := dlpproxy.NewSecrets([]string{"old-secret-1234567890"})
	fwd := &proxy.Proxy{}
	dlpCfg := &dlpconfig.Config{MinSecretLen: 8}

	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)

	reloadAll(dlpCfgPath, dlpCfg, set, be, fwd, logger)

	// 2 回目の backend Reload を失敗させても旧セットが維持される（fail-safe）
	be.setValues([]string{"new-secret-1234567890"})
	be.setReload(errors.New("bw session expired (simulated)"))
	reloadAll(dlpCfgPath, dlpCfg, set, be, fwd, logger)

	if got := set.Snapshot(); len(got) != 1 || got[0] != "old-secret-1234567890" {
		t.Fatalf("set changed on failed reload: %v (want old secret kept)", got)
	}
	if !strings.Contains(buf.String(), "WARN: backend reload failed") {
		t.Fatalf("expected WARN log, got: %s", buf.String())
	}
}

func TestServeのrecoverミドルウェアはpanicを500に変換する(t *testing.T) {
	panicHandler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("simulated handler bug")
	})
	h := recoverMiddleware(panicHandler, log.New(io.Discard, "", 0))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}
