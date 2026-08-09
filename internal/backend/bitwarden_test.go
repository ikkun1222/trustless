package backend

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testItemsJSON = `[
  {
    "id": "item-1",
    "name": "iria/api/openrouter",
    "type": 2,
    "secureNote": {"type": 0},
    "fields": [
      {"name": "value", "type": 1, "value": "sk-or-v1-secret"}
    ],
    "notes": "created 2026-01-01\nfor openrouter"
  },
  {
    "id": "item-2",
    "name": "gh-api",
    "type": 1,
    "login": {"username": "me", "password": "ghp_githubpass"},
    "fields": [],
    "notes": ""
  },
  {
    "id": "item-3",
    "name": "legacy/key",
    "type": 2,
    "secureNote": {"type": 0},
    "fields": [],
    "notes": "the-value-line\nmeta line"
  },
  {
    "id": "item-4",
    "name": "item/no-value",
    "type": 2,
    "secureNote": {"type": 0},
    "fields": [
      {"name": "other", "type": 1, "value": "x"}
    ],
    "notes": ""
  }
]`

func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestアイテムマッピングSecureNoteのフィールドから値を取得(t *testing.T) {
	entries, err := parseBWItems([]byte(testItemsJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	val, ok := entries["iria/api/openrouter"]
	if !ok || val != "sk-or-v1-secret" {
		t.Fatalf("secureNote value: got %q ok=%v", val, ok)
	}
}

func TestアイテムマッピングLogin型はパスワードを値として扱う(t *testing.T) {
	entries, err := parseBWItems([]byte(testItemsJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	val, ok := entries["gh-api"]
	if !ok || val != "ghp_githubpass" {
		t.Fatalf("login password: got %q ok=%v", val, ok)
	}
}

func TestアイテムマッピングNotes全体を値として扱う多行対応(t *testing.T) {
	entries, err := parseBWItems([]byte(testItemsJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	val, ok := entries["legacy/key"]
	if !ok || val != "the-value-line\nmeta line" {
		t.Fatalf("notes fallback (full notes): got %q ok=%v", val, ok)
	}
}

// 多行の秘密（PEM 等）が notes に格納されている場合、全行を値として返す
// （先頭1行のみに切断されないこと。2026-08-09 oci/api-key の再発防止）。
func TestアイテムマッピングNotesの多行PEMを全行返す(t *testing.T) {
	jsonData := `[
  {
    "id": "pem-1",
    "name": "multiline/pem",
    "type": 2,
    "secureNote": {"type": 0},
    "fields": [],
    "notes": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj\n-----END PRIVATE KEY-----\n"
  }
]`
	entries, err := parseBWItems([]byte(jsonData))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	val, ok := entries["multiline/pem"]
	if !ok {
		t.Fatalf("key not found")
	}
	want := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj\n-----END PRIVATE KEY-----"
	if val != want {
		t.Fatalf("multiline notes: got %q want %q", val, want)
	}
}

func Testアイテムマッピング値が無いアイテムはスキップ(t *testing.T) {
	noValueJSON := `[
  {
    "id": "item-x",
    "name": "item/no-value",
    "type": 2,
    "secureNote": {"type": 0},
    "fields": [
      {"name": "other", "type": 1, "value": "x"}
    ],
    "notes": ""
  }
]`
	entries, err := parseBWItems([]byte(noValueJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if len(entries) != 0 {
		t.Fatalf("expected item without value to be skipped, got %d entries", len(entries))
	}
}

func TestアイテムマッピングJSON不正はエラー(t *testing.T) {
	if _, err := parseBWItems([]byte("{invalid")); err == nil {
		t.Fatalf("expected error for invalid JSON")
	}
}

func Testセッションファイルの保存と読込(t *testing.T) {
	dir := t.TempDir()
	sessionPath := filepath.Join(dir, "bw-session")

	if err := saveSession(sessionPath, "session-key-abc"); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := loadSession(sessionPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got != "session-key-abc" {
		t.Fatalf("session: got %q", got)
	}

	info, err := os.Stat(sessionPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("session file perm = %o, want 600", perm)
	}
}

func Testセッションファイルは改行を除去して読込(t *testing.T) {
	dir := t.TempDir()
	sessionPath := writeTestFile(t, dir, "bw-session", "session-key-with-newline\n")

	got, err := loadSession(sessionPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got != "session-key-with-newline" {
		t.Fatalf("session: got %q", got)
	}
}

func Testセッションファイル不存在はエラー(t *testing.T) {
	if _, err := loadSession(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatalf("expected error for missing session file")
	}
}

func Testセッションファイルは上書きしても権限を600に保つ(t *testing.T) {
	dir := t.TempDir()
	sessionPath := writeTestFile(t, dir, "bw-session", "old-session")

	if err := saveSession(sessionPath, "new-session"); err != nil {
		t.Fatalf("save: %v", err)
	}

	info, err := os.Stat(sessionPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("session file perm = %o, want 600", perm)
	}
}

func TestキャッシュTTL24時間以内は有効(t *testing.T) {
	now := time.Now()
	ttl := 24 * time.Hour
	if !cacheFresh(now.Add(-23*time.Hour), now, ttl) {
		t.Fatalf("expected cache within TTL to be fresh")
	}
}

func TestキャッシュTTL24時間超は失効(t *testing.T) {
	now := time.Now()
	ttl := 24 * time.Hour
	if cacheFresh(now.Add(-25*time.Hour), now, ttl) {
		t.Fatalf("expected cache beyond TTL to be stale")
	}
}

func TestキャッシュTTLちょうど24時間は有効(t *testing.T) {
	now := time.Now()
	ttl := 24 * time.Hour
	if !cacheFresh(now.Add(-ttl), now, ttl) {
		t.Fatalf("expected cache at exactly TTL to be fresh")
	}
}

func Testキャッシュタイムスタンプなしは失効(t *testing.T) {
	now := time.Now()
	if cacheFresh(time.Time{}, now, 24*time.Hour) {
		t.Fatalf("expected cache without timestamp to be stale")
	}
}

func Testブートストラップ認証ファイルの読込(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "bitwarden-credentials.env", "client_id=abc\nclient_secret=xyz\n")

	clientID, clientSecret, err := loadCredentials(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if clientID != "abc" || clientSecret != "xyz" {
		t.Fatalf("got client_id=%q client_secret=%q", clientID, clientSecret)
	}
}

func Testブートストラップ認証ファイルの改行と空白を除去(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "bitwarden-credentials.env", "client_id = abc  \nclient_secret= xyz\n")

	clientID, clientSecret, err := loadCredentials(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if clientID != "abc" || clientSecret != "xyz" {
		t.Fatalf("got client_id=%q client_secret=%q", clientID, clientSecret)
	}
}

func Testブートストラップ認証ファイルの必須キー欠落はエラー(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "bitwarden-credentials.env", "client_id=abc\n")

	if _, _, err := loadCredentials(path); err == nil {
		t.Fatalf("expected error when client_secret is missing")
	}
}

func Testブートストラップ認証ファイル不存在はエラー(t *testing.T) {
	if _, _, err := loadCredentials(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatalf("expected error for missing credentials file")
	}
}

func Testバックエンド作成はキャッシュを即時ロードする(t *testing.T) {
	fake := &fakeBW{listOutput: testItemsJSON, listErr: nil}

	be := NewBitwardenBackend(Options{
		SessionPath: filepath.Join(t.TempDir(), "bw-session"),
		runList:     fake.runList,
	})
	if err := be.Load(context.Background()); err != nil {
		t.Fatalf("load: %v", err)
	}

	if fake.listCalls != 1 {
		t.Fatalf("expected exactly 1 list call at load, got %d", fake.listCalls)
	}
	entries, err := be.List(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
}

func Testセッション失効時はキャッシュを使わずfailClosed(t *testing.T) {
	fake := &fakeBW{listOutput: testItemsJSON, listErr: nil, statusErr: errTestSessionExpired}

	be := NewBitwardenBackend(Options{
		SessionPath: filepath.Join(t.TempDir(), "bw-session"),
		runList:     fake.runList,
	})
	if err := be.Load(context.Background()); err != nil {
		t.Fatalf("load: %v", err)
	}
	fake.statusErr = errTestSessionExpired

	if _, err := be.Resolve(context.Background(), "iria/api/openrouter"); err == nil {
		t.Fatalf("expected fail-closed on session expiry")
	}
}

func Testセッション状態はTTL内はbwステータスを1回しか実行しない(t *testing.T) {
	fake := &fakeBW{listOutput: testItemsJSON, listErr: nil}

	be := NewBitwardenBackend(Options{
		SessionPath:     filepath.Join(t.TempDir(), "bw-session"),
		runList:         fake.runList,
		runStatus:       fake.runStatus,
		SessionCheckTTL: time.Hour, // 将来実装: TTL内は status チェックをスキップ
	})
	if err := be.Load(context.Background()); err != nil {
		t.Fatalf("load: %v", err)
	}

	for _, key := range []string{"iria/api/openrouter", "gh-api"} {
		if _, err := be.Resolve(context.Background(), key); err != nil {
			t.Fatalf("resolve %s: %v", key, err)
		}
	}

	if fake.statusCalls != 1 {
		t.Fatalf("expected bw status to run exactly once within TTL, got %d", fake.statusCalls)
	}
}

func Testセッション状態はTTL経過後に再チェックする(t *testing.T) {
	fake := &fakeBW{listOutput: testItemsJSON, listErr: nil}

	be := NewBitwardenBackend(Options{
		SessionPath:     filepath.Join(t.TempDir(), "bw-session"),
		runList:         fake.runList,
		runStatus:       fake.runStatus,
		SessionCheckTTL: time.Nanosecond, // TTL が即失効するため再チェックされる
	})
	if err := be.Load(context.Background()); err != nil {
		t.Fatalf("load: %v", err)
	}

	if _, err := be.Resolve(context.Background(), "iria/api/openrouter"); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if _, err := be.Resolve(context.Background(), "gh-api"); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if fake.statusCalls < 2 {
		t.Fatalf("expected bw status to re-run after TTL expiry, got %d calls", fake.statusCalls)
	}
}

func Testセッション失効はTTLキャッシュがあってもfailClosedする(t *testing.T) {
	fake := &fakeBW{listOutput: testItemsJSON, listErr: nil, statusErr: errTestSessionExpired}

	be := NewBitwardenBackend(Options{
		SessionPath:     filepath.Join(t.TempDir(), "bw-session"),
		runList:         fake.runList,
		SessionCheckTTL: time.Hour, // 将来実装: キャッシュがあっても失効は必ず fail-closed
	})
	if err := be.Load(context.Background()); err != nil {
		t.Fatalf("load: %v", err)
	}
	fake.statusErr = errTestSessionExpired

	if _, err := be.Resolve(context.Background(), "iria/api/openrouter"); err == nil {
		t.Fatalf("expected fail-closed on session expiry even with TTL cache")
	}
}

func Testアイテム欠落はErrNotFound(t *testing.T) {
	fake := &fakeBW{listOutput: testItemsJSON, listErr: nil}

	be := NewBitwardenBackend(Options{
		SessionPath: filepath.Join(t.TempDir(), "bw-session"),
		runList:     fake.runList,
	})
	if err := be.Load(context.Background()); err != nil {
		t.Fatalf("load: %v", err)
	}

	_, err := be.Resolve(context.Background(), "does/not/exist")
	if _, ok := err.(*ErrNotFound); !ok {
		t.Fatalf("expected ErrNotFound, got %T: %v", err, err)
	}
}

func Testリスト出力のbwエラーはプロパゲート(t *testing.T) {
	fake := &fakeBW{listErr: errTestBwDown}

	be := NewBitwardenBackend(Options{
		SessionPath: filepath.Join(t.TempDir(), "bw-session"),
		runList:     fake.runList,
	})
	if err := be.Load(context.Background()); err == nil {
		t.Fatalf("expected load error when bw list fails")
	}
}

var (
	errTestBwDown         = &fakeBWError{msg: "bw not reachable"}
	errTestSessionExpired = &fakeBWError{msg: "not logged in"}
)

type fakeBWError struct{ msg string }

func (e *fakeBWError) Error() string { return e.msg }

type fakeBW struct {
	listOutput  string
	listErr     error
	statusErr   error
	listCalls   int
	statusCalls int
}

func (f *fakeBW) runList(ctx context.Context) ([]byte, error) {
	f.listCalls++
	return []byte(f.listOutput), f.listErr
}

func (f *fakeBW) runStatus(ctx context.Context) ([]byte, error) {
	f.statusCalls++
	return nil, f.statusErr
}

func Testコマンド成功はbw実行を返す(t *testing.T) {
	cmd := buildBWCommand("bw", []string{"list", "items"}, "SESSION")
	if cmd == nil {
		t.Fatalf("expected cmd")
	}
	if len(cmd.Args) != 3 || cmd.Args[1] != "list" || cmd.Args[2] != "items" {
		t.Fatalf("unexpected args: %v", cmd.Args)
	}
	found := false
	for _, kv := range cmd.Env {
		if kv == "BW_SESSION=SESSION" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("BW_SESSION not set in env: %v", cmd.Env)
	}
	// The session value must appear only in BW_SESSION, never elsewhere.
	for _, kv := range cmd.Env {
		if !strings.Contains(kv, "=SESSION") {
			continue
		}
		if !strings.HasPrefix(kv, "BW_SESSION=") {
			t.Fatalf("session leaked in env var: %q", kv)
		}
	}
}

func Testセッション失効判定はプロンプト要求も検知する(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		want bool
	}{
		{"not logged in", "bw list: exit status 1: You are not logged in.", true},
		{"invalid session", "bw list: exit status 1: Invalid session.", true},
		{"master password prompt", "bw list: exit status 1: ? Master password: [input is hidden]", true},
		{"network error", "bw list: exit status 1: connect: connection refused", false},
		{"timeout", "bw list: signal: killed", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSessionErr(&bwError{msg: tc.msg}); got != tc.want {
				t.Fatalf("isSessionErr(%q) = %v, want %v", tc.msg, got, tc.want)
			}
		})
	}
}

func Testセッション状態キャッシュは並行Resolveで安全(t *testing.T) {
	fake := &fakeBW{listOutput: testItemsJSON, listErr: nil}

	be := NewBitwardenBackend(Options{
		SessionPath:     filepath.Join(t.TempDir(), "bw-session"),
		runList:         fake.runList,
		runStatus:       fake.runStatus,
		SessionCheckTTL: time.Hour,
	})
	if err := be.Load(context.Background()); err != nil {
		t.Fatalf("load: %v", err)
	}

	const goroutines = 16
	const iters = 50
	keys := []string{"iria/api/openrouter", "gh-api", "legacy/key"}
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines*iters)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				key := keys[(g+i)%len(keys)]
				if _, err := be.Resolve(context.Background(), key); err != nil {
					errCh <- fmt.Errorf("resolve %s: %w", key, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}
