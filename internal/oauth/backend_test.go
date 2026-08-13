package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ikkun1222/trustless/internal/backend"
)

// memBackend はテスト用のインメモリ backend.Backend 実装。
type memBackend struct {
	mu  sync.Mutex
	m   map[string]string
	set map[string]int // Set 呼び出し回数（書き戻し検証用）
}

func newMemBackend() *memBackend {
	return &memBackend{m: make(map[string]string), set: make(map[string]int)}
}

func (mb *memBackend) Resolve(ctx context.Context, key string) (string, error) {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	v, ok := mb.m[key]
	if !ok {
		return "", &backend.ErrNotFound{Key: key, Reason: "not in memBackend"}
	}
	return v, nil
}

func (mb *memBackend) List(ctx context.Context) ([]backend.Entry, error) {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	out := make([]backend.Entry, 0, len(mb.m))
	for k := range mb.m {
		out = append(out, backend.Entry{Key: k, Value: mb.m[k]})
	}
	return out, nil
}

func (mb *memBackend) Set(ctx context.Context, key, value string) error {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	mb.m[key] = value
	mb.set[key]++
	return nil
}

func (mb *memBackend) Values(ctx context.Context, minLen int) ([]string, error) {
	return nil, nil
}

// 直接書き換え（別プロセスの書き込みを模擬）
func (mb *memBackend) putRaw(key, value string) {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	mb.m[key] = value
}

// countingTokenServer はリクエスト回数をカウントする疑似 token サーバ。
type countingTokenServer struct {
	calls atomic.Int64
	body  string // 応答ボディ（テストごとに差し替え）
}

func (ts *countingTokenServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, ts.body)
	})
}

// marshalEntry は OAuthEntry を単一行 JSON に変換する。
func marshalEntry(t *testing.T, e *OAuthEntry) string {
	t.Helper()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}
	return string(b)
}

// newOAuthBackend は memBackend + 疑似 token サーバで OAuthBackend を組み立てる。
func newOAuthBackend(t *testing.T, ts *countingTokenServer) (*OAuthBackend, *memBackend) {
	t.Helper()
	mb := newMemBackend()
	providers := map[string]Provider{
		"google": {Name: "google", TokenURL: "", Refreshable: true},
		"lark":   {Name: "lark", TokenURL: "", TokenRequestStyle: "json", Refreshable: true},
	}
	if ts != nil {
		srv := httptest.NewServer(ts.handler())
		t.Cleanup(srv.Close)
		p := providers["google"]
		p.TokenURL = srv.URL
		providers["google"] = p
		p = providers["lark"]
		p.TokenURL = srv.URL
		providers["lark"] = p
	}
	b := NewBackend(mb, providers).(*OAuthBackend)
	return b, mb
}

func TestBackendのResolveは静的エントリを素通しする(t *testing.T) {
	b, mb := newOAuthBackend(t, nil)
	mb.putRaw("static", "static-secret")
	got, err := b.Resolve(context.Background(), "static")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got != "static-secret" {
		t.Errorf("Resolve() = %q, want %q", got, "static-secret")
	}
}

func TestBackendのResolveは未失効ならキャッシュから返しHTTP呼び出ししない(t *testing.T) {
	ts := &countingTokenServer{body: `{"access_token":"access-1","expires_in":3600}`}
	b, mb := newOAuthBackend(t, ts)
	// 失効済みエントリで一度 refresh させ、キャッシュを暖める
	entry := &OAuthEntry{Provider: "google", Access: "access-0", Refresh: "refresh-1", ExpiresAt: time.Now().Add(-1 * time.Minute)}
	mb.putRaw("oauth-key", marshalEntry(t, entry))
	if _, err := b.Resolve(context.Background(), "oauth-key"); err != nil {
		t.Fatalf("Resolve() warmup error = %v", err)
	}
	if ts.calls.Load() != 1 {
		t.Fatalf("token server calls after warmup = %d, want 1", ts.calls.Load())
	}
	// 未失効エントリへの解決はキャッシュから返り、HTTP 呼び出しが発生しない
	got, err := b.Resolve(context.Background(), "oauth-key")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got != "access-1" {
		t.Errorf("Resolve() = %q, want %q", got, "access-1")
	}
	if ts.calls.Load() != 1 {
		t.Errorf("token server calls = %d, want still 1", ts.calls.Load())
	}
}

func TestBackendのResolveは失効していたら自動refreshして新しいトークンを返す(t *testing.T) {
	ts := &countingTokenServer{body: `{"access_token":"access-new","expires_in":3600}`}
	b, mb := newOAuthBackend(t, ts)
	entry := &OAuthEntry{Provider: "google", Access: "access-old", Refresh: "refresh-1", ExpiresAt: time.Now().Add(-1 * time.Minute)}
	mb.putRaw("oauth-key", marshalEntry(t, entry))
	got, err := b.Resolve(context.Background(), "oauth-key")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got != "access-new" {
		t.Errorf("Resolve() = %q, want %q", got, "access-new")
	}
	if ts.calls.Load() != 1 {
		t.Errorf("token server calls = %d, want 1", ts.calls.Load())
	}
}

func TestBackendのResolveはrefresh成功後にエントリを書き戻す(t *testing.T) {
	ts := &countingTokenServer{body: `{"access_token":"access-new","refresh_token":"refresh-2","expires_in":3600}`}
	b, mb := newOAuthBackend(t, ts)
	entry := &OAuthEntry{Provider: "google", Access: "access-old", Refresh: "refresh-1", ExpiresAt: time.Now().Add(-1 * time.Minute)}
	mb.putRaw("oauth-key", marshalEntry(t, entry))
	if _, err := b.Resolve(context.Background(), "oauth-key"); err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	raw, _ := mb.Resolve(context.Background(), "oauth-key")
	var updated OAuthEntry
	if err := json.Unmarshal([]byte(raw), &updated); err != nil {
		t.Fatalf("unmarshal stored entry: %v", err)
	}
	if updated.Refresh != "refresh-2" {
		t.Errorf("stored Refresh = %q, want rotated %q", updated.Refresh, "refresh-2")
	}
	if updated.Access != "access-new" {
		t.Errorf("stored Access = %q, want %q", updated.Access, "access-new")
	}
}

// TestBackendのResolveはrefresh中に別プロセスが書き換えたら書き戻さない:
// 疑似 token サーバを refresh 実行中にブロックし、その隙に別プロセスが
// エントリを書き換える。refresh 完了後も別プロセスの値が保持される
// （CAS ガードにより上書きされない）ことを検証する。
func TestBackendのResolveはrefresh中に別プロセスが書き換えたら書き戻さない(t *testing.T) {
	blocked := make(chan struct{})
	ts := &countingTokenServer{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.calls.Add(1)
		<-blocked // refresh 実行中を模擬
		fmt.Fprint(w, `{"access_token":"access-new","refresh_token":"refresh-2","expires_in":3600}`)
	}))
	t.Cleanup(srv.Close)
	mb := newMemBackend()
	providers := map[string]Provider{
		"google": {Name: "google", TokenURL: srv.URL, Refreshable: true},
	}
	b := NewBackend(mb, providers).(*OAuthBackend)

	entry := &OAuthEntry{Provider: "google", Access: "access-old", Refresh: "refresh-1", ExpiresAt: time.Now().Add(-1 * time.Minute)}
	mb.putRaw("oauth-key", marshalEntry(t, entry))

	// refresh を別 goroutine で開始（HTTP 呼び出しでブロックされる）
	resCh := make(chan struct{})
	go func() {
		b.Resolve(context.Background(), "oauth-key")
		close(resCh)
	}()
	// サーバがリクエストを受けたことを待つ
	deadline := time.Now().Add(5 * time.Second)
	for ts.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if ts.calls.Load() != 1 {
		t.Fatalf("token server calls = %d, want 1 (refresh in flight)", ts.calls.Load())
	}
	// 別プロセスが refresh 中にエントリを書き換える
	other := &OAuthEntry{Provider: "google", Access: "other-access", Refresh: "other-refresh", ExpiresAt: time.Now().Add(10 * time.Minute)}
	otherJSON := marshalEntry(t, other)
	mb.putRaw("oauth-key", otherJSON)
	// ブロック解除 → refresh 完了
	close(blocked)
	select {
	case <-resCh:
	case <-time.After(5 * time.Second):
		t.Fatal("Resolve() did not finish after unblocking")
	}
	// CAS ガードにより別プロセスの値が保持される
	raw, _ := mb.Resolve(context.Background(), "oauth-key")
	if raw != otherJSON {
		t.Errorf("stored value = %q, want other process value %q (CAS guard)", raw, otherJSON)
	}
}

func TestBackendのResolveはinvalidGrantでErrInvalidGrantを返し自動リトライしない(t *testing.T) {
	ts := &countingTokenServer{body: `{"error":"invalid_grant","error_description":"bad token"}`}
	b, mb := newOAuthBackend(t, ts)
	entry := &OAuthEntry{Provider: "google", Access: "access-old", Refresh: "refresh-1", ExpiresAt: time.Now().Add(-1 * time.Minute)}
	mb.putRaw("oauth-key", marshalEntry(t, entry))
	_, err := b.Resolve(context.Background(), "oauth-key")
	if !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("Resolve() error = %v, want ErrInvalidGrant", err)
	}
	if ts.calls.Load() != 1 {
		t.Errorf("token server calls = %d, want 1 (no retry)", ts.calls.Load())
	}
}

func TestBackendのResolveはRefreshableがfalseならキャッシュもHTTPも使わずaccessを返す(t *testing.T) {
	ts := &countingTokenServer{body: `{"access_token":"should-not-be-used","expires_in":3600}`}
	mb := newMemBackend()
	// Refreshable=false のプロバイダを追加
	providers := map[string]Provider{
		"static-provider": {Name: "static-provider", TokenURL: "", Refreshable: false},
	}
	if ts != nil {
		srv := httptest.NewServer(ts.handler())
		t.Cleanup(srv.Close)
		p := providers["static-provider"]
		p.TokenURL = srv.URL
		providers["static-provider"] = p
	}
	bb := NewBackend(mb, providers).(*OAuthBackend)
	entry := &OAuthEntry{Provider: "static-provider", Access: "access-static", Refresh: "refresh-1", ExpiresAt: time.Now().Add(-1 * time.Minute)}
	mb.putRaw("oauth-key", marshalEntry(t, entry))
	got, err := bb.Resolve(context.Background(), "oauth-key")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got != "access-static" {
		t.Errorf("Resolve() = %q, want %q", got, "access-static")
	}
	if ts.calls.Load() != 0 {
		t.Errorf("token server calls = %d, want 0", ts.calls.Load())
	}
}

func TestBackendのValuesはOAuthキーのfreshアクセスと静的キーを含みdedupソートする(t *testing.T) {
	ts := &countingTokenServer{body: `{"access_token":"access-fresh","expires_in":3600}`}
	b, mb := newOAuthBackend(t, ts)
	entry := &OAuthEntry{Provider: "google", Access: "access-old", Refresh: "refresh-1", ExpiresAt: time.Now().Add(-1 * time.Minute)}
	mb.putRaw("oauth-key", marshalEntry(t, entry))
	mb.putRaw("static-key", "static-secret")
	got, err := b.Values(context.Background(), 1)
	if err != nil {
		t.Fatalf("Values() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Values() = %v, want 2 values", got)
	}
	if got[0] != "access-fresh" {
		t.Errorf("Values()[0] = %q, want fresh access token", got[0])
	}
	if got[1] != "static-secret" {
		t.Errorf("Values()[1] = %q, want static secret", got[1])
	}
}

func TestBackendのResolveエラー文字列にトークン値が含まれない(t *testing.T) {
	ts := &countingTokenServer{body: `{"error":"invalid_grant","error_description":"bad token"}`}
	b, mb := newOAuthBackend(t, ts)
	entry := &OAuthEntry{Provider: "google", Access: "access-secret-value", Refresh: "refresh-secret-value", ExpiresAt: time.Now().Add(-1 * time.Minute)}
	mb.putRaw("oauth-key", marshalEntry(t, entry))
	_, err := b.Resolve(context.Background(), "oauth-key")
	if err == nil {
		t.Fatal("Resolve() error = nil, want non-nil")
	}
	for _, secret := range []string{"access-secret-value", "refresh-secret-value"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error message %q leaks secret %q", err.Error(), secret)
		}
	}
}
