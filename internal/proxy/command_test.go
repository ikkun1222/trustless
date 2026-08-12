package proxy

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/ikkun1222/trustless/internal/backend"
	"github.com/ikkun1222/trustless/internal/config"
)

// mockBackend is a minimal in-memory Backend for proxy tests.
type mockBackend struct {
	values map[string]string
}

func (m *mockBackend) Resolve(_ context.Context, key string) (string, error) {
	if v, ok := m.values[key]; ok {
		return v, nil
	}
	return "", errors.New("not found")
}
func (m *mockBackend) List(context.Context) ([]backend.Entry, error) { return nil, nil }
func (m *mockBackend) Set(context.Context, string, string) error     { return errors.New("read only") }

func newTestProxy(rules map[string]config.ProxyRule, allowlist []string) *Proxy {
	return &Proxy{
		backend: &mockBackend{values: map[string]string{
			"xai":        "sk-test-xai-12345",
			"openrouter": "sk-or-v1-test",
			"edinet":     "ESTAT-APPID-999",
			"estat":      "ESTAT-APPID-999",
		}},
		rules:     rules,
		allowlist: allowlist,
	}
}

func TestProxyホストベース注入でヘッダーが付与される(t *testing.T) {
	p := newTestProxy(map[string]config.ProxyRule{
		"api.x.ai": {Header: "Authorization", Key: "xai", Prefix: "Bearer "},
	}, nil)

	req := httptestNewRequest("GET", "https://api.x.ai/v1/models")
	p.substituteRequest(req)

	got := req.Header.Get("Authorization")
	if got != "Bearer sk-test-xai-12345" {
		t.Fatalf("Authorization = %q, want %q", got, "Bearer sk-test-xai-12345")
	}
}

func TestProxyホストベース注入は既存ヘッダーを上書きしない(t *testing.T) {
	p := newTestProxy(map[string]config.ProxyRule{
		"api.x.ai": {Header: "Authorization", Key: "xai", Prefix: "Bearer "},
	}, nil)

	req := httptestNewRequest("GET", "https://api.x.ai/v1/models")
	req.Header.Set("Authorization", "custom-value")
	p.substituteRequest(req)

	if got := req.Header.Get("Authorization"); got != "custom-value" {
		t.Fatalf("Authorization = %q, want existing %q untouched", got, "custom-value")
	}
}

func TestProxyホストベース注入はルール外ホストに何もしない(t *testing.T) {
	p := newTestProxy(map[string]config.ProxyRule{
		"api.x.ai": {Header: "Authorization", Key: "xai", Prefix: "Bearer "},
	}, nil)

	req := httptestNewRequest("GET", "https://other.example.com/")
	p.substituteRequest(req)

	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("Authorization = %q, want empty", got)
	}
}

func TestProxyホストベース注入はプレースホルダ互換のキー解決を使う(t *testing.T) {
	// key に iria/api/ プレフィックス付きでも解決できる
	p := newTestProxy(map[string]config.ProxyRule{
		"api.edinet-fsa.go.jp": {Header: "Ocp-Apim-Subscription-Key", Key: "edinet"},
	}, nil)

	req := httptestNewRequest("GET", "https://api.edinet-fsa.go.jp/v2/documents.json")
	p.substituteRequest(req)

	if got := req.Header.Get("Ocp-Apim-Subscription-Key"); got != "ESTAT-APPID-999" {
		t.Fatalf("Ocp-Apim-Subscription-Key = %q, want ESTAT-APPID-999", got)
	}
}

func TestProxyホストベース注入は未解決キーでfailOpen(t *testing.T) {
	p := newTestProxy(map[string]config.ProxyRule{
		"api.unknown.io": {Header: "Authorization", Key: "does-not-exist", Prefix: "Bearer "},
	}, nil)

	req := httptestNewRequest("GET", "https://api.unknown.io/")
	p.substituteRequest(req)

	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("Authorization = %q, want empty (unresolved key must not be injected)", got)
	}
}

func TestProxyプレースホルダ方式は廃止されホストルールで解決する(t *testing.T) {
	// 旧プレースホルダ（__KEY__）は解決されず、そのまま残る
	p := newTestProxy(nil, nil)

	req := httptestNewRequest("GET", "https://api.x.ai/v1/models?x=__XAI__")
	req.Header.Set("Authorization", "Bearer __XAI__")
	p.substituteRequest(req)

	if got := req.Header.Get("Authorization"); got != "Bearer __XAI__" {
		t.Fatalf("Authorization = %q, want placeholder left untouched (host rules only)", got)
	}
}

func TestProxyクエリパラメータ注入(t *testing.T) {
	p := newTestProxy(map[string]config.ProxyRule{
		"statdb.nstac.go.jp": {Query: "appid", Key: "estat"},
	}, nil)

	req := httptestNewRequest("GET", "https://statdb.nstac.go.jp/api/getStatsList")
	p.substituteRequest(req)

	if got := req.URL.Query().Get("appid"); got != "ESTAT-APPID-999" {
		t.Fatalf("query appid = %q, want ESTAT-APPID-999", got)
	}
}

func TestProxyクエリ注入は既存パラメータを上書きしない(t *testing.T) {
	p := newTestProxy(map[string]config.ProxyRule{
		"statdb.nstac.go.jp": {Query: "appid", Key: "estat"},
	}, nil)

	req := httptestNewRequest("GET", "https://statdb.nstac.go.jp/api/getStatsList?appid=user-supplied")
	p.substituteRequest(req)

	if got := req.URL.Query().Get("appid"); got != "user-supplied" {
		t.Fatalf("query appid = %q, want existing value untouched", got)
	}
}

func TestProxyクエリ注入は他のパラメータを保持する(t *testing.T) {
	p := newTestProxy(map[string]config.ProxyRule{
		"statdb.nstac.go.jp": {Query: "appid", Key: "estat"},
	}, nil)

	req := httptestNewRequest("GET", "https://statdb.nstac.go.jp/api/getStatsList?lang=J&statsDataId=001")
	p.substituteRequest(req)

	q := req.URL.Query()
	if got := q.Get("appid"); got != "ESTAT-APPID-999" {
		t.Fatalf("query appid = %q, want ESTAT-APPID-999", got)
	}
	if got := q.Get("lang"); got != "J" {
		t.Fatalf("query lang = %q, want J preserved", got)
	}
}

func TestProxyallowlistは許可ホストのみ通す(t *testing.T) {
	p := newTestProxy(nil, []string{"api.x.ai"})

	if !p.allowedHost("api.x.ai") {
		t.Fatal("allowedHost(api.x.ai) = false, want true")
	}
	if !p.allowedHost("api.x.ai:443") {
		t.Fatal("allowedHost(api.x.ai:443) = false, want true (port stripped)")
	}
	if p.allowedHost("evil.example.com") {
		t.Fatal("allowedHost(evil.example.com) = true, want false")
	}
}

func TestProxyallowlist空は全許可(t *testing.T) {
	p := newTestProxy(nil, nil)

	if !p.allowedHost("anything.example.com") {
		t.Fatal("empty allowlist must permit all hosts (backwards compatible)")
	}
}

// httptestNewRequest builds an http.Request without importing net/http/httptest
// (keeps the proxy package dependency surface small).
func httptestNewRequest(method, url string) *http.Request {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		panic(err)
	}
	return req
}
