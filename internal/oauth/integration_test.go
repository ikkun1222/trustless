// E2E 統合テスト（外部パッケージ視点）:
// httptest 疑似プロバイダ + インメモリ mock backend のみで、
// 実プロバイダ・実 config・実バックエンド（pass/bitwarden）に一切触れない。
// login（device flow）→ 保存 → Resolve（キャッシュ / 失効 refresh / ローテーション / invalid_grant）→
// 静的エントリ混在の素通し、を一連のシナリオとして検証する。
package oauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ikkun1222/trustless/internal/backend"
	"github.com/ikkun1222/trustless/internal/oauth"
)

// entryJSON は type=oauth の compact 単一行 JSON かどうかを検証するヘルパー。
func entryJSON(t *testing.T, s string) *oauth.OAuthEntry {
	t.Helper()
	if strings.ContainsAny(s, "\n\r") {
		t.Fatalf("stored entry is not single-line JSON: %q", s)
	}
	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal([]byte(s), &probe); err != nil {
		t.Fatalf("unmarshal type probe: %v", err)
	}
	if probe.Type != "oauth" {
		t.Fatalf("stored entry type = %q, want %q", probe.Type, "oauth")
	}
	var e oauth.OAuthEntry
	if err := json.Unmarshal([]byte(s), &e); err != nil {
		t.Fatalf("unmarshal stored entry: %v", err)
	}
	return &e
}

// reqCount は疑似プロバイダへのリクエスト回数を数える。
type reqCount struct{ n atomic.Int64 }

func (c *reqCount) add() { c.n.Add(1) }

// tokenHandler は /token へのリクエストを処理する。リクエストの
// 認証スタイル（Basic ヘッダ or form/JSON ボディ）と内容を記録する。
type tokenHandler struct {
	count  *reqCount
	mu     sync.Mutex
	seq    []string
	auths  []string
	params []map[string]string
	// resp は応答ボディのキュー。1 回の refresh につき先頭を消費する。
	// 応答が無ければ 401 を返す（refresh 不要の検証に使う）。
	resp []string
}

func (h *tokenHandler) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.count.add()
		h.mu.Lock()
		defer h.mu.Unlock()
		auth := r.Header.Get("Authorization")
		ct := r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		h.seq = append(h.seq, fmt.Sprintf("%s %s", r.Method, r.URL.Path))
		h.auths = append(h.auths, auth)
		p := map[string]string{"content_type": ct}
		if strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
			vals, err := url.ParseQuery(string(body))
			if err == nil {
				for k := range vals {
					p[k] = vals.Get(k)
				}
			}
		} else {
			var m map[string]string
			if err := json.Unmarshal(body, &m); err == nil {
				for k := range m {
					p[k] = m[k]
				}
			}
		}
		h.params = append(h.params, p)
		if len(h.resp) == 0 {
			http.Error(w, `{"error":"unexpected_token_request"}`, http.StatusUnauthorized)
			return
		}
		bodyResp := h.resp[0]
		h.resp = h.resp[1:]
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, bodyResp)
	}
}

// deviceHandler は /device（device 認可開始）を処理する。
// リクエストの認証スタイルも記録する。
type deviceHandler struct {
	count *reqCount
	auths []string
}

func (h *deviceHandler) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.count.add()
		h.auths = append(h.auths, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"device_code":"dc-e2e","user_code":"ABCD-1234","verification_uri":"https://example.test/verify","verification_uri_complete":"https://example.test/verify?user_code=ABCD-1234","expires_in":240,"interval":5}`)
	}
}

// mockServer は疑似プロバイダ一式（device 認可 + token endpoint）を立てる。
// /device と /token の 2 パスを持ち、token の認証スタイル（Basic / body）と
// 応答スタイル（form / json）はプロバイダ定義で切り替える。
type mockServer struct {
	srv    *httptest.Server
	device *deviceHandler
	token  *tokenHandler
}

// newMockServer は疑似プロバイダを立て、テスト終了時に閉じる。
func newMockServer(t *testing.T) *mockServer {
	t.Helper()
	ms := &mockServer{
		device: &deviceHandler{count: &reqCount{}},
		token:  &tokenHandler{count: &reqCount{}},
	}
	ms.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/device"):
			ms.device.handler()(w, r)
		case strings.HasSuffix(r.URL.Path, "/token"):
			ms.token.handler()(w, r)
		default:
			http.Error(w, "unknown path", http.StatusNotFound)
		}
	}))
	t.Cleanup(ms.srv.Close)
	return ms
}

// provider は疑似プロバイダの定義（form/basic の組み合わせ）を作る。
func (ms *mockServer) provider(name string, tokenStyle, deviceAuth string, scopes ...string) oauth.Provider {
	return oauth.Provider{
		Name:              name,
		TokenURL:          ms.srv.URL + "/token",
		DeviceURL:         ms.srv.URL + "/device",
		ClientID:          "e2e-client-id",
		ClientSecret:      "e2e-client-secret",
		Scopes:            scopes,
		TokenRequestStyle: tokenStyle,
		DeviceAuthStyle:   deviceAuth,
		Refreshable:       true,
	}
}

// providerMap は google（form/body）と lark（json/basic）の定義を返す。
func (ms *mockServer) providerMap() map[string]oauth.Provider {
	return map[string]oauth.Provider{
		"google": ms.provider("google", "form", "body", "a", "b"),
		"lark":   ms.provider("lark", "json", "basic", "offline_access"),
	}
}

// memBackendE2E は E2E 用インメモリ backend.Backend。
type memBackendE2E struct {
	mu  sync.Mutex
	m   map[string]string
	set map[string]int
}

func newMemBackendE2E() *memBackendE2E {
	return &memBackendE2E{m: make(map[string]string), set: make(map[string]int)}
}

func (mb *memBackendE2E) Resolve(ctx context.Context, key string) (string, error) {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	v, ok := mb.m[key]
	if !ok {
		return "", &backend.ErrNotFound{Key: key, Reason: "not in memBackendE2E"}
	}
	return v, nil
}

func (mb *memBackendE2E) List(ctx context.Context) ([]backend.Entry, error) {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	out := make([]backend.Entry, 0, len(mb.m))
	for k := range mb.m {
		out = append(out, backend.Entry{Key: k, Value: mb.m[k]})
	}
	return out, nil
}

func (mb *memBackendE2E) Set(ctx context.Context, key, value string) error {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	mb.m[key] = value
	mb.set[key]++
	return nil
}

func (mb *memBackendE2E) Values(ctx context.Context, minLen int) ([]string, error) {
	return nil, nil
}

func (mb *memBackendE2E) get(key string) (string, bool) {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	v, ok := mb.m[key]
	return v, ok
}

// resolve は既存の Provider 定義で組み立てた OAuthBackend を通じて解決する。
func resolve(t *testing.T, mb *memBackendE2E, p map[string]oauth.Provider, key string) (string, error) {
	t.Helper()
	return oauth.NewBackend(mb, p).Resolve(context.Background(), key)
}

// mustGet は backend から key の値を返し、無ければテストを失敗させる。
func mustGet(t *testing.T, mb *memBackendE2E, key string) string {
	t.Helper()
	v, ok := mb.get(key)
	if !ok {
		t.Fatalf("backend has no key %q", key)
	}
	return v
}

// deviceFlowLogin は DeviceStart → DevicePoll → backend 保存の
// login 相当フローを実行し、保存されたエントリを返す。
// poll は interval=5 の実待ちがあるため 1 回の応答で成功させること。
func deviceFlowLogin(t *testing.T, ms *mockServer, mb *memBackendE2E, provider oauth.Provider, key string) *oauth.OAuthEntry {
	t.Helper()
	resp, err := oauth.DeviceStart(context.Background(), http.DefaultClient, provider)
	if err != nil {
		t.Fatalf("DeviceStart() error = %v", err)
	}
	data, err := oauth.DevicePoll(context.Background(), http.DefaultClient, provider, resp.DeviceCode, 0, 0)
	if err != nil {
		t.Fatalf("DevicePoll() error = %v", err)
	}
	entry := &oauth.OAuthEntry{
		Provider: provider.Name,
		Access:   data.AccessToken,
		Refresh:  data.RefreshToken,
	}
	if data.ExpiresIn > 0 {
		entry.ExpiresAt = time.Now().Add(time.Duration(data.ExpiresIn) * time.Second)
	}
	if data.RefreshExpiresIn > 0 {
		entry.RefreshExpiresAt = time.Now().Add(time.Duration(data.RefreshExpiresIn) * time.Second)
	}
	entry.Scopes = strings.Fields(data.Scope)
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}
	if err := mb.Set(context.Background(), key, string(raw)); err != nil {
		t.Fatalf("backend Set() error = %v", err)
	}
	return entryJSON(t, mustGet(t, mb, key))
}

func TestOAuth統合のloginは疑似deviceフローでエントリを保存する(t *testing.T) {
	ms := newMockServer(t)
	mb := newMemBackendE2E()
	// device 認可開始 + poll の全応答（poll は interval=5 の実待ちがあるため 1 回で成功させる）
	ms.token.resp = []string{
		`{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600,"refresh_token_expires_in":604800,"scope":"a b"}`,
	}
	// google（form/body）で login 相当の device flow を実行
	stored := deviceFlowLogin(t, ms, mb, ms.provider("google", "form", "body", "a", "b"), "api/google")
	// 保存されたエントリ: compact 1 行 JSON・type=oauth・最小化（access/scopes 非永続）
	if stored.Provider != "google" || stored.Refresh != "refresh-1" {
		t.Errorf("stored = %+v, want google/refresh-1", stored)
	}
	if stored.Access != "" {
		t.Errorf("stored Access = %q, want empty (minimized entry)", stored.Access)
	}
	if len(stored.Scopes) != 0 {
		t.Errorf("stored Scopes = %v, want empty (scopes not persisted)", stored.Scopes)
	}
	// 保存 JSON にも access / scopes が含まれない
	raw := mustGet(t, mb, "api/google")
	if strings.Contains(raw, "access-1") {
		t.Errorf("stored raw contains access token: %q", raw)
	}
	if strings.Contains(raw, `"scopes"`) {
		t.Errorf("stored raw contains scopes: %q", raw)
	}
	// DeviceStart の body スタイル: Authorization ヘッダを使わない
	if len(ms.device.auths) != 1 {
		t.Fatalf("device auth headers = %v, want 1", ms.device.auths)
	}
	if ms.device.auths[0] != "" {
		t.Errorf("device Authorization = %q, want empty (body style)", ms.device.auths[0])
	}
}

func TestOAuth統合のResolveは未失効ならキャッシュから返しサーバカウンタが増えない(t *testing.T) {
	ms := newMockServer(t)
	mb := newMemBackendE2E()
	// 失効済みエントリ（Refreshable=true の google）: 1 回目で refresh させる
	raw, err := json.Marshal(&oauth.OAuthEntry{
		Provider:  "google",
		Access:    "access-old",
		Refresh:   "refresh-1",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	})
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}
	mb.m["api/google"] = string(raw)
	ob := oauth.NewBackend(mb, ms.providerMap()).(*oauth.OAuthBackend)

	// 1 回目の Resolve: 失効済み → refresh で access-new を取得
	ms.token.resp = []string{`{"access_token":"access-new","expires_in":3600}`}
	got, err := ob.Resolve(context.Background(), "api/google")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got != "access-new" {
		t.Errorf("Resolve() = %q, want %q", got, "access-new")
	}
	if ms.token.count.n.Load() != 1 {
		t.Errorf("token calls = %d, want 1", ms.token.count.n.Load())
	}

	// 2 回目の Resolve: キャッシュから返り、疑似サーバのカウンタが増えない
	got, err = ob.Resolve(context.Background(), "api/google")
	if err != nil {
		t.Fatalf("Resolve() #2 error = %v", err)
	}
	if got != "access-new" {
		t.Errorf("Resolve() #2 = %q, want %q", got, "access-new")
	}
	if ms.token.count.n.Load() != 1 {
		t.Errorf("token calls after cached resolve = %d, want still 1", ms.token.count.n.Load())
	}
}

func TestOAuth統合のResolveは失効したら自動refreshし新トークンとエントリ書き戻しをする(t *testing.T) {
	ms := newMockServer(t)
	mb := newMemBackendE2E()
	raw, err := json.Marshal(&oauth.OAuthEntry{
		Provider:  "google",
		Access:    "access-old",
		Refresh:   "refresh-1",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	})
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}
	mb.m["api/google"] = string(raw)
	ms.token.resp = []string{`{"access_token":"access-new","expires_in":3600}`}

	got, err := resolve(t, mb, ms.providerMap(), "api/google")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got != "access-new" {
		t.Errorf("Resolve() = %q, want %q", got, "access-new")
	}
	if ms.token.count.n.Load() != 1 {
		t.Errorf("token calls = %d, want 1", ms.token.count.n.Load())
	}
	// エントリ書き戻し: 最小化形式のため access は永続化されない
	stored := entryJSON(t, mustGet(t, mb, "api/google"))
	if stored.Access != "" {
		t.Errorf("stored Access = %q, want empty (minimized write-back)", stored.Access)
	}
	// refresh リクエストは form スタイルで client_secret をボディに含む
	if len(ms.token.params) != 1 {
		t.Fatalf("token params = %v, want 1", ms.token.params)
	}
	p := ms.token.params[0]
	if !strings.HasPrefix(p["content_type"], "application/x-www-form-urlencoded") {
		t.Errorf("token content-type = %q, want form urlencoded", p["content_type"])
	}
	if p["client_id"] != "e2e-client-id" || p["client_secret"] != "e2e-client-secret" {
		t.Errorf("token body client_id/secret = %q/%q, want e2e values in form body", p["client_id"], p["client_secret"])
	}
}

func TestOAuth統合のLark式はJSONボディとBasic認証でrefreshする(t *testing.T) {
	ms := newMockServer(t)
	mb := newMemBackendE2E()
	raw, err := json.Marshal(&oauth.OAuthEntry{
		Provider:  "lark",
		Access:    "access-old",
		Refresh:   "refresh-1",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	})
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}
	mb.m["api/lark"] = string(raw)
	// lark（json/basic）: code=0 の成功応答
	ms.token.resp = []string{`{"code":0,"access_token":"lark-access-new","refresh_token":"lark-refresh-2","expires_in":7200}`}

	got, err := resolve(t, mb, ms.providerMap(), "api/lark")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got != "lark-access-new" {
		t.Errorf("Resolve() = %q, want %q", got, "lark-access-new")
	}
	p := ms.token.params[0]
	if !strings.HasPrefix(p["content_type"], "application/json") {
		t.Errorf("token content-type = %q, want application/json", p["content_type"])
	}
	if p["grant_type"] != "refresh_token" || p["refresh_token"] != "refresh-1" {
		t.Errorf("token JSON body = %v, want refresh grant with refresh-1", p)
	}
	if ms.token.auths[0] != "" {
		t.Errorf("token Authorization = %q, want empty (Lark refresh sends client_id/secret in JSON body)", ms.token.auths[0])
	}
	// ローテーション: refresh が書き戻されている
	stored := entryJSON(t, mustGet(t, mb, "api/lark"))
	if stored.Refresh != "lark-refresh-2" {
		t.Errorf("stored Refresh = %q, want rotated lark-refresh-2", stored.Refresh)
	}
}

func TestOAuth統合のrefreshTokenローテーション後もResolveがCASで上書きされない(t *testing.T) {
	ms := newMockServer(t)
	mb := newMemBackendE2E()
	raw, err := json.Marshal(&oauth.OAuthEntry{
		Provider:  "lark",
		Access:    "access-0",
		Refresh:   "refresh-1",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	})
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}
	mb.m["api/lark"] = string(raw)
	ob := oauth.NewBackend(mb, ms.providerMap()).(*oauth.OAuthBackend)
	// 1 回目の refresh: refresh-1 → refresh-2（ローテーション）
	ms.token.resp = []string{`{"code":0,"access_token":"access-1","refresh_token":"refresh-2","expires_in":7200}`}
	if _, err := ob.Resolve(context.Background(), "api/lark"); err != nil {
		t.Fatalf("Resolve() #1 error = %v", err)
	}
	if got := mustGet(t, mb, "api/lark"); !strings.Contains(got, "refresh-2") {
		t.Fatalf("stored after rotation = %q, want refresh-2", got)
	}
	// 2 回目: refresh はキャッシュから返るためトークンサーバの呼び出しが増えない
	ms.token.resp = []string{`{"code":0,"access_token":"access-2","refresh_token":"refresh-3","expires_in":7200}`}
	got, err := ob.Resolve(context.Background(), "api/lark")
	if err != nil {
		t.Fatalf("Resolve() #2 error = %v", err)
	}
	if got != "access-1" {
		t.Errorf("Resolve() #2 = %q, want cached access-1", got)
	}
	if ms.token.count.n.Load() != 1 {
		t.Errorf("token calls after cached resolve = %d, want still 1", ms.token.count.n.Load())
	}
	// 書き戻しはローテーション 1 回分のみ（CAS ガードにより古い refresh で上書きされない）
	stored := entryJSON(t, mustGet(t, mb, "api/lark"))
	if stored.Refresh != "refresh-2" {
		t.Errorf("stored Refresh = %q, want refresh-2 (CAS guard must not overwrite)", stored.Refresh)
	}
	if stored.Access != "" {
		t.Errorf("stored Access = %q, want empty (minimized write-back)", stored.Access)
	}
}

// TestOAuth統合のrefreshTokenローテーションはCASガードの上で連鎖する:
// oauth refresh 相当の ForceRefresh はキャッシュを無視するため、
// refresh-1 → refresh-2 → refresh-3 と連鎖しても古いエントリで上書きされない。
func TestOAuth統合のrefreshTokenローテーションは連鎖してもCASで上書きされない(t *testing.T) {
	ms := newMockServer(t)
	mb := newMemBackendE2E()
	raw, err := json.Marshal(&oauth.OAuthEntry{
		Provider:  "lark",
		Access:    "access-0",
		Refresh:   "refresh-1",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	})
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}
	mb.m["api/lark"] = string(raw)
	ob := oauth.NewBackend(mb, ms.providerMap()).(*oauth.OAuthBackend)

	// 1 回目の ForceRefresh: refresh-1 → refresh-2
	ms.token.resp = []string{`{"code":0,"access_token":"access-1","refresh_token":"refresh-2","expires_in":7200}`}
	if _, err := ob.ForceRefresh(context.Background(), "api/lark"); err != nil {
		t.Fatalf("ForceRefresh() #1 error = %v", err)
	}
	if got := mustGet(t, mb, "api/lark"); !strings.Contains(got, "refresh-2") {
		t.Fatalf("stored after rotation 1 = %q, want refresh-2", got)
	}
	// 2 回目の ForceRefresh: refresh-2 → refresh-3。CAS ガードは現在値(refresh-2)と
	// 比較するため書き戻しが成功し、refresh-3 が保持される。
	ms.token.resp = []string{`{"code":0,"access_token":"access-2","refresh_token":"refresh-3","expires_in":7200}`}
	if _, err := ob.ForceRefresh(context.Background(), "api/lark"); err != nil {
		t.Fatalf("ForceRefresh() #2 error = %v", err)
	}
	stored := entryJSON(t, mustGet(t, mb, "api/lark"))
	if stored.Refresh != "refresh-3" {
		t.Errorf("stored Refresh = %q, want refresh-3 (rotation chain via CAS)", stored.Refresh)
	}
	if stored.Access != "" {
		t.Errorf("stored Access = %q, want empty (minimized write-back)", stored.Access)
	}
}

func TestOAuth統合のinvalidGrantはErrInvalidGrantを返し再認証が必要になる(t *testing.T) {
	ms := newMockServer(t)
	mb := newMemBackendE2E()
	raw, err := json.Marshal(&oauth.OAuthEntry{
		Provider:  "google",
		Access:    "access-old",
		Refresh:   "refresh-expired",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	})
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}
	mb.m["api/google"] = string(raw)
	ms.token.resp = []string{`{"error":"invalid_grant","error_description":"refresh token revoked"}`}

	_, err = resolve(t, mb, ms.providerMap(), "api/google")
	if !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatalf("Resolve() error = %v, want ErrInvalidGrant", err)
	}
	// 自動リトライしない
	if ms.token.count.n.Load() != 1 {
		t.Errorf("token calls = %d, want 1 (no auto retry)", ms.token.count.n.Load())
	}
	// 再認証必要: status 相当の判定（ForceRefresh も同じエラーになる）
	entry, err := oauth.NewBackend(mb, ms.providerMap()).(*oauth.OAuthBackend).ResolveEntry(context.Background(), "api/google")
	if err != nil {
		t.Fatalf("ResolveEntry() error = %v", err)
	}
	if entry == nil {
		t.Fatal("ResolveEntry() = nil, want entry")
	}
	if !entry.ExpiresAt.Before(time.Now()) {
		t.Errorf("entry ExpiresAt = %v, want expired (reauth required)", entry.ExpiresAt)
	}
}

// TestOAuth統合の最小化エントリは保存されResolveがrefresh1回でaccessを返す:
// login 相当で保存したエントリが最小化形式（access 非永続）であること、
// Resolve が refresh を 1 回だけ行い access を返し、2 回目はキャッシュから
// 返ることを疑似プロバイダのカウンタで検証する。
func TestOAuth統合の最小化エントリは保存されResolveがrefresh1回でaccessを返す(t *testing.T) {
	ms := newMockServer(t)
	mb := newMemBackendE2E()
	ms.token.resp = []string{
		`{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600,"refresh_token_expires_in":604800,"scope":"a b"}`,
	}
	// login 相当の device flow（最小化保存は backend.Set 前の Marshal で行われる）
	stored := deviceFlowLogin(t, ms, mb, ms.provider("google", "form", "body", "a", "b"), "api/google")
	if stored.Provider != "google" || stored.Refresh != "refresh-1" {
		t.Errorf("stored = %+v, want google/refresh-1", stored)
	}
	// 保存 JSON は最小化: access / expires_at / scopes を含まない
	raw := mustGet(t, mb, "api/google")
	if strings.Contains(raw, "access-1") {
		t.Errorf("stored raw contains access token: %q", raw)
	}
	if strings.Contains(raw, `"expires_at"`) {
		t.Errorf("stored raw contains expires_at: %q", raw)
	}
	if strings.Contains(raw, `"scopes"`) {
		t.Errorf("stored raw contains scopes: %q", raw)
	}
	// 以降の refresh 応答（access 空エントリの 1 回目 + キャッシュ検証用）
	ms.token.resp = []string{`{"access_token":"access-new","expires_in":3600}`}
	ob := oauth.NewBackend(mb, ms.providerMap()).(*oauth.OAuthBackend)
	// login の poll で token を 1 回消費済みのため、Resolve 前のカウントから差分を検証する
	before := ms.token.count.n.Load()

	got, err := ob.Resolve(context.Background(), "api/google")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got != "access-new" {
		t.Errorf("Resolve() = %q, want %q", got, "access-new")
	}
	if calls := ms.token.count.n.Load() - before; calls != 1 {
		t.Errorf("token calls during Resolve = %d, want 1", calls)
	}
	// 2 回目はキャッシュから返り HTTP 呼び出しが増えない
	got, err = ob.Resolve(context.Background(), "api/google")
	if err != nil {
		t.Fatalf("Resolve() #2 error = %v", err)
	}
	if got != "access-new" {
		t.Errorf("Resolve() #2 = %q, want %q", got, "access-new")
	}
	if calls := ms.token.count.n.Load() - before; calls != 1 {
		t.Errorf("token calls after cached resolve = %d, want still 1", calls)
	}
}

// TestOAuth統合の圧縮経路は3500バイト超エントリでもloginからrefreshまで通る:
// 5000 文字級のダミー refresh token を持つエントリを保存し、
// zlib 圧縮（z ラップ）を経て Resolve の refresh が動作することを検証する。
func TestOAuth統合の圧縮経路は3500バイト超エントリでもloginからrefreshまで通る(t *testing.T) {
	ms := newMockServer(t)
	mb := newMemBackendE2E()
	bigRefresh := strings.Repeat("R", 5000)
	ms.token.resp = []string{
		// login 相当の device flow: 5000 文字級の refresh token を返す
		`{"access_token":"access-1","refresh_token":"` + bigRefresh + `","expires_in":3600}`,
		// 圧縮エントリからの refresh 応答
		`{"access_token":"access-new","expires_in":3600}`,
	}
	stored := deviceFlowLogin(t, ms, mb, ms.provider("google", "form", "body", "a", "b"), "api/big")
	if stored.Refresh != bigRefresh {
		t.Fatalf("stored Refresh mismatch (len=%d want %d)", len(stored.Refresh), len(bigRefresh))
	}
	raw := mustGet(t, mb, "api/big")
	if len(raw) > 5000 {
		t.Errorf("stored raw length = %d, want <= 5000 (bitwarden limit)", len(raw))
	}
	// z ラップの圧縮エントリになっている
	var probe struct {
		Z bool `json:"z"`
	}
	if err := json.Unmarshal([]byte(raw), &probe); err != nil {
		t.Fatalf("unmarshal z-probe: %v", err)
	}
	if !probe.Z {
		t.Errorf("stored raw = %q..., want z-wrapped compressed entry", raw[:min(len(raw), 120)])
	}
	// 圧縮エントリからでも Resolve → refresh が通る
	ob := oauth.NewBackend(mb, ms.providerMap()).(*oauth.OAuthBackend)
	// login の poll で token を 1 回消費済みのため、Resolve 前のカウントから差分を検証する
	before := ms.token.count.n.Load()
	got, err := ob.Resolve(context.Background(), "api/big")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got != "access-new" {
		t.Errorf("Resolve() = %q, want %q", got, "access-new")
	}
	if calls := ms.token.count.n.Load() - before; calls != 1 {
		t.Errorf("token calls during Resolve = %d, want 1", calls)
	}
}

func TestOAuth統合の静的エントリ混在はOAuth処理を通らず素通しする(t *testing.T) {
	ms := newMockServer(t)
	mb := newMemBackendE2E()
	// 静的エントリ + OAuth エントリが混在
	mb.m["api/static"] = "plain-secret"
	raw, err := json.Marshal(&oauth.OAuthEntry{
		Provider:  "google",
		Access:    "access-1",
		Refresh:   "refresh-1",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	})
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}
	mb.m["api/google"] = string(raw)
	ms.token.resp = []string{`{"access_token":"access-new","expires_in":3600}`}

	// 静的エントリ: そのまま返り、token サーバへの呼び出しが無い
	got, err := resolve(t, mb, ms.providerMap(), "api/static")
	if err != nil {
		t.Fatalf("Resolve(static) error = %v", err)
	}
	if got != "plain-secret" {
		t.Errorf("Resolve(static) = %q, want plain-secret", got)
	}
	if ms.token.count.n.Load() != 0 {
		t.Errorf("token calls after static resolve = %d, want 0", ms.token.count.n.Load())
	}
	// OAuth エントリは引き続き refresh される
	got, err = resolve(t, mb, ms.providerMap(), "api/google")
	if err != nil {
		t.Fatalf("Resolve(oauth) error = %v", err)
	}
	if got != "access-new" {
		t.Errorf("Resolve(oauth) = %q, want access-new", got)
	}
}
