package oauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testTokenServer は疑似 token endpoint を立てる。
// jsonBody=true なら Lark 式 JSON 応答（code フィールド）を返し、
// それ以外は Google 式 form 応答を返す。リクエストのボディは取得して返す。
func testTokenServer(t *testing.T, jsonBody bool) (*httptest.Server, *string) {
	t.Helper()
	var lastBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(strings.Builder)
		if _, err := io.Copy(buf, r.Body); err != nil {
			t.Errorf("read request body: %v", err)
		}
		lastBody = buf.String()
		w.Header().Set("Content-Type", "application/json")
		if jsonBody {
			fmt.Fprint(w, `{"code":0,"access_token":"lark-access-new","expires_in":7200}`)
			return
		}
		fmt.Fprint(w, `{"access_token":"google-access-new","expires_in":3600,"token_type":"Bearer"}`)
	}))
	t.Cleanup(srv.Close)
	return srv, &lastBody
}

func TestRefreshはformスタイルで新しいaccessトークンを返す(t *testing.T) {
	srv, lastBody := testTokenServer(t, false)
	p := Provider{Name: "google", TokenURL: srv.URL, Refreshable: true}
	e := &OAuthEntry{Provider: "google", Refresh: "refresh-1"}
	if err := Refresh(context.Background(), http.DefaultClient, p, e); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if e.Access != "google-access-new" {
		t.Errorf("Access = %q, want %q", e.Access, "google-access-new")
	}
	if e.Refresh != "refresh-1" {
		t.Errorf("Refresh = %q, want unchanged %q", e.Refresh, "refresh-1")
	}
	want := "grant_type=refresh_token&refresh_token=refresh-1"
	if !strings.Contains(*lastBody, want) {
		t.Errorf("request body = %q, want contains %q", *lastBody, want)
	}
}

func TestRefreshはjsonスタイルで新しいaccessトークンを返す(t *testing.T) {
	srv, lastBody := testTokenServer(t, true)
	p := Provider{Name: "lark", TokenURL: srv.URL, TokenRequestStyle: "json", Refreshable: true}
	e := &OAuthEntry{Provider: "lark", Refresh: "refresh-1"}
	if err := Refresh(context.Background(), http.DefaultClient, p, e); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if e.Access != "lark-access-new" {
		t.Errorf("Access = %q, want %q", e.Access, "lark-access-new")
	}
	if !strings.Contains(*lastBody, `"grant_type":"refresh_token"`) {
		t.Errorf("request body = %q, want json grant_type", *lastBody)
	}
	if !strings.Contains(*lastBody, `"refresh_token":"refresh-1"`) {
		t.Errorf("request body = %q, want refresh_token field", *lastBody)
	}
}

func TestRefreshは応答のrefreshトークンでローテーションする(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"access-2","refresh_token":"refresh-2","expires_in":3600}`)
	}))
	t.Cleanup(srv.Close)
	p := Provider{TokenURL: srv.URL, Refreshable: true}
	e := &OAuthEntry{Refresh: "refresh-1"}
	if err := Refresh(context.Background(), http.DefaultClient, p, e); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if e.Refresh != "refresh-2" {
		t.Errorf("Refresh = %q, want rotated %q", e.Refresh, "refresh-2")
	}
}

func TestRefreshはexpiresInが無ければExpiresAtをゼロのままにする(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"access-3"}`)
	}))
	t.Cleanup(srv.Close)
	p := Provider{TokenURL: srv.URL, Refreshable: true}
	e := &OAuthEntry{Refresh: "refresh-1"}
	if err := Refresh(context.Background(), http.DefaultClient, p, e); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if !e.ExpiresAt.IsZero() {
		t.Errorf("ExpiresAt = %v, want zero", e.ExpiresAt)
	}
}

func TestRefreshは非200かつinvalidGrantボディでErrInvalidGrantを返す(t *testing.T) {
	// 実測（2026-08-13）: Lark は refresh token 消費後 400 + {"code":20064,"error":"invalid_grant"} を返す。
	// 非200パスでも ErrInvalidGrant にマップされ、status が reauth_required を出せること。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"code":20064,"error":"invalid_grant","error_description":"The refresh token has been revoked. Please note that a refresh token can only be used once."}`)
	}))
	t.Cleanup(srv.Close)
	p := Provider{TokenURL: srv.URL, TokenRequestStyle: "json", Refreshable: true}
	e := &OAuthEntry{Refresh: "refresh-1"}
	err := Refresh(context.Background(), http.DefaultClient, p, e)
	if err == nil {
		t.Fatal("Refresh() error = nil, want ErrInvalidGrant")
	}
	if !errors.Is(err, ErrInvalidGrant) {
		t.Errorf("Refresh() error = %v, want wrapped ErrInvalidGrant", err)
	}
}

func TestRefreshは非200かつ通常エラーボディでErrInvalidGrantにしない(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":"server_error"}`)
	}))
	t.Cleanup(srv.Close)
	p := Provider{TokenURL: srv.URL, Refreshable: true}
	e := &OAuthEntry{Refresh: "refresh-1"}
	err := Refresh(context.Background(), http.DefaultClient, p, e)
	if err == nil {
		t.Fatal("Refresh() error = nil, want non-nil")
	}
	if errors.Is(err, ErrInvalidGrant) {
		t.Errorf("Refresh() error = %v, must NOT be ErrInvalidGrant", err)
	}
}

func TestRefreshはinvalidGrantでErrInvalidGrantを返す(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"error":"invalid_grant","error_description":"bad token"}`)
	}))
	t.Cleanup(srv.Close)
	for _, style := range []string{"form", "json"} {
		p := Provider{TokenURL: srv.URL, TokenRequestStyle: style, Refreshable: true}
		e := &OAuthEntry{Refresh: "refresh-1"}
		err := Refresh(context.Background(), http.DefaultClient, p, e)
		if !errors.Is(err, ErrInvalidGrant) {
			t.Errorf("style=%s Refresh() error = %v, want ErrInvalidGrant", style, err)
		}
	}
}

func TestRefreshはLarkのcode非ゼロでエラーを返す(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"code":10001,"error":"invalid_grant","error_description":"refresh token expired"}`)
	}))
	t.Cleanup(srv.Close)
	p := Provider{TokenURL: srv.URL, TokenRequestStyle: "json", Refreshable: true}
	e := &OAuthEntry{Refresh: "refresh-1"}
	err := Refresh(context.Background(), http.DefaultClient, p, e)
	if err == nil {
		t.Fatal("Refresh() error = nil, want non-nil")
	}
	if !errors.Is(err, ErrInvalidGrant) {
		t.Errorf("Refresh() error = %v, want ErrInvalidGrant", err)
	}
	if !strings.Contains(err.Error(), "refresh token expired") {
		t.Errorf("error message = %q, want contains error_description", err.Error())
	}
}

func TestRefreshはRefreshableがfalseなら何もしない(t *testing.T) {
	e := &OAuthEntry{Refresh: "refresh-1", Access: "access-old"}
	p := Provider{Refreshable: false, TokenURL: "http://127.0.0.1:1/never"}
	if err := Refresh(context.Background(), http.DefaultClient, p, e); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if e.Access != "access-old" {
		t.Errorf("Access = %q, want unchanged %q", e.Access, "access-old")
	}
}

func TestRefreshIfNeededは未失効ならrefreshせずfalseを返す(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		fmt.Fprint(w, `{"access_token":"access-new"}`)
	}))
	t.Cleanup(srv.Close)
	p := Provider{TokenURL: srv.URL, Refreshable: true}
	e := &OAuthEntry{Refresh: "refresh-1", ExpiresAt: time.Now().Add(10 * time.Minute)}
	did, err := RefreshIfNeeded(context.Background(), http.DefaultClient, p, e, 30*time.Second)
	if err != nil {
		t.Fatalf("RefreshIfNeeded() error = %v", err)
	}
	if did {
		t.Error("RefreshIfNeeded() = true, want false (not expired)")
	}
	if calls != 0 {
		t.Errorf("refresh called %d times, want 0", calls)
	}
}

func TestRefreshIfNeededは失効していたらrefreshしてtrueを返す(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		fmt.Fprint(w, `{"access_token":"access-new"}`)
	}))
	t.Cleanup(srv.Close)
	p := Provider{TokenURL: srv.URL, Refreshable: true}
	e := &OAuthEntry{Refresh: "refresh-1", ExpiresAt: time.Now().Add(-1 * time.Minute)}
	did, err := RefreshIfNeeded(context.Background(), http.DefaultClient, p, e, 30*time.Second)
	if err != nil {
		t.Fatalf("RefreshIfNeeded() error = %v", err)
	}
	if !did {
		t.Error("RefreshIfNeeded() = false, want true (expired)")
	}
	if calls != 1 {
		t.Errorf("refresh called %d times, want 1", calls)
	}
}
