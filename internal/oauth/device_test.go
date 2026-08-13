package oauth

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeDeviceWait は deviceWait を差し替え、実際に待たずに待機時間を記録する。
func fakeDeviceWait(t *testing.T) *[]time.Duration {
	t.Helper()
	var waits []time.Duration
	orig := deviceWait
	deviceWait = func(ctx context.Context, d time.Duration) error {
		waits = append(waits, d)
		return ctx.Err()
	}
	t.Cleanup(func() { deviceWait = orig })
	return &waits
}

// deviceStartServer は疑似 device 認可開始 endpoint を立てる。
// リクエストのヘッダとボディを取得して返す。
func deviceStartServer(t *testing.T, body string) (*httptest.Server, *string, *string) {
	t.Helper()
	var lastAuth, lastBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastAuth = r.Header.Get("Authorization")
		buf := new(strings.Builder)
		if _, err := io.Copy(buf, r.Body); err != nil {
			t.Errorf("read request body: %v", err)
		}
		lastBody = buf.String()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, &lastAuth, &lastBody
}

func TestDeviceStartはbodyスタイルでformにclientSecretを含めて送る(t *testing.T) {
	srv, _, lastBody := deviceStartServer(t, `{"device_code":"dc-1","user_code":"1234","verification_uri":"https://example/verify","verification_uri_complete":"https://example/verify?user_code=1234","expires_in":1800,"interval":5}`)
	p := Provider{
		TokenURL:        srv.URL + "/token",
		DeviceURL:       srv.URL,
		ClientID:        "client-1",
		ClientSecret:    "secret-1",
		Scopes:          []string{"a", "b"},
		DeviceAuthStyle: "body",
	}
	resp, err := DeviceStart(context.Background(), http.DefaultClient, p)
	if err != nil {
		t.Fatalf("DeviceStart() error = %v", err)
	}
	if resp.DeviceCode != "dc-1" || resp.UserCode != "1234" {
		t.Errorf("DeviceCode/UserCode = %q/%q, want dc-1/1234", resp.DeviceCode, resp.UserCode)
	}
	if resp.VerificationURI != "https://example/verify" {
		t.Errorf("VerificationURI = %q", resp.VerificationURI)
	}
	if resp.VerificationURIComplete != "https://example/verify?user_code=1234" {
		t.Errorf("VerificationURIComplete = %q", resp.VerificationURIComplete)
	}
	if resp.ExpiresIn != 1800 || resp.Interval != 5 {
		t.Errorf("ExpiresIn/Interval = %d/%d, want 1800/5", resp.ExpiresIn, resp.Interval)
	}
	for _, want := range []string{"client_id=client-1", "client_secret=secret-1", "scope=a+b"} {
		if !strings.Contains(*lastBody, want) {
			t.Errorf("request body = %q, want contains %q", *lastBody, want)
		}
	}
}

func TestDeviceStartはbasicスタイルでAuthorizationヘッダを送る(t *testing.T) {
	srv, lastAuth, lastBody := deviceStartServer(t, `{"device_code":"dc-1","user_code":"1234","verification_uri":"https://example/verify","expires_in":240,"interval":5}`)
	p := Provider{
		TokenURL:        srv.URL + "/token",
		DeviceURL:       srv.URL,
		ClientID:        "client-1",
		ClientSecret:    "secret-1",
		Scopes:          []string{"a"},
		DeviceAuthStyle: "basic",
	}
	if _, err := DeviceStart(context.Background(), http.DefaultClient, p); err != nil {
		t.Fatalf("DeviceStart() error = %v", err)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("client-1:secret-1"))
	if *lastAuth != wantAuth {
		t.Errorf("Authorization = %q, want %q", *lastAuth, wantAuth)
	}
	if strings.Contains(*lastBody, "client_secret") {
		t.Errorf("request body = %q, want no client_secret (Basic 認証に含める)", *lastBody)
	}
	if !strings.Contains(*lastBody, "client_id=client-1") {
		t.Errorf("request body = %q, want contains client_id", *lastBody)
	}
}

func TestDeviceStartはHTTPエラーでエラーを返す(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	p := Provider{DeviceURL: srv.URL, ClientID: "c", DeviceAuthStyle: "body"}
	if _, err := DeviceStart(context.Background(), http.DefaultClient, p); err == nil {
		t.Fatal("DeviceStart() error = nil, want non-nil")
	}
}

func TestDeviceStartはerrorフィールドでエラーを返す(t *testing.T) {
	srv, _, _ := deviceStartServer(t, `{"error":"invalid_client","error_description":"bad client"}`)
	p := Provider{DeviceURL: srv.URL, ClientID: "c", DeviceAuthStyle: "body"}
	_, err := DeviceStart(context.Background(), http.DefaultClient, p)
	if err == nil {
		t.Fatal("DeviceStart() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "bad client") {
		t.Errorf("error = %q, want contains error_description", err.Error())
	}
}

// pollDeviceServer は疑似 token endpoint を立てる。
// handler は poll ごとに呼ばれ、応答 body を返す。
// リクエストのボディは取得して返す。
func pollDeviceServer(t *testing.T, handler func(r *http.Request) string) (*httptest.Server, *string) {
	t.Helper()
	var lastBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(strings.Builder)
		if _, err := io.Copy(buf, r.Body); err != nil {
			t.Errorf("read request body: %v", err)
		}
		lastBody = buf.String()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, handler(r))
	}))
	t.Cleanup(srv.Close)
	return srv, &lastBody
}

func TestDevicePollはformでdeviceCodeを送って成功時にトークンを返す(t *testing.T) {
	waits := fakeDeviceWait(t)
	var polls int
	srv, lastBody := pollDeviceServer(t, func(r *http.Request) string {
		polls++
		return `{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600,"refresh_token_expires_in":604800,"scope":"a b"}`
	})
	p := Provider{TokenURL: srv.URL, ClientID: "client-1", ClientSecret: "secret-1"}
	data, err := DevicePoll(context.Background(), http.DefaultClient, p, "dc-1", 0, 0)
	if err != nil {
		t.Fatalf("DevicePoll() error = %v", err)
	}
	if polls != 1 {
		t.Errorf("polls = %d, want 1", polls)
	}
	if data.AccessToken != "access-1" || data.RefreshToken != "refresh-1" {
		t.Errorf("AccessToken/RefreshToken = %q/%q, want access-1/refresh-1", data.AccessToken, data.RefreshToken)
	}
	if data.ExpiresIn != 3600 || data.RefreshExpiresIn != 604800 || data.Scope != "a b" {
		t.Errorf("ExpiresIn/RefreshExpiresIn/Scope = %d/%d/%q, want 3600/604800/a b", data.ExpiresIn, data.RefreshExpiresIn, data.Scope)
	}
	wantGrant := "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"
	for _, want := range []string{wantGrant, "device_code=dc-1", "client_id=client-1", "client_secret=secret-1"} {
		if !strings.Contains(*lastBody, want) {
			t.Errorf("request body = %q, want contains %q", *lastBody, want)
		}
	}
	if len(*waits) != 1 {
		t.Errorf("waits = %v, want 1 wait of default 5s", *waits)
	}
}

func TestDevicePollはLark式の400pending応答でも再試行して成功する(t *testing.T) {
	// 実測（2026-08-13）: Lark は pending 状態を 400 + {"error":"authorization_pending"} で返す。
	// ステータスコードを無視してボディの error フィールドで判定すること。
	waits := fakeDeviceWait(t)
	var polls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		polls++
		if polls == 1 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"code":0,"error":"authorization_pending"}`)
			return
		}
		fmt.Fprint(w, `{"code":0,"access_token":"access-1","expires_in":3600,"refresh_token":"refresh-1"}`)
	}))
	t.Cleanup(srv.Close)
	p := Provider{TokenURL: srv.URL, ClientID: "client-1", ClientSecret: "secret-1", TokenRequestStyle: "json"}
	data, err := DevicePoll(context.Background(), http.DefaultClient, p, "dc-1", 0, 0)
	if err != nil {
		t.Fatalf("DevicePoll() error = %v, want nil (400 pending は継続)", err)
	}
	if polls != 2 {
		t.Errorf("polls = %d, want 2", polls)
	}
	if data.AccessToken != "access-1" || data.RefreshToken != "refresh-1" {
		t.Errorf("token = %+v, want access-1/refresh-1", data)
	}
	if len(*waits) != 2 {
		t.Errorf("waits = %v, want 2 waits", *waits)
	}
}

func TestDevicePollはLark式の400expired応答でエラーを返す(t *testing.T) {
	waits := fakeDeviceWait(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"code":10004,"error":"expired_token"}`)
	}))
	t.Cleanup(srv.Close)
	p := Provider{TokenURL: srv.URL, ClientID: "client-1", ClientSecret: "secret-1", TokenRequestStyle: "json"}
	_, err := DevicePoll(context.Background(), http.DefaultClient, p, "dc-1", 0, 0)
	if err == nil {
		t.Fatal("DevicePoll() error = nil, want non-nil (expired_token)")
	}
	_ = waits
}

func TestDevicePollはpendingから承認まで再試行して成功する(t *testing.T) {
	waits := fakeDeviceWait(t)
	var polls int
	srv, _ := pollDeviceServer(t, func(r *http.Request) string {
		polls++
		if polls == 1 {
			return `{"error":"authorization_pending"}`
		}
		return `{"access_token":"access-1","expires_in":3600}`
	})
	p := Provider{TokenURL: srv.URL, ClientID: "client-1", ClientSecret: "secret-1"}
	data, err := DevicePoll(context.Background(), http.DefaultClient, p, "dc-1", 0, 0)
	if err != nil {
		t.Fatalf("DevicePoll() error = %v", err)
	}
	if polls != 2 {
		t.Errorf("polls = %d, want 2 (pending 再試行)", polls)
	}
	if data.AccessToken != "access-1" {
		t.Errorf("AccessToken = %q, want access-1", data.AccessToken)
	}
	if len(*waits) != 2 {
		t.Errorf("waits = %v, want 2 waits", *waits)
	}
}

func TestDevicePollはslowDownでintervalを増やして再試行する(t *testing.T) {
	waits := fakeDeviceWait(t)
	var polls int
	srv, _ := pollDeviceServer(t, func(r *http.Request) string {
		polls++
		if polls == 1 {
			return `{"error":"slow_down"}`
		}
		return `{"access_token":"access-1","expires_in":3600}`
	})
	p := Provider{TokenURL: srv.URL, ClientID: "client-1", ClientSecret: "secret-1"}
	data, err := DevicePoll(context.Background(), http.DefaultClient, p, "dc-1", 5, 240)
	if err != nil {
		t.Fatalf("DevicePoll() error = %v", err)
	}
	if polls != 2 {
		t.Errorf("polls = %d, want 2", polls)
	}
	if data.AccessToken != "access-1" {
		t.Errorf("AccessToken = %q, want access-1", data.AccessToken)
	}
	if len(*waits) != 2 {
		t.Fatalf("waits = %v, want 2 waits", *waits)
	}
	if (*waits)[1] != 10*time.Second {
		t.Errorf("2nd wait = %v, want 10s (interval 5 + 5)", (*waits)[1])
	}
}

func TestDevicePollはslowDownのinterval上限を60sに抑える(t *testing.T) {
	waits := fakeDeviceWait(t)
	var polls int
	srv, _ := pollDeviceServer(t, func(r *http.Request) string {
		polls++
		if polls <= 2 {
			return `{"error":"slow_down"}`
		}
		return `{"access_token":"access-1","expires_in":3600}`
	})
	p := Provider{TokenURL: srv.URL, ClientID: "client-1", ClientSecret: "secret-1"}
	if _, err := DevicePoll(context.Background(), http.DefaultClient, p, "dc-1", 55, 240); err != nil {
		t.Fatalf("DevicePoll() error = %v", err)
	}
	if len(*waits) != 3 {
		t.Fatalf("waits = %v, want 3 waits", *waits)
	}
	if (*waits)[2] != 60*time.Second {
		t.Errorf("3rd wait = %v, want 60s (slow_down 上限)", (*waits)[2])
	}
}

func TestDevicePollはaccessDeniedでエラーを返す(t *testing.T) {
	fakeDeviceWait(t)
	srv, _ := pollDeviceServer(t, func(r *http.Request) string {
		return `{"error":"access_denied","error_description":"user said no"}`
	})
	p := Provider{TokenURL: srv.URL, ClientID: "client-1", ClientSecret: "secret-1"}
	_, err := DevicePoll(context.Background(), http.DefaultClient, p, "dc-1", 0, 0)
	if err == nil {
		t.Fatal("DevicePoll() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "Authorization denied") {
		t.Errorf("error = %q, want contains %q", err.Error(), "Authorization denied")
	}
}

func TestDevicePollはexpiredTokenでエラーを返す(t *testing.T) {
	fakeDeviceWait(t)
	for _, e := range []string{"expired_token", "invalid_grant"} {
		srv, _ := pollDeviceServer(t, func(r *http.Request) string {
			return fmt.Sprintf(`{"error":%q}`, e)
		})
		p := Provider{TokenURL: srv.URL, ClientID: "client-1", ClientSecret: "secret-1"}
		_, err := DevicePoll(context.Background(), http.DefaultClient, p, "dc-1", 0, 0)
		if err == nil {
			t.Errorf("error=%s DevicePoll() error = nil, want non-nil", e)
		}
	}
}

func TestDevicePollはjsonスタイルのcode非ゼロでエラーを返す(t *testing.T) {
	fakeDeviceWait(t)
	srv, _ := pollDeviceServer(t, func(r *http.Request) string {
		return `{"code":10001,"error":"invalid_grant","error_description":"expired"}`
	})
	p := Provider{TokenURL: srv.URL, ClientID: "client-1", ClientSecret: "secret-1", TokenRequestStyle: "json"}
	_, err := DevicePoll(context.Background(), http.DefaultClient, p, "dc-1", 0, 0)
	if err == nil {
		t.Fatal("DevicePoll() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error = %q, want contains error_description", err.Error())
	}
}

func TestDevicePollはコンテキストキャンセルで即エラーを返す(t *testing.T) {
	fakeDeviceWait(t)
	srv, _ := pollDeviceServer(t, func(r *http.Request) string {
		return `{"error":"authorization_pending"}`
	})
	p := Provider{TokenURL: srv.URL, ClientID: "client-1", ClientSecret: "secret-1"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := DevicePoll(ctx, http.DefaultClient, p, "dc-1", 0, 0)
	if err == nil {
		t.Fatal("DevicePoll() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("error = %q, want context canceled", err.Error())
	}
}

func TestDevicePollはrefreshTokenが無くても成功する(t *testing.T) {
	fakeDeviceWait(t)
	srv, _ := pollDeviceServer(t, func(r *http.Request) string {
		return `{"access_token":"access-1","expires_in":3600}`
	})
	p := Provider{TokenURL: srv.URL, ClientID: "client-1", ClientSecret: "secret-1"}
	data, err := DevicePoll(context.Background(), http.DefaultClient, p, "dc-1", 0, 0)
	if err != nil {
		t.Fatalf("DevicePoll() error = %v", err)
	}
	if data.RefreshToken != "" {
		t.Errorf("RefreshToken = %q, want empty (無くても成功)", data.RefreshToken)
	}
}
