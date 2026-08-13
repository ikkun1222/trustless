package oauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"
)

// randomToken はランダム文字列を返す（charset は 36 種: 小文字+数字）。
func randomToken(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

// dummyRefreshJWT は実測（2026-08-13）の Lark refresh token 相当のダミー JWT
// を構築する。実 JWT は「固定ヘッダ + 構造化 claims の base64url + シグネチャ」
// であり、zlib の圧縮効率がランダム文字列より高い（実測: 5902B → 3528B）。
func dummyRefreshJWT(n int) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	var claims []string
	for i := 0; ; i++ {
		claim := fmt.Sprintf(`"iss":"https://open.larksuite.com","sub":"ou_%s","aud":"cli_%s","exp":%d,"iat":%d`,
			randomToken(24), randomToken(16), time.Now().Unix()+86400, time.Now().Unix())
		claims = append(claims, claim)
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{` + strings.Join(claims, ",") + `}`))
		if len(header)+1+len(payload)+1+43 >= n {
			// 指定長 n に最も近いサイズで確定
			return header + "." + payload + "." + randomToken(43)
		}
	}
}

func TestOAuthEntryMarshalJSONは単一行でtypeフィールドを持つ(t *testing.T) {
	e := &OAuthEntry{
		Provider:         "google",
		Refresh:          "refresh-1",
		ExpiresAt:        time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		RefreshExpiresAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	s := string(b)
	if strings.ContainsAny(s, "\n\r") {
		t.Errorf("marshaled JSON contains newline: %q", s)
	}
	if !strings.HasPrefix(s, `{"type":"oauth",`) {
		t.Errorf("marshaled JSON = %s, want type first", s)
	}
	var got OAuthEntry
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got.Provider != "google" || got.Refresh != "refresh-1" {
		t.Errorf("roundtrip mismatch: %+v", got)
	}
	if !got.ExpiresAt.Equal(time.Time{}) {
		t.Errorf("ExpiresAt = %v, want zero (not persisted)", got.ExpiresAt)
	}
	if !got.RefreshExpiresAt.Equal(e.RefreshExpiresAt) {
		t.Errorf("RefreshExpiresAt = %v, want %v", got.RefreshExpiresAt, e.RefreshExpiresAt)
	}
}

func TestOAuthEntryUnmarshalはtypeがoauth以外ならエラーを返す(t *testing.T) {
	var e OAuthEntry
	err := json.Unmarshal([]byte(`{"type":"password","access":"x"}`), &e)
	if err == nil {
		t.Fatal("Unmarshal() error = nil, want non-nil")
	}
}

func TestOAuthEntryUnmarshalは空の時刻フィールドをゼロ値として許容する(t *testing.T) {
	// 実測バグ（2026-08-13）: refresh_expires_at="" で time.Time の
	// UnmarshalJSON がエラーになり、oauth status/refresh が全体失敗した。
	var e OAuthEntry
	err := json.Unmarshal([]byte(`{"type":"oauth","provider":"google","access":"a","refresh":"r","expires_at":"","refresh_expires_at":""}`), &e)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v, want nil", err)
	}
	if !e.ExpiresAt.IsZero() || !e.RefreshExpiresAt.IsZero() {
		t.Errorf("time fields = %v/%v, want zero values", e.ExpiresAt, e.RefreshExpiresAt)
	}
}

func TestOAuthEntryMarshalはゼロ時刻を空文字で出力する(t *testing.T) {
	e := OAuthEntry{Provider: "google", Refresh: "r"}
	// production は常に *OAuthEntry で Marshal する（command.go の json.Marshal(entry)）。
	b, err := json.Marshal(&e)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if got := string(b); !strings.Contains(got, `"refresh_expires_at":""`) {
		t.Errorf("Marshal() = %s, want empty refresh_expires_at", got)
	}
}

func TestIsOAuthEntryはtypeoauthのJSONのみtrueを返す(t *testing.T) {
	cases := []struct {
		data string
		want bool
	}{
		{`{"type":"oauth","provider":"google"}`, true},
		{`{"type":"password"}`, false},
		{`not json`, false},
		{``, false},
	}
	for _, c := range cases {
		if got := IsOAuthEntry([]byte(c.data)); got != c.want {
			t.Errorf("IsOAuthEntry(%q) = %v, want %v", c.data, got, c.want)
		}
	}
}

// TestOAuthEntryMarshalはaccessやscopesを出力せず最小化する:
// access / expires_at / scopes はランタイム専用フィールドであり、
// 永続化されない（保存エントリが bitwarden の 5000 文字制限に
// 収まるよう refresh 関連のみを保存する）。
func TestOAuthEntryMarshalはaccessやscopesを出力せず最小化する(t *testing.T) {
	e := &OAuthEntry{
		Provider:         "lark",
		Access:           "access-secret",
		Refresh:          strings.Repeat("r", 200),
		ExpiresAt:        time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		RefreshExpiresAt: time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC),
		Scopes:           []string{"drive", "gmail.readonly"},
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	s := string(b)
	if strings.Contains(s, "access-secret") {
		t.Errorf("marshaled JSON contains access token: %q", s)
	}
	if strings.Contains(s, "drive") || strings.Contains(s, "gmail.readonly") {
		t.Errorf("marshaled JSON contains scopes: %q", s)
	}
	if strings.Contains(s, `"expires_at"`) {
		t.Errorf("marshaled JSON contains expires_at: %q", s)
	}
	// 永続化フィールドは保持される
	var got OAuthEntry
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got.Provider != "lark" || got.Refresh != e.Refresh {
		t.Errorf("roundtrip = %+v, want provider=lark refresh=%q", got, e.Refresh)
	}
	if !got.RefreshExpiresAt.Equal(e.RefreshExpiresAt) {
		t.Errorf("RefreshExpiresAt = %v, want %v", got.RefreshExpiresAt, e.RefreshExpiresAt)
	}
}

// TestOAuthEntry圧縮ラウンドトリップは3500バイト超をzラップで往復できる:
// 実測値（2026-08-13）の Lark refresh token（JWT 5790 文字）はヘッダ・
// ペイロードがランダムで圧縮効率が低いため、ランダムな 5000 文字級ダミーで
// 圧縮経路（Marshal → Unmarshal）を検証する。
func TestOAuthEntry圧縮ラウンドトリップは3500バイト超をzラップで往復できる(t *testing.T) {
	refresh := dummyRefreshJWT(5000)
	// 圧縮前の wire サイズが閾値を超えることを保証（ダミー refresh 自体が 3500B 超）
	if len(refresh) <= compressThreshold {
		t.Fatalf("dummy refresh length = %d, want > %d", len(refresh), compressThreshold)
	}
	e := &OAuthEntry{
		Provider:         "lark",
		Refresh:          refresh,
		RefreshExpiresAt: time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	var probe struct {
		Type string `json:"type"`
		Z    bool   `json:"z"`
		Data string `json:"data"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		t.Fatalf("unmarshal z-probe: %v", err)
	}
	if probe.Type != "oauth" {
		t.Errorf("z-wrapped type = %q, want oauth", probe.Type)
	}
	if !probe.Z || probe.Data == "" {
		t.Fatalf("z-wrapped = %+v, want z=true and non-empty data", probe)
	}
	var got OAuthEntry
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if got.Refresh != refresh {
		t.Errorf("Refresh mismatch after roundtrip: len(got)=%d want len=%d", len(got.Refresh), len(refresh))
	}
	if !got.RefreshExpiresAt.Equal(e.RefreshExpiresAt) {
		t.Errorf("RefreshExpiresAt = %v, want %v", got.RefreshExpiresAt, e.RefreshExpiresAt)
	}
	// 圧縮エントリも type=oauth として検出される
	if !IsOAuthEntry(b) {
		t.Error("IsOAuthEntry(z-wrapped) = false, want true")
	}
}

// TestOAuthEntry圧縮は5000バイト制限以内に収まる:
// bitwarden の暗号化値上限 5000 文字に収まることが zlib 圧縮の目的。
func TestOAuthEntry圧縮は5000バイト制限以内に収まる(t *testing.T) {
	// 実測相当: Lark refresh token（JWT 5790 文字）+ provider + 時刻フィールド
	refresh := dummyRefreshJWT(5790)
	e := &OAuthEntry{Provider: "lark", Refresh: refresh}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	if len(b) > 5000 {
		t.Errorf("marshaled length = %d, want <= 5000 (bitwarden limit)", len(b))
	}
}

// TestOAuthEntry旧形式エントリもUnmarshalできる:
// 既存の bitwarden エントリ（access/scopes 入り）との後方互換を保証する。
func TestOAuthEntry旧形式エントリもUnmarshalできる(t *testing.T) {
	var e OAuthEntry
	err := json.Unmarshal([]byte(`{"type":"oauth","provider":"google","access":"access-1","refresh":"refresh-1","expires_at":"2026-01-02T03:04:05Z","refresh_expires_at":"","scopes":["a","b"]}`), &e)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if e.Access != "access-1" || e.Refresh != "refresh-1" {
		t.Errorf("entry = %+v, want access/refresh preserved", e)
	}
	if len(e.Scopes) != 2 || e.Scopes[0] != "a" {
		t.Errorf("Scopes = %v, want [a b]", e.Scopes)
	}
}
