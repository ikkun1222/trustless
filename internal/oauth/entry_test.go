package oauth

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestOAuthEntryMarshalJSONは単一行でtypeフィールドを持つ(t *testing.T) {
	e := &OAuthEntry{
		Provider:  "google",
		Access:    "access-1",
		Refresh:   "refresh-1",
		ExpiresAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Scopes:    []string{"drive", "gmail.readonly"},
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
	if got.Provider != "google" || got.Access != "access-1" || got.Refresh != "refresh-1" {
		t.Errorf("roundtrip mismatch: %+v", got)
	}
	if !got.ExpiresAt.Equal(e.ExpiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, e.ExpiresAt)
	}
	if len(got.Scopes) != 2 || got.Scopes[0] != "drive" {
		t.Errorf("Scopes = %v, want [drive gmail.readonly]", got.Scopes)
	}
}

func TestOAuthEntryUnmarshalはtypeがoauth以外ならエラーを返す(t *testing.T) {
	var e OAuthEntry
	err := json.Unmarshal([]byte(`{"type":"password","access":"x"}`), &e)
	if err == nil {
		t.Fatal("Unmarshal() error = nil, want non-nil")
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
