package oauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// TypeOAuth は OAuth エントリを識別する固定の type フィールド値。
const TypeOAuth = "oauth"

// OAuthEntry は pass/bitwarden に compact 単一行 JSON として保存される
// OAuth 資格情報エントリ。
type OAuthEntry struct {
	Provider         string    `json:"provider"`
	Access           string    `json:"access"`
	Refresh          string    `json:"refresh"`
	ExpiresAt        time.Time `json:"expires_at"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
	Scopes           []string  `json:"scopes"`
}

type oauthEntryWire struct {
	Type             string    `json:"type"`
	Provider         string    `json:"provider"`
	Access           string    `json:"access"`
	Refresh          string    `json:"refresh"`
	ExpiresAt        time.Time `json:"expires_at"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
	Scopes           []string  `json:"scopes"`
}

// MarshalJSON は pass の 1 行制約を満たすため、改行を含まない
// compact な単一行 JSON を出力する。
func (e *OAuthEntry) MarshalJSON() ([]byte, error) {
	wire := oauthEntryWire{
		Type:             TypeOAuth,
		Provider:         e.Provider,
		Access:           e.Access,
		Refresh:          e.Refresh,
		ExpiresAt:        e.ExpiresAt,
		RefreshExpiresAt: e.RefreshExpiresAt,
		Scopes:           e.Scopes,
	}
	b, err := json.Marshal(wire)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, b); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalJSON は type フィールドを検証し、"oauth" 以外はエラーを返す。
func (e *OAuthEntry) UnmarshalJSON(data []byte) error {
	var wire oauthEntryWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.Type != TypeOAuth {
		return fmt.Errorf("oauth: entry type %q is not %q", wire.Type, TypeOAuth)
	}
	*e = OAuthEntry{
		Provider:         wire.Provider,
		Access:           wire.Access,
		Refresh:          wire.Refresh,
		ExpiresAt:        wire.ExpiresAt,
		RefreshExpiresAt: wire.RefreshExpiresAt,
		Scopes:           wire.Scopes,
	}
	return nil
}

// IsOAuthEntry は data が JSON かつ type=="oauth" の OAuth エントリかどうかを
// 判定する。backend デコレータが型検出に使う。
func IsOAuthEntry(data []byte) bool {
	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return probe.Type == TypeOAuth
}
