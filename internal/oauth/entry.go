package oauth

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// TypeOAuth は OAuth エントリを識別する固定の type フィールド値。
const TypeOAuth = "oauth"

// compressThreshold は wire JSON のバイト数がこの値を超えた場合に
// zlib 圧縮する閾値。bitwarden の暗号化値 5000 文字制限を満たすため、
// 閾値を下回るエントリは従来どおり compact 単一行 JSON で保存する。
const compressThreshold = 3500

// OAuthEntry は pass/bitwarden に compact 単一行 JSON として保存される
// OAuth 資格情報エントリ。
//
// 永続化フィールド（Marshal で出力）: Provider / Refresh / RefreshExpiresAt。
// ランタイム専用フィールド（Marshal では常に省略）: Access / ExpiresAt / Scopes。
// access token は resolve 時に refresh で取得しインメモリキャッシュするため
// 永続不要。scopes は refresh 応答から復元し、expires_at は access に紐づく。
// ただし Refreshable=false のプロバイダ（将来）は access 永続が必要になる
// （v1 の google/lark は両方 refreshable=true のため問題なし）。
type OAuthEntry struct {
	Provider         string    `json:"provider"`
	Access           string    `json:"access"`
	Refresh          string    `json:"refresh"`
	ExpiresAt        time.Time `json:"expires_at"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
	Scopes           []string  `json:"scopes"`
}

type oauthEntryWire struct {
	Type             string `json:"type"`
	Provider         string `json:"provider"`
	Refresh          string `json:"refresh"`
	RefreshExpiresAt string `json:"refresh_expires_at"`
}

// oauthEntryLegacyWire は access / expires_at / scopes を含む旧形式エントリの
// Unmarshal 互換用 wire。Marshal では使わない（非永続フィールド）。
type oauthEntryLegacyWire struct {
	Type             string   `json:"type"`
	Provider         string   `json:"provider"`
	Access           string   `json:"access"`
	Refresh          string   `json:"refresh"`
	ExpiresAt        string   `json:"expires_at"`
	RefreshExpiresAt string   `json:"refresh_expires_at"`
	Scopes           []string `json:"scopes"`
}

// zlibWrap は圧縮エントリのラップ構造。
// {"type":"oauth","z":true,"data":"<base64(zlib)>"} として保存する。
type zlibWrap struct {
	Type string `json:"type"`
	Z    bool   `json:"z"`
	Data string `json:"data"`
}

// parseTime は空文字をゼロ値として許容する time パース。
// pass エントリの手動編集や旧形式エントリで空欄があり得るため、
// 空文字でエラーにしない（実測: refresh_expires_at="" で全体が失敗した）。
func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339Nano, s)
}

// formatTime はゼロ値を空文字として出力する（parseTime との往復保証）。
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339Nano)
}

// MarshalJSON は pass の 1 行制約を満たす compact な単一行 JSON を出力する。
// 永続化フィールド（type/provider/refresh/refresh_expires_at）のみを含み、
// wire サイズが compressThreshold を超える場合は zlib 圧縮して
// {"type":"oauth","z":true,"data":"<b64>"} のラップ形式で出力する。
func (e *OAuthEntry) MarshalJSON() ([]byte, error) {
	wire := oauthEntryWire{
		Type:             TypeOAuth,
		Provider:         e.Provider,
		Refresh:          e.Refresh,
		RefreshExpiresAt: formatTime(e.RefreshExpiresAt),
	}
	b, err := json.Marshal(wire)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, b); err != nil {
		return nil, err
	}
	if buf.Len() <= compressThreshold {
		return buf.Bytes(), nil
	}
	compressed, err := compressZlib(buf.Bytes())
	if err != nil {
		return nil, err
	}
	return json.Marshal(zlibWrap{Type: TypeOAuth, Z: true, Data: compressed})
}

// UnmarshalJSON は type フィールドを検証し、"oauth" 以外はエラーを返す。
// z ラップ（zlib 圧縮）形式なら base64 デコード → zlib 展開してから
// 通常パースする。時刻フィールドは空文字をゼロ値として許容し、
// 旧形式（access/scopes 入り）も後方互換のため読み込む。
func (e *OAuthEntry) UnmarshalJSON(data []byte) error {
	var wrap zlibWrap
	if err := json.Unmarshal(data, &wrap); err == nil && wrap.Z && wrap.Type == TypeOAuth {
		raw, err := decompressZlib(wrap.Data)
		if err != nil {
			return fmt.Errorf("oauth: decompress entry: %w", err)
		}
		return e.unmarshalPlain(raw)
	}
	return e.unmarshalPlain(data)
}

// unmarshalPlain は非圧縮の wire JSON をパースする。
func (e *OAuthEntry) unmarshalPlain(data []byte) error {
	var wire oauthEntryLegacyWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.Type != TypeOAuth {
		return fmt.Errorf("oauth: entry type %q is not %q", wire.Type, TypeOAuth)
	}
	expiresAt, err := parseTime(wire.ExpiresAt)
	if err != nil {
		return fmt.Errorf("oauth: invalid expires_at: %w", err)
	}
	refreshExpiresAt, err := parseTime(wire.RefreshExpiresAt)
	if err != nil {
		return fmt.Errorf("oauth: invalid refresh_expires_at: %w", err)
	}
	*e = OAuthEntry{
		Provider:         wire.Provider,
		Access:           wire.Access,
		Refresh:          wire.Refresh,
		ExpiresAt:        expiresAt,
		RefreshExpiresAt: refreshExpiresAt,
		Scopes:           wire.Scopes,
	}
	return nil
}

// compressZlib はデータを zlib 圧縮（BestCompression）して base64 化する。
func compressZlib(data []byte) (string, error) {
	var buf bytes.Buffer
	zw, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if err != nil {
		return "", err
	}
	if _, err := zw.Write(data); err != nil {
		zw.Close()
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// decompressZlib は base64 → zlib 展開の逆変換を行う。
func decompressZlib(encoded string) ([]byte, error) {
	compressed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	zr, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	raw, err := io.ReadAll(io.LimitReader(zr, 1<<20))
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// IsOAuthEntry は data が JSON かつ type=="oauth" の OAuth エントリかどうかを
// 判定する。backend デコレータが型検出に使う。z ラップ（圧縮）形式でも
// type=="oauth" なので true を返す。
func IsOAuthEntry(data []byte) bool {
	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return probe.Type == TypeOAuth
}
