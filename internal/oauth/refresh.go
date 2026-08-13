package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Provider は OAuth プロバイダの設定を表す。
type Provider struct {
	Name              string
	TokenURL          string
	DeviceURL         string
	ClientID          string
	ClientSecret      string
	Scopes            []string
	TokenRequestStyle string // "form" | "json"
	DeviceAuthStyle   string // "body" | "basic"
	Refreshable       bool
}

// ErrInvalidGrant は invalid_grant 応答を表す。refresh_token が無効・
// 失効しており、自動リトライは禁止。
var ErrInvalidGrant = errors.New("oauth: invalid_grant")

// ErrReauthRequired は再認証が必要なことを表す。
// 現時点では ErrInvalidGrant のラッパーとして定義する。
var ErrReauthRequired = fmt.Errorf("oauth: reauth required: %w", ErrInvalidGrant)

const (
	tokenStyleForm = "form"
	tokenStyleJSON = "json"
)

// tokenResponse は refresh grant の成功応答（共通フィールド）。
// Lark 式 JSON 応答では code フィールドで成功/失敗を判定する。
type tokenResponse struct {
	AccessToken           string `json:"access_token"`
	ExpiresIn             int64  `json:"expires_in"`
	RefreshToken          string `json:"refresh_token"`
	RefreshTokenExpiresIn int64  `json:"refresh_token_expires_in"`
	Scope                 string `json:"scope"`
	Error                 string `json:"error"`
	ErrorDescription      string `json:"error_description"`
	Code                  int    `json:"code"`
}

// Refresh は refresh grant で access token を更新し entry を書き換える。
// Refreshable が false なら何もせず nil を返す。
func Refresh(ctx context.Context, client *http.Client, provider Provider, entry *OAuthEntry) error {
	if !provider.Refreshable {
		return nil
	}
	reqBody, contentType, err := refreshRequestBody(provider, entry)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.TokenURL, strings.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		// エラーボディに invalid_grant が含まれる場合は ErrInvalidGrant に
		// マップする（Lark は 400 + {"code":...,"error":"invalid_grant"} で返す。
		// 実測 2026-08-13: refresh token は single-use のため消費後は必ずこれ）。
		var tr tokenResponse
		if err := json.Unmarshal(body, &tr); err == nil && tr.Error == "invalid_grant" {
			return fmt.Errorf("oauth: token endpoint returned %s: %w", resp.Status, ErrInvalidGrant)
		}
		return fmt.Errorf("oauth: token endpoint returned %s", resp.Status)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return fmt.Errorf("oauth: parse token response: %w", err)
	}
	return applyTokenResponse(provider, entry, &tr)
}

// refreshRequestBody は token リクエストのボディと Content-Type を返す。
// form スタイルは application/x-www-form-urlencoded、
// json スタイル（Lark）は application/json。
func refreshRequestBody(provider Provider, entry *OAuthEntry) (string, string, error) {
	switch provider.TokenRequestStyle {
	case tokenStyleJSON:
		payload := map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": entry.Refresh,
			"client_id":     provider.ClientID,
			"client_secret": provider.ClientSecret,
		}
		b, err := json.Marshal(payload)
		if err != nil {
			return "", "", err
		}
		return string(b), "application/json", nil
	default: // form（RFC 6749 §6 標準）
		form := url.Values{}
		form.Set("grant_type", "refresh_token")
		form.Set("refresh_token", entry.Refresh)
		form.Set("client_id", provider.ClientID)
		form.Set("client_secret", provider.ClientSecret)
		return form.Encode(), "application/x-www-form-urlencoded", nil
	}
}

// applyTokenResponse は成功応答を entry に反映する。
// Lark 式応答（json スタイル）では code != 0 をエラーとして扱う。
func applyTokenResponse(provider Provider, entry *OAuthEntry, tr *tokenResponse) error {
	if provider.TokenRequestStyle == tokenStyleJSON && tr.Code != 0 {
		return larkCodeError(tr)
	}
	if tr.Error != "" {
		return tokenError(tr)
	}
	entry.Access = tr.AccessToken
	if tr.ExpiresIn > 0 {
		entry.ExpiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	if tr.RefreshToken != "" {
		entry.Refresh = tr.RefreshToken
	}
	if tr.RefreshTokenExpiresIn > 0 {
		entry.RefreshExpiresAt = time.Now().Add(time.Duration(tr.RefreshTokenExpiresIn) * time.Second)
	}
	if tr.Scope != "" {
		entry.Scopes = strings.Fields(tr.Scope)
	}
	return nil
}

// tokenError は RFC 6749 形式の error 応答をエラーに変換する。
func tokenError(tr *tokenResponse) error {
	msg := tr.Error
	if tr.ErrorDescription != "" {
		msg += ": " + tr.ErrorDescription
	}
	if tr.Error == "invalid_grant" {
		return fmt.Errorf("oauth: %s: %w", msg, ErrInvalidGrant)
	}
	return errors.New("oauth: " + msg)
}

// larkCodeError は Lark 式応答の code != 0 をエラーに変換する。
func larkCodeError(tr *tokenResponse) error {
	msg := tr.ErrorDescription
	if msg == "" {
		msg = tr.Error
	}
	if msg == "" {
		msg = fmt.Sprintf("code %d", tr.Code)
	}
	if tr.Error == "invalid_grant" {
		return fmt.Errorf("oauth: %s: %w", msg, ErrInvalidGrant)
	}
	return errors.New("oauth: " + msg)
}

// RefreshIfNeeded は ExpiresAt から skew を引いた時刻を過ぎていれば
// Refresh を実行して true を返す。未失効なら false を返す。
func RefreshIfNeeded(ctx context.Context, client *http.Client, provider Provider, entry *OAuthEntry, skew time.Duration) (bool, error) {
	if !entry.ExpiresAt.IsZero() && time.Now().Before(entry.ExpiresAt.Add(-skew)) {
		return false, nil
	}
	if err := Refresh(ctx, client, provider, entry); err != nil {
		return false, err
	}
	return true, nil
}
