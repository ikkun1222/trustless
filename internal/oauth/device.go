package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	deviceAuthStyleBody  = "body"
	deviceAuthStyleBasic = "basic"

	defaultDeviceInterval = 5
	defaultDeviceExpires  = 240

	// slowDownIntervalMax は slow_down 応答後の interval の上限（RFC 8628 §3.5）。
	slowDownIntervalMax = 60
)

// DeviceAuthResponse は device 認可開始（RFC 8628 §3.1）の応答。
type DeviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
	Error                   string `json:"error"`
	ErrorDescription        string `json:"error_description"`
}

// DeviceFlowTokenData は device フロー完了時に得られるトークン一式。
// refresh_token はプロバイダによって返らないことがある。
type DeviceFlowTokenData struct {
	AccessToken      string
	RefreshToken     string
	ExpiresIn        int
	RefreshExpiresIn int
	Scope            string
}

// deviceWait は poll の合間に interval 秒だけ待機する。
// 実時間待ちをテストから差し替え可能にするため関数変数としている。
var deviceWait = func(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// DeviceStart は device 認可を開始し、ユーザーに提示するコードを返す。
// DeviceAuthStyle=body（Google）は form ボディに client_secret を含め、
// basic（Lark）は Authorization: Basic ヘッダで資格情報を送る。
func DeviceStart(ctx context.Context, client *http.Client, provider Provider) (*DeviceAuthResponse, error) {
	form := url.Values{}
	form.Set("client_id", provider.ClientID)
	form.Set("scope", strings.Join(provider.Scopes, " "))
	if provider.DeviceAuthStyle == deviceAuthStyleBody {
		form.Set("client_secret", provider.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.DeviceURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if provider.DeviceAuthStyle == deviceAuthStyleBasic {
		token := base64.StdEncoding.EncodeToString([]byte(provider.ClientID + ":" + provider.ClientSecret))
		req.Header.Set("Authorization", "Basic "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("oauth: device authorization returned %s", resp.Status)
	}
	var da DeviceAuthResponse
	if err := json.Unmarshal(body, &da); err != nil {
		return nil, fmt.Errorf("oauth: parse device response: %w", err)
	}
	if da.Error != "" {
		msg := da.Error
		if da.ErrorDescription != "" {
			msg += ": " + da.ErrorDescription
		}
		return nil, errors.New("oauth: " + msg)
	}
	return &da, nil
}

// DevicePoll は device_code でトークン発行を poll する（RFC 8628 §3.3-3.5）。
// interval / expiresIn が既定値未満なら下限（5s / 240s）に引き上げる。
// authorization_pending は待機を継続し、slow_down は interval を +5s（上限 60s）する。
// access_denied / expired_token / invalid_grant はエラーで中断する。
func DevicePoll(ctx context.Context, client *http.Client, provider Provider, deviceCode string, interval, expiresIn int) (*DeviceFlowTokenData, error) {
	if interval < defaultDeviceInterval {
		interval = defaultDeviceInterval
	}
	if expiresIn < defaultDeviceExpires {
		expiresIn = defaultDeviceExpires
	}
	deadline := time.Now().Add(time.Duration(expiresIn) * time.Second)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("oauth: device authorization expired after %ds", expiresIn)
		}
		if err := deviceWait(ctx, time.Duration(interval)*time.Second); err != nil {
			return nil, err
		}
		data, err := pollOnce(ctx, client, provider, deviceCode)
		if err != nil {
			return nil, err
		}
		if data != nil {
			return data, nil
		}
		// slow_down は interval を増やして再試行（RFC 8628 §3.5）
		interval += 5
		if interval > slowDownIntervalMax {
			interval = slowDownIntervalMax
		}
	}
}

// pollOnce は 1 回の poll を行い、成功時はトークンを、
// 継続可能なエラー（authorization_pending / slow_down）時は nil を返す。
// 中断すべきエラーはそのまま返す。
func pollOnce(ctx context.Context, client *http.Client, provider Provider, deviceCode string) (*DeviceFlowTokenData, error) {
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	form.Set("device_code", deviceCode)
	form.Set("client_id", provider.ClientID)
	form.Set("client_secret", provider.ClientSecret)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oauth: token endpoint returned %s", resp.Status)
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("oauth: parse token response: %w", err)
	}
	if provider.TokenRequestStyle == tokenStyleJSON && tr.Code != 0 {
		return nil, larkCodeError(&tr)
	}
	switch tr.Error {
	case "authorization_pending":
		return nil, nil
	case "slow_down":
		return nil, nil
	case "access_denied":
		return nil, errors.New("oauth: Authorization denied")
	case "expired_token", "invalid_grant":
		return nil, tokenError(&tr)
	}
	if tr.Error != "" {
		return nil, tokenError(&tr)
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("oauth: token response without access_token")
	}
	return &DeviceFlowTokenData{
		AccessToken:      tr.AccessToken,
		RefreshToken:     tr.RefreshToken,
		ExpiresIn:        int(tr.ExpiresIn),
		RefreshExpiresIn: int(tr.RefreshTokenExpiresIn),
		Scope:            tr.Scope,
	}, nil
}
