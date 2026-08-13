package oauth

import (
	"fmt"
	"net/url"
	"strings"
)

// builtinProvider は組み込みプロバイダの定義を表す。
// タグ付きフィールドは config 側から上書きされる（ClientID/ClientSecret は空で定義）。
type builtinProvider struct {
	tokenURL          string
	deviceURL         string
	scopes            []string
	tokenRequestStyle string
	deviceAuthStyle   string
}

// Builtin は組み込みプロバイダ（google / lark）の定義を返す。
// ClientID / ClientSecret は空のままにして config 側で上書きする。
func Builtin() map[string]Provider {
	m := map[string]builtinProvider{
		"google": {
			tokenURL:          "https://oauth2.googleapis.com/token",
			deviceURL:         "https://oauth2.googleapis.com/device/code",
			tokenRequestStyle: tokenStyleForm,
			deviceAuthStyle:   deviceAuthStyleBody,
		},
		"lark": {
			tokenURL:          "https://open.larksuite.com/open-apis/authen/v2/oauth/token",
			deviceURL:         "https://accounts.larksuite.com/oauth/v1/device_authorization",
			scopes:            []string{"offline_access"},
			tokenRequestStyle: tokenStyleJSON,
			deviceAuthStyle:   deviceAuthStyleBasic,
		},
	}
	out := make(map[string]Provider, len(m))
	for name, def := range m {
		out[name] = Provider{
			Name:              name,
			TokenURL:          def.tokenURL,
			DeviceURL:         def.deviceURL,
			Scopes:            append([]string(nil), def.scopes...),
			TokenRequestStyle: def.tokenRequestStyle,
			DeviceAuthStyle:   def.deviceAuthStyle,
			Refreshable:       true,
		}
	}
	return out
}

// Validate はプロバイダ定義の妥当性を検証する。
// 1 つでも不正があればエラーを返す。Refreshable のゼロ値は true 扱い。
func Validate(p Provider) error {
	var errs []string
	if !isHTTPSURL(p.TokenURL) {
		errs = append(errs, fmt.Sprintf("token url %q must be an http(s) url", p.TokenURL))
	}
	if !isHTTPSURL(p.DeviceURL) {
		errs = append(errs, fmt.Sprintf("device url %q must be an http(s) url", p.DeviceURL))
	}
	if p.TokenRequestStyle != tokenStyleForm && p.TokenRequestStyle != tokenStyleJSON {
		errs = append(errs, fmt.Sprintf("token request style %q must be form or json", p.TokenRequestStyle))
	}
	if p.DeviceAuthStyle != deviceAuthStyleBody && p.DeviceAuthStyle != deviceAuthStyleBasic {
		errs = append(errs, fmt.Sprintf("device auth style %q must be body or basic", p.DeviceAuthStyle))
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("oauth: invalid provider %q: %s", p.Name, strings.Join(errs, "; "))
}

// isHTTPSURL は s が http(s) スキームの有効な URL かどうかを返す。
func isHTTPSURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}
