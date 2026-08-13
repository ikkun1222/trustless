package oauth

import (
	"strings"
	"testing"
)

func TestBuiltinはgoogleプロバイダを含む(t *testing.T) {
	p, ok := Builtin()["google"]
	if !ok {
		t.Fatal(`Builtin() has no "google" provider`)
	}
	if p.TokenURL != "https://oauth2.googleapis.com/token" {
		t.Errorf("TokenURL = %q, want https://oauth2.googleapis.com/token", p.TokenURL)
	}
	if p.DeviceURL != "https://oauth2.googleapis.com/device/code" {
		t.Errorf("DeviceURL = %q, want https://oauth2.googleapis.com/device/code", p.DeviceURL)
	}
	if p.TokenRequestStyle != "form" {
		t.Errorf("TokenRequestStyle = %q, want form", p.TokenRequestStyle)
	}
	if p.DeviceAuthStyle != "body" {
		t.Errorf("DeviceAuthStyle = %q, want body", p.DeviceAuthStyle)
	}
	if !p.Refreshable {
		t.Error("Refreshable = false, want true")
	}
	if len(p.Scopes) != 0 {
		t.Errorf("Scopes = %v, want empty", p.Scopes)
	}
}

func TestBuiltinはlarkプロバイダを含む(t *testing.T) {
	p, ok := Builtin()["lark"]
	if !ok {
		t.Fatal(`Builtin() has no "lark" provider`)
	}
	if p.TokenURL != "https://open.larksuite.com/open-apis/authen/v2/oauth/token" {
		t.Errorf("TokenURL = %q, want lark token endpoint", p.TokenURL)
	}
	if p.DeviceURL != "https://accounts.larksuite.com/oauth/v1/device_authorization" {
		t.Errorf("DeviceURL = %q, want lark device endpoint", p.DeviceURL)
	}
	if p.TokenRequestStyle != "json" {
		t.Errorf("TokenRequestStyle = %q, want json", p.TokenRequestStyle)
	}
	if p.DeviceAuthStyle != "basic" {
		t.Errorf("DeviceAuthStyle = %q, want basic", p.DeviceAuthStyle)
	}
	if !p.Refreshable {
		t.Error("Refreshable = false, want true")
	}
}

func TestBuiltinのlarkは既定スコープにofflineAccessを含む(t *testing.T) {
	p := Builtin()["lark"]
	found := false
	for _, s := range p.Scopes {
		if s == "offline_access" {
			found = true
		}
	}
	if !found {
		t.Errorf("lark Scopes = %v, want contains offline_access", p.Scopes)
	}
}

func TestBuiltinの各プロバイダはValidateを通る(t *testing.T) {
	for name, p := range Builtin() {
		if err := Validate(p); err != nil {
			t.Errorf("Validate(%s) error = %v, want nil", name, err)
		}
	}
}

func TestValidateはClientIDが空でも通す(t *testing.T) {
	p := Provider{
		TokenURL:          "https://example.com/token",
		DeviceURL:         "https://example.com/device",
		TokenRequestStyle: "form",
		DeviceAuthStyle:   "body",
	}
	if err := Validate(p); err != nil {
		t.Errorf("Validate() error = %v, want nil (ClientID overridden by config)", err)
	}
}

func TestValidateはRefreshableがゼロ値ならtrue扱いする(t *testing.T) {
	p := Provider{
		TokenURL:          "https://example.com/token",
		DeviceURL:         "https://example.com/device",
		TokenRequestStyle: "form",
		DeviceAuthStyle:   "body",
	}
	if err := Validate(p); err != nil {
		t.Errorf("Validate() error = %v, want nil", err)
	}
	if p.Refreshable {
		t.Error("Refreshable = true, want unchanged false (validation must not mutate)")
	}
}

func TestValidateは不正なTokenURLをエラーにする(t *testing.T) {
	cases := map[string]Provider{
		"not-url": {
			TokenURL:          "not-a-url",
			DeviceURL:         "https://example.com/device",
			TokenRequestStyle: "form",
			DeviceAuthStyle:   "body",
		},
		"non-http-scheme": {
			TokenURL:          "ftp://example.com/token",
			DeviceURL:         "https://example.com/device",
			TokenRequestStyle: "form",
			DeviceAuthStyle:   "body",
		},
		"empty": {
			TokenURL:          "",
			DeviceURL:         "https://example.com/device",
			TokenRequestStyle: "form",
			DeviceAuthStyle:   "body",
		},
	}
	for name, p := range cases {
		if err := Validate(p); err == nil {
			t.Errorf("%s: Validate() error = nil, want non-nil", name)
		}
	}
}

func TestValidateは不正なDeviceURLをエラーにする(t *testing.T) {
	p := Provider{
		TokenURL:          "https://example.com/token",
		DeviceURL:         "not-a-url",
		TokenRequestStyle: "form",
		DeviceAuthStyle:   "body",
	}
	if err := Validate(p); err == nil {
		t.Error("Validate() error = nil, want non-nil")
	}
}

func TestValidateは不正なTokenRequestStyleをエラーにする(t *testing.T) {
	p := Provider{
		TokenURL:          "https://example.com/token",
		DeviceURL:         "https://example.com/device",
		TokenRequestStyle: "xml",
		DeviceAuthStyle:   "body",
	}
	if err := Validate(p); err == nil {
		t.Error("Validate() error = nil, want non-nil")
	}
}

func TestValidateは不正なDeviceAuthStyleをエラーにする(t *testing.T) {
	p := Provider{
		TokenURL:          "https://example.com/token",
		DeviceURL:         "https://example.com/device",
		TokenRequestStyle: "form",
		DeviceAuthStyle:   "xml",
	}
	if err := Validate(p); err == nil {
		t.Error("Validate() error = nil, want non-nil")
	}
}

func TestValidateのエラーメッセージにプロバイダ名と内容が含まれる(t *testing.T) {
	p := Provider{
		Name:              "test",
		TokenURL:          "not-a-url",
		DeviceURL:         "https://example.com/device",
		TokenRequestStyle: "form",
		DeviceAuthStyle:   "body",
	}
	err := Validate(p)
	if err == nil {
		t.Fatal("Validate() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "test") {
		t.Errorf("error = %q, want contains provider name", err.Error())
	}
	if !strings.Contains(err.Error(), "token url") {
		t.Errorf("error = %q, want contains field name", err.Error())
	}
}
