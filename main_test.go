package main

import "testing"

func TestValidateConfigValue(t *testing.T) {
	valid := []struct{ key, value string }{
		{"backend", "pass"},
		{"backend", "env"},
		{"backend", "bitwarden"},
		{"run_defaults.sanitize", "true"},
		{"run_defaults.sanitize", "false"},
		{"run_defaults.timeout", "30s"},
		{"run_defaults.timeout", "5m"},
		{"proxy.port", "1"},
		{"proxy.port", "8080"},
		{"proxy.port", "65535"},
		{"output", "anything"}, // 実行時に参照されないキーは検証しない
	}
	for _, c := range valid {
		if err := validateConfigValue(c.key, c.value); err != nil {
			t.Errorf("validateConfigValue(%q, %q) = %v, want nil", c.key, c.value, err)
		}
	}

	invalid := []struct{ key, value string }{
		{"backend", "passwor"},
		{"backend", "PASS"},
		{"backend", " bitwarden"},
		{"run_defaults.sanitize", "yes"},
		{"run_defaults.sanitize", "1"},
		{"run_defaults.timeout", "xyz"},
		{"run_defaults.timeout", "30"}, // 単位なし
		{"proxy.port", "0"},
		{"proxy.port", "-1"},
		{"proxy.port", "65536"},
		{"proxy.port", "abc"},
	}
	for _, c := range invalid {
		if err := validateConfigValue(c.key, c.value); err == nil {
			t.Errorf("validateConfigValue(%q, %q) = nil, want error", c.key, c.value)
		}
	}
}
