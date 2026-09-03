package main

import (
	"testing"

	"github.com/ikkun1222/trustless/internal/backend"
	"github.com/ikkun1222/trustless/internal/config"
)

func TestNewBackend(t *testing.T) {
	if be := newBackend(&config.Config{Backend: ""}); be == nil {
		t.Fatal(`newBackend("") returned nil`)
	} else if _, ok := be.(*backend.PassBackend); !ok {
		t.Fatalf(`newBackend("") = %T, want *backend.PassBackend`, be)
	}
	if be := newBackend(&config.Config{Backend: "pass"}); be == nil {
		t.Fatal(`newBackend("pass") returned nil`)
	} else if _, ok := be.(*backend.PassBackend); !ok {
		t.Fatalf(`newBackend("pass") = %T, want *backend.PassBackend`, be)
	}
	if be := newBackend(&config.Config{Backend: "env"}); be == nil {
		t.Fatal(`newBackend("env") returned nil`)
	} else if _, ok := be.(*backend.EnvBackend); !ok {
		t.Fatalf(`newBackend("env") = %T, want *backend.EnvBackend`, be)
	}
	// Every validBackends entry except bitwarden (which calls Load and may
	// exit) must construct without exiting; "" aliases pass.
	for _, name := range validBackends {
		if name == "bitwarden" {
			continue
		}
		if be := newBackend(&config.Config{Backend: name}); be == nil {
			t.Fatalf("newBackend(%q) returned nil", name)
		}
	}
}

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
		{"output", "json"},
		{"output", "text"},
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
		{"output", "anything"},
		{"output", "JSON"},
		{"output", ""},
	}
	for _, c := range invalid {
		if err := validateConfigValue(c.key, c.value); err == nil {
			t.Errorf("validateConfigValue(%q, %q) = nil, want error", c.key, c.value)
		}
	}
}
