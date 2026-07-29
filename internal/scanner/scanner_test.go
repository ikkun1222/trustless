package scanner

import (
	"strings"
	"testing"
)

func TestScan_GitHubToken(t *testing.T) {
	s := New()
	input := []byte("token=ghp_abc123def456xyz789")
	output := s.Scan(input)
	if strings.Contains(string(output), "ghp_abc") {
		t.Errorf("expected redacted, got: %s", string(output))
	}
}

func TestScan_OpenAIKey(t *testing.T) {
	s := New()
	input := []byte("OPENAI_API_KEY=sk-proj-abc123def456xyz789abc123def456")
	output := s.Scan(input)
	if strings.Contains(string(output), "sk-proj-abc") {
		t.Errorf("expected redacted, got: %s", string(output))
	}
}

func TestScan_XAIKey(t *testing.T) {
	s := New()
	input := []byte("xai-8R...4Hvc")
	output := s.Scan(input)
	if strings.Contains(string(output), "xai-8R") {
		t.Errorf("expected redacted, got: %s", string(output))
	}
}

func TestScanWithValues_ExtraValues(t *testing.T) {
	s := New()
	output := s.ScanWithValues([]byte("my-secret-value"), []string{"my-secret-value"})
	if string(output) != "[REDACTED]" {
		t.Errorf("expected [REDACTED], got: %s", string(output))
	}
}

func TestScan_CleanInput(t *testing.T) {
	s := New()
	input := []byte("hello world this is safe")
	output := s.Scan(input)
	if string(output) != "hello world this is safe" {
		t.Errorf("expected unchanged, got: %s", string(output))
	}
}

func TestScan_NoFalsePositives(t *testing.T) {
	s := New()
	input := []byte("The quick brown fox")
	output := s.Scan(input)
	if string(output) != "The quick brown fox" {
		t.Errorf("expected unchanged, got: %s", string(output))
	}
}

func TestAddPattern_InvalidRegex(t *testing.T) {
	s := New()
	err := s.AddPattern(`[invalid`)
	if err == nil {
		t.Error("expected error for invalid regex")
	}
}

func TestScan_EmptyInput(t *testing.T) {
	s := New()
	output := s.Scan([]byte{})
	if len(output) != 0 {
		t.Errorf("expected empty output, got: %s", string(output))
	}
}

func TestScanWithValues_EmptyValues(t *testing.T) {
	s := New()
	input := []byte("hello world")
	output := s.ScanWithValues(input, []string{})
	if string(output) != "hello world" {
		t.Errorf("expected unchanged, got: %s", string(output))
	}
}

func TestContainsCredentials_GitHubToken(t *testing.T) {
	s := New()
	if !s.ContainsCredentials([]byte("ghp_abc123def456xyz789"), nil) {
		t.Error("expected true for GitHub token")
	}
}

func TestContainsCredentials_OpenAIKey(t *testing.T) {
	s := New()
	if !s.ContainsCredentials([]byte("sk-proj-abc123def456xyz789abc123def456"), nil) {
		t.Error("expected true for OpenAI key")
	}
}

func TestContainsCredentials_ExactValue(t *testing.T) {
	s := New()
	if !s.ContainsCredentials([]byte("my-secret-value"), []string{"my-secret-value"}) {
		t.Error("expected true for extra value match")
	}
}

func TestContainsCredentials_CleanInput(t *testing.T) {
	s := New()
	if s.ContainsCredentials([]byte("hello world this is safe"), nil) {
		t.Error("expected false for clean input")
	}
}

func TestContainsCredentials_EmptyInput(t *testing.T) {
	s := New()
	if s.ContainsCredentials([]byte{}, nil) {
		t.Error("expected false for empty input")
	}
}

func TestContainsCredentials_EmptyExtraValues(t *testing.T) {
	s := New()
	if s.ContainsCredentials([]byte("safe input"), []string{}) {
		t.Error("expected false for empty extra values")
	}
}

func TestContainsCredentials_ExtraValueNotPresent(t *testing.T) {
	s := New()
	if s.ContainsCredentials([]byte("safe input"), []string{"not-present"}) {
		t.Error("expected false when extra value is not present")
	}
}
