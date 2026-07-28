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
