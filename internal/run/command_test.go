package run

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/ikkun1222/trustless/internal/scanner"
)

func TestSanitizingWriterStreamsLines(t *testing.T) {
	var out bytes.Buffer
	s := scanner.New()
	w := &sanitizingWriter{dst: &out, s: s, values: []string{"sekrit-value-12345"}}

	// No newline yet: stays buffered
	w.Write([]byte("no newline yet "))
	if out.Len() != 0 {
		t.Fatalf("expected buffered output, got %q", out.String())
	}

	// Newline flushes the complete buffered line (with redaction)
	w.Write([]byte("hello sk-abcdefghijklmnopqrstuvwxyz\n"))
	got := out.String()
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("expected credential redacted, got %q", got)
	}
	if strings.Contains(got, "sk-abcdefghijklmnopqrstuvwxyz") {
		t.Fatalf("credential leaked: %q", got)
	}
	if !strings.Contains(got, "no newline yet") {
		t.Fatalf("expected full line flushed on newline, got %q", got)
	}

	// Exact-value redaction on a later line
	out.Reset()
	w.Write([]byte("token=sekrit-value-12345\n"))
	if !strings.Contains(out.String(), "[REDACTED]") {
		t.Fatalf("expected exact value redacted, got %q", out.String())
	}

	// Flush writes trailing partial line
	out.Reset()
	w.Write([]byte("tail secret sk-zyxwvutsrqponmlkjihgfedcba"))
	if out.Len() != 0 {
		t.Fatalf("expected no flush before Flush(), got %q", out.String())
	}
	w.Flush()
	if !strings.Contains(out.String(), "[REDACTED]") {
		t.Fatalf("expected trailing line redacted after flush, got %q", out.String())
	}
}

func TestSanitizingWriterExactValueAcrossChunks(t *testing.T) {
	var out bytes.Buffer
	s := scanner.New()
	val := "very-long-credential-token-abcdef123456"
	w := &sanitizingWriter{dst: &out, s: s, values: []string{val}}

	// Split the credential across two writes with a trailing newline.
	half := len(val) / 2
	w.Write([]byte("key=" + val[:half]))
	w.Write([]byte(val[half:] + "\n"))

	got := out.String()
	if strings.Contains(got, val) {
		t.Fatalf("credential leaked across chunks: %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("expected redaction, got %q", got)
	}
}

func TestRunPassthroughForwardsStdin(t *testing.T) {
	tmp := t.TempDir()
	script := tmp + "/stdin-echo.sh"
	content := "#!/bin/bash\nIFS= read -r line\necho \"GOT:$line\"\n"
	if err := os.WriteFile(script, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(script)
	cmd.Stdin = strings.NewReader("hello-from-test\n")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	var out bytes.Buffer
	s := scanner.New()
	w := &sanitizingWriter{dst: &out, s: s, values: nil}
	cmd.Stdout = w
	if err := cmd.Run(); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	w.Flush()
	if !strings.Contains(out.String(), "GOT:hello-from-test") {
		t.Fatalf("stdin not forwarded: %q", out.String())
	}
}
