package backend

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newFakePass は t.TempDir() にフェイク pass バイナリを生成する。
// 呼び出し args を logFile に、stdin の内容を stdinFile に保存するだけの
// シェルスクリプトで、実機の pass には一切触れない。
func newFakePass(t *testing.T) (logFile, stdinFile string) {
	t.Helper()
	dir := t.TempDir()
	logFile = filepath.Join(dir, "pass-args.log")
	stdinFile = filepath.Join(dir, "pass-stdin.txt")

	script := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" > " + logFile + "\n" +
		"cat > " + stdinFile + "\n"
	if err := os.WriteFile(filepath.Join(dir, "pass"), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake pass: %v", err)
	}

	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	return logFile, stdinFile
}

func TestPassBackendSetはpassinsertを呼び値をstdinで渡す(t *testing.T) {
	logFile, stdinFile := newFakePass(t)

	be := NewPassBackend()
	if err := be.Set(context.Background(), "iria/api/test-key", "secret-value"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	args := readFakePassArgs(t, logFile)
	if len(args) != 3 ||
		args[0] != "insert" || args[1] != "--force" || args[2] != "iria/api/test-key" {
		t.Fatalf("pass args = %q, want [insert --force iria/api/test-key]", args)
	}

	stdin, err := os.ReadFile(stdinFile)
	if err != nil {
		t.Fatalf("read stdin file: %v", err)
	}
	if got := string(stdin); got != "secret-value\n" {
		t.Fatalf("pass stdin = %q, want %q", got, "secret-value\n")
	}
}

// readFakePassArgs はフェイク pass の呼び出しログから引数を読み出す。
func readFakePassArgs(t *testing.T, logFile string) []string {
	t.Helper()
	raw, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read args log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}
	return lines
}
