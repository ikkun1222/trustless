package backend

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// newFakePassStore は t.TempDir() にフェイク pass バイナリとパスワード
// ストアを生成する。フェイク pass は `pass show <key>` をストア内の
// プレーンテキスト（先頭行が秘密）で応答し、`pass insert` は記録のみ。
// 実機の pass には一切触れない。
func newFakePassStore(t *testing.T) (storeDir string) {
	t.Helper()
	dir := t.TempDir()
	storeDir = filepath.Join(dir, ".password-store")
	if err := os.MkdirAll(storeDir, 0o755); err != nil {
		t.Fatalf("mkdir store: %v", err)
	}

	script := "#!/bin/sh\n" +
		"if [ \"$1\" = \"show\" ]; then\n" +
		"  key=$2\n" +
		"  file=" + storeDir + "/\"$key.gpg\"\n" +
		"  if [ -f \"$file\" ]; then\n" +
		"    if head -n 1 \"$file\" | grep -q '^ERROR$'; then\n" +
		"      echo \"pass: decryption failed\" >&2\n" +
		"      exit 1\n" +
		"    fi\n" +
		"    cat \"$file\"\n" +
		"    exit 0\n" +
		"  fi\n" +
		"  echo \"pass: no such entry\" >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		"printf '%s\\n' \"$@\" > " + filepath.Join(dir, "pass-args.log") + "\n" +
		"cat > " + filepath.Join(dir, "pass-stdin.txt") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "pass"), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake pass: %v", err)
	}

	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("PASSWORD_STORE_DIR", storeDir)
	return storeDir
}

// writePassEntry はフェイクストアにキー名に対応するプレーンテキストの
// 秘密ファイル（.gpg 拡張子）を書く。
func writePassEntry(t *testing.T, storeDir, key, content string) {
	t.Helper()
	path := filepath.Join(storeDir, key+".gpg")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir entry dir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write entry %s: %v", key, err)
	}
}

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

func TestValuesはpassストアの全エントリを復号して返す(t *testing.T) {
	storeDir := newFakePassStore(t)
	writePassEntry(t, storeDir, "iria/api", "sk-or-v1-secret\nmeta\n")
	writePassEntry(t, storeDir, "gh-api", "ghp_githubpass\n")
	writePassEntry(t, storeDir, "short", "abc\n")

	be := NewPassBackend()
	got, err := be.Values(context.Background(), 5)
	if err != nil {
		t.Fatalf("values: %v", err)
	}
	// 先頭行のみが値。minLen=5 なので "abc" は除外される
	want := []string{"ghp_githubpass", "sk-or-v1-secret"}
	if !slices.Equal(got, want) {
		t.Fatalf("values = %q, want %q", got, want)
	}
}

func TestValuesはpassの復号エラー時にエラーを返す(t *testing.T) {
	storeDir := newFakePassStore(t)
	writePassEntry(t, storeDir, "iria/api", "sk-or-v1-secret\n")
	// フェイク pass は先頭行が ERROR のエントリを復号失敗で応答する
	writePassEntry(t, storeDir, "broken", "ERROR\n")

	be := NewPassBackend()
	if _, err := be.Values(context.Background(), 0); err == nil {
		t.Fatalf("expected error when pass show fails")
	}
}
