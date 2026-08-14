package dlp

import (
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestRunScrub_DryRunAndApply verifies the scrub-db default (dry-run) reports
// hits without modifying the DB, and --apply scrubs it (with backup).
func TestRunScrub_DryRunAndApply(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	sql := `CREATE TABLE messages (id INTEGER PRIMARY KEY, content TEXT);
INSERT INTO messages (content) VALUES ('key is sk-supersecret1234567890 here');
INSERT INTO messages (content) VALUES ('plain text');`
	if out, err := exec.Command("sqlite3", dbPath, sql).CombinedOutput(); err != nil {
		t.Fatalf("create db: %v (%s)", err, out)
	}

	logger := log.New(io.Discard, "", 0)
	secrets := []string{"sk-supersecret1234567890"}

	// Dry-run: reports hits, leaves DB untouched.
	if err := runScrubWithSecrets(dbPath, secrets, 8, false, false, nil, false, logger); err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	got, err := exec.Command("sqlite3", dbPath, "SELECT content FROM messages WHERE id=1").Output()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(got), "sk-supersecret1234567890") {
		t.Fatalf("dry-run modified DB: %q", got)
	}

	// Apply: scrubs the secret.
	if err := runScrubWithSecrets(dbPath, secrets, 8, true, true, nil, true, logger); err != nil {
		t.Fatalf("apply: %v", err)
	}
	got2, err := exec.Command("sqlite3", dbPath, "SELECT content FROM messages WHERE id=1").Output()
	if err != nil {
		t.Fatalf("read2: %v", err)
	}
	if strings.Contains(string(got2), "sk-supersecret1234567890") {
		t.Fatalf("secret remains after apply: %q", got2)
	}
	if !strings.Contains(string(got2), "<redacted>") {
		t.Fatalf("marker missing after apply: %q", got2)
	}
	if _, err := os.Stat(dbPath + ".bak"); err != nil {
		t.Fatalf("backup missing: %v", err)
	}
}

// TestRunScrubText_DryRunAndApply verifies the scrub-text dry-run leaves
// files untouched, and apply replaces the secret with <redacted>. Secrets
// are injected (pure core) so the test never touches a real backend/config.
// The scrub core (walk/binary-skip/email-exclusion) is covered in
// internal/dlp/scrub; here we exercise the command layer.
func TestRunScrubText_DryRunAndApply(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "agent.log")
	secret := "sk-supersecret1234567890"
	if err := os.WriteFile(logPath, []byte("token "+secret+" in log\n"), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	logger := log.New(io.Discard, "", 0)

	// Dry-run: reports hits, leaves the file untouched.
	if err := runScrubTextWithSecrets(logPath, []string{secret}, 8, false, nil, false, logger); err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(data), secret) {
		t.Fatalf("dry-run modified file: %q", data)
	}

	// Apply: scrubs the secret.
	if err := runScrubTextWithSecrets(logPath, []string{secret}, 8, true, nil, true, logger); err != nil {
		t.Fatalf("apply: %v", err)
	}
	data2, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read2: %v", err)
	}
	if strings.Contains(string(data2), secret) {
		t.Fatalf("secret remains after apply: %q", data2)
	}
	if !strings.Contains(string(data2), "<redacted>") {
		t.Fatalf("marker missing after apply: %q", data2)
	}
}

// TestRunScrubE_PatternsFromConfig verifies the command wiring: a config in
// t.TempDir with a rules_file enables the pattern layer for scrub-db, and
// pattern_disabled turns a rule off. The pass store is pointed at an empty
// t.TempDir via PASSWORD_STORE_DIR, so loadSecrets returns no secrets
// without invoking the pass CLI or touching a real store.
func TestRunScrubE_PatternsFromConfig(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.toml")
	rules := `
[[rules]]
id = "test-slack-bot-token"
description = "test rule for scrub wiring"
regex = '''xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*'''
keywords = ["xoxb"]
entropy = 3
`
	if err := os.WriteFile(rulesPath, []byte(rules), 0o600); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	// Empty pass store: Values() returns no secrets, no pass CLI call.
	emptyStore := filepath.Join(dir, "empty-store")
	if err := os.MkdirAll(emptyStore, 0o700); err != nil {
		t.Fatalf("mkdir store: %v", err)
	}
	t.Setenv("PASSWORD_STORE_DIR", emptyStore)

	writeCfg := func(name, extra string) string {
		p := filepath.Join(dir, name)
		cfg := `{
  "listen": "127.0.0.1:8787",
  "secrets_source": "pass",
  "secrets_refresh_interval": "10m",
  "routes": [{"prefix": "/v1", "url": "http://127.0.0.1:9999/v1"}],
  "rules_file": "` + rulesPath + `"` + extra + `
}`
		if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
			t.Fatalf("write config %s: %v", name, err)
		}
		return p
	}
	cfgPath := writeCfg("config.json", "")
	cfgDisabled := writeCfg("config-disabled.json", `,
  "pattern_disabled": ["test-slack-bot-token"]`)

	mkDB := func(name string) string {
		p := filepath.Join(dir, name)
		sql := `CREATE TABLE messages (id INTEGER PRIMARY KEY, content TEXT);
INSERT INTO messages (content) VALUES ('token xoxb-1234567890-1234567890 end');`
		if out, err := exec.Command("sqlite3", p, sql).CombinedOutput(); err != nil {
			t.Fatalf("create db %s: %v (%s)", name, err, out)
		}
		return p
	}
	dbPath := mkDB("test.db")
	dbDisabled := mkDB("disabled.db")

	// Dry-run: pattern detected via rules_file (flags before the positional,
	// as Go's flag parser stops at the first non-flag argument).
	var buf strings.Builder
	capLogger := log.New(&buf, "", 0)
	if err := runScrubE([]string{"--config", cfgPath, dbPath}, capLogger); err != nil {
		t.Fatalf("runScrubE dry-run: %v", err)
	}
	if !strings.Contains(buf.String(), "1 hits") {
		t.Fatalf("expected 1 hit in dry-run, got log: %q", buf.String())
	}

	// Apply: pattern masked.
	if err := runScrubE([]string{"--apply", "--config", cfgPath, dbPath}, log.New(io.Discard, "", 0)); err != nil {
		t.Fatalf("runScrubE apply: %v", err)
	}
	out, err := exec.Command("sqlite3", dbPath, "SELECT content FROM messages WHERE id=1").Output()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(out), "xoxb-1234567890-abcdefghij") {
		t.Fatalf("pattern remains after apply: %q", out)
	}
	if !strings.Contains(string(out), "<redacted>") {
		t.Fatalf("marker missing after apply: %q", out)
	}

	// pattern_disabled: the rule is filtered out, so the dry-run reports 0 hits.
	var buf2 strings.Builder
	capLogger2 := log.New(&buf2, "", 0)
	if err := runScrubE([]string{"--config", cfgDisabled, dbDisabled}, capLogger2); err != nil {
		t.Fatalf("runScrubE disabled dry-run: %v", err)
	}
	if !strings.Contains(buf2.String(), "0 hits") {
		t.Fatalf("expected 0 hits with pattern disabled, got log: %q", buf2.String())
	}
}
