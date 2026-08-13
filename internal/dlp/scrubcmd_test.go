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
	if err := runScrubWithSecrets(dbPath, secrets, 8, false, false, logger); err != nil {
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
	if err := runScrubWithSecrets(dbPath, secrets, 8, true, true, logger); err != nil {
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
	if err := runScrubTextWithSecrets(logPath, []string{secret}, 8, false, logger); err != nil {
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
	if err := runScrubTextWithSecrets(logPath, []string{secret}, 8, true, logger); err != nil {
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
