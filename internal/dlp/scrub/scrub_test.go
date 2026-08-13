package scrub

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// newTestDB creates a temp SQLite DB with a messages-like table (content
// column, FTS5 external-content index) and returns its path.
func newTestDB(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/test.db"

	sql := `
CREATE TABLE messages (id INTEGER PRIMARY KEY, content TEXT, role TEXT);
INSERT INTO messages (content, role) VALUES ('my key is sk-supersecret1234567890 ok', 'user');
INSERT INTO messages (content, role) VALUES ('hello world', 'user');
INSERT INTO messages (content, role) VALUES ('token xoxb-1234567890-abcdefghij end', 'user');
CREATE VIRTUAL TABLE messages_fts USING fts5(content, content='messages', content_rowid='id');
INSERT INTO messages_fts(messages_fts) VALUES('rebuild');
`
	if err := exec.Command("sqlite3", path, sql).Run(); err != nil {
		t.Fatalf("create test db: %v", err)
	}
	return path
}

func TestScanDB_FindsHits(t *testing.T) {
	path := newTestDB(t)
	secrets := []string{"sk-supersecret1234567890", "xoxb-1234567890-abcdefghij"}

	rep, err := ScanDB(path, secrets, 8)
	if err != nil {
		t.Fatalf("ScanDB: %v", err)
	}
	if rep.TotalHits() != 2 {
		t.Fatalf("TotalHits = %d, want 2 (got %+v)", rep.TotalHits(), rep)
	}
	// messages.content should have 2 hits (both secrets)
	mc := rep.TableHits("messages", "content")
	if mc != 2 {
		t.Fatalf("messages.content hits = %d, want 2", mc)
	}
}

func TestScanDB_NoMatch(t *testing.T) {
	path := newTestDB(t)
	rep, err := ScanDB(path, []string{"nothing-here-to-match-12345"}, 8)
	if err != nil {
		t.Fatalf("ScanDB: %v", err)
	}
	if rep.TotalHits() != 0 {
		t.Fatalf("TotalHits = %d, want 0", rep.TotalHits())
	}
}

func TestScrubDB_ReplacesAndRebuildsFTS(t *testing.T) {
	path := newTestDB(t)
	secrets := []string{"sk-supersecret1234567890", "xoxb-1234567890-abcdefghij"}

	rep, err := ScrubDB(path, secrets, 8, false)
	if err != nil {
		t.Fatalf("ScrubDB: %v", err)
	}
	if rep.TotalHits() != 2 {
		t.Fatalf("TotalHits = %d, want 2", rep.TotalHits())
	}

	// After scrub: no secrets remain in base table
	rep2, err := ScanDB(path, secrets, 8)
	if err != nil {
		t.Fatalf("re-ScanDB: %v", err)
	}
	if rep2.TotalHits() != 0 {
		t.Fatalf("secrets remain after scrub: %+v", rep2)
	}

	// FTS must be rebuilt so it no longer contains the secrets either.
	// Note: FTS5 MATCH treats '-' as a NOT operator, so query a unique
	// token of the secret instead of the full hyphenated value.
	out, err := exec.Command("sqlite3", path,
		"SELECT content FROM messages_fts WHERE messages_fts MATCH 'supersecret1234567890'").Output()
	if err != nil {
		t.Fatalf("fts query: %v", err)
	}
	if strings.Contains(string(out), "sk-supersecret1234567890") {
		t.Fatalf("FTS still contains secret: %q", out)
	}
	// And the redacted marker should be findable
	out2, err := exec.Command("sqlite3", path,
		"SELECT content FROM messages_fts WHERE messages_fts MATCH 'redacted'").Output()
	if err != nil {
		t.Fatalf("fts query redacted: %v", err)
	}
	if !strings.Contains(string(out2), "<redacted>") {
		t.Fatalf("FTS missing redacted marker: %q", out2)
	}
}

func TestScrubDB_BackupCreatesCopy(t *testing.T) {
	path := newTestDB(t)
	secrets := []string{"sk-supersecret1234567890"}

	if _, err := ScrubDB(path, secrets, 8, true); err != nil {
		t.Fatalf("ScrubDB with backup: %v", err)
	}
	if _, err := scanFile(path + ".bak"); err != nil {
		t.Fatalf("backup file not created/readable: %v", err)
	}
}

func TestScrubDB_SkipsFTSVirtualTables(t *testing.T) {
	// ScrubDB must not attempt UPDATE on virtual FTS tables directly.
	path := newTestDB(t)
	secrets := []string{"sk-supersecret1234567890"}
	if _, err := ScrubDB(path, secrets, 8, false); err != nil {
		t.Fatalf("ScrubDB should skip FTS tables cleanly: %v", err)
	}
}

func TestSecretHexEscape_QuoteSafe(t *testing.T) {
	// A secret containing a single quote must be safe in SQL.
	secret := "it's-a-secret-value-12345"
	hex := secretHex(secret)
	if !strings.HasPrefix(hex, "X'") || !strings.HasSuffix(hex, "'") {
		t.Fatalf("bad hex literal: %q", hex)
	}
	if !strings.Contains(hex, "27") { // 0x27 = '
		t.Fatalf("hex literal missing quote byte: %q", hex)
	}
	// The hex literal itself must not contain a raw quote.
	if strings.Contains(hex, "it's") {
		t.Fatalf("hex literal leaked raw secret: %q", hex)
	}
}

func TestScrubDB_ManySecretsNoParserOverflow(t *testing.T) {
	// Regression: 42 secrets nested in one UPDATE overflows SQLite's parser
	// stack ("parser stack overflow"). Per-secret UPDATEs must avoid it.
	path := newTestDB(t)
	secrets := make([]string, 42)
	for i := range secrets {
		secrets[i] = fmt.Sprintf("secret-value-%d-abcdefghijklmnop", i)
	}
	// Put one of them in the DB.
	if _, err := exec.Command("sqlite3", path,
		"INSERT INTO messages (content, role) VALUES ('leaked secret-value-7-abcdefghijklmnop here', 'user');").Output(); err != nil {
		t.Fatalf("insert: %v", err)
	}

	if _, err := ScrubDB(path, secrets, 8, false); err != nil {
		t.Fatalf("ScrubDB with 42 secrets: %v", err)
	}
	rep, err := ScanDB(path, secrets, 8)
	if err != nil {
		t.Fatalf("re-scan: %v", err)
	}
	if rep.TotalHits() != 0 {
		t.Fatalf("secrets remain: %+v", rep)
	}
}

func TestScrubDB_VacuumPurgesPhysicalRemnants(t *testing.T) {
	// Regression: SQL UPDATEs leave the old (longer) secret bytes in freed
	// pages; sqlite3.backup() copies free pages verbatim, so a backup taken
	// after scrubbing still contains secrets at the byte level. VACUUM must
	// purge them from the physical file.
	path := newTestDB(t)
	secret := "sk-vacuum-test-secret-abcdef1234567890"
	long := "prefix " + secret + " suffix padding padding padding"
	if _, err := exec.Command("sqlite3", path,
		"INSERT INTO messages (content, role) VALUES ('"+long+"', 'user');").Output(); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Verify the secret is physically present before scrubbing.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Contains(data, []byte(secret)) {
		t.Fatal("precondition failed: secret not physically present")
	}

	if _, err := ScrubDB(path, []string{secret}, 8, false); err != nil {
		t.Fatalf("ScrubDB: %v", err)
	}

	// After scrub + VACUUM, the secret must be gone from the physical file.
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("read2: %v", err)
	}
	if bytes.Contains(data, []byte(secret)) {
		t.Fatal("secret still present in physical file after VACUUM")
	}
	if !bytes.Contains(data, []byte("<redacted>")) {
		t.Fatal("marker missing in physical file")
	}
}

func TestScrubDB_SkipsFTSSShadowTablesWithAlnumSecret(t *testing.T) {
	// Regression (2026-08-10, state.db): FTS5 shadow tables (messages_fts_data
	// etc.) carry type='table' in sqlite_master with a plain CREATE TABLE
	// statement, so the old 'NOT LIKE %VIRTUAL TABLE%' filter listed them as
	// scrub targets. A purely-alphanumeric secret survives tokenization as a
	// single term and lands verbatim in the shadow block, so countHits>0 →
	// UPDATE issued → SQLite rejects it ("table messages_fts_data may not be
	// modified"). listTables must exclude type='shadow' via PRAGMA table_list.
	dir := t.TempDir()
	path := dir + "/test.db"
	sql := `
CREATE TABLE messages (id INTEGER PRIMARY KEY, content TEXT, role TEXT);
INSERT INTO messages (content, role) VALUES ('leak supersecretvalue123456 end', 'user');
CREATE VIRTUAL TABLE messages_fts USING fts5(content, content='messages', content_rowid='id');
INSERT INTO messages_fts(messages_fts) VALUES('rebuild');
`
	if err := exec.Command("sqlite3", path, sql).Run(); err != nil {
		t.Fatalf("create test db: %v", err)
	}
	// Precondition: the alnum secret must be present in the shadow table,
	// otherwise this test does not reproduce the original failure.
	out, err := exec.Command("sqlite3", path,
		"SELECT COUNT(*) FROM messages_fts_data WHERE instr(block, X'737570657273656372657476616c7565313233343536') > 0;").Output()
	if err != nil {
		t.Fatalf("shadow precondition query: %v", err)
	}
	if strings.TrimSpace(string(out)) == "0" {
		t.Fatal("precondition failed: alnum secret not in shadow table")
	}

	secrets := []string{"supersecretvalue123456"}
	rep, err := ScrubDB(path, secrets, 8, false)
	if err != nil {
		t.Fatalf("ScrubDB with shadow-table hits must succeed: %v", err)
	}
	if rep.TotalHits() != 1 {
		t.Fatalf("TotalHits = %d, want 1 (got %+v)", rep.TotalHits(), rep)
	}
	// Base table scrubbed, FTS rebuilt so the term is gone from the index.
	rep2, err := ScanDB(path, secrets, 8)
	if err != nil {
		t.Fatalf("re-ScanDB: %v", err)
	}
	if rep2.TotalHits() != 0 {
		t.Fatalf("secrets remain after scrub: %+v", rep2)
	}
}
