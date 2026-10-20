package scrub

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/ikkun1222/trustless/internal/dlp/redact"
)

// newTestDB creates a temp SQLite DB with a messages-like table (content
// column, FTS5 external-content index) and returns its path.
func newTestDB(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/test.db"

	sql := fmt.Sprintf(`
CREATE TABLE messages (id INTEGER PRIMARY KEY, content TEXT, role TEXT);
INSERT INTO messages (content, role) VALUES ('my key is sk-supersecret1234567890 ok', 'user');
INSERT INTO messages (content, role) VALUES ('hello world', 'user');
INSERT INTO messages (content, role) VALUES ('token xoxb-1234567890-abcdefghij end', 'user');
INSERT INTO messages (content, role) VALUES ('oai %s end', 'user');
CREATE VIRTUAL TABLE messages_fts USING fts5(content, content='messages', content_rowid='id');
INSERT INTO messages_fts(messages_fts) VALUES('rebuild');
`, openaiDummy(t))
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

// loadBundledPatterns returns the bundled pattern set for pattern-layer tests.
func loadBundledPatterns(t *testing.T) *redact.PatternSet {
	t.Helper()
	ps, err := redact.DefaultPatterns()
	if err != nil {
		t.Fatalf("DefaultPatterns: %v", err)
	}
	return ps
}

// openaiDummy は bundled の openai-api-key ルール（sk-proj-{58}T3BlbkFJ{58}・entropy 3）に
// 一致するダミーキー。固定シードで決定論的に生成する（パターン層テスト用）。
func openaiDummy(t *testing.T) string {
	t.Helper()
	r := rand.New(rand.NewSource(42))
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	rnd := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = chars[r.Intn(len(chars))]
		}
		return string(b)
	}
	return "sk-proj-" + rnd(58) + "T3BlbkFJ" + rnd(58)
}

// TestScanDBPatterns_DetectsPatternHit verifies the pattern dry-run detects
// a slack-bot-token shaped value that is not a known secret.
func TestScanDBPatterns_DetectsPatternHit(t *testing.T) {
	path := newTestDB(t)
	patterns := loadBundledPatterns(t)

	rep, err := ScanDBPatterns(path, nil, 8, patterns, true)
	if err != nil {
		t.Fatalf("ScanDBPatterns: %v", err)
	}
	if rep.TotalHits() != 1 {
		t.Fatalf("TotalHits = %d, want 1 (got %+v)", rep.TotalHits(), rep)
	}
	if mc := rep.TableHits("messages", "content"); mc != 1 {
		t.Fatalf("messages.content hits = %d, want 1", mc)
	}
}

// TestScrubDBPatterns_MasksPatternAndRebuildsFTS verifies --apply masks
// pattern matches and rebuilds the FTS index.
func TestScrubDBPatterns_MasksPatternAndRebuildsFTS(t *testing.T) {
	path := newTestDB(t)
	patterns := loadBundledPatterns(t)

	rep, err := ScrubDBPatterns(path, nil, 8, patterns, true, false)
	if err != nil {
		t.Fatalf("ScrubDBPatterns: %v", err)
	}
	if rep.TotalHits() != 1 {
		t.Fatalf("TotalHits = %d, want 1", rep.TotalHits())
	}
	if len(rep.FTSRebuilt) != 1 {
		t.Fatalf("FTSRebuilt = %v, want 1 table", rep.FTSRebuilt)
	}

	// The pattern must be gone from the base table.
	dummy := openaiDummy(t)
	out, err := exec.Command("sqlite3", path,
		"SELECT content FROM messages WHERE id=4").Output()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(out), dummy) {
		t.Fatalf("pattern remains after scrub: %q", out)
	}
	if !strings.Contains(string(out), "<redacted>") {
		t.Fatalf("marker missing after scrub: %q", out)
	}

	// FTS rebuilt: the original pattern value must not be served by the index.
	out2, err := exec.Command("sqlite3", path,
		"SELECT content FROM messages_fts").Output()
	if err != nil {
		t.Fatalf("fts query: %v", err)
	}
	if strings.Contains(string(out2), dummy) {
		t.Fatalf("FTS still contains pattern: %q", out2)
	}
}

// TestScrubDBPatterns_LogModeCountsWithoutMasking verifies pattern_mode:
// "log": pattern hits are counted but the value stays; known values are
// still masked.
func TestScrubDBPatterns_LogModeCountsWithoutMasking(t *testing.T) {
	path := newTestDB(t)
	patterns := loadBundledPatterns(t)
	secret := "sk-supersecret1234567890"

	rep, err := ScrubDBPatterns(path, []string{secret}, 8, patterns, false, false)
	if err != nil {
		t.Fatalf("ScrubDBPatterns: %v", err)
	}
	if rep.TotalHits() != 2 {
		t.Fatalf("TotalHits = %d, want 2 (known value + pattern) tables=%+v", rep.TotalHits(), rep.Tables)
	}

	// Known value masked; pattern left intact.
	out, err := exec.Command("sqlite3", path,
		"SELECT content FROM messages WHERE id=1").Output()
	if err != nil {
		t.Fatalf("read id=1: %v", err)
	}
	if strings.Contains(string(out), secret) {
		t.Fatalf("known value not masked in log mode: %q", out)
	}
	out2, err := exec.Command("sqlite3", path,
		"SELECT content FROM messages WHERE id=4").Output()
	if err != nil {
		t.Fatalf("read id=4: %v", err)
	}
	if !strings.Contains(string(out2), openaiDummy(t)) {
		t.Fatalf("pattern was masked in log mode: %q", out2)
	}
}

// TestScrubDBPatterns_Backup verifies the .bak copy is created.
func TestScrubDBPatterns_Backup(t *testing.T) {
	path := newTestDB(t)
	patterns := loadBundledPatterns(t)

	if _, err := ScrubDBPatterns(path, nil, 8, patterns, true, true); err != nil {
		t.Fatalf("ScrubDBPatterns with backup: %v", err)
	}
	if _, err := scanFile(path + ".bak"); err != nil {
		t.Fatalf("backup file not created/readable: %v", err)
	}
}

// TestScrubDBPatterns_NonTextColumnSkipped verifies numeric columns are not
// scanned by the row-based path.
func TestScrubDBPatterns_NonTextColumnSkipped(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.db"
	sql := fmt.Sprintf(`
CREATE TABLE t (id INTEGER PRIMARY KEY, n INTEGER, content TEXT);
INSERT INTO t (n, content) VALUES (12345, 'oai %s end');
`, openaiDummy(t))
	if err := exec.Command("sqlite3", path, sql).Run(); err != nil {
		t.Fatalf("create test db: %v", err)
	}
	patterns := loadBundledPatterns(t)

	rep, err := ScanDBPatterns(path, nil, 8, patterns, true)
	if err != nil {
		t.Fatalf("ScanDBPatterns: %v", err)
	}
	if rep.TotalHits() != 1 {
		t.Fatalf("TotalHits = %d, want 1 (only content scanned)", rep.TotalHits())
	}
	if rep.TableHits("t", "n") != 0 {
		t.Fatalf("numeric column was scanned: %+v", rep.Tables)
	}
}

// TestScrubDBPatterns_LargeRowValue guards the daily scrub-history failure
// first seen 2026-09-12: a rewritten value is hex-encoded inside its UPDATE
// statement, so a row over 64 KiB produced an argv entry over Linux's 128 KiB
// MAX_ARG_STRLEN and the sqlite3 child died with E2BIG ("argument list too
// long") — aborting the run before messages.content was scrubbed at all.
func TestScrubDBPatterns_LargeRowValue(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.db"
	dummy := openaiDummy(t)
	val := strings.Repeat("a", 80*1024) + " token=" + dummy + " " + strings.Repeat("b", 80*1024)
	wantLen := len(val) - len(dummy) + len(Marker)

	// The seed statement is itself >128 KiB, so it goes in on stdin too.
	cmd := exec.Command("sqlite3", path)
	cmd.Stdin = strings.NewReader(fmt.Sprintf(
		"CREATE TABLE big (id INTEGER PRIMARY KEY, content TEXT);\nINSERT INTO big (content) VALUES ('%s');\n", val))
	if err := cmd.Run(); err != nil {
		t.Fatalf("create test db: %v", err)
	}

	rep, err := ScrubDBPatterns(path, nil, 8, loadBundledPatterns(t), true, false)
	if err != nil {
		t.Fatalf("ScrubDBPatterns with a 400 KiB row: %v", err)
	}
	if got := rep.TableHits("big", "content"); got != 1 {
		t.Fatalf("big.content hits = %d, want 1 (%+v)", got, rep.Tables)
	}
	out, err := exec.Command("sqlite3", path, fmt.Sprintf(
		"SELECT length(content), instr(content,'%s'), instr(content,'%s') FROM big;", Marker, dummy)).Output()
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	got := strings.Split(strings.TrimSpace(string(out)), "|")
	if len(got) != 3 || got[0] != strconv.Itoa(wantLen) || got[1] == "0" || got[2] != "0" {
		t.Fatalf("row not masked as expected: length/marker/leftover = %q (want %d/marker/none)", out, wantLen)
	}
}

// TestScrubDBPatterns_ManyRows covers the batched rewrite replay: changed rows
// are appended to a temp SQL file and replayed by one sqlite3 process on
// stdin once the scan finishes, instead of one process per row.
func TestScrubDBPatterns_ManyRows(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.db"
	dummy := openaiDummy(t)
	const rows = 500

	var seed strings.Builder
	seed.WriteString("CREATE TABLE many (id INTEGER PRIMARY KEY, content TEXT);\n")
	for i := 0; i < rows; i++ {
		fmt.Fprintf(&seed, "INSERT INTO many (content) VALUES ('row %d %s');\n", i, dummy)
	}
	cmd := exec.Command("sqlite3", path)
	cmd.Stdin = strings.NewReader(seed.String())
	if err := cmd.Run(); err != nil {
		t.Fatalf("create test db: %v", err)
	}

	before := updateTempFiles(t)
	rep, err := ScrubDBPatterns(path, nil, 8, loadBundledPatterns(t), true, false)
	if err != nil {
		t.Fatalf("ScrubDBPatterns: %v", err)
	}
	if got := rep.TableHits("many", "content"); got != rows {
		t.Fatalf("many.content hits = %d, want %d", got, rows)
	}
	out, err := exec.Command("sqlite3", path, fmt.Sprintf(
		"SELECT (SELECT COUNT(*) FROM many WHERE instr(content,'%s')>0), (SELECT COUNT(*) FROM many WHERE instr(content,'%s')>0);",
		Marker, dummy)).Output()
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != fmt.Sprintf("%d|0", rows) {
		t.Fatalf("masked/leftover row counts = %q, want %d|0", got, rows)
	}

	// The rewrite temp file must not survive this run. Compared against the
	// set that existed beforehand: /tmp is shared, so a leftover from an
	// unrelated (e.g. killed) run must not fail this test.
	for name := range updateTempFiles(t) {
		if !before[name] {
			t.Fatalf("leaked update temp file: %s", name)
		}
	}
}

// TestScrubDBPatterns_SkipsSQLiteManagedTables guards the abort that left every
// table sorting after sqlite_schema unscrubbed: SQLite refuses direct writes to
// sqlite_schema ("may not be modified") and the -bail batch stopped there, so
// tables later in the alphabet (system_prompts) were never scanned.
func TestScrubDBPatterns_SkipsSQLiteManagedTables(t *testing.T) {
	path := t.TempDir() + "/test.db"
	const ddlKey = "api_key=abcdef1234567890abcdef"

	// The DDL itself carries a pattern hit: the pattern layer matches the
	// literal in the CHECK clause, but that text lives in sqlite_schema.sql,
	// which SQLite will not let us rewrite.
	seed := "CREATE TABLE ddl_meta (id INTEGER PRIMARY KEY, owner TEXT CHECK (owner <> '" + ddlKey + "'));\n" +
		"CREATE TABLE zz_notes (id INTEGER PRIMARY KEY, body TEXT);\n" +
		"INSERT INTO zz_notes (body) VALUES ('dump " + ddlKey + " now');\n"
	cmd := exec.Command("sqlite3", path)
	cmd.Stdin = strings.NewReader(seed)
	if err := cmd.Run(); err != nil {
		t.Fatalf("create test db: %v", err)
	}

	// Precondition: this fixture only covers the abort path if the pattern
	// layer really matches the text sitting in sqlite_schema.sql.
	ddl, err := exec.Command("sqlite3", path,
		"SELECT sql FROM sqlite_schema WHERE name='ddl_meta';").Output()
	if err != nil {
		t.Fatalf("read ddl: %v", err)
	}
	patterns := loadBundledPatterns(t)
	if _, changed := patterns.Scan(string(ddl)); !changed {
		t.Fatalf("fixture does not exercise the DDL case (no pattern match in %q)", strings.TrimSpace(string(ddl)))
	}

	rep, err := ScrubDBPatterns(path, nil, 8, patterns, true, false)
	if err != nil {
		t.Fatalf("ScrubDBPatterns: %v", err)
	}
	if n := rep.TableHits("sqlite_schema", "sql"); n != 0 {
		t.Fatalf("sqlite_schema.sql hits = %d, want 0 (SQLite-managed tables are excluded)", n)
	}
	if got := rep.TableHits("zz_notes", "body"); got != 1 {
		t.Fatalf("zz_notes.body hits = %d, want 1 (a table sorting after sqlite_schema must still be scrubbed)", got)
	}
	out, err := exec.Command("sqlite3", path, "SELECT body FROM zz_notes;").Output()
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if strings.Contains(string(out), ddlKey) {
		t.Fatalf("pattern hit survived the scrub: %q", strings.TrimSpace(string(out)))
	}
}

// updateTempFiles returns the set of rewrite temp files currently in /tmp.
func updateTempFiles(t *testing.T) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(os.TempDir())
	if err != nil {
		t.Fatalf("read temp dir: %v", err)
	}
	out := map[string]bool{}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "trustless-scrub-updates-") {
			out[e.Name()] = true
		}
	}
	return out
}

// TestCopyFile_StreamsInsteadOfBuffering guards the --backup path. copyFile used
// os.ReadFile, so every backup held the whole database in memory (opencode.db:
// 1.9 GB RSS). The bound is checked against cumulative allocations, which no GC
// can hide.
func TestCopyFile_StreamsInsteadOfBuffering(t *testing.T) {
	const size = 32 << 20
	dir := t.TempDir()
	src := dir + "/big.bin"
	f, err := os.Create(src)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	chunk := make([]byte, 1<<20)
	for i := range chunk {
		chunk[i] = byte(i % 251)
	}
	for i := 0; i < size/(1<<20); i++ {
		if _, err := f.Write(chunk); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	if err := copyFile(src, src+".bak"); err != nil {
		t.Fatalf("copyFile: %v", err)
	}
	runtime.ReadMemStats(&after)
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 8<<20 {
		t.Fatalf("copyFile allocated %d bytes for a %d MiB input: it must stream, not buffer the whole file",
			alloc, size>>20)
	}

	st, err := os.Stat(src + ".bak")
	if err != nil || st.Size() != size {
		t.Fatalf("backup stat = %v (err %v), want %d bytes", st, err, size)
	}
	want, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read src: %v", err)
	}
	got, err := os.ReadFile(src + ".bak")
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if !bytes.Equal(want, got) {
		t.Fatal("backup content differs from source")
	}
}

// TestScrubDBPatterns_SkipsOversizedValues guards the scan-size limit: a value
// beyond maxScanValue must be skipped and counted, not abort the run. A 51 MiB
// message.data row in opencode.db used to end a 13-minute scrub with
// "bufio.Scanner: token too long", so every other table lost its scrub too.
func TestScrubDBPatterns_SkipsOversizedValues(t *testing.T) {
	old := maxScanValue
	maxScanValue = 4096
	t.Cleanup(func() { maxScanValue = old })

	path := t.TempDir() + "/test.db"
	const pattern = "api_key=abcdef1234567890abcdef"
	small := "small row with " + pattern
	huge := strings.Repeat("x", 5000) + " " + pattern

	run := func(sql string) {
		cmd := exec.Command("sqlite3", path)
		cmd.Stdin = strings.NewReader(sql)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("sqlite3 %q: %v: %s", sql, err, out)
		}
	}
	run(`CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT);`)
	run(`INSERT INTO notes (body) VALUES ('` + small + `');`)
	run(`INSERT INTO notes (body) VALUES ('` + huge + `');`)

	rep, err := ScrubDBPatterns(path, nil, 8, loadBundledPatterns(t), true, false)
	if err != nil {
		t.Fatalf("ScrubDBPatterns: %v", err)
	}
	if rep.Oversized != 1 {
		t.Fatalf("oversized = %d, want 1 (only the 5 kB row is over the 4 kB limit)", rep.Oversized)
	}
	if n := rep.TableHits("notes", "body"); n != 1 {
		t.Fatalf("notes.body hits = %d, want 1", n)
	}
	got, err := exec.Command("sqlite3", path, "SELECT body FROM notes ORDER BY id;").Output()
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(got)), "\n")
	if len(lines) != 2 {
		t.Fatalf("rows = %d, want 2: %q", len(lines), got)
	}
	if strings.Contains(lines[0], pattern) {
		t.Fatalf("small row was not scrubbed: %q", lines[0])
	}
	if !strings.Contains(lines[1], pattern) {
		t.Fatalf("oversized row must be left untouched (only counted), got %q", lines[1][:60])
	}
}

// sqliteQuery は sqlite3 CLI で 1 クエリを実行し、末尾改行を落として返す。
func sqliteQuery(t *testing.T, path, q string) string {
	t.Helper()
	out, err := exec.Command("sqlite3", path, q).Output()
	if err != nil {
		t.Fatalf("sqlite3 %s: %v", q, err)
	}
	return strings.TrimRight(string(out), "\n")
}

// TestScrubDBPatterns_PreservesStorageClass は、パターン層の書き戻しが行の
// 型を変えないことを検証する。書き戻しに使っていた X'..' リテラルは SQLite
// では BLOB なので、TEXT 行が blob 化していた（state.db の
// messages.content / system_prompts.prompt、bizmeshi.db の shops.details が
// 実際に壊れた）。TEXT は TEXT のまま、BLOB は BLOB のまま書き戻すこと。
func TestScrubDBPatterns_PreservesStorageClass(t *testing.T) {
	path := newTestDB(t)
	dummy := openaiDummy(t)
	ddl := fmt.Sprintf(`CREATE TABLE keep(id INTEGER PRIMARY KEY, txt TEXT, bin BLOB);
INSERT INTO keep VALUES(1, 'a %s b', CAST('a %s b' AS BLOB));`, dummy, dummy)
	if out, err := exec.Command("sqlite3", path, ddl).CombinedOutput(); err != nil {
		t.Fatalf("fixture: %v: %s", err, out)
	}
	if _, err := ScrubDBPatterns(path, nil, 8, loadBundledPatterns(t), true, false); err != nil {
		t.Fatalf("ScrubDBPatterns: %v", err)
	}
	got := sqliteQuery(t, path,
		`SELECT typeof(txt), txt, typeof(bin), CAST(bin AS TEXT) FROM keep WHERE id=1;`)
	want := "text|a <redacted> b|blob|a <redacted> b"
	if got != want {
		t.Fatalf("storage class mangled:\n got %q\nwant %q", got, want)
	}
}

// testQuoteIdent / testQuoteLiteral are independent fixture helpers: the
// regression tests must be able to create malicious schema on the unfixed
// code, so they cannot depend on the production quoting functions they guard.
func testQuoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

func testQuoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// sqlCharExpr encodes an ASCII string as a SQLite char() expression, so a
// payload can name an absolute path without embedding quote characters.
func sqlCharExpr(s string) string {
	parts := make([]string, 0, len(s))
	for _, b := range []byte(s) {
		parts = append(parts, strconv.Itoa(int(b)))
	}
	return "char(" + strings.Join(parts, ",") + ")"
}

// runSQLFile executes SQL against path through the sqlite3 CLI on stdin.
func runSQLFile(t *testing.T, path, sql string) {
	t.Helper()
	cmd := exec.Command("sqlite3", path)
	cmd.Stdin = strings.NewReader(sql)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sqlite3 fixture: %v: %s", err, out)
	}
}

// TestScanDBPatterns_ColumnNameInjectionDoesNotWriteFile guards the confirmed
// audit finding: a hostile column name was interpolated into SQL, so the
// pattern dry-run executed writefile() and created an arbitrary file. The
// column must be quoted as an identifier and the whole table still scanned.
func TestScanDBPatterns_ColumnNameInjectionDoesNotWriteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "attack.db")
	attackFile := filepath.Join(dir, "pwned")
	dummy := openaiDummy(t)

	col := `c" ) LIMIT 1; SELECT writefile(` + sqlCharExpr(attackFile) + `, 'CLI'); --`
	runSQLFile(t, path, fmt.Sprintf(`CREATE TABLE t (id INTEGER PRIMARY KEY, %s TEXT);
INSERT INTO t (id, %s) VALUES (1, '%s');`,
		testQuoteIdent(col), testQuoteIdent(col), dummy))

	rep, err := ScanDBPatterns(path, nil, 8, loadBundledPatterns(t), true)
	if _, statErr := os.Stat(attackFile); statErr == nil {
		t.Fatalf("column-name injection executed writefile: %s was created", attackFile)
	}
	if err != nil {
		t.Fatalf("ScanDBPatterns on a quoted identifier: %v", err)
	}
	if got := rep.TableHits("t", col); got != 1 {
		t.Fatalf("attack table was not scanned: %v", rep.Tables)
	}
}

// TestScanDB_TableNameInjectionDoesNotAttach guards the same finding for the
// table name: a payload ending the PRAGMA literal used to run ATTACH and
// CREATE TABLE in the target file.
func TestScanDB_TableNameInjectionDoesNotAttach(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "attack.db")
	evil := filepath.Join(dir, "evil.db")
	secret := "sk-table-injection-1234567890"

	tbl := `x'); ATTACH DATABASE '` + evil + `' AS e; CREATE TABLE e.t(v); --`
	runSQLFile(t, path, fmt.Sprintf(`CREATE TABLE %s (id INTEGER PRIMARY KEY, content TEXT);
INSERT INTO %s (id, content) VALUES (1, '%s');`,
		testQuoteIdent(tbl), testQuoteIdent(tbl), secret))

	rep, err := ScanDB(path, []string{secret}, 8)
	if _, statErr := os.Stat(evil); statErr == nil {
		t.Fatalf("table-name injection executed ATTACH: %s was created", evil)
	}
	if err != nil {
		t.Fatalf("ScanDB on a quoted identifier: %v", err)
	}
	if got := rep.TableHits(tbl, "content"); got != 1 {
		t.Fatalf("attack table was not scanned: %v", rep.Tables)
	}
}

// TestScrubDBPatterns_MixedColumnWithNumericFirstRow は、先頭行が数値の列に
// ある TEXT の秘密も走査・マスクされることを検証する。旧 isTextColumn は
// 先頭行の typeof だけで列ごと除外していたため、こうした行は素通りしていた。
func TestScrubDBPatterns_MixedColumnWithNumericFirstRow(t *testing.T) {
	path := newTestDB(t)
	dummy := openaiDummy(t)
	ddl := fmt.Sprintf(`CREATE TABLE mixed(id INTEGER PRIMARY KEY, v);
INSERT INTO mixed VALUES(1, 7);
INSERT INTO mixed VALUES(2, 'k %s');`, dummy)
	if out, err := exec.Command("sqlite3", path, ddl).CombinedOutput(); err != nil {
		t.Fatalf("fixture: %v: %s", err, out)
	}
	if _, err := ScrubDBPatterns(path, nil, 8, loadBundledPatterns(t), true, false); err != nil {
		t.Fatalf("ScrubDBPatterns: %v", err)
	}
	got := sqliteQuery(t, path, `SELECT id, typeof(v), CAST(v AS TEXT) FROM mixed ORDER BY id;`)
	want := "1|integer|7\n2|text|k <redacted>"
	if got != want {
		t.Fatalf("mixed column:\n got %q\nwant %q", got, want)
	}
}
