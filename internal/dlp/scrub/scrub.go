// Package scrub scans SQLite databases (Hermes state.db, opencode.db) for
// known secret values and replaces them with the <redacted> marker. It is
// the backfill/audit counterpart to the outbound DLP proxy: secrets that
// already leaked into local conversation history before the proxy existed
// are scrubbed in place, and FTS5 indexes are rebuilt.
//
// Implementation uses the system sqlite3 CLI (zero Go dependencies, same
// pattern as passstore's pass CLI). SQL travels on the child's stdin and
// secrets appear only as hex literals (X'...'), so neither quote characters
// nor argument-length limits (MAX_ARG_STRLEN = 128 KiB per argv entry) can
// break a statement.
package scrub

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/ikkun1222/trustless/internal/dlp/redact"
)

// Marker is the replacement text, matching the proxy's redact.Marker.
const Marker = "<redacted>"

// Report holds per-table, per-column hit counts.
type Report struct {
	// Tables maps "table.column" -> hit count.
	Tables map[string]int
	// FTSRebuilt lists FTS5 virtual tables that were rebuilt.
	FTSRebuilt []string
}

// NewReport returns an empty report.
func NewReport() *Report {
	return &Report{Tables: map[string]int{}}
}

// TotalHits sums all column hits.
func (r *Report) TotalHits() int {
	n := 0
	for _, c := range r.Tables {
		n += c
	}
	return n
}

// TableHits returns hits for a specific table.column, or 0.
func (r *Report) TableHits(table, col string) int {
	return r.Tables[table+"."+col]
}

// secretHex encodes a secret as a SQLite blob literal (X'...').
func secretHex(secret string) string {
	return "X'" + hex.EncodeToString([]byte(secret)) + "'"
}

// sqlite runs the sqlite3 CLI against path with the given SQL, returning
// combined stdout/stderr. A generous busy_timeout lets concurrent Hermes
// processes (the gateway or an active CLI session) release their locks
// instead of failing immediately with "database is locked".
//
// The SQL is fed on stdin rather than as argv: Linux caps a single argument
// at MAX_ARG_STRLEN (128 KiB), and a row-rewrite UPDATE carries the value
// hex-encoded, so any row larger than 64 KiB failed with E2BIG ("argument
// list too long") and aborted the whole run. -bail keeps the argv form's
// fail-fast semantics (plain stdin mode logs an error and carries on).
func sqlite(path string, sql string) (string, error) {
	return sqliteStdin(path, strings.NewReader(sql+"\n"))
}

// sqliteStdin is sqlite() with the SQL streamed from r, so statements of
// unbounded size (a batched UPDATE replay) can be passed without argv limits.
func sqliteStdin(path string, r io.Reader) (string, error) {
	cmd := exec.Command("sqlite3", "-batch", "-bail", "-cmd", ".timeout 30000", path)
	cmd.Stdin = r
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("sqlite3: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// sqliteEachRow runs a SELECT through the sqlite3 CLI and hands each stdout
// line to fn as it arrives. sqlite() buffers the entire result, which costs
// 2x the column size for a hex-encoded scan (opencode.db reached 5.9 GB RSS
// and would have been OOM-killed on the 11 GB host).
func sqliteEachRow(path, sql string, fn func(line string) error) error {
	cmd := exec.Command("sqlite3", "-batch", "-bail", "-cmd", ".timeout 30000", path)
	cmd.Stdin = strings.NewReader(sql + "\n")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("sqlite3: %w", err)
	}
	var errBuf strings.Builder
	cmd.Stderr = &errBuf
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("sqlite3: %w", err)
	}
	sc := bufio.NewScanner(stdout)
	// One row per line, hex-encoded: 64 MiB is far above any row we ship
	// (the 64 KiB default would trip on a 32 KiB value).
	sc.Buffer(make([]byte, 0, 1<<16), 1<<26)
	var fnErr error
	for sc.Scan() {
		if fnErr = fn(sc.Text()); fnErr != nil {
			break
		}
	}
	if fnErr == nil {
		fnErr = sc.Err()
	}
	if fnErr != nil {
		// fn bailed out: the child may be blocked writing to a full pipe.
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if fnErr != nil {
		return fnErr
	}
	if waitErr != nil {
		return fmt.Errorf("sqlite3: %w: %s", waitErr, strings.TrimSpace(errBuf.String()))
	}
	return nil
}

// listTables returns real base-table names. FTS5 virtual tables AND their
// shadow tables (messages_fts_data / _idx / _docsize / _config) are excluded:
// the virtual table's content columns mirror the base table (handled via
// rebuild after scrubbing), and shadow tables must never be modified
// directly — SQLite rejects UPDATEs on them ("may not be modified").
// PRAGMA table_list is used because shadow tables carry the sqlite_master
// type='table' marker with a plain CREATE TABLE statement, so the old
// 'NOT LIKE %VIRTUAL TABLE%' filter let them through.
//
// The SQLite-managed sqlite_* family (schema/sequence/stat) is excluded too:
// SQLite refuses direct writes to it ("table sqlite_master may not be
// modified"), and because the rewrite batch replays with -bail that error
// aborted the whole run — every table after sqlite_schema (by name) stayed
// unscrubbed. Its content is DDL/bookkeeping, which this tool cannot rewrite,
// so it is out of scope by design instead of a hit that never clears.
func listTables(path string) ([]string, error) {
	out, err := sqlite(path, "SELECT name FROM pragma_table_list WHERE type='table' AND schema='main' AND name NOT LIKE 'sqlite_%' ORDER BY name;")
	if err != nil {
		return nil, err
	}
	var tables []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line != "" {
			tables = append(tables, line)
		}
	}
	return tables, nil
}

// listColumns returns column names for a table.
func listColumns(path, table string) ([]string, error) {
	out, err := sqlite(path, fmt.Sprintf("PRAGMA table_info('%s');", table))
	if err != nil {
		return nil, err
	}
	var cols []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		// PRAGMA table_info: cid|name|type|notnull|dflt|pk
		parts := strings.Split(line, "|")
		if len(parts) >= 2 {
			cols = append(cols, parts[1])
		}
	}
	return cols, nil
}

// listFTS returns FTS5 virtual table names (those whose SQL contains fts5).
func listFTS(path string) ([]string, error) {
	out, err := sqlite(path, "SELECT name FROM sqlite_master WHERE sql LIKE '%fts5%' ORDER BY name;")
	if err != nil {
		return nil, err
	}
	var fts []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line != "" {
			fts = append(fts, line)
		}
	}
	return fts, nil
}

// scanColumns returns the text-ish columns of a table: TEXT and untyped
// (declared with no type, which SQLite treats as TEXT affinity) columns.
// Used to decide which columns to scan in the row-based pattern path.
func scanColumns(path, table string) ([]string, error) {
	cols, err := listColumns(path, table)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(cols))
	for _, c := range cols {
		if isTextColumn(path, table, c) {
			out = append(out, c)
		}
	}
	return out, nil
}

// isTextColumn reports whether col in table is a text-like column.
func isTextColumn(path, table, col string) bool {
	out, err := sqlite(path, fmt.Sprintf("SELECT typeof(\"%s\") FROM \"%s\" LIMIT 1;", col, table))
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) == "text"
}

// countHits counts rows in table.column containing any secret.
func countHits(path, table, col string, secrets []string, minLen int) (int, error) {
	conds := make([]string, 0, len(secrets))
	for _, s := range secrets {
		if len(s) < minLen {
			continue
		}
		conds = append(conds, fmt.Sprintf("instr(\"%s\", %s) > 0", col, secretHex(s)))
	}
	if len(conds) == 0 {
		return 0, nil
	}
	q := fmt.Sprintf("SELECT COUNT(*) FROM \"%s\" WHERE %s;", table, strings.Join(conds, " OR "))
	out, err := sqlite(path, q)
	if err != nil {
		return 0, err
	}
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(out), "%d", &n); err != nil {
		return 0, fmt.Errorf("parse count %q: %w", out, err)
	}
	return n, nil
}

// ScanDB reads path and reports how many rows in each text column contain
// any secret (length >= minLen). Read-only; nothing is modified.
func ScanDB(path string, secrets []string, minLen int) (*Report, error) {
	rep := NewReport()
	tables, err := listTables(path)
	if err != nil {
		return nil, err
	}
	for _, t := range tables {
		cols, err := listColumns(path, t)
		if err != nil {
			return nil, err
		}
		for _, c := range cols {
			n, err := countHits(path, t, c, secrets, minLen)
			if err != nil {
				return nil, fmt.Errorf("%s.%s: %w", t, c, err)
			}
			if n > 0 {
				rep.Tables[t+"."+c] = n
			}
		}
	}
	return rep, nil
}

// ScrubDB replaces every occurrence of any secret (length >= minLen) in
// every text column with <redacted>, then rebuilds FTS5 indexes. If backup
// is true, a .bak copy of the DB is made first. Returns hit counts.
func ScrubDB(path string, secrets []string, minLen int, backup bool) (*Report, error) {
	if backup {
		if err := copyFile(path, path+".bak"); err != nil {
			return nil, fmt.Errorf("backup: %w", err)
		}
	}

	rep := NewReport()
	tables, err := listTables(path)
	if err != nil {
		return nil, err
	}

	for _, t := range tables {
		cols, err := listColumns(path, t)
		if err != nil {
			return nil, err
		}
		for _, c := range cols {
			n, err := scrubColumn(path, t, c, secrets, minLen)
			if err != nil {
				return nil, fmt.Errorf("%s.%s: %w", t, c, err)
			}
			if n > 0 {
				rep.Tables[t+"."+c] = n
			}
		}
	}

	// Rebuild FTS5 indexes so they no longer serve scrubbed secrets.
	fts, err := listFTS(path)
	if err != nil {
		return nil, err
	}
	for _, f := range fts {
		if _, err := sqlite(path, fmt.Sprintf("INSERT INTO \"%s\"(\"%s\") VALUES('rebuild');", f, f)); err != nil {
			return nil, fmt.Errorf("fts rebuild %s: %w", f, err)
		}
		rep.FTSRebuilt = append(rep.FTSRebuilt, f)
	}
	sort.Strings(rep.FTSRebuilt)

	// VACUUM to purge physical remnants: SQL UPDATEs leave the old (longer)
	// secret bytes in freed pages, and sqlite3.backup() copies free pages
	// verbatim — so a backup taken after scrubbing would still contain the
	// secrets at the byte level. Rebuilding the DB file drops them entirely.
	// Only run when something was actually replaced: with zero hits there is
	// no new remnant (the previous VACUUM already purged the last batch),
	// and VACUUM on a multi-GB DB costs minutes.
	if rep.TotalHits() > 0 {
		if _, err := sqlite(path, "VACUUM;"); err != nil {
			return nil, fmt.Errorf("vacuum: %w", err)
		}
	}

	return rep, nil
}

// scrubColumn replaces secrets in one column, returning the number of rows
// that contained at least one secret. Each secret gets its own UPDATE
// statement: nesting 40+ replace() calls in a single expression overflows
// SQLite's parser stack (observed with 42 secrets), and per-secret UPDATEs
// keep every statement trivially simple. <redacted> is never a substring of
// a real secret, so ordering between statements is irrelevant.
func scrubColumn(path, table, col string, secrets []string, minLen int) (int, error) {
	n, err := countHits(path, table, col, secrets, minLen)
	if err != nil || n == 0 {
		return n, err
	}
	for _, s := range secrets {
		if len(s) < minLen {
			continue
		}
		q := fmt.Sprintf(
			"UPDATE \"%s\" SET \"%s\" = replace(\"%s\", %s, '%s') WHERE instr(\"%s\", %s) > 0;",
			table, col, col, secretHex(s), Marker, col, secretHex(s),
		)
		if _, err := sqlite(path, q); err != nil {
			return 0, err
		}
	}
	return n, nil
}

// copyFile streams src to dst (used for the pre-scrub backup). The previous
// os.ReadFile/os.WriteFile pair held the whole file in memory: --backup on
// opencode.db (1.9 GB) pushed RSS above 2.4 GB on every daily run, an OOM risk
// on the 11 GB host.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// scanFile stat-checks a path exists (helper for tests).
func scanFile(path string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d", st.Size()), nil
}

// ScanDBPatterns is the pattern-layer dry-run: every text column is read
// row by row and each value is scanned with the known-value layer and the
// pattern layer (redact.ScanAll). When maskPatterns is false (pattern_mode:
// "log") the pattern layer only counts detections; known-value hits are
// still counted (and would be applied by ScrubDBPatterns). Read-only;
// nothing is modified.
func ScanDBPatterns(path string, secrets []string, minLen int, patterns *redact.PatternSet, maskPatterns bool) (*Report, error) {
	rep := NewReport()
	tables, err := listTables(path)
	if err != nil {
		return nil, err
	}
	for _, t := range tables {
		cols, err := scanColumns(path, t)
		if err != nil {
			return nil, err
		}
		for _, c := range cols {
			n, err := scanColumnRows(path, t, c, secrets, minLen, patterns, maskPatterns, false)
			if err != nil {
				return nil, fmt.Errorf("%s.%s: %w", t, c, err)
			}
			if n > 0 {
				rep.Tables[t+"."+c] = n
			}
		}
	}
	return rep, nil
}

// ScrubDBPatterns is the pattern-layer apply: every text column is read row
// by row, each value is scanned with redact.ScanAll (or layer 1 only when
// maskPatterns is false), and changed rows are written back with a single
// UPDATE. FTS5 indexes are rebuilt and backup is honored, matching ScrubDB.
func ScrubDBPatterns(path string, secrets []string, minLen int, patterns *redact.PatternSet, maskPatterns bool, backup bool) (*Report, error) {
	if backup {
		if err := copyFile(path, path+".bak"); err != nil {
			return nil, fmt.Errorf("backup: %w", err)
		}
	}
	rep := NewReport()
	tables, err := listTables(path)
	if err != nil {
		return nil, err
	}
	for _, t := range tables {
		cols, err := scanColumns(path, t)
		if err != nil {
			return nil, err
		}
		for _, c := range cols {
			n, err := scanColumnRows(path, t, c, secrets, minLen, patterns, maskPatterns, true)
			if err != nil {
				return nil, fmt.Errorf("%s.%s: %w", t, c, err)
			}
			if n > 0 {
				rep.Tables[t+"."+c] = n
			}
		}
	}

	fts, err := listFTS(path)
	if err != nil {
		return nil, err
	}
	for _, f := range fts {
		if _, err := sqlite(path, fmt.Sprintf("INSERT INTO \"%s\"(\"%s\") VALUES('rebuild');", f, f)); err != nil {
			return nil, fmt.Errorf("fts rebuild %s: %w", f, err)
		}
		rep.FTSRebuilt = append(rep.FTSRebuilt, f)
	}
	sort.Strings(rep.FTSRebuilt)

	// Purge physical remnants of scrubbed secrets, matching ScrubDB.
	if rep.TotalHits() > 0 {
		if _, err := sqlite(path, "VACUUM;"); err != nil {
			return nil, fmt.Errorf("vacuum: %w", err)
		}
	}
	return rep, nil
}

// scanColumnRows streams every value of one text column and returns how many
// rows hit. When write is true, changed values are written back with a single
// UPDATE per row. Row ids are hex-encoded so they never appear unescaped in
// SQL; row values are matched in Go (redact.ScanAll).
//
// Rows are streamed one at a time (see sqliteEachRow) and the rewrites are
// batched into a temp file that one sqlite3 process replays on stdin. The
// previous shape — one sqlite() call per changed row — failed with E2BIG
// ("argument list too long") on any value over 64 KiB, because the rewritten
// value travels hex-encoded inside the statement and a single argv entry is
// capped at 128 KiB.
func scanColumnRows(path, table, col string, secrets []string, minLen int, patterns *redact.PatternSet, maskPatterns, write bool) (int, error) {
	var batch *updateBatch
	if write {
		b, err := newUpdateBatch()
		if err != nil {
			return 0, err
		}
		batch = b
		defer batch.Discard()
	}
	n := 0
	err := sqliteEachRow(path, fmt.Sprintf("SELECT rowid, hex(\"%s\") FROM \"%s\";", col, table), func(line string) error {
		if line == "" {
			return nil
		}
		rid, hexVal, ok := strings.Cut(line, "|")
		if !ok {
			return nil
		}
		val, err := hex.DecodeString(hexVal)
		if err != nil {
			return fmt.Errorf("decode hex value: %w", err)
		}
		text, changed, patHits := rewriteRow(string(val), secrets, minLen, patterns, maskPatterns)
		n += patHits
		if !changed {
			return nil
		}
		n++
		if batch == nil {
			return nil
		}
		return batch.Add(table, col, text, rid)
	})
	if err != nil {
		return n, err
	}
	if batch != nil {
		if err := batch.Replay(path); err != nil {
			return n, err
		}
	}
	return n, nil
}

// rewriteRow applies the configured layers to one value and returns the
// rewritten text, whether it changed, and how many pattern detections are
// counted without masking (pattern_mode: "log" counts layer 2 and applies
// layer 1).
func rewriteRow(text string, secrets []string, minLen int, patterns *redact.PatternSet, maskPatterns bool) (string, bool, int) {
	if text == "" {
		return text, false, 0
	}
	if maskPatterns {
		masked, changed := redact.ScanAll(text, secrets, minLen, patterns)
		return masked, changed, 0
	}
	masked, changed := redact.ScanAndRedact(text, secrets, minLen)
	if _, patHit := patterns.Scan(masked); patHit {
		return masked, changed, 1
	}
	return masked, changed, 0
}

// updateBatch buffers row rewrites as UPDATE statements in a temp file, so one
// sqlite3 process can replay them on stdin instead of one process (and one
// argv entry, capped at MAX_ARG_STRLEN) per row. Only rewritten — already
// masked — values are written, and the file is removed by Discard.
type updateBatch struct {
	f    *os.File
	name string
}

// newUpdateBatch creates the temp update file (0600 in os.TempDir).
func newUpdateBatch() (*updateBatch, error) {
	f, err := os.CreateTemp("", "trustless-scrub-updates-*.sql")
	if err != nil {
		return nil, fmt.Errorf("temp updates file: %w", err)
	}
	return &updateBatch{f: f, name: f.Name()}, nil
}

// Add appends one rewritten row.
func (b *updateBatch) Add(table, col, text, rid string) error {
	if _, err := fmt.Fprintf(b.f, "UPDATE \"%s\" SET \"%s\" = %s WHERE rowid = %s;\n", table, col, secretHex(text), rid); err != nil {
		return fmt.Errorf("write updates: %w", err)
	}
	return nil
}

// Replay flushes the batch and applies it through a single sqlite3 process.
func (b *updateBatch) Replay(path string) error {
	if err := b.f.Close(); err != nil {
		return fmt.Errorf("close updates: %w", err)
	}
	sqlFile, err := os.Open(b.name)
	if err != nil {
		return fmt.Errorf("reopen updates: %w", err)
	}
	defer sqlFile.Close()
	if _, err := sqliteStdin(path, sqlFile); err != nil {
		return err
	}
	return nil
}

// Discard closes and removes the temp file; safe to call after Replay.
func (b *updateBatch) Discard() {
	_ = b.f.Close()
	_ = os.Remove(b.name)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
