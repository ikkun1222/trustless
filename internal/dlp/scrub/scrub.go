// Package scrub scans SQLite databases (Hermes state.db, opencode.db) for
// known secret values and replaces them with the <redacted> marker. It is
// the backfill/audit counterpart to the outbound DLP proxy: secrets that
// already leaked into local conversation history before the proxy existed
// are scrubbed in place, and FTS5 indexes are rebuilt.
//
// Implementation uses the system sqlite3 CLI (zero Go dependencies, same
// pattern as passstore's pass CLI). Secrets never appear in shell command
// lines: values are passed as hex literals (CAST(X'...' AS TEXT)) so quote
// characters cannot break out of the SQL.
package scrub

import (
	"encoding/hex"
	"fmt"
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
func sqlite(path string, sql string) (string, error) {
	cmd := exec.Command("sqlite3", "-batch", "-cmd", ".timeout 30000", path, sql)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("sqlite3: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// listTables returns real base-table names. FTS5 virtual tables AND their
// shadow tables (messages_fts_data / _idx / _docsize / _config) are excluded:
// the virtual table's content columns mirror the base table (handled via
// rebuild after scrubbing), and shadow tables must never be modified
// directly — SQLite rejects UPDATEs on them ("may not be modified").
// PRAGMA table_list is used because shadow tables carry the sqlite_master
// type='table' marker with a plain CREATE TABLE statement, so the old
// 'NOT LIKE %VIRTUAL TABLE%' filter let them through.
func listTables(path string) ([]string, error) {
	out, err := sqlite(path, "SELECT name FROM pragma_table_list WHERE type='table' AND schema='main' ORDER BY name;")
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

// copyFile copies src to dst (used for pre-scrub backup).
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o600)
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

// scanColumnRows reads every value of one text column and returns how many
// rows hit. When write is true, changed values are written back with a
// single UPDATE per row. Row ids are hex-encoded so they never appear
// unescaped in SQL; row values are matched in Go (redact.ScanAll).
func scanColumnRows(path, table, col string, secrets []string, minLen int, patterns *redact.PatternSet, maskPatterns, write bool) (int, error) {
	out, err := sqlite(path, fmt.Sprintf("SELECT rowid, hex(\"%s\") FROM \"%s\";", col, table))
	if err != nil {
		return 0, err
	}
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		rid, hexVal, ok := strings.Cut(line, "|")
		if !ok {
			continue
		}
		val, err := hex.DecodeString(hexVal)
		if err != nil {
			return n, fmt.Errorf("decode hex value: %w", err)
		}
		text := string(val)
		if text == "" {
			continue
		}
		changed := false
		if maskPatterns {
			var masked string
			masked, changed = redact.ScanAll(text, secrets, minLen, patterns)
			text = masked
		} else {
			// pattern_mode: "log" — layer 1 (known values) is applied;
			// layer 2 counts detections only.
			var masked string
			masked, changed = redact.ScanAndRedact(text, secrets, minLen)
			_, patHit := patterns.Scan(masked)
			n += boolInt(patHit)
			text = masked
		}
		if !changed {
			continue
		}
		n++
		if !write {
			continue
		}
		var b strings.Builder
		b.Grow(len(text) * 2)
		for i := 0; i < len(text); i++ {
			fmt.Fprintf(&b, "%02X", text[i])
		}
		q := fmt.Sprintf("UPDATE \"%s\" SET \"%s\" = X'%s' WHERE rowid = %s;", table, col, b.String(), rid)
		if _, err := sqlite(path, q); err != nil {
			return n, err
		}
	}
	return n, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
