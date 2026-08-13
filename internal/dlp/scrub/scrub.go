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
