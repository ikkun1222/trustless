package scrub

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScrubTextFiles_FileAndDir(t *testing.T) {
	dir := t.TempDir()
	secret := "sk-textfile-secret-1234567890"

	// Single file with a secret.
	f1 := filepath.Join(dir, "note.md")
	if err := os.WriteFile(f1, []byte("key is "+secret+" here"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Nested file without a secret.
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	f2 := filepath.Join(sub, "clean.txt")
	if err := os.WriteFile(f2, []byte("no secrets"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Binary-looking file must be skipped.
	f3 := filepath.Join(dir, "data.bin")
	if err := os.WriteFile(f3, []byte("key is "+secret+"\x00\x01\x02"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Scan: only f1 should hit.
	rep, err := ScanTextFiles(dir, []string{secret}, 8, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Hits) != 1 {
		t.Fatalf("scan hits = %v, want only f1", rep.Hits)
	}
	if _, ok := rep.Hits[f1]; !ok {
		t.Fatalf("f1 missing from hits: %v", rep.Hits)
	}

	// Scrub: f1 gets masked, f2/f3 untouched.
	srep, err := ScrubTextFiles(dir, []string{secret}, 8, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if srep.TotalHits() < 1 {
		t.Fatalf("scrub hits = %d, want >= 1", srep.TotalHits())
	}
	data, _ := os.ReadFile(f1)
	if strings.Contains(string(data), secret) {
		t.Fatalf("f1 still contains secret: %q", data)
	}
	if !strings.Contains(string(data), "<redacted>") {
		t.Fatalf("f1 missing marker: %q", data)
	}
	data3, _ := os.ReadFile(f3)
	if !strings.Contains(string(data3), secret) {
		t.Fatalf("binary file was modified: %q", data3)
	}
}

func TestScrubTextFiles_EmailExcluded(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "doc.md")
	email := "someone@example.com"
	if err := os.WriteFile(f, []byte("contact "+email), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := ScrubTextFiles(dir, []string{email}, 8, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if rep.TotalHits() != 0 {
		t.Fatalf("email should not be scrubbed: %v", rep.Hits)
	}
	data, _ := os.ReadFile(f)
	if !strings.Contains(string(data), email) {
		t.Fatal("email was removed")
	}
}

func TestIsTextFile_RotatedLogs(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"agent.log", true},
		{"agent.log.1", true},
		{"gateway.log.2", true},
		{"errors.log.3", true},
		{"blog.2", false}, // unrelated numeric-suffix file
		{"notes.md", true},
		{"data.bin", false},
		{"archive.tar.gz", false},
	}
	for _, c := range cases {
		got := isTextFile(c.name)
		if got != c.want {
			t.Errorf("isTextFile(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestScanTextFiles_PatternHits verifies the dry-run pattern layer: a
// github-pat shaped value (ghp_...) that is not a known secret is still
// detected via the bundled rules.
func TestScanTextFiles_PatternHits(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "note.md")
	if err := os.WriteFile(f, []byte("token ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ end"), 0o600); err != nil {
		t.Fatal(err)
	}
	patterns := loadBundledPatterns(t)

	// patterns == nil: no hit (value not in secrets).
	rep, err := ScanTextFiles(dir, nil, 8, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.TotalHits() != 0 {
		t.Fatalf("patterns nil hits = %d, want 0", rep.TotalHits())
	}

	// patterns != nil: detected.
	rep2, err := ScanTextFiles(dir, nil, 8, patterns)
	if err != nil {
		t.Fatal(err)
	}
	if rep2.TotalHits() != 1 {
		t.Fatalf("pattern hits = %d, want 1 (%+v)", rep2.TotalHits(), rep2.Hits)
	}
	if _, ok := rep2.Hits[f]; !ok {
		t.Fatalf("hit file missing: %v", rep2.Hits)
	}
}

// TestScrubTextFiles_PatternMask verifies --apply masks pattern matches.
func TestScrubTextFiles_PatternMask(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "note.md")
	if err := os.WriteFile(f, []byte("token ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ end"), 0o600); err != nil {
		t.Fatal(err)
	}
	patterns := loadBundledPatterns(t)

	rep, err := ScrubTextFiles(dir, nil, 8, patterns, true)
	if err != nil {
		t.Fatal(err)
	}
	if rep.TotalHits() < 1 {
		t.Fatalf("scrub hits = %d, want >= 1", rep.TotalHits())
	}
	data, _ := os.ReadFile(f)
	if strings.Contains(string(data), "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ") {
		t.Fatalf("pattern still present: %q", data)
	}
	if !strings.Contains(string(data), "<redacted>") {
		t.Fatalf("marker missing: %q", data)
	}
}

// TestScrubTextFiles_PatternLogMode verifies pattern_mode: "log": pattern
// matches are counted but not replaced; known values are still masked.
func TestScrubTextFiles_PatternLogMode(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "note.md")
	secret := "sk-kno...7890"
	content := "token " + openaiDummy(t) + " and " + secret
	if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	patterns := loadBundledPatterns(t)

	rep, err := ScrubTextFiles(dir, []string{secret}, 8, patterns, false)
	if err != nil {
		t.Fatal(err)
	}
	if rep.TotalHits() < 2 {
		t.Fatalf("hits = %d, want >= 2 (known value + pattern)", rep.TotalHits())
	}
	data, _ := os.ReadFile(f)
	if !strings.Contains(string(data), openaiDummy(t)) {
		t.Fatalf("pattern was masked in log mode: %q", data)
	}
	if strings.Contains(string(data), secret) {
		t.Fatalf("known value not masked: %q", data)
	}
	if !strings.Contains(string(data), "<redacted>") {
		t.Fatalf("marker missing: %q", data)
	}
}
