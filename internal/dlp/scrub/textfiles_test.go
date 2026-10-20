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
	// The scan must report how many files it covered: a clean run and a no-op
	// walk both printed "0 hits in 0 files" before.
	if rep.Files != 2 {
		t.Fatalf("scan files = %d, want 2 (note.md + sub/clean.txt; data.bin is filtered out)", rep.Files)
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
	if srep.Files != 2 {
		t.Fatalf("scrub files = %d, want 2", srep.Files)
	}
}

// TestScanTextFiles_SingleFileCountsOne covers the file (not directory) branch
// of the walk: the report must say one file was scanned, not zero.
func TestScanTextFiles_SingleFileCountsOne(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "note.md")
	if err := os.WriteFile(f, []byte("nothing to find here"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := ScanTextFiles(f, nil, 8, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Files != 1 {
		t.Fatalf("scan files = %d, want 1", rep.Files)
	}
	if rep.TotalHits() != 0 {
		t.Fatalf("hits = %d, want 0", rep.TotalHits())
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

// TestScrubTextFiles_SkipsSymlinkToOutside is the regression for the symlink
// escape: a symlink inside root pointing outside must not be followed (the
// target must stay untouched), while a regular file in the same root is still
// scrubbed.
func TestScrubTextFiles_SkipsSymlinkToOutside(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	mustNoErr(t, os.MkdirAll(root, 0o755))
	mustNoErr(t, os.MkdirAll(outside, 0o755))
	secret := "sk-symlink-secret-1234567890"

	victim := filepath.Join(outside, "secret.md")
	mustNoErr(t, os.WriteFile(victim, []byte("outside key "+secret), 0o600))
	link := filepath.Join(root, "victim.md")
	mustNoErr(t, os.Symlink(victim, link))
	regular := filepath.Join(root, "note.md")
	mustNoErr(t, os.WriteFile(regular, []byte("inside key "+secret), 0o600))

	rep, err := ScrubTextFiles(root, []string{secret}, 8, nil, true)
	mustNoErr(t, err)

	outsideData, err := os.ReadFile(victim)
	mustNoErr(t, err)
	if !strings.Contains(string(outsideData), secret) {
		t.Fatalf("symlink target outside root was modified: %q", outsideData)
	}
	insideData, err := os.ReadFile(regular)
	mustNoErr(t, err)
	if strings.Contains(string(insideData), secret) || !strings.Contains(string(insideData), "<redacted>") {
		t.Fatalf("regular file was not scrubbed: %q", insideData)
	}
	info, err := os.Lstat(link)
	mustNoErr(t, err)
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink was replaced by a regular file: mode=%v", info.Mode())
	}
	if rep.Skipped < 1 {
		t.Fatalf("skipped count = %d, want >= 1", rep.Skipped)
	}
	if rep.Files != 1 {
		t.Fatalf("files scanned = %d, want 1 (only the regular file)", rep.Files)
	}
}

// TestScanTextFiles_SkipsSymlink keeps the dry-run target set identical to
// --apply: the symlink must not be reported as a hit and must not count as a
// scanned file.
func TestScanTextFiles_SkipsSymlink(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := "sk-scan-symlink-secret-123456"

	victim := filepath.Join(outside, "secret.md")
	if err := os.WriteFile(victim, []byte("key "+secret), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "victim.md")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	regular := filepath.Join(root, "note.md")
	if err := os.WriteFile(regular, []byte("key "+secret), 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := ScanTextFiles(root, []string{secret}, 8, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rep.Hits[link]; ok {
		t.Fatalf("symlink reported as a hit: %v", rep.Hits)
	}
	if _, ok := rep.Hits[regular]; !ok {
		t.Fatalf("regular file missing from hits: %v", rep.Hits)
	}
	if rep.Skipped < 1 {
		t.Fatalf("skipped count = %d, want >= 1", rep.Skipped)
	}
	if rep.Files != 1 {
		t.Fatalf("files scanned = %d, want 1", rep.Files)
	}
}

// TestScrubTextFiles_DoesNotFollowDirectorySymlink pins the existing behavior:
// a directory symlink is never descended into.
func TestScrubTextFiles_DoesNotFollowDirectorySymlink(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := "sk-dirlink-secret-1234567890"

	victim := filepath.Join(outside, "secret.md")
	if err := os.WriteFile(victim, []byte("key "+secret), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linkdir")); err != nil {
		t.Fatal(err)
	}

	if _, err := ScrubTextFiles(root, []string{secret}, 8, nil, true); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), secret) {
		t.Fatalf("directory symlink was descended into and target modified: %q", data)
	}
}

func mustNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
