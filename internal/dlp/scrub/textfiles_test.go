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
	rep, err := ScanTextFiles(dir, []string{secret}, 8)
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
	srep, err := ScrubTextFiles(dir, []string{secret}, 8)
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
	email := "takahashi.iria@gmail.com"
	if err := os.WriteFile(f, []byte("contact "+email), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := ScrubTextFiles(dir, []string{email}, 8)
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
