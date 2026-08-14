package scrub

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/ikkun1222/trustless/internal/dlp/redact"
)

// Report summarizes a scan/scrub run.
type TextReport struct {
	Files int            // files scanned
	Hits  map[string]int // file -> number of secrets replaced
}

func (r *TextReport) TotalHits() int {
	n := 0
	for _, v := range r.Hits {
		n += v
	}
	return n
}

func NewTextReport() *TextReport {
	return &TextReport{Hits: map[string]int{}}
}

// ScanTextFiles walks root (file or directory) and returns which files
// contain any secret (length >= minLen) or pattern match. Email addresses
// are excluded. patterns == nil means known values only (legacy behavior);
// otherwise pattern hits are counted per file too.
func ScanTextFiles(root string, secrets []string, minLen int, patterns *redact.PatternSet) (*TextReport, error) {
	rep := NewTextReport()
	err := walkTextFiles(root, func(path string, data []byte) error {
		text := string(data)
		if patterns == nil {
			for _, s := range secrets {
				if len(s) >= minLen && !redact.IsEmail(s) && strings.Contains(text, s) {
					rep.Hits[path]++
				}
			}
			return nil
		}
		// Pattern path: reuse the same layer-1 + layer-2 detection as the
		// proxy (ScanAll). A file counts once per detection layer that hit.
		if _, changed := redact.ScanAll(text, secrets, minLen, patterns); changed {
			rep.Hits[path]++
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rep, nil
}

// ScrubTextFiles walks root (file or directory) and replaces every
// occurrence of any secret (length >= minLen) with <redacted>. Email
// addresses are excluded. When patterns != nil, pattern matches are also
// replaced unless maskPatterns is false (pattern_mode: "log"), in which
// case pattern hits are counted without changing the file. Returns a
// report of files scrubbed.
func ScrubTextFiles(root string, secrets []string, minLen int, patterns *redact.PatternSet, maskPatterns bool) (*TextReport, error) {
	rep := NewTextReport()
	err := walkTextFiles(root, func(path string, data []byte) error {
		orig := string(data)
		out := orig
		if patterns == nil {
			for _, s := range secrets {
				if len(s) >= minLen && !redact.IsEmail(s) {
					out = strings.ReplaceAll(out, s, redact.Marker)
				}
			}
		} else if maskPatterns {
			out, _ = redact.ScanAll(out, secrets, minLen, patterns)
		} else {
			// pattern_mode: "log" — layer 1 (known values) is always
			// applied; layer 2 is detection only.
			out, _ = redact.ScanAndRedact(out, secrets, minLen)
			if _, hit := patterns.Scan(out); hit {
				rep.Hits[path]++
			}
		}
		if out != orig {
			// log モードでパターン検出のカウントが既に加算されている場合があるため、
			// 上書きではなく加算する（+=）。
			rep.Hits[path] += countDiff(orig, out)
			return os.WriteFile(path, []byte(out), 0o600)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rep, nil
}

// walkTextFiles walks root; if root is a file it processes just that file.
// Only text-ish extensions are processed to avoid corrupting binaries.
func walkTextFiles(root string, fn func(path string, data []byte) error) error {
	info, err := os.Stat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		data, err := os.ReadFile(root)
		if err != nil {
			return err
		}
		return fn(root, data)
	}
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !isTextFile(path) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return fn(path, data)
	})
}

// isTextFile reports whether a path looks like a text file worth scanning.
func isTextFile(path string) bool {
	base := filepath.Base(path)
	// Rotated logs: agent.log.2, gateway.log.1 — basename contains ".log"
	// followed by a numeric rotation index, or ends in ".log".
	if i := strings.Index(base, ".log"); i >= 0 {
		rest := base[i+len(".log"):]
		if rest == "" {
			return true
		}
		if strings.HasPrefix(rest, ".") && isDigits(rest[1:]) {
			return true
		}
	}
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json", ".jsonl", ".md", ".txt", ".yaml", ".yml", ".py",
		".sh", ".go", ".js", ".ts", ".html", ".csv", ".log", ".toml",
		".ini", ".cfg", ".conf", ".env":
		return true
	}
	// Dotfiles without a recognized extension (e.g. .hermes_history) are
	// text candidates too — peek at content for null bytes.
	if strings.HasPrefix(base, ".") {
		return !hasNullBytes(path)
	}
	return false
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func hasNullBytes(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return true
	}
	defer f.Close()
	buf := make([]byte, 512)
	n, _ := f.Read(buf)
	return strings.IndexByte(string(buf[:n]), 0) >= 0
}

func countDiff(a, b string) int {
	// Count how many <redacted> markers appear in b but not in a.
	return strings.Count(b, redact.Marker) - strings.Count(a, redact.Marker)
}
