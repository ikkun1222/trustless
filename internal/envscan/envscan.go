// Package envscan is the shared .env tree-walk core used by both
// `trustless setup` (import) and `trustless doctor` (scan): directory
// exclusion, .env name matching, entry parsing, and secret-pattern matching.
// Both callers must apply the same exclusion rules so a tree skipped by one
// is skipped by the other.
package envscan

import (
	"strings"
)

// skippedDirs は .env 走査から除外するディレクトリ名。巨大・機密系ツリーの
// 走査コストと誤検知を避ける。setup と doctor で共有する。
var skippedDirs = map[string]struct{}{
	".git": {}, ".config": {}, "node_modules": {},
	".cache": {}, ".password-store": {}, ".gnupg": {},
}

// SkipDir reports whether a directory (by base name) is excluded from .env
// scans. Besides the shared VCS/cache/tooling list, backup roots are
// excluded: "backup" and ".env-backup-*" (the setup backup layout), so a
// backup tree placed inside the scanned tree is never re-imported.
func SkipDir(name string) bool {
	if _, skip := skippedDirs[name]; skip {
		return true
	}
	return name == "backup" || strings.HasPrefix(name, ".env-backup-")
}

// IsEnvFile reports whether a file name is a scanned .env file (exact match).
func IsEnvFile(name string) bool {
	return name == ".env"
}

// Entry is one KEY=VALUE line parsed from a .env file.
type Entry struct {
	Key   string
	Value string
}

// ParseEntries parses .env content into entries. Blank lines, "#" comments,
// and lines without "=" are skipped; keys are trimmed. Values are kept
// verbatim (surrounding quotes are NOT stripped: E="quoted" reads back as
// `"quoted"`), so an import→pass→export round-trip preserves the original
// text the program being configured expects.
func ParseEntries(data []byte) []Entry {
	var out []Entry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" {
			continue
		}
		out = append(out, Entry{Key: key, Value: value})
	}
	return out
}

// ContainsSecret reports whether .env content has a credential-like line:
// a non-comment line containing one of the patterns.
func ContainsSecret(data []byte, patterns []string) bool {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, p := range patterns {
			if strings.Contains(line, p) {
				return true
			}
		}
	}
	return false
}
