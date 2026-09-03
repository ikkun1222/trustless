package setup

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

type EnvFile struct {
	Path    string
	Entries []EnvEntry
}

type EnvEntry struct {
	Key   string
	Value string
}

func ScanEnvFiles(searchPaths []string) ([]EnvFile, error) {
	var envFiles []EnvFile
	seen := make(map[string]bool)

	for _, sp := range searchPaths {
		absPath, err := filepath.Abs(sp)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve path %s: %w", sp, err)
		}

		err = filepath.WalkDir(absPath, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if d.Name() != ".env" {
				return nil
			}
			if seen[path] {
				return nil
			}
			seen[path] = true

			f, err := os.Open(path)
			if err != nil {
				return fmt.Errorf("failed to open %s: %w", path, err)
			}
			defer f.Close()

			var entries []EnvEntry
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
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
				entries = append(entries, EnvEntry{Key: key, Value: value})
			}
			if err := scanner.Err(); err != nil {
				return fmt.Errorf("error reading %s: %w", path, err)
			}

			if len(entries) > 0 {
				envFiles = append(envFiles, EnvFile{Path: path, Entries: entries})
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("error scanning %s: %w", absPath, err)
		}
	}

	return envFiles, nil
}

// passKeyPattern は `pass insert` に渡して安全なキー文字の許可リスト。
var passKeyPattern = regexp.MustCompile(`^[A-Za-z0-9/_.-]+$`)

// validPassKey reports whether key is safe to hand to `pass insert`:
// allow-listed characters only, and no ".." segments (path escape).
func validPassKey(key string) bool {
	if key == "" || !passKeyPattern.MatchString(key) {
		return false
	}
	return !strings.Contains(key, "..")
}

func ImportToPass(envFiles []EnvFile) error {
	for _, ef := range envFiles {
		for _, entry := range ef.Entries {
			if !validPassKey(entry.Key) {
				return fmt.Errorf("refusing to import unsafe pass key %q from %s", entry.Key, ef.Path)
			}
			cmd := exec.Command("pass", "insert", "-f", entry.Key)
			stdin, err := cmd.StdinPipe()
			if err != nil {
				return fmt.Errorf("failed to create stdin pipe: %w", err)
			}
			if _, err := io.WriteString(stdin, entry.Value+"\n"); err != nil {
				stdin.Close()
				return fmt.Errorf("failed to write to stdin: %w", err)
			}
			stdin.Close()
			out, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("pass insert failed for %s: %w\n%s", entry.Key, err, string(out))
			}
		}
	}
	return nil
}

func BackupEnvFiles(envFiles []EnvFile, backupDir string) error {
	absBackup, err := filepath.Abs(backupDir)
	if err != nil {
		return fmt.Errorf("failed to resolve backup dir: %w", err)
	}
	for _, ef := range envFiles {
		absPath, err := filepath.Abs(ef.Path)
		if err != nil {
			return fmt.Errorf("failed to get absolute path: %w", err)
		}
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get working directory: %w", err)
		}
		relPath, err := filepath.Rel(cwd, absPath)
		if err != nil {
			return fmt.Errorf("failed to get relative path: %w", err)
		}
		dst := filepath.Join(absBackup, relPath)
		// relPath が ".." を含むと backupDir 外へ解決されるため拒否
		// （パストラバーサル防止）。
		if rel, err := filepath.Rel(absBackup, dst); err != nil ||
			rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("refusing to back up outside backup dir: %s", ef.Path)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", filepath.Dir(dst), err)
		}
		if err := copyFile(absPath, dst); err != nil {
			return fmt.Errorf("failed to copy %s to %s: %w", absPath, dst, err)
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	r, err := os.Open(src)
	if err != nil {
		return err
	}
	defer r.Close()

	// 0600 で作成（平文バックアップの保護）。OpenFile は既存ファイルの
	// モードを変えないため後段で Chmod し直す。
	w, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, r); err != nil {
		w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, 0600)
}

func RemoveEnvFiles(envFiles []EnvFile) error {
	for _, ef := range envFiles {
		if err := os.Remove(ef.Path); err != nil {
			return fmt.Errorf("failed to remove %s: %w", ef.Path, err)
		}
	}
	return nil
}
