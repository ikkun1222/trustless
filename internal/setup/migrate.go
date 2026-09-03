package setup

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ikkun1222/trustless/internal/envscan"
)

// ErrPassInsert は `pass insert` 失敗のセンチネル。呼び出し側は errors.Is
// で判定すること（文字列一致に依存しない）。
var ErrPassInsert = errors.New("pass insert failed")

type EnvFile struct {
	Path    string
	Entries []EnvEntry
}

// EnvEntry aliases the shared envscan entry type so setup and doctor parse
// .env lines identically (quotes preserved verbatim — see envscan).
type EnvEntry = envscan.Entry

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
			// 除外ルールは doctor と共有 (envscan.SkipDir)。backup ツリー内に
			// 置かれたコピーを再取り込みしない。
			if d.IsDir() {
				if envscan.SkipDir(d.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if !envscan.IsEnvFile(d.Name()) {
				return nil
			}
			if seen[path] {
				return nil
			}
			seen[path] = true

			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("failed to open %s: %w", path, err)
			}
			entries := envscan.ParseEntries(data)

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
				return fmt.Errorf("%w for %s: %v\n%s", ErrPassInsert, entry.Key, err, string(out))
			}
		}
	}
	return nil
}

// backupDst は env ファイルの backupDir 内の保存先を解決する。cwd 基準の
// 相対レイアウトを保ち、backupDir 外への解決は拒否する（パストラバーサル
// 防止）。BackupEnvFiles と RemoveEnvFiles で共有する。
func backupDst(envPath, backupDir string) (src, dst string, err error) {
	absBackup, err := filepath.Abs(backupDir)
	if err != nil {
		return "", "", fmt.Errorf("failed to resolve backup dir: %w", err)
	}
	absPath, err := filepath.Abs(envPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to get absolute path: %w", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", "", fmt.Errorf("failed to get working directory: %w", err)
	}
	relPath, err := filepath.Rel(cwd, absPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to get relative path: %w", err)
	}
	dst = filepath.Join(absBackup, relPath)
	// relPath が ".." を含むと backupDir 外へ解決されるため拒否
	// （パストラバーサル防止）。
	if rel, rerr := filepath.Rel(absBackup, dst); rerr != nil ||
		rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", "", fmt.Errorf("refusing to back up outside backup dir: %s", envPath)
	}
	return absPath, dst, nil
}

func BackupEnvFiles(envFiles []EnvFile, backupDir string) error {
	for _, ef := range envFiles {
		absPath, dst, err := backupDst(ef.Path, backupDir)
		if err != nil {
			return err
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

// isRemovableEnvFile は削除対象の拡張子ガード: base 名が ".env" または
// ".env.*" のものだけを削除する（"a.env" 等は対象外）。
func isRemovableEnvFile(path string) bool {
	base := filepath.Base(path)
	return base == ".env" || strings.HasPrefix(base, ".env.")
}

// RemoveEnvFiles deletes scanned .env files after verifying each one has a
// backup under backupDir. Files failing the extension guard are skipped
// (never deleted); a missing backup is a refusal error.
func RemoveEnvFiles(envFiles []EnvFile, backupDir string) error {
	for _, ef := range envFiles {
		if !isRemovableEnvFile(ef.Path) {
			continue
		}
		_, dst, err := backupDst(ef.Path, backupDir)
		if err != nil {
			return err
		}
		if _, err := os.Stat(dst); err != nil {
			return fmt.Errorf("refusing to remove %s: no backup at %s", ef.Path, dst)
		}
		if err := os.Remove(ef.Path); err != nil {
			return fmt.Errorf("failed to remove %s: %w", ef.Path, err)
		}
	}
	return nil
}
