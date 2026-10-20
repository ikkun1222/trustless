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
	"syscall"

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
	skipped := 0

	for _, sp := range searchPaths {
		absPath, err := filepath.Abs(sp)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve path %s: %w", sp, err)
		}
		resolvedRoot, err := filepath.EvalSymlinks(absPath)
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
			if !envscan.IsEnvFile(d.Name()) || seen[path] {
				return nil
			}
			ef, ok, err := loadEnvFile(path, resolvedRoot, d)
			if err != nil {
				return err
			}
			if !ok {
				skipped++
				return nil
			}
			seen[path] = true

			if len(ef.Entries) > 0 {
				envFiles = append(envFiles, ef)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("error scanning %s: %w", absPath, err)
		}
	}

	logSkipped("scan", skipped)
	return envFiles, nil
}

// loadEnvFile reads one .env candidate only when it is a regular file whose
// symlink-resolved path stays under resolvedRoot. Symlinks (even in-root
// ones), other non-regular files, and unresolvable/escaping paths return
// ok=false so the caller skips them instead of following the link. A real
// read failure on an eligible file is still an error.
func loadEnvFile(path, resolvedRoot string, d os.DirEntry) (EnvFile, bool, error) {
	if !d.Type().IsRegular() {
		return EnvFile{}, false, nil
	}
	resolved, ok := resolveWithinRoot(resolvedRoot, path)
	if !ok {
		return EnvFile{}, false, nil
	}
	data, err := readFileNoFollow(resolved)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return EnvFile{}, false, nil
		}
		return EnvFile{}, false, fmt.Errorf("failed to open %s: %w", path, err)
	}
	return EnvFile{Path: path, Entries: envscan.ParseEntries(data)}, true, nil
}

// resolveWithinRoot resolves target through symlinks and reports whether the
// resolved path is still under root. root must already be symlink-resolved.
// Callers skip unresolvable or escaping paths rather than following them.
func resolveWithinRoot(root, target string) (string, bool) {
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil {
		return "", false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return resolved, true
}

// resolvedCwd returns the working directory with symlinks resolved. Backup and
// removal use it as the containment root, matching backupDst's cwd-relative
// layout.
func resolvedCwd() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get working directory: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(cwd)
	if err != nil {
		return "", fmt.Errorf("failed to resolve working directory: %w", err)
	}
	return resolved, nil
}

// regularFileWithin reports whether path is a regular file (not a symlink)
// whose resolved location stays under resolvedRoot. Non-regular and
// escaping/unresolvable paths are reported as false; stat errors are returned
// so missing inputs still fail loudly.
func regularFileWithin(resolvedRoot, path string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, nil
	}
	_, ok := resolveWithinRoot(resolvedRoot, path)
	return ok, nil
}

// logSkipped reports how many .env candidates were deliberately not followed
// (symlinks, other non-regular files, or paths resolving outside the root).
// stderr keeps the setup command's stdout report unchanged.
func logSkipped(stage string, n int) {
	if n == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "trustless setup: %s: skipped %d non-regular or out-of-root .env path(s)\n", stage, n)
}

func readFileNoFollow(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
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
	resolvedRoot, err := resolvedCwd()
	if err != nil {
		return err
	}
	skipped := 0

	for _, ef := range envFiles {
		absPath, dst, err := backupDst(ef.Path, backupDir)
		if err != nil {
			return err
		}
		ok, err := regularFileWithin(resolvedRoot, absPath)
		if err != nil {
			return fmt.Errorf("failed to inspect %s: %w", absPath, err)
		}
		if !ok {
			skipped++
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", filepath.Dir(dst), err)
		}
		if err := copyFile(absPath, dst); err != nil {
			// A symlink swapped in after the check is skipped, not followed.
			if errors.Is(err, syscall.ELOOP) {
				skipped++
				continue
			}
			return fmt.Errorf("failed to copy %s to %s: %w", absPath, dst, err)
		}
	}
	logSkipped("backup", skipped)
	return nil
}

func copyFile(src, dst string) error {
	r, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
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
	resolvedRoot, err := resolvedCwd()
	if err != nil {
		return err
	}
	skipped := 0

	for _, ef := range envFiles {
		if !isRemovableEnvFile(ef.Path) {
			continue
		}
		absPath, dst, err := backupDst(ef.Path, backupDir)
		if err != nil {
			return err
		}
		ok, err := regularFileWithin(resolvedRoot, absPath)
		if err != nil {
			return fmt.Errorf("failed to inspect %s: %w", absPath, err)
		}
		if !ok {
			skipped++
			continue
		}
		if _, err := os.Stat(dst); err != nil {
			return fmt.Errorf("refusing to remove %s: no backup at %s", ef.Path, dst)
		}
		if err := os.Remove(absPath); err != nil {
			return fmt.Errorf("failed to remove %s: %w", ef.Path, err)
		}
	}
	logSkipped("remove", skipped)
	return nil
}
