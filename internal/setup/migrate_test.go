package setup

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestScanEnvFiles_ParsesAndFiltersLines(t *testing.T) {
	dir := t.TempDir()

	writeTestFile(t, filepath.Join(dir, ".env"), strings.Join([]string{
		"A=1",
		"# comment line",
		"",
		"  B =  two words  ",
		"C=",
		"=no-key",
		"D",
		`E="quoted"`,
	}, "\n"))
	writeTestFile(t, filepath.Join(dir, "sub", ".env"), "SUB=1\n")
	// Not an exact ".env" name: must be ignored.
	writeTestFile(t, filepath.Join(dir, "config.env"), "SKIP=1\n")
	writeTestFile(t, filepath.Join(dir, ".env.bak"), "SKIP=1\n")
	// Only comments/blank lines: must not produce an EnvFile.
	writeTestFile(t, filepath.Join(dir, "empty", ".env"), "# nothing here\n\n")

	envFiles, err := ScanEnvFiles([]string{dir})
	if err != nil {
		t.Fatalf("ScanEnvFiles: %v", err)
	}
	if len(envFiles) != 2 {
		t.Fatalf("found %d env files, want 2: %+v", len(envFiles), envFiles)
	}

	var root *EnvFile
	for i := range envFiles {
		if envFiles[i].Path == filepath.Join(dir, ".env") {
			root = &envFiles[i]
		}
	}
	if root == nil {
		t.Fatal("root .env not scanned")
	}

	got := map[string]string{}
	for _, e := range root.Entries {
		got[e.Key] = e.Value
	}
	want := map[string]string{
		"A": "1",
		"B": "two words",
		"C": "",
		`E`: `"quoted"`, // quotes are preserved verbatim by the current parser
	}
	if len(got) != len(want) {
		t.Fatalf("entries = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("entry %q = %q, want %q", k, got[k], v)
		}
	}
}

func TestScanEnvFiles_DedupsOverlappingSearchPaths(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, ".env"), "A=1\n")

	envFiles, err := ScanEnvFiles([]string{dir, dir})
	if err != nil {
		t.Fatalf("ScanEnvFiles: %v", err)
	}
	if len(envFiles) != 1 {
		t.Fatalf("found %d env files for overlapping paths, want 1", len(envFiles))
	}
}

func TestScanEnvFiles_ErrorsOnMissingSearchPath(t *testing.T) {
	_, err := ScanEnvFiles([]string{filepath.Join(t.TempDir(), "does-not-exist")})
	if err == nil {
		t.Fatal("expected error for missing search path")
	}
}

func TestBackupEnvFiles_PreservesRelativeLayout(t *testing.T) {
	// BackupEnvFiles mirrors paths relative to the process working directory
	// (the dir the user runs `trustless setup` in), so pin the cwd to the
	// fixture root. Without this the destination resolves relative to the
	// go test package dir and can collapse back onto the source file.
	root := t.TempDir()
	t.Chdir(root)
	backupDir := filepath.Join(root, "backup")

	paths := []string{
		filepath.Join(root, "a", ".env"),
		filepath.Join(root, "b", "c", ".env"),
	}
	var envFiles []EnvFile
	for _, p := range paths {
		writeTestFile(t, p, "K=V\n")
		envFiles = append(envFiles, EnvFile{Path: p})
	}

	if err := BackupEnvFiles(envFiles, backupDir); err != nil {
		t.Fatalf("BackupEnvFiles: %v", err)
	}

	for _, p := range paths {
		rel, err := filepath.Rel(root, p)
		if err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(backupDir, rel)
		got, err := os.ReadFile(dst)
		if err != nil {
			t.Fatalf("backup %s not created: %v", dst, err)
		}
		if string(got) != "K=V\n" {
			t.Fatalf("backup %s content = %q, want K=V", dst, got)
		}
	}
}

func TestBackupEnvFiles_RejectsPathOutsideCwd(t *testing.T) {
	// cwd 外の絶対パスは backupDir 外へ解決されるため拒否されなければならない
	// （パストラバーサル防止）。
	root := t.TempDir()
	t.Chdir(root)
	outside := t.TempDir()
	outsideEnv := filepath.Join(outside, ".env")
	writeTestFile(t, outsideEnv, "K=V\n")

	err := BackupEnvFiles([]EnvFile{{Path: outsideEnv}}, filepath.Join(root, "backup"))
	if err == nil {
		t.Fatal("BackupEnvFiles accepted a path outside cwd, want traversal error")
	}
}

// TestBackupEnvFiles_RejectsTmpAbsolutePath demonstrates the P1-4 path
// traversal guard end to end: an absolute .env path outside the cwd (e.g.
// under /tmp) is refused AND nothing is written outside the backup dir.
func TestBackupEnvFiles_RejectsTmpAbsolutePath(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	backupDir := filepath.Join(root, "backup")

	outsideEnv := filepath.Join(t.TempDir(), ".env")
	writeTestFile(t, outsideEnv, "K=V\n")

	err := BackupEnvFiles([]EnvFile{{Path: outsideEnv}}, backupDir)
	if err == nil {
		t.Fatal("BackupEnvFiles accepted /tmp absolute path, want traversal error")
	}

	// backupDir 外にも backupDir 内にも何も書き出されていないこと。
	var written []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, _ error) error {
		if d != nil && !d.IsDir() {
			written = append(written, path)
		}
		return nil
	})
	if len(written) != 0 {
		t.Fatalf("refused backup wrote files: %v", written)
	}
	if _, statErr := os.Stat(filepath.Join(backupDir, outsideEnv)); !os.IsNotExist(statErr) {
		t.Fatal("absolute source path materialized under backup dir")
	}
	// ソース自体は無事なこと。
	if got, readErr := os.ReadFile(outsideEnv); readErr != nil || string(got) != "K=V\n" {
		t.Fatalf("source altered: %q, %v", got, readErr)
	}
}

func TestBackupEnvFiles_Mode0600(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	backupDir := filepath.Join(root, "backup")

	src := filepath.Join(root, "a", ".env")
	writeTestFile(t, src, "K=V\n")

	if err := BackupEnvFiles([]EnvFile{{Path: src}}, backupDir); err != nil {
		t.Fatalf("BackupEnvFiles: %v", err)
	}
	rel, _ := filepath.Rel(root, src)
	dst := filepath.Join(backupDir, rel)
	if perm := fileMode(t, dst); perm != 0o600 {
		t.Fatalf("backup mode = %04o, want 0600", perm)
	}

	// 既存 0644 ファイルへの再バックアップでも 0600 に矯正されること。
	if err := os.Chmod(dst, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := BackupEnvFiles([]EnvFile{{Path: src}}, backupDir); err != nil {
		t.Fatalf("BackupEnvFiles: %v", err)
	}
	if perm := fileMode(t, dst); perm != 0o600 {
		t.Fatalf("re-backup mode = %04o, want 0600", perm)
	}
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}
func TestScanEnvFiles_RecursesIntoNestedDirs(t *testing.T) {
	// The walk is recursive over the given search root: any .env below it is
	// scanned — except excluded dirs (shared with doctor via envscan).
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, ".env"), "A=1\n")
	writeTestFile(t, filepath.Join(root, "sub", "deep", ".env"), "SUB=1\n")
	// Backup roots inside the tree must NOT be re-imported …
	writeTestFile(t, filepath.Join(root, "backup", "b", "c", ".env"), "OLD=1\n")
	writeTestFile(t, filepath.Join(root, ".env-backup-20260101", ".env"), "OLD=1\n")
	// … nor must VCS/tooling trees (same rules as doctor's scan).
	writeTestFile(t, filepath.Join(root, ".git", ".env"), "SKIP=1\n")
	writeTestFile(t, filepath.Join(root, "node_modules", "pkg", ".env"), "SKIP=1\n")

	envFiles, err := ScanEnvFiles([]string{root})
	if err != nil {
		t.Fatalf("ScanEnvFiles: %v", err)
	}
	if len(envFiles) != 2 {
		t.Fatalf("found %d env files, want 2 (nested .env only): %+v", len(envFiles), envFiles)
	}
}

func TestRemoveEnvFiles_DeletesOnlyEnvFilesWithBackup(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	backupDir := filepath.Join(root, "backup")

	dotenv := filepath.Join(root, "sub", ".env")
	dotenvVariant := filepath.Join(root, "sub", ".env.local")
	other := filepath.Join(root, "sub", "a.env")
	for _, p := range []string{dotenv, dotenvVariant, other} {
		writeTestFile(t, p, "K=V\n")
	}
	envFiles := []EnvFile{{Path: dotenv}, {Path: dotenvVariant}, {Path: other}}
	if err := BackupEnvFiles(envFiles, backupDir); err != nil {
		t.Fatalf("BackupEnvFiles: %v", err)
	}

	if err := RemoveEnvFiles(envFiles, backupDir); err != nil {
		t.Fatalf("RemoveEnvFiles: %v", err)
	}
	// .env / .env.* は削除される。
	for _, p := range []string{dotenv, dotenvVariant} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s still exists: %v", p, err)
		}
	}
	// 非 .env ファイルは削除対象外。
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("non-.env file must be preserved, stat: %v", err)
	}

	// 二重削除はエラーになること。
	if err := RemoveEnvFiles([]EnvFile{{Path: dotenv}}, backupDir); err == nil {
		t.Fatal("second removal of already-deleted files must error")
	}
}

func TestRemoveEnvFiles_RefusesWithoutBackup(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	backupDir := filepath.Join(root, "backup")

	dotenv := filepath.Join(root, "sub", ".env")
	writeTestFile(t, dotenv, "K=V\n")

	// バックアップなしでの削除は拒否され、ファイルは残る。
	if err := RemoveEnvFiles([]EnvFile{{Path: dotenv}}, backupDir); err == nil {
		t.Fatal("RemoveEnvFiles without backup must error")
	}
	if _, err := os.Stat(dotenv); err != nil {
		t.Fatalf(".env must be preserved when backup is missing, stat: %v", err)
	}
}

func TestImportToPass_RequiresPassBinary(t *testing.T) {
	if _, err := exec.LookPath("pass"); err == nil {
		t.Skip("pass is installed; ImportToPass would mutate a real store")
	}

	err := ImportToPass([]EnvFile{{
		Path:    "/nonexistent/.env",
		Entries: []EnvEntry{{Key: "some_key", Value: "some value"}},
	}})
	if err == nil {
		t.Fatal("expected error when pass binary is missing")
	}
	if !errors.Is(err, ErrPassInsert) {
		t.Fatalf("error = %v, want it to wrap ErrPassInsert", err)
	}
}

// TestImportToPass_WithFakePassBinary runs the happy path against a fake
// `pass` script on PATH so CI covers the main route without touching a real
// store and without reading any real credential.
func TestImportToPass_WithFakePassBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake pass script needs a POSIX shell")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls.log")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + logPath + "\ncat >> " + logPath + "\n"
	passPath := filepath.Join(dir, "bin", "pass")
	if err := os.MkdirAll(filepath.Dir(passPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(passPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", filepath.Dir(passPath)+string(os.PathListSeparator)+os.Getenv("PATH"))

	err := ImportToPass([]EnvFile{{
		Path: filepath.Join(dir, ".env"),
		Entries: []EnvEntry{
			{Key: "some_key", Value: "some value"},
			{Key: "iria/api/xai", Value: "another-value"},
		},
	}})
	if err != nil {
		t.Fatalf("ImportToPass with fake pass: %v", err)
	}
	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("fake pass produced no log: %v", err)
	}
	for _, want := range []string{"some_key", "some value", "iria/api/xai", "another-value"} {
		if !strings.Contains(string(log), want) {
			t.Fatalf("fake pass log = %q, want it to contain %q", log, want)
		}
	}
}

func TestImportToPass_RejectsUnsafeKeys(t *testing.T) {
	// 検証は `pass` 実行より先に行われるため、バイナリの有無に依存しない。
	bad := []string{
		"",
		"../evil",
		"a/../../b",
		"key with space",
		"key;rm -rf",
		"key$var",
		`"quoted"`,
		"key=value",
		"..",
	}
	for _, key := range bad {
		err := ImportToPass([]EnvFile{{
			Path:    "/fake/.env",
			Entries: []EnvEntry{{Key: key, Value: "v"}},
		}})
		if err == nil {
			t.Errorf("ImportToPass accepted unsafe key %q, want error", key)
			continue
		}
		if !strings.Contains(err.Error(), "unsafe") {
			t.Errorf("ImportToPass(%q) error = %q, want it to mention unsafe key", key, err)
		}
	}
}

func TestValidPassKey(t *testing.T) {
	good := []string{"API_KEY", "iria/api/xai", "my-key", "a.b_c/d-e", "X1"}
	for _, key := range good {
		if !validPassKey(key) {
			t.Errorf("validPassKey(%q) = false, want true", key)
		}
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
