package setup

import (
	"os"
	"os/exec"
	"path/filepath"
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

func TestScanEnvFiles_RecursesIntoNestedDirs(t *testing.T) {
	// The walk is recursive over the given search root: any .env below it is
	// scanned, including files that look like backup copies. Keeping backups
	// outside the scanned tree is the caller's responsibility.
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, ".env"), "A=1\n")
	writeTestFile(t, filepath.Join(root, "backup", "b", "c", ".env"), "OLD=1\n")

	envFiles, err := ScanEnvFiles([]string{root})
	if err != nil {
		t.Fatalf("ScanEnvFiles: %v", err)
	}
	if len(envFiles) != 2 {
		t.Fatalf("found %d env files, want 2 (nested .env included): %+v", len(envFiles), envFiles)
	}
}

func TestRemoveEnvFiles_RemovesAndReportsMissing(t *testing.T) {
	dir := t.TempDir()
	p1 := filepath.Join(dir, "a.env")
	p2 := filepath.Join(dir, "b.env")
	for _, p := range []string{p1, p2} {
		writeTestFile(t, p, "K=V\n")
	}

	envFiles := []EnvFile{{Path: p1}, {Path: p2}}
	if err := RemoveEnvFiles(envFiles); err != nil {
		t.Fatalf("RemoveEnvFiles: %v", err)
	}
	for _, p := range []string{p1, p2} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s still exists: %v", p, err)
		}
	}

	if err := RemoveEnvFiles(envFiles); err == nil {
		t.Fatal("second removal of already-deleted files must error")
	}
}

func TestImportToPass_RequiresPassBinary(t *testing.T) {
	if _, err := exec.LookPath("pass"); err == nil {
		t.Skip("pass is installed; ImportToPass would mutate a real store")
	}

	err := ImportToPass([]EnvFile{{
		Path:    "/nonexistent/.env",
		Entries: []EnvEntry{{Key: "some_key", Value: "some value"}},
	}}, "")
	if err == nil {
		t.Fatal("expected error when pass binary is missing")
	}
	if !strings.Contains(err.Error(), "pass insert failed") {
		t.Fatalf("error = %q, want it to mention pass insert failure", err)
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
