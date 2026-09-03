package doctor

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// isolatedRunEnv pins HOME to an empty temp dir and TRUSTLESS_CONFIG to a
// backend="env" file, so Run exercises the pass-branch checks with no GPG
// key and no pass store (guaranteed error status) without touching the real
// machine. No real credentials are read.
func isolatedRunEnv(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfgPath, []byte("backend = \"env\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TRUSTLESS_CONFIG", cfgPath)
}

func TestRun_ReturnsOneWhenGPGMissing(t *testing.T) {
	isolatedRunEnv(t)
	var stdout, stderr bytes.Buffer
	// runE injects writers: the test never swaps os.Stdout/os.Stderr.
	if got := runE(nil, &stdout, &stderr); got != 1 {
		t.Fatalf("runE(nil) = %d, want 1 (GPG/pass checks must error)", got)
	}
	if !strings.Contains(stdout.String(), "Summary:") {
		t.Fatalf("stdout = %q, want human report with Summary", stdout.String())
	}
}

func TestRun_JSONOutputsResults(t *testing.T) {
	isolatedRunEnv(t)
	var stdout, stderr bytes.Buffer
	if got := runE([]string{"--json"}, &stdout, &stderr); got != 1 {
		t.Fatalf("runE(--json) = %d, want 1", got)
	}
	var results []CheckResult
	if err := json.Unmarshal(stdout.Bytes(), &results); err != nil {
		t.Fatalf("stdout is not a JSON check list: %v\n%s", err, stdout.String())
	}
	if len(results) == 0 {
		t.Fatal("JSON report has no checks")
	}
}

func TestRun_JSONFixReportsCounts(t *testing.T) {
	isolatedRunEnv(t)
	var stdout, stderr bytes.Buffer
	if got := runE([]string{"--json", "--fix"}, &stdout, &stderr); got != 1 {
		t.Fatalf("runE(--json --fix) = %d, want 1", got)
	}
	// --fix runs before JSON output: the JSON report still lands on stdout …
	var results []CheckResult
	if err := json.Unmarshal(stdout.Bytes(), &results); err != nil {
		t.Fatalf("stdout is not a JSON check list: %v\n%s", err, stdout.String())
	}
	// … and the apply/skip totals land on stderr.
	got := stderr.String()
	if !strings.Contains(got, "applied") || !strings.Contains(got, "skipped") {
		t.Fatalf("stderr = %q, want applyFixes applied/skipped report", got)
	}
}
