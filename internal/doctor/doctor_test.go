package doctor

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyFixes_RunsFixesAndToleratesErrors(t *testing.T) {
	var ran []string
	checks := []CheckResult{
		{Name: "ok-no-fix", Status: StatusOK},
		{Name: "fixed", Status: StatusError, Fixable: true, Fix: func() error {
			ran = append(ran, "fixed")
			return nil
		}},
		{Name: "broken-fix", Status: StatusWarning, Fixable: true, Fix: func() error {
			ran = append(ran, "broken-fix")
			return errors.New("fake fix failure")
		}},
	}
	// Fix の失敗は全体を落とさず stderr 報告のみ（panic/exit しないこと）。
	applyFixes(checks, io.Discard)
	if len(ran) != 2 || ran[0] != "fixed" || ran[1] != "broken-fix" {
		t.Fatalf("applyFixes ran %v, want [fixed broken-fix] in order", ran)
	}
}

func TestApplyFixes_SkipsNilFix(t *testing.T) {
	checks := []CheckResult{
		{Name: "no-fix", Status: StatusError, Fixable: true, Fix: nil},
	}
	applyFixes(checks, io.Discard) // panic しないこと
}

func TestApplyFixes_OnlyErrorWarningAreFixed(t *testing.T) {
	var ran []string
	mkFix := func(name string) func() error {
		return func() error {
			ran = append(ran, name)
			return nil
		}
	}
	checks := []CheckResult{
		{Name: "ok", Status: StatusOK, Fixable: true, Fix: mkFix("ok")},
		{Name: "info", Status: StatusInfo, Fixable: true, Fix: mkFix("info")},
		{Name: "err", Status: StatusError, Fixable: true, Fix: mkFix("err")},
		{Name: "warn-nofix", Status: StatusWarning, Fixable: true, Fix: nil},
	}
	var sb strings.Builder
	applyFixes(checks, &sb)
	stderr := sb.String()
	if len(ran) != 1 || ran[0] != "err" {
		t.Fatalf("applyFixes ran %v, want only [err]", ran)
	}
	if !strings.Contains(stderr, "applied 1 fix(es), skipped 1") {
		t.Fatalf("stderr report = %q, want applied 1 / skipped 1", stderr)
	}
}

func TestCheckEnvFiles_WarningIsNotFixable(t *testing.T) {
	// HOME 配下に資格情報らしき .env を置いても Fixable:true になってはならない。
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(home+"/proj", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(home+"/proj/.env", []byte("API_KEY=dummy-value\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// CheckEnvFiles は home と home/projects を走査する。home 直下の proj/.env
	// が home 走査で見つかるはず。
	r := CheckEnvFiles()
	if r.Status != StatusWarning {
		t.Fatalf("CheckEnvFiles status = %v (%s), want StatusWarning", r.Status, r.Message)
	}
	if r.Fixable || r.Fix != nil {
		t.Fatal("CheckEnvFiles .env warning must not claim Fixable (no-op fix)")
	}
	if !strings.Contains(r.Message, "trustless setup") {
		t.Fatalf("warning message = %q, want migration hint", r.Message)
	}
}

func TestDedupeSearchDirs(t *testing.T) {
	home := "/home/testuser"
	got := dedupeSearchDirs([]string{home, home + "/projects"})
	if len(got) != 1 || got[0] != home {
		t.Fatalf("dedupeSearchDirs = %v, want [%s] (nested ~/projects dropped)", got, home)
	}
	got = dedupeSearchDirs([]string{home, home})
	if len(got) != 1 {
		t.Fatalf("dedupeSearchDirs exact dup = %v, want single entry", got)
	}
	got = dedupeSearchDirs([]string{"/a", "/b"})
	if len(got) != 2 {
		t.Fatalf("dedupeSearchDirs disjoint = %v, want both kept", got)
	}
}

func TestScanEnvDir_CountsWalkErrors(t *testing.T) {
	var found []string
	// 存在しないルートはコールバックにエラーとして届き、カウントされる
	// （全体は失敗せず継続する）。
	n := scanEnvDir("/nonexistent-dir-for-doctor-test-xyz", []string{"API_KEY"}, &found)
	if n == 0 {
		t.Fatal("scanEnvDir on missing dir = 0 walk errors, want >= 1")
	}
	if len(found) != 0 {
		t.Fatalf("found = %v, want empty", found)
	}
}

func TestScanEnvDir_FindsSecretsAndSkipsExcluded(t *testing.T) {
	root := t.TempDir()
	writeFile := func(path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(root+"/proj/.env", "API_KEY=dummy\n")
	writeFile(root+"/.git/.env", "API_KEY=dummy\n") // 除外ディレクトリ
	writeFile(root+"/plain/.env", "# nothing secret here\n")

	var found []string
	n := scanEnvDir(root, []string{"API_KEY"}, &found)
	if n != 0 {
		t.Fatalf("walk errors = %d, want 0", n)
	}
	if len(found) != 1 || found[0] != root+"/proj/.env" {
		t.Fatalf("found = %v, want only proj/.env", found)
	}
}

func TestCheckBitwardenCLI(t *testing.T) {
	r := CheckBitwardenCLI()
	// 環境に bw があるか無いかで期待値が変わるため、ステータスの範囲だけ検証:
	// エラーは「bw not found」、OK は「bw CLI found」のいずれかでなければならない。
	if r.Status != StatusOK && r.Status != StatusError {
		t.Fatalf("CheckBitwardenCLI: unexpected status %v (%s)", r.Status, r.Message)
	}
	if r.Name != "Bitwarden CLI" {
		t.Fatalf("CheckBitwardenCLI: name = %q, want Bitwarden CLI", r.Name)
	}
}

func TestCheckBitwardenSessionNoFile(t *testing.T) {
	// 実ファイルに依存しないよう、存在しないパスを検証する代わりに
	// チェックが「No bw session file」メッセージを返せることを確認する。
	// （テスト環境の $HOME に bw-session が無い前提: あれば SKIP）
	t.Setenv("HOME", "/nonexistent-home-for-doctor-test")
	r := CheckBitwardenSession()
	if r.Status != StatusError {
		t.Fatalf("CheckBitwardenSession with no home: status = %v (%s), want StatusError", r.Status, r.Message)
	}
}

func TestStatusDisplay_DistinguishesWarningFromError(t *testing.T) {
	wCh, wCol := statusDisplay(StatusWarning)
	eCh, eCol := statusDisplay(StatusError)
	// Glyph は TTY 有無によらず異なること。
	if wCh == eCh {
		t.Fatalf("warning glyph %q must differ from error glyph %q", wCh, eCh)
	}
	// 色は TTY 時のみ有効（go test では空）。有効な場合は Warning=黄色系・
	// Error=赤で、互いに異なること。
	if yellow != "" && wCol != yellow {
		t.Fatalf("warning color = %q, want yellow %q", wCol, yellow)
	}
	if red != "" && eCol != red {
		t.Fatalf("error color = %q, want red %q", eCol, red)
	}
	if yellow != "" && red != "" && wCol == eCol {
		t.Fatalf("warning color %q must differ from error color %q", wCol, eCol)
	}
	if ch, _ := statusDisplay(StatusOK); ch == wCh {
		t.Fatalf("warning glyph %q must differ from OK glyph", wCh)
	}
}

func TestCheckAgentIntegration_ScansAllPaths(t *testing.T) {
	dir := t.TempDir()
	configured := filepath.Join(dir, "configured.json")
	raw := filepath.Join(dir, "raw.json")
	if err := os.WriteFile(configured, []byte(`{"x": "trustless"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(raw, []byte(`{"apiKey": "sk-raw"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	fn := func(data []byte) bool { return strings.Contains(string(data), "trustless") }

	// 先頭が configured でも、後続に未 trustless 化があれば要修正。
	r := CheckAgentIntegration("Test", []string{configured, raw}, fn)
	if r.Status != StatusWarning {
		t.Fatalf("configured-first = %v (%s), want StatusWarning", r.Status, r.Message)
	}
	// 順序を入れ替えても同じ判定。
	r = CheckAgentIntegration("Test", []string{raw, configured}, fn)
	if r.Status != StatusWarning {
		t.Fatalf("raw-first = %v (%s), want StatusWarning", r.Status, r.Message)
	}
	// 全て configured なら OK。
	r = CheckAgentIntegration("Test", []string{configured}, fn)
	if r.Status != StatusOK {
		t.Fatalf("all-configured = %v (%s), want StatusOK", r.Status, r.Message)
	}
	// 存在ファイルなしは Info（未検出）。
	r = CheckAgentIntegration("Test", []string{filepath.Join(dir, "missing.json")}, fn)
	if r.Status != StatusInfo {
		t.Fatalf("missing = %v (%s), want StatusInfo", r.Status, r.Message)
	}
}

func TestExitCode(t *testing.T) {
	// StatusError が1つでもあれば gate は失敗(1)。警告・情報のみなら成功(0)。
	tests := []struct {
		name   string
		checks []CheckResult
		want   int
	}{
		{"all ok", []CheckResult{{Name: "a", Status: StatusOK}}, 0},
		{"warnings only", []CheckResult{{Name: "a", Status: StatusWarning}}, 0},
		{"info only", []CheckResult{{Name: "a", Status: StatusInfo}}, 0},
		{"one error", []CheckResult{{Name: "a", Status: StatusOK}, {Name: "b", Status: StatusError}}, 1},
		{"mixed", []CheckResult{{Name: "a", Status: StatusError}, {Name: "b", Status: StatusWarning}}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exitCode(tt.checks); got != tt.want {
				t.Fatalf("exitCode(%v) = %d, want %d", tt.checks, got, tt.want)
			}
		})
	}
}

func TestAgentDetectFns(t *testing.T) {
	// trustless 経由設定の代表パターン:
	// 1) "trustless" 文字列参照  2) DLP プロキシ(8787)参照  3) 注入プロキシ(8080)参照
	cases := []struct {
		name string
		data string
	}{
		{"trustless literal", `"trustless": true`},
		{"dlp proxy baseURL", `"baseURL": "http://127.0.0.1:8787/v1/openrouter"`},
		{"dlp proxy base_url", `base_url = "http://127.0.0.1:8787/v1/meta"`},
		{"inject proxy", `"baseURL": "http://127.0.0.1:8080"`},
	}
	fns := map[string]func([]byte) bool{
		"opencode": opencodeDetectFn,
		"codex":    codexDetectFn,
		"hermes":   hermesDetectFn,
	}
	for name, fn := range fns {
		for _, c := range cases {
			if !fn([]byte(c.data)) {
				t.Errorf("%s detect: %q should be detected as trustless-configured", name, c.data)
			}
		}
	}
	// 未設定パターンは検出しないこと
	neg := `"baseURL": "https://api.openai.com/v1"`
	for name, fn := range fns {
		if fn([]byte(neg)) {
			t.Errorf("%s detect: %q must NOT be detected", name, neg)
		}
	}
}
