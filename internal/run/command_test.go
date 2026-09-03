package run

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/ikkun1222/trustless/internal/backend"
	"github.com/ikkun1222/trustless/internal/config"
	"github.com/ikkun1222/trustless/internal/scanner"
)

func TestSanitizingWriterStreamsLines(t *testing.T) {
	var out bytes.Buffer
	s := scanner.New()
	w := &sanitizingWriter{dst: &out, s: s, values: []string{"sekrit-value-12345"}}

	// No newline yet: stays buffered
	w.Write([]byte("no newline yet "))
	if out.Len() != 0 {
		t.Fatalf("expected buffered output, got %q", out.String())
	}

	// Newline flushes the complete buffered line (with redaction)
	w.Write([]byte("hello sk-abcdefghijklmnopqrstuvwxyz\n"))
	got := out.String()
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("expected credential redacted, got %q", got)
	}
	if strings.Contains(got, "sk-abcdefghijklmnopqrstuvwxyz") {
		t.Fatalf("credential leaked: %q", got)
	}
	if !strings.Contains(got, "no newline yet") {
		t.Fatalf("expected full line flushed on newline, got %q", got)
	}

	// Exact-value redaction on a later line
	out.Reset()
	w.Write([]byte("token=sekrit-value-12345\n"))
	if !strings.Contains(out.String(), "[REDACTED]") {
		t.Fatalf("expected exact value redacted, got %q", out.String())
	}

	// Flush writes trailing partial line
	out.Reset()
	w.Write([]byte("tail secret sk-zyxwvutsrqponmlkjihgfedcba"))
	if out.Len() != 0 {
		t.Fatalf("expected no flush before Flush(), got %q", out.String())
	}
	w.Flush()
	if !strings.Contains(out.String(), "[REDACTED]") {
		t.Fatalf("expected trailing line redacted after flush, got %q", out.String())
	}
}

func TestSanitizingWriterExactValueAcrossChunks(t *testing.T) {
	var out bytes.Buffer
	s := scanner.New()
	val := "very-long-credential-token-abcdef123456"
	w := &sanitizingWriter{dst: &out, s: s, values: []string{val}}

	// Split the credential across two writes with a trailing newline.
	half := len(val) / 2
	w.Write([]byte("key=" + val[:half]))
	w.Write([]byte(val[half:] + "\n"))

	got := out.String()
	if strings.Contains(got, val) {
		t.Fatalf("credential leaked across chunks: %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("expected redaction, got %q", got)
	}
}

func TestRunPassthroughForwardsStdin(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not in PATH (Windows/sh-less environment)")
	}
	tmp := t.TempDir()
	script := tmp + "/stdin-echo.sh"
	content := "#!/bin/bash\nIFS= read -r line\necho \"GOT:$line\"\n"
	if err := os.WriteFile(script, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(script)
	cmd.Stdin = strings.NewReader("hello-from-test\n")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	var out bytes.Buffer
	s := scanner.New()
	w := &sanitizingWriter{dst: &out, s: s, values: nil}
	cmd.Stdout = w
	if err := cmd.Run(); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	w.Flush()
	if !strings.Contains(out.String(), "GOT:hello-from-test") {
		t.Fatalf("stdin not forwarded: %q", out.String())
	}
}

type mockBackend struct {
	values map[string]string
}

func (m *mockBackend) Resolve(_ context.Context, key string) (string, error) {
	if v, ok := m.values[key]; ok {
		return v, nil
	}
	return "", errors.New("not found")
}
func (m *mockBackend) List(context.Context) ([]backend.Entry, error) { return nil, nil }
func (m *mockBackend) Set(context.Context, string, string) error     { return nil }
func (m *mockBackend) Values(context.Context, int) ([]string, error) { return nil, nil }

func TestCheckPolicy_OverrideDeniesOnlyMatchingKeyAndCommand(t *testing.T) {
	cfg := &config.Config{}
	cfg.Policy.Overrides = []config.PolicyOverride{
		{SecretKey: "iria/api/xai", PolicyRule: config.PolicyRule{DeniedCommands: []string{"curl"}}},
	}

	if err := CheckPolicy("curl", []string{"iria/api/xai"}, cfg.Policy); err == nil {
		t.Fatal("expected denial for curl with iria/api/xai")
	}
	if err := CheckPolicy("wget", []string{"iria/api/xai"}, cfg.Policy); err != nil {
		t.Fatalf("wget must not be denied: %v", err)
	}
	// The override applies only when the secret key is actually in use.
	if err := CheckPolicy("curl", []string{"other-secret"}, cfg.Policy); err != nil {
		t.Fatalf("curl with unrelated secret must not be denied: %v", err)
	}
}

func TestCheckPolicy_DefaultDeniedCommands(t *testing.T) {
	cfg := &config.Config{}
	cfg.Policy.Default.DeniedCommands = []string{"sh", "bash"}

	if err := CheckPolicy("sh", []string{"any-key"}, cfg.Policy); err == nil {
		t.Fatal("expected default denial for sh")
	}
	if err := CheckPolicy("python3", []string{"any-key"}, cfg.Policy); err != nil {
		t.Fatalf("python3 must not be denied: %v", err)
	}
	// The default deny-list is command-based: it applies even when no
	// secrets are requested at all.
	if err := CheckPolicy("sh", nil, cfg.Policy); err == nil {
		t.Fatal("default denied command must fail even with no secrets")
	}
}

func TestCheckPolicy_CaseInsensitiveDenial(t *testing.T) {
	cfg := &config.Config{}
	cfg.Policy.Default.DeniedCommands = []string{"sh", "Curl"}
	cfg.Policy.Overrides = []config.PolicyOverride{
		{SecretKey: "iria/api/xai", PolicyRule: config.PolicyRule{DeniedCommands: []string{"Wget"}}},
	}

	denied := []struct {
		cmd  string
		keys []string
	}{
		{"SH", nil},
		{"Sh", nil},
		{"sh", nil},
		{"CURL", nil},
		{"curl", nil},
		{"Curl", nil},
		{"WGET", []string{"iria/api/xai"}},
		{"wget", []string{"iria/api/xai"}},
		{"Wget", []string{"iria/api/xai"}},
	}
	for _, tc := range denied {
		if err := CheckPolicy(tc.cmd, tc.keys, cfg.Policy); err == nil {
			t.Errorf("CheckPolicy(%q) = nil, want denial", tc.cmd)
		}
	}

	// 許可コマンド・無関係キーは大文字でも通ること。
	if err := CheckPolicy("PYTHON3", nil, cfg.Policy); err != nil {
		t.Errorf("CheckPolicy(PYTHON3) = %v, want nil", err)
	}
	if err := CheckPolicy("WGET", []string{"other-secret"}, cfg.Policy); err != nil {
		t.Errorf("CheckPolicy(WGET, unrelated key) = %v, want nil", err)
	}
}

func TestEnvVarName_DerivesSafeEnvName(t *testing.T) {
	cases := map[string]string{
		"iria/api/xai":     "XAI",
		"my-key-with-dash": "MY_KEY_WITH_DASH",
		"simple":           "SIMPLE",
		"a/b/C":            "C",
	}
	for key, want := range cases {
		if got := envVarName(key); got != want {
			t.Errorf("envVarName(%q) = %q, want %q", key, got, want)
		}
	}
}

func TestResolveEnvNames_RejectsCollisions(t *testing.T) {
	// 生成名同士の衝突: "a/b-foo" と "c/b_foo" はどちらも B_FOO になる。
	if _, err := resolveEnvNames(stringSlice{"a/b-foo", "c/b_foo"}, nil); err == nil {
		t.Error("resolveEnvNames accepted generated-name collision, want error")
	}
	// 明示エイリアスと生成名の衝突: "iria/api/xai" → XAI と "other:XAI"。
	if _, err := resolveEnvNames(stringSlice{"iria/api/xai", "other:XAI"}, nil); err == nil {
		t.Error("resolveEnvNames accepted alias collision with XAI, want error")
	}
	// 既存環境変数のシャドウイング: XAI が既に存在する場合。
	if _, err := resolveEnvNames(stringSlice{"iria/api/xai"}, []string{"XAI=old", "PATH=/usr/bin"}); err == nil {
		t.Error("resolveEnvNames shadowed existing XAI, want error")
	}

	// 衝突なしは通ること。
	names, err := resolveEnvNames(stringSlice{"iria/api/xai", "stats:USE_STATS"}, []string{"PATH=/usr/bin"})
	if err != nil {
		t.Fatalf("resolveEnvNames = %v, want nil", err)
	}
	if len(names) != 2 || names[0] != "XAI" || names[1] != "USE_STATS" {
		t.Fatalf("resolveEnvNames = %v, want [XAI USE_STATS]", names)
	}
}

func TestExtractSecretKeys_StripsEnvNameAliases(t *testing.T) {
	got := extractSecretKeys(stringSlice{"iria/api/xai", "other:MY_ENV"})
	want := []string{"iria/api/xai", "other"}
	if len(got) != len(want) {
		t.Fatalf("extractSecretKeys = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("extractSecretKeys = %v, want %v", got, want)
		}
	}
}

func TestResolveSecrets_AppendsEnvAndTracksValues(t *testing.T) {
	be := &mockBackend{values: map[string]string{
		"iria/api/xai": "sk-xai-secret-value",
		"stats":        "estat-appid-999",
		"my-key":       "dashed-key-value",
	}}

	cases := []struct {
		spec     string
		wantEnv  string
		wantCred string
	}{
		{"iria/api/xai", "XAI=sk-xai-secret-value", "sk-xai-secret-value"},
		{"stats:USE_STATS", "USE_STATS=estat-appid-999", "estat-appid-999"},
		{"my-key:OVERRIDE", "OVERRIDE=dashed-key-value", "dashed-key-value"},
	}

	for _, tc := range cases {
		base := len(os.Environ())
		env, cred, err := resolveSecrets(context.Background(), stringSlice{tc.spec}, be)
		if err != nil {
			t.Fatalf("resolveSecrets(%q) = %v, want nil", tc.spec, err)
		}
		if len(env) != base+1 {
			t.Fatalf("env grew to %d, want %d (base %d)", len(env), base+1, base)
		}
		if !slices.Contains(env, tc.wantEnv) {
			t.Errorf("env missing %q: got %v", tc.wantEnv, env)
		}
		if len(cred) != 1 || cred[0] != tc.wantCred {
			t.Errorf("credValues = %v, want [%q]", cred, tc.wantCred)
		}
	}
}

func TestResolveSecrets_MissingKeyReturnsError(t *testing.T) {
	be := &mockBackend{values: map[string]string{}}
	if _, _, err := resolveSecrets(context.Background(), stringSlice{"no-such-key"}, be); err == nil {
		t.Fatal("resolveSecrets with missing key = nil, want error (no os.Exit)")
	}
}

func TestResolveSecrets_CollisionReturnsError(t *testing.T) {
	be := &mockBackend{values: map[string]string{"a/b-foo": "v1", "c/b_foo": "v2"}}
	if _, _, err := resolveSecrets(context.Background(), stringSlice{"a/b-foo", "c/b_foo"}, be); err == nil {
		t.Fatal("resolveSecrets with colliding names = nil, want error")
	}
}

func TestBuildScanner_LoadsPolicyFilePatterns(t *testing.T) {
	dir := t.TempDir()
	policyPath := dir + "/policy.txt"
	if err := os.WriteFile(policyPath, []byte("# comment line\n\ncustom-token-[a-z0-9]{12}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	s, err := buildScanner(true, config.Default(), policyPath)
	if err != nil {
		t.Fatalf("buildScanner = %v, want nil", err)
	}
	if s == nil {
		t.Fatal("buildScanner returned nil")
	}
	out := s.ScanWithValues([]byte("leak custom-token-abcdef123456 here"), nil)
	if !strings.Contains(string(out), "[REDACTED]") {
		t.Fatalf("custom pattern not applied: %q", out)
	}
	if strings.Contains(string(out), "custom-token-abcdef123456") {
		t.Fatalf("pattern value leaked: %q", out)
	}
}

func TestBuildScanner_DisabledReturnsNil(t *testing.T) {
	s, err := buildScanner(false, config.Default(), "")
	if err != nil {
		t.Fatalf("buildScanner = %v, want nil", err)
	}
	if s != nil {
		t.Fatal("buildScanner with sanitize=false must return nil")
	}
}

func TestBuildScanner_ErrorPaths(t *testing.T) {
	badCfg := config.Default()
	badCfg.Sanitize.Patterns = []string{"(["}
	if _, err := buildScanner(true, badCfg, ""); err == nil {
		t.Error("buildScanner with invalid config pattern = nil, want error")
	}
	if _, err := buildScanner(true, config.Default(), "/nonexistent/policy.txt"); err == nil {
		t.Error("buildScanner with missing policy file = nil, want error")
	}
	dir := t.TempDir()
	badPath := dir + "/bad-policy.txt"
	if err := os.WriteFile(badPath, []byte("([invalid\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := buildScanner(true, config.Default(), badPath); err == nil {
		t.Error("buildScanner with invalid policy pattern = nil, want error")
	}
}

func TestRunJSON_ReportsExitCodeAndSanitizesOutput(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not in PATH (Windows/sh-less environment)")
	}
	s := scanner.New()
	values := []string{"sekrit-plain-value-123456"}
	cmd := exec.Command("sh", "-c",
		`echo "leak sk-abcdefghijklmnopqrstuvwxyz"; echo "exact sekrit-plain-value-123456" >&2; exit 3`)

	// runJSON writes to the injected writer — no os.Stdout swapping.
	var out bytes.Buffer
	if err := runJSON(cmd, true, s, values, &out); err != nil {
		t.Fatalf("runJSON = %v, want nil", err)
	}

	var res runResult
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out.String())
	}
	if res.ExitCode != 3 {
		t.Fatalf("exit_code = %d, want 3", res.ExitCode)
	}
	if strings.Contains(res.Stdout, "sk-abcdefghijklmnopqrstuvwxyz") {
		t.Fatalf("pattern credential leaked in stdout: %q", res.Stdout)
	}
	if !strings.Contains(res.Stdout, "[REDACTED]") {
		t.Fatalf("stdout not sanitized: %q", res.Stdout)
	}
	if strings.Contains(res.Stderr, "sekrit-plain-value-123456") {
		t.Fatalf("exact credential leaked in stderr: %q", res.Stderr)
	}
	if !strings.Contains(res.Stderr, "[REDACTED]") {
		t.Fatalf("stderr not sanitized: %q", res.Stderr)
	}
}

func TestRunJSON_StartFailureReturnsError(t *testing.T) {
	cmd := exec.Command("trustless-nonexistent-binary-xyz")
	var out bytes.Buffer
	if err := runJSON(cmd, false, nil, nil, &out); err == nil {
		t.Fatal("runJSON with missing binary = nil, want error (no os.Exit)")
	}
}

func TestRunJSON_WritesNothingOnStartFailure(t *testing.T) {
	cmd := exec.Command("trustless-nonexistent-binary-xyz")
	var out bytes.Buffer
	_ = runJSON(cmd, false, nil, nil, &out)
	if out.Len() != 0 {
		t.Fatalf("runJSON wrote %q before start failure, want no output", out.String())
	}
}
