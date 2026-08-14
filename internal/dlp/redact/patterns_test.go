package redact

import (
	"strings"
	"sync"
	"testing"
)

// loadDefault returns the bundled PatternSet, failing the test if the
// embedded rules.toml cannot be loaded. All tests here use the real
// shipped asset so detection behavior is exercised against the rules that
// will run in production.
func loadDefault(t *testing.T) *PatternSet {
	t.Helper()
	ps, err := DefaultPatterns()
	if err != nil {
		t.Fatalf("DefaultPatterns: %v", err)
	}
	return ps
}

// mustNotContainAny asserts that none of the needles appears in s.
func mustNotContainAny(t *testing.T, s string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if strings.Contains(s, n) {
			t.Fatalf("secret leaked in output: %q contains %q", s, n)
		}
	}
}

// ---- detection (dummy high-entropy keys) ----

func TestScan_OpenAIProjKey(t *testing.T) {
	// The bundled openai-api-key rule matches sk-proj- + 74 (or 58) chars +
	// T3BlbkFJ + 74 (or 58) chars, all base62-ish.
	seg := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" +
		"abcdefghijkl" // 62 + 12 = 74
	if len(seg) != 74 {
		t.Fatalf("fixture: 74-char segment required, got %d", len(seg))
	}
	dummy := "sk-proj-" + seg + "T3BlbkFJ" + seg
	out, changed := loadDefault(t).Scan("the key is " + dummy + " end")
	if !changed {
		t.Fatalf("expected changed=true for OpenAI key")
	}
	mustNotContainAny(t, out, dummy)
	if !strings.Contains(out, Marker) {
		t.Fatalf("expected %q marker in output, got %q", Marker, out)
	}
}

func TestScan_GitHubPAT(t *testing.T) {
	// Deterministic 36-char token body (a-zA-Z0-9), high entropy.
	dummy := "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if len(dummy) != 4+36 {
		t.Fatalf("fixture: ghp_ + 36 chars required, got %d", len(dummy))
	}
	out, changed := loadDefault(t).Scan("token: " + dummy + " in text")
	if !changed {
		t.Fatalf("expected changed=true for GitHub PAT")
	}
	mustNotContainAny(t, out, dummy)
}

func TestScan_AWSAccessKey(t *testing.T) {
	dummy := "AKIA" + "ABCDEFGHIJKLMNOP"
	if len(dummy) != 4+16 {
		t.Fatalf("fixture: AKIA + 16 chars required, got %d", len(dummy))
	}
	out, changed := loadDefault(t).Scan("aws access key " + dummy + " here")
	if !changed {
		t.Fatalf("expected changed=true for AWS access key")
	}
	mustNotContainAny(t, out, dummy)
}

func TestScan_JWT(t *testing.T) {
	dummy := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	out, changed := loadDefault(t).Scan("token " + dummy + " end")
	if !changed {
		t.Fatalf("expected changed=true for JWT")
	}
	mustNotContainAny(t, out, dummy)
}

func TestScan_PrivateKey(t *testing.T) {
	body := strings.Repeat("MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwgg", 5) // 180 chars, high entropy
	dummy := "-----BEGIN RSA PRIVATE KEY-----\n" + body + "\n-----END RSA PRIVATE KEY-----"
	if len(dummy) <= 100 {
		t.Fatalf("fixture: key body must exceed 100 chars, got %d", len(dummy))
	}
	out, changed := loadDefault(t).Scan("leaked key:\n" + dummy + "\nend")
	if !changed {
		t.Fatalf("expected changed=true for private key")
	}
	mustNotContainAny(t, out, "BEGIN RSA PRIVATE KEY")
}

func TestScan_StripeKey(t *testing.T) {
	dummy := "sk_live_51HxYtZAbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefghijklmnopqrstuvwxyz"
	out, changed := loadDefault(t).Scan("stripe " + dummy + " now")
	if !changed {
		t.Fatalf("expected changed=true for Stripe key")
	}
	mustNotContainAny(t, out, dummy)
}

// ---- false-positive suppression ----

func TestScan_LowEntropyKeywordMatchPasses(t *testing.T) {
	// "sk-" matches the twilio keyword gate but the value is a single
	// repeated char — entropy 0, below every threshold.
	dummy := "sk-" + strings.Repeat("a", 40)
	out, changed := loadDefault(t).Scan("value " + dummy + " end")
	if changed {
		t.Fatalf("low-entropy string must pass through, got %q", out)
	}
	if !strings.Contains(out, dummy) {
		t.Fatalf("low-entropy string must remain in output: %q", out)
	}
}

func TestScan_ShortJwtLikePasses(t *testing.T) {
	// "ey" gates the jwt rule, but "ey" alone is far below the 17-char
	// minimum in the regex and has entropy 0.
	out, changed := loadDefault(t).Scan("the word ey appears in prose")
	if changed {
		t.Fatalf("plain text must pass through, got %q", out)
	}
	if !strings.Contains(out, "ey") {
		t.Fatalf("plain text must remain unchanged: %q", out)
	}
}

// ---- plain text and code pass through ----

func TestScan_PlainProseUntouched(t *testing.T) {
	prose := "The quick brown fox jumps over the lazy dog. Please send the report to " +
		"someone@example.com by Friday, and remember to water the plants."
	out, changed := loadDefault(t).Scan(prose)
	if changed {
		t.Fatalf("prose must pass through unchanged, got %q", out)
	}
	if out != prose {
		t.Fatalf("output differs from input: %q", out)
	}
}

func TestScan_CodeSnippetUntouched(t *testing.T) {
	// apiKey=… triggers the generic-api-key keyword gate, but the value is
	// a low-entropy placeholder.
	code := `const apiKey = "configured via env";`
	out, changed := loadDefault(t).Scan(code)
	if changed {
		t.Fatalf("code snippet must pass through unchanged, got %q", out)
	}
	if out != code {
		t.Fatalf("output differs from input: %q", out)
	}
}

// ---- known-value layer (ScanAndRedact) coexists with the pattern layer ----

func TestScanAll_KnownValueAndPatternNoDoubleMask(t *testing.T) {
	known := "sk-known-secret-value-abc123"
	seg := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" +
		"abcdefghijkl" // 62 + 12 = 74
	pat := "sk-proj-" + seg + "T3BlbkFJ" + seg
	out, changed := ScanAll("known="+known+" pat="+pat, []string{known}, 8, loadDefault(t))
	if !changed {
		t.Fatal("expected changed=true")
	}
	mustNotContainAny(t, out, known, pat)
	if strings.Count(out, Marker) != 2 {
		t.Fatalf("expected exactly 2 markers (no double mask), got %d in %q", strings.Count(out, Marker), out)
	}
}

func TestScanAll_KnownValueOnly(t *testing.T) {
	known := "sk-known-secret-value-abc123"
	out, changed := ScanAll("key "+known, []string{known}, 8, loadDefault(t))
	if !changed {
		t.Fatal("expected changed=true")
	}
	mustNotContainAny(t, out, known)
	if strings.Count(out, Marker) != 1 {
		t.Fatalf("expected exactly 1 marker, got %d in %q", strings.Count(out, Marker), out)
	}
}

// ---- marker verification ----

func TestScan_MarkerShape(t *testing.T) {
	seg := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" +
		"abcdefghijkl" // 62 + 12 = 74
	pat := "sk-proj-" + seg + "T3BlbkFJ" + seg
	out, changed := loadDefault(t).Scan("key " + pat)
	if !changed {
		t.Fatal("expected changed=true")
	}
	if !strings.Contains(out, "<redacted>") {
		t.Fatalf("expected <redacted> marker, got %q", out)
	}
	if strings.Contains(out, "[REDACTED]") {
		t.Fatalf("must not contain [REDACTED], got %q", out)
	}
}

// ---- backward compatibility ----

func TestScanAll_NilPatternsIsLayer1Only(t *testing.T) {
	out, changed := ScanAll("hello world", nil, 0, nil)
	if changed {
		t.Fatalf("expected changed=false with nil patterns and no known secrets")
	}
	if out != "hello world" {
		t.Fatalf("expected unchanged text, got %q", out)
	}
}

func TestScan_NilAndEmptySets(t *testing.T) {
	var nilSet *PatternSet
	if out, changed := nilSet.Scan("sk-proj-anything"); changed || out != "sk-proj-anything" {
		t.Fatalf("nil set must be a no-op, got changed=%v out=%q", changed, out)
	}
	empty, err := LoadPatterns([]byte("rules = []\n"))
	if err == nil {
		t.Fatal("expected error for empty rule set")
	}
	_ = empty
}

// ---- LoadPatterns validation ----

func TestLoadPatterns_InvalidTOML(t *testing.T) {
	if _, err := LoadPatterns([]byte("this is [[[not toml")); err == nil {
		t.Fatal("expected error for invalid TOML")
	}
}

func TestLoadPatterns_DuplicateIDs(t *testing.T) {
	data := `
[[rules]]
id = "dup"
regex = "abc"
[[rules]]
id = "dup"
regex = "def"
`
	if _, err := LoadPatterns([]byte(data)); err == nil {
		t.Fatal("expected error for duplicate rule ids")
	}
}

func TestLoadPatterns_UncompilableRegex(t *testing.T) {
	data := `
[[rules]]
id = "bad"
regex = "([unclosed"
`
	if _, err := LoadPatterns([]byte(data)); err == nil {
		t.Fatal("expected error for uncompilable regex")
	}
}

func TestLoadPatterns_EmptyRules(t *testing.T) {
	if _, err := LoadPatterns([]byte("rules = []\n")); err == nil {
		t.Fatal("expected error for zero rules")
	}
}

// ---- hot-swap (Replace / Has / Filter) ----

// testTwoRules returns a set with two distinct rules: "test-openai"
// (sk-proj-…, keywords ["sk-proj-"]) and "test-aws" (AKIA…, keywords
// ["akia"]). Helpers used by the swap tests below.
func testTwoRules(t *testing.T) *PatternSet {
	t.Helper()
	ps, err := LoadPatterns([]byte(`
[[rules]]
id = "test-openai"
description = "openai rule"
regex = '''sk-proj-[A-Za-z0-9]{40}'''
keywords = ["sk-proj-"]
entropy = 3.0
[[rules]]
id = "test-aws"
description = "aws rule"
regex = '''AKIA[A-Z0-9]{16}'''
keywords = ["akia"]
entropy = 3.0
`))
	if err != nil {
		t.Fatalf("LoadPatterns: %v", err)
	}
	return ps
}

// highEntropy62 returns the first n characters of a 62-char alphabet so the
// match clears the entropy threshold.
func highEntropy62(n int) string {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	return alpha[:n]
}

// TestPatternSet_ReplaceSwapsRules verifies that Replace atomically swaps
// the rule set: the same PatternSet instance starts detecting pattern A,
// and after Replace detects pattern B instead.
func TestPatternSet_ReplaceSwapsRules(t *testing.T) {
	oldSet, err := LoadPatterns([]byte(`
[[rules]]
id = "old-rule"
regex = '''sk-proj-[A-Za-z0-9]{40}'''
keywords = ["sk-proj-"]
entropy = 3.0
`))
	if err != nil {
		t.Fatalf("LoadPatterns(old): %v", err)
	}
	newSet, err := LoadPatterns([]byte(`
[[rules]]
id = "new-rule"
regex = '''ghp_[A-Za-z0-9]{36}'''
keywords = ["ghp_"]
entropy = 3.0
`))
	if err != nil {
		t.Fatalf("LoadPatterns(new): %v", err)
	}

	patA := "sk-proj-" + highEntropy62(40)
	patB := "ghp_" + highEntropy62(36)
	shared := oldSet // リロードで中身が差し替わる共有インスタンス

	if out, changed := shared.Scan("key " + patA + " end"); !changed || strings.Contains(out, patA) {
		t.Fatalf("pre-swap: expected patA detected, got changed=%v out=%q", changed, out)
	}
	if out, changed := shared.Scan("key " + patB + " end"); changed || !strings.Contains(out, patB) {
		t.Fatalf("pre-swap: patB must pass through, got changed=%v out=%q", changed, out)
	}

	shared.Replace(newSet)

	if out, changed := shared.Scan("key " + patA + " end"); changed || !strings.Contains(out, patA) {
		t.Fatalf("post-swap: patA must pass through, got changed=%v out=%q", changed, out)
	}
	if out, changed := shared.Scan("key " + patB + " end"); !changed || strings.Contains(out, patB) {
		t.Fatalf("post-swap: expected patB detected, got changed=%v out=%q", changed, out)
	}
}

// TestPatternSet_ReplaceConcurrentScan verifies that Scan racing Replace is
// race-free: goroutines scan while the shared set is repeatedly swapped
// between two rule sets. Run under -race.
func TestPatternSet_ReplaceConcurrentScan(t *testing.T) {
	oldSet := testTwoRules(t)
	newSet, err := LoadPatterns([]byte(`
[[rules]]
id = "test-aws"
regex = '''AKIA[A-Z0-9]{16}'''
keywords = ["akia"]
entropy = 3.0
`))
	if err != nil {
		t.Fatalf("LoadPatterns(new): %v", err)
	}

	patOpenAI := "sk-proj-" + highEntropy62(40)
	patAWS := "AKIA" + highEntropy62(16)
	shared := oldSet

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = shared.Scan("key " + patOpenAI + " and " + patAWS + " end")
				}
			}
		}()
	}
	for i := 0; i < 200; i++ {
		shared.Replace(newSet)
		shared.Replace(oldSet)
	}
	close(stop)
	wg.Wait()
}

// TestPatternSet_Has verifies Has reports rule existence.
func TestPatternSet_Has(t *testing.T) {
	ps := testTwoRules(t)
	if !ps.Has("test-openai") {
		t.Fatal("expected Has(test-openai)=true")
	}
	if !ps.Has("test-aws") {
		t.Fatal("expected Has(test-aws)=true")
	}
	if ps.Has("nope") {
		t.Fatal("expected Has(nope)=false")
	}
	if ps.Has("") {
		t.Fatal("expected Has(\"\")=false")
	}
}

// TestPatternSet_FilterRemovesRules verifies Filter excludes the disabled ids
// while keeping the rest, and that the returned set behaves accordingly.
func TestPatternSet_FilterRemovesRules(t *testing.T) {
	ps := testTwoRules(t)
	filtered, err := ps.Filter([]string{"test-aws"})
	if err != nil {
		t.Fatalf("Filter: %v", err)
	}
	if filtered.Has("test-aws") {
		t.Fatal("disabled rule must be excluded")
	}
	if !filtered.Has("test-openai") {
		t.Fatal("non-disabled rule must remain")
	}

	patAWS := "AKIA" + highEntropy62(16)
	if out, changed := filtered.Scan("key " + patAWS + " end"); changed || !strings.Contains(out, patAWS) {
		t.Fatalf("disabled rule must not detect, got changed=%v out=%q", changed, out)
	}
	patOpenAI := "sk-proj-" + highEntropy62(40)
	if out, changed := filtered.Scan("key " + patOpenAI + " end"); !changed || strings.Contains(out, patOpenAI) {
		t.Fatalf("kept rule must still detect, got changed=%v out=%q", changed, out)
	}
	// 元のセットは不変（Filter は新しいセットを返す）。
	if !ps.Has("test-aws") {
		t.Fatal("Filter must not mutate the original set")
	}
}

// TestPatternSet_FilterUnknownIDErrors verifies Filter fails on an unknown
// id (fail-closed: typo detection).
func TestPatternSet_FilterUnknownIDErrors(t *testing.T) {
	ps := testTwoRules(t)
	if _, err := ps.Filter([]string{"test-typo"}); err == nil {
		t.Fatal("expected error for unknown rule id")
	}
}

// TestPatternSet_FilterEmptyIDErrors verifies Filter rejects an empty id.
func TestPatternSet_FilterEmptyIDErrors(t *testing.T) {
	ps := testTwoRules(t)
	if _, err := ps.Filter([]string{""}); err == nil {
		t.Fatal("expected error for empty rule id")
	}
}

// TestPatternSet_FilterDuplicateIDs verifies duplicate ids are harmless
// (deduplicated) and do not error.
func TestPatternSet_FilterDuplicateIDs(t *testing.T) {
	ps := testTwoRules(t)
	filtered, err := ps.Filter([]string{"test-aws", "test-aws"})
	if err != nil {
		t.Fatalf("Filter with duplicates: %v", err)
	}
	if filtered.Has("test-aws") {
		t.Fatal("disabled rule must be excluded")
	}
	if !filtered.Has("test-openai") {
		t.Fatal("non-disabled rule must remain")
	}
}
