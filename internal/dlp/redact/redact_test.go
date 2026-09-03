package redact

import (
	"strings"
	"testing"
)

func TestScanAndRedact_Basic(t *testing.T) {
	secrets := []string{"sk-supersecretkey1234567890"}
	out, changed := ScanAndRedact("call api with sk-supersecretkey1234567890 now", secrets, 8)
	if !changed {
		t.Fatal("expected changed=true")
	}
	if strings.Contains(out, "sk-supersecretkey1234567890") {
		t.Fatalf("secret leaked in output: %q", out)
	}
	if !strings.Contains(out, "<redacted>") {
		t.Fatalf("expected <redacted> marker, got %q", out)
	}
}

func TestScanAndRedact_MidString(t *testing.T) {
	// Secret appears as a substring inside a larger blob (e.g. pasted config).
	secrets := []string{"xoxb-1234567890-abcdefghij"}
	blob := "token=\"xoxb-1234567890-abcdefghij\""
	out, changed := ScanAndRedact(blob, secrets, 8)
	if !changed {
		t.Fatal("expected changed=true")
	}
	if strings.Contains(out, "xoxb-1234567890-abcdefghij") {
		t.Fatalf("secret leaked: %q", out)
	}
}

func TestScanAndRedact_MultipleSecrets(t *testing.T) {
	secrets := []string{"firstsecretvalue123", "secondsecretvalue456"}
	out, changed := ScanAndRedact("a firstsecretvalue123 and secondsecretvalue456", secrets, 8)
	if !changed {
		t.Fatal("expected changed=true")
	}
	if strings.Contains(out, "firstsecretvalue123") || strings.Contains(out, "secondsecretvalue456") {
		t.Fatalf("secrets leaked: %q", out)
	}
}

func TestScanAndRedact_ShortSecretExcluded(t *testing.T) {
	// Secrets shorter than minLen must NOT match (avoids prose destruction).
	secrets := []string{"abc"}
	out, changed := ScanAndRedact("the alphabet starts with abc and ends with z", secrets, 8)
	if changed {
		t.Fatalf("expected no change for short secret, got %q", out)
	}
	if !strings.Contains(out, "abc") {
		t.Fatalf("short secret should be untouched: %q", out)
	}
}

func TestScanAndRedact_NoMatch(t *testing.T) {
	secrets := []string{"nope-nothing-here-12345"}
	out, changed := ScanAndRedact("this text has no secrets", secrets, 8)
	if changed {
		t.Fatalf("expected changed=false, got %q", out)
	}
	if out != "this text has no secrets" {
		t.Fatalf("output should be unchanged, got %q", out)
	}
}

func TestScanAndRedact_LongerSecretFirst(t *testing.T) {
	// If a short secret is a substring of a long one, masking the short one
	// first would leave the long one's remainder leaking. Longest-first
	// ordering must prevent that.
	secrets := []string{"prefix-super-common", "super-common"}
	out, changed := ScanAndRedact("token prefix-super-common here", secrets, 4)
	if !changed {
		t.Fatal("expected changed=true")
	}
	if strings.Contains(out, "super-common") {
		t.Fatalf("short-secret remainder leaked after masking: %q", out)
	}
	if strings.Contains(out, "prefix-") {
		t.Fatalf("long secret prefix leaked: %q", out)
	}
}

func TestScanAndRedact_EmptyInput(t *testing.T) {
	secrets := []string{"somethinglongenough123"}
	out, changed := ScanAndRedact("", secrets, 8)
	if changed || out != "" {
		t.Fatalf("expected empty unchanged, got changed=%v out=%q", changed, out)
	}
}

func TestScanAndRedact_EmptySecrets(t *testing.T) {
	out, changed := ScanAndRedact("hello world", nil, 8)
	if changed || out != "hello world" {
		t.Fatalf("expected unchanged, got changed=%v out=%q", changed, out)
	}
}

func TestScanAndRedact_ExactLengthAtMin(t *testing.T) {
	// A secret exactly at minLen must still match (>= not >).
	secrets := []string{"12345678"}
	out, changed := ScanAndRedact("value 12345678 end", secrets, 8)
	if !changed {
		t.Fatal("expected changed=true for secret at min length")
	}
	if strings.Contains(out, "12345678") {
		t.Fatalf("secret leaked: %q", out)
	}
}

func TestScanAndRedact_EmailAddressNotMasked(t *testing.T) {
	// Email addresses are identifiers, not credentials. They appear
	// naturally in diffs, docs, and message footers, so masking them
	// destroys readability for zero security value. (2026-08-07: the
	// xiaomi/credentials pass entry stores the account email on line 1,
	// which caused <redacted> spam in every conversation containing a
	// diff with the address.)
	email := "someone@example.com"
	out, changed := ScanAndRedact("send report to "+email+" now", []string{email}, 8)
	if changed {
		t.Fatalf("email address should NOT be masked, got %q", out)
	}
	if !strings.Contains(out, email) {
		t.Fatalf("email address must pass through unchanged: %q", out)
	}
}

func TestIsEmail_Boundaries(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"admin@example.com", true},
		{"someone@example.co.jp", true},
		{"a@b.c", false},                  // TLD 1 文字は email でない → credential として残る
		{"user name@corp.example", false}, // 空白入りは email でない
		{"admin@exa mple.com", false},     // ドメイン内空白は email でない
		{"a@@b.com", false},               // @ 複数は拒否
		{"@example.com", false},           // 先頭 @（ローカル部空）は拒否
		{"admin@", false},                 // ドメイン部空は拒否
		{"admin@example", false},          // ドットなしドメインは拒否
		{"not-an-email", false},           // @ なしは拒否
		{"", false},
	}
	for _, tc := range cases {
		if got := IsEmail(tc.in); got != tc.want {
			t.Errorf("IsEmail(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestScanAndRedact_ShortIdentifierIsMasked(t *testing.T) {
	// a@b.c は email 扱いされないため、credential としてマスキングされる。
	secret := "a@b.c"
	out, changed := ScanAndRedact("token "+secret+" end", []string{secret}, 1)
	if !changed {
		t.Fatalf("expected changed=true for non-email identifier, got %q", out)
	}
	if strings.Contains(out, secret) {
		t.Fatalf("credential leaked: %q", out)
	}
}

func TestScanAndRedact_MixedEmailAndSecret(t *testing.T) {
	// A real secret alongside an email: only the secret is masked.
	secret := "sk-real-secret-abcdef123456"
	email := "someone@example.com"
	out, changed := ScanAndRedact(
		"user "+email+" key "+secret+" end", []string{secret, email}, 8)
	if !changed {
		t.Fatal("expected changed=true")
	}
	if strings.Contains(out, secret) {
		t.Fatalf("secret leaked: %q", out)
	}
	if !strings.Contains(out, email) {
		t.Fatalf("email must survive: %q", out)
	}
}
