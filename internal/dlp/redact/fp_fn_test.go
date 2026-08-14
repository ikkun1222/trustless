// FP/FN マトリクス: パターン第2層（gitleaks 互換ルール）の実運用品質を担保する。
// FN ケース（検出すべき秘密を検出して Marker で置換する）と FP ケース
// （平文・疑似秘密を素通しして本文を無変更で残す）を固定テストにする。
// 使用 API は public な Scan / ScanAll のみ。内部構造には依存しない。
// ダミーキーはすべてテスト内で生成する（実シークレットなし・外部 API 呼び出しなし）。
package redact

import (
	"math/rand/v2"
	"strings"
	"testing"
)

// randFrom returns n characters drawn from charset using a seeded PRNG.
// A fixed seed keeps every run deterministic and the assertions stable.
func randFrom(charset string, n int) string {
	rng := rand.New(rand.NewPCG(1, 2)) // fixed seed
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[rng.IntN(len(charset))]
	}
	return string(b)
}

func randBase62(n int) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	return randFrom(charset, n)
}

func randDigits(n int) string {
	return randFrom("0123456789", n)
}

// mustRedact scans text and asserts the entire secret is gone: changed=true,
// the output contains the Marker, and no fragment of the dummy leaks out.
func mustRedact(t *testing.T, text, dummy string) {
	t.Helper()
	out, changed := loadDefault(t).Scan(text)
	if !changed {
		t.Fatalf("expected changed=true for %q, got unchanged output %q", dummy, out)
	}
	mustNotContainAny(t, out, dummy)
	if !strings.Contains(out, Marker) {
		t.Fatalf("expected %q marker in output, got %q", Marker, out)
	}
}

// ---- FN: 検出すべき秘密（高エントロピー・形式一致）は必ず置換される ----

func Test第2層は各サービス形式のキーをマスクする(t *testing.T) {
	cases := []struct {
		name  string
		dummy string
	}{
		{
			name:  "openai 新形式 (sk-proj-)",
			dummy: "sk-proj-" + randBase62(58) + "T3BlbkFJ" + randBase62(58),
		},
		{
			name:  "openai 旧形式 (sk-)",
			dummy: "sk-" + randBase62(20) + "T3BlbkFJ" + randBase62(20),
		},
		{
			name:  "anthropic (sk-ant-api03-)",
			dummy: "sk-ant-api03-" + randBase62(93) + "AA",
		},
		{
			name:  "github pat (ghp_)",
			dummy: "ghp_" + randBase62(36),
		},
		{
			name:  "github fine-grained pat (github_pat_)",
			dummy: "github_pat_" + randBase62(82),
		},
		{
			name:  "aws access key (AKIA)",
			dummy: "AKIA" + randFrom("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16),
		},
		{
			name:  "gcp api key (AIza)",
			dummy: "AIza" + randFrom("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-", 35),
		},
		{
			name:  "slack bot token (xoxb-)",
			dummy: "xoxb-" + randDigits(12) + "-" + randDigits(12),
		},
		{
			name:  "slack user token (xoxp-)",
			dummy: "xoxp-" + randDigits(12) + "-" + randDigits(12) + "-" + randDigits(12) + "-" + randBase62(28),
		},
		{
			name:  "stripe (sk_live_)",
			dummy: "sk_live_" + randBase62(24),
		},
		{
			name:  "jwt",
			dummy: "eyJhbGciOiJIUzI1NiJ9." + "ey" + randBase62(28) + "." + randBase62(40),
		},
		{
			name: "private key",
			dummy: "-----BEGIN RSA PRIVATE KEY-----\n" + randBase62(80) +
				"\n-----END RSA PRIVATE KEY-----",
		},
		{
			name:  "telegram bot token",
			dummy: "telegram token 123456789:AA" + randFrom("abcdefghijklmnopqrstuvwxyz0123456789_-", 34),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mustRedact(t, "the secret is "+tc.dummy+" end", tc.dummy)
		})
	}
}

// ---- FP: 平文・疑似秘密・低エントロピー値は無変更で素通しされる ----

func Test第2層は平文と疑似秘密を誤検出しない(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{
			name: "低エントロピー sk- プレースホルダ",
			text: "sk-" + strings.Repeat("a", 40),
		},
		{
			name: "低エントロピー ghp_ プレースホルダ",
			text: "ghp_" + strings.Repeat("a", 36),
		},
		{
			name: "base64 データを含む散文",
			text: "The attachment is a JPEG: /9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/wAALCAABAAEBAREA/8QAFAABAAAAAAAAAAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAD8AVN//2Q==",
		},
		{
			name: "標準 UUID と sha256 ハッシュ",
			text: "reference 6d2f10e2-9a4b-4c7e-b2f8-1e5a3d7c9b0a hashes 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		},
		{
			name: "鍵形式でない平文散文",
			text: "The api key is configured via environment variables. task-12345 must be reviewed. The ey is a letter and sk- is a substring of plain English words.",
		},
		{
			name: "コード断片 (placeholder 値)",
			text: `const key = "placeholder";`,
		},
		{
			name: "JSON プレースホルダ値",
			text: `{"token": "placeholder", "apiKey": "configured"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, changed := loadDefault(t).Scan(tc.text)
			if changed {
				t.Fatalf("expected changed=false for %q, got %q", tc.text, out)
			}
			if out != tc.text {
				t.Fatalf("output differs from input: %q", out)
			}
		})
	}
}
