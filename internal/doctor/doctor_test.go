package doctor

import (
	"testing"
)

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
