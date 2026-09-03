package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withHome runs fn with HOME pointed at a fresh temp dir so agent detection
// reads only the fixtures the test creates.
func withHome(t *testing.T, fn func(home string)) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	fn(home)
}

func TestFindSkillDir_AgentLayouts(t *testing.T) {
	withHome(t, func(home string) {
		cases := map[string]string{
			"opencode":    filepath.Join(home, ".config", "opencode", "skills", "trustless-usage"),
			"claude-code": filepath.Join(home, ".claude", "skills", "trustless-usage"),
			"codex":       filepath.Join(home, ".codex", "skills", "trustless-usage"),
			"hermes":      filepath.Join(home, ".hermes", "skills", "credential-management", "trustless-usage"),
		}
		for agent, want := range cases {
			got, err := findSkillDir(agent)
			if err != nil {
				t.Fatalf("findSkillDir(%q): %v", agent, err)
			}
			if got != want {
				t.Errorf("findSkillDir(%q) = %q, want %q", agent, got, want)
			}
		}
		if _, err := findSkillDir("unknown-agent"); err == nil {
			t.Fatal("findSkillDir with unknown agent must error")
		}
	})
}

func TestInstallTrustlessSkill_WritesSkillFile(t *testing.T) {
	withHome(t, func(home string) {
		if err := InstallTrustlessSkill("opencode"); err != nil {
			t.Fatalf("InstallTrustlessSkill: %v", err)
		}
		skillPath := filepath.Join(home, ".config", "opencode", "skills", "trustless-usage", "SKILL.md")
		data, err := os.ReadFile(skillPath)
		if err != nil {
			t.Fatalf("SKILL.md not written: %v", err)
		}
		if !strings.HasPrefix(string(data), "# trustless-usage") {
			t.Fatalf("SKILL.md unexpected content: %q", data[:40])
		}
	})
	if err := InstallTrustlessSkill("bogus"); err == nil {
		t.Fatal("InstallTrustlessSkill with unknown agent must error")
	}
}

func TestDetectOpenCode_NoConfigReturnsNil(t *testing.T) {
	withHome(t, func(_ string) {
		res, err := DetectOpenCode()
		if err != nil {
			t.Fatalf("DetectOpenCode: %v", err)
		}
		if res != nil {
			t.Fatalf("expected nil, got %+v", res)
		}
	})
}

func TestDetectOpenCode_FindsRawAPIKeys(t *testing.T) {
	withHome(t, func(home string) {
		cfg := filepath.Join(home, ".config", "opencode", "providers.yaml")
		writeTestFile(t, cfg, "providers:\n  xai:\n    apiKey: sk-raw-value-123\n")

		res, err := DetectOpenCode()
		if err != nil {
			t.Fatalf("DetectOpenCode: %v", err)
		}
		if res == nil {
			t.Fatal("expected detection result")
		}
		if !res.NeedsChange {
			t.Fatal("raw apiKey must trigger NeedsChange")
		}
		if !strings.Contains(res.Description, "1 apiKey") {
			t.Fatalf("description = %q, want mention of 1 apiKey", res.Description)
		}
	})
}

func TestDetectOpenCode_TrustlessWrappedIsClean(t *testing.T) {
	withHome(t, func(home string) {
		cfg := filepath.Join(home, ".config", "opencode", "providers.yaml")
		writeTestFile(t, cfg, "providers:\n  xai:\n    apiKey: $(trustless get iria/api/xai)\n")

		res, err := DetectOpenCode()
		if err != nil {
			t.Fatalf("DetectOpenCode: %v", err)
		}
		if res == nil || res.NeedsChange {
			t.Fatalf("trustless-wrapped key must not need change, got %+v", res)
		}
	})
}

func TestDetectOpenCode_ConfigDirOverrideWins(t *testing.T) {
	withHome(t, func(_ string) {
		cfgDir := t.TempDir()
		t.Setenv("OPENCODE_CONFIG_DIR", cfgDir)
		writeTestFile(t, filepath.Join(cfgDir, "opencode.json"), "providers:\n  apiKey: sk-raw-12345\n")

		res, err := DetectOpenCode()
		if err != nil {
			t.Fatalf("DetectOpenCode: %v", err)
		}
		if res == nil || !res.NeedsChange {
			t.Fatalf("expected detection via OPENCODE_CONFIG_DIR, got %+v", res)
		}
		if res.ConfigPath != filepath.Join(cfgDir, "opencode.json") {
			t.Fatalf("ConfigPath = %q, want %q", res.ConfigPath, filepath.Join(cfgDir, "opencode.json"))
		}
	})
}

func TestDetectClaudeCode_EnvFileStatus(t *testing.T) {
	withHome(t, func(home string) {
		cfg := filepath.Join(home, ".claude", ".claude.env")

		writeTestFile(t, cfg, "export ANTHROPIC_API_KEY=sk-raw-12345\n")
		res, err := DetectClaudeCode()
		if err != nil {
			t.Fatalf("DetectClaudeCode: %v", err)
		}
		if res == nil || !res.NeedsChange {
			t.Fatalf("unwrapped env file must need change, got %+v", res)
		}

		writeTestFile(t, cfg, "export TRUSTLESS_OPENAI=1\n")
		res, err = DetectClaudeCode()
		if err != nil {
			t.Fatalf("DetectClaudeCode: %v", err)
		}
		if res == nil || res.NeedsChange {
			t.Fatalf("trustless-wrapped env file must be clean, got %+v", res)
		}
	})
}

func TestDetectCodex_CredentialReferences(t *testing.T) {
	withHome(t, func(home string) {
		cfg := filepath.Join(home, ".codex", "config.toml")

		writeTestFile(t, cfg, "[model_providers]\n  api_key = \"sk-raw-12345\"\n")
		res, err := DetectCodex()
		if err != nil {
			t.Fatalf("DetectCodex: %v", err)
		}
		if res == nil || !res.NeedsChange {
			t.Fatalf("config with api_key must need change, got %+v", res)
		}

		writeTestFile(t, cfg, "[model_providers]\n  api_key = \"$(trustless get codex)\"\n")
		res, err = DetectCodex()
		if err != nil {
			t.Fatalf("DetectCodex: %v", err)
		}
		if res == nil || res.NeedsChange {
			t.Fatalf("trustless-wrapped config must be clean, got %+v", res)
		}
	})
}

func TestDetectHermes_CountsRawValues(t *testing.T) {
	withHome(t, func(home string) {
		cfg := filepath.Join(home, ".hermes", "config.yaml")

		// Raw value counts; empty/quote-only values must not.
		writeTestFile(t, cfg, strings.Join([]string{
			"model:",
			"  api_key: sk-raw-12345",
			"  token: \"\"",
			"  other: ''",
		}, "\n"))
		res, err := DetectHermes()
		if err != nil {
			t.Fatalf("DetectHermes: %v", err)
		}
		if res == nil || !res.NeedsChange {
			t.Fatalf("raw api_key must need change, got %+v", res)
		}
		if !strings.Contains(res.Description, "1 api_key/token") {
			t.Fatalf("description = %q, want 1 raw value reported", res.Description)
		}

		writeTestFile(t, cfg, "model:\n  api_key: $(trustless get hermes-key)\n")
		res, err = DetectHermes()
		if err != nil {
			t.Fatalf("DetectHermes: %v", err)
		}
		if res == nil || res.NeedsChange {
			t.Fatalf("trustless-wrapped config must be clean, got %+v", res)
		}
	})
}

func TestDetectAllAgents_CollectsOnlyPresentConfigs(t *testing.T) {
	withHome(t, func(home string) {
		writeTestFile(t, filepath.Join(home, ".config", "opencode", "providers.yaml"), "apiKey: sk-raw-1\n")
		writeTestFile(t, filepath.Join(home, ".codex", "config.toml"), "token = \"sk-raw-2\"\n")

		results := DetectAllAgents()
		if len(results) != 2 {
			t.Fatalf("detected %d agents, want 2: %+v", len(results), results)
		}
		names := map[string]bool{}
		for _, r := range results {
			names[r.Name] = true
		}
		if !names["opencode"] || !names["codex"] {
			t.Fatalf("missing agents: %v", names)
		}
	})
}
