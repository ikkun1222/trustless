package redact

import (
	"os"
	"regexp"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// rulesFile is the gitleaks-derived DLP pattern asset bundled with this
// package. It is read from disk (not go:embed) so the test exercises the
// shipped file itself; go:embed wiring lands in the next step.
const rulesFile = "rules.toml"

// dlpRule mirrors the gitleaks-compatible schema used in rules.toml.
// Only the fields we bundle appear here.
type dlpRule struct {
	ID          string   `toml:"id"`
	Description string   `toml:"description"`
	Regex       string   `toml:"regex"`
	Keywords    []string `toml:"keywords,omitempty"`
	Entropy     *float64 `toml:"entropy,omitempty"`
}

func loadRules(t *testing.T) []dlpRule {
	t.Helper()
	b, err := os.ReadFile(rulesFile)
	if err != nil {
		t.Fatalf("read %s: %v", rulesFile, err)
	}
	var doc struct {
		Rules []dlpRule `toml:"rules"`
	}
	if err := toml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("parse %s: %v", rulesFile, err)
	}
	return doc.Rules
}

func TestRulesAssetCount(t *testing.T) {
	rules := loadRules(t)
	if len(rules) < 30 || len(rules) > 50 {
		t.Fatalf("expected 30-50 rules, got %d", len(rules))
	}
	if len(rules) != 40 {
		t.Fatalf("expected 40 rules, got %d", len(rules))
	}
}

func TestRulesRequiredFields(t *testing.T) {
	for _, r := range loadRules(t) {
		if r.ID == "" {
			t.Fatal("rule with empty id")
		}
		if r.Regex == "" {
			t.Fatalf("rule %q has empty regex", r.ID)
		}
	}
}

func TestRulesUniqueIDs(t *testing.T) {
	seen := make(map[string]bool)
	for _, r := range loadRules(t) {
		if seen[r.ID] {
			t.Fatalf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
	}
}

func TestRulesEntropyNonNegative(t *testing.T) {
	for _, r := range loadRules(t) {
		if r.Entropy != nil && *r.Entropy < 0 {
			t.Fatalf("rule %q has negative entropy %v", r.ID, *r.Entropy)
		}
	}
}

func TestRulesRegexCompiles(t *testing.T) {
	for _, r := range loadRules(t) {
		if _, err := regexp.Compile(r.Regex); err != nil {
			t.Fatalf("rule %q regex does not compile: %v", r.ID, err)
		}
	}
}
