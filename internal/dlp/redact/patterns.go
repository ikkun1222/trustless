// Layer 2 of the outbound DLP pipeline: gitleaks-compatible pattern rules.
// After the known-value substring scan (ScanAndRedact), every text body is
// also matched against a bundled rule set. Each rule gates on keywords
// (cheap prefix filter), then a RE2 regex, then a Shannon entropy threshold
// on the captured secret. Low-entropy matches are passed through untouched
// to avoid destroying ordinary prose.
package redact

import (
	"embed"
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"

	"github.com/pelletier/go-toml/v2"
)

//go:embed rules.toml
var rulesFS embed.FS

// Rule は gitleaks 互換のルール定義（rules.toml 1 エントリ）。
type Rule struct {
	ID          string   `toml:"id"`
	Description string   `toml:"description"`
	Regex       string   `toml:"regex"`
	Keywords    []string `toml:"keywords,omitempty"`
	Entropy     float64  `toml:"entropy,omitempty"`      // 0 = デフォルト閾値（DefaultEntropyThreshold）
	SecretGroup int      `toml:"secret_group,omitempty"` // 0 = マッチ全体を置換
}

// DefaultEntropyThreshold はルール指定が無い場合の Shannon entropy 下限。
const DefaultEntropyThreshold = 3.5

// PatternSet はコンパイル済みルールの集合（unexported フィールドのみ）。
// ホットリロード（reloadAll からの Replace）に対応し、リクエスト処理中の
// スワップも安全（Scan は RLock で rules スライスを読取）。
type PatternSet struct {
	mu    sync.RWMutex
	rules []compiledRule
}

// Replace は新しい PatternSet のルールで原子的に置き換える。
// リクエスト処理中の Swap も安全（Scan は RLock で読取）。
func (p *PatternSet) Replace(new *PatternSet) {
	if new == nil {
		new = &PatternSet{}
	}
	// スライスは共有せずコピーしてから入れる（-race で安全・参照切り離し）。
	rules := make([]compiledRule, len(new.rules))
	copy(rules, new.rules)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rules = rules
}

// Count は現在のルール数を返す（ホットリロード時のログ用）。
func (p *PatternSet) Count() int {
	if p == nil {
		return 0
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.rules)
}

// Has は指定 id のルールが存在するか報告する。
func (p *PatternSet) Has(id string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, r := range p.rules {
		if r.id == id {
			return true
		}
	}
	return false
}

// Filter は disabled に含まれる id のルールを除外した新しい PatternSet を返す。
// disabled に未知の id が含まれる場合は error（fail-closed: タイポを検出）。
// 空の disabled はそのままのルールで新規セットを返す。
func (p *PatternSet) Filter(disabled []string) (*PatternSet, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	excluded := make(map[string]bool, len(disabled))
	for _, id := range disabled {
		if id == "" {
			return nil, fmt.Errorf("filter: empty rule id in pattern_disabled")
		}
		if excluded[id] {
			continue
		}
		if !p.hasLocked(id) {
			return nil, fmt.Errorf("filter: unknown rule id %q in pattern_disabled", id)
		}
		excluded[id] = true
	}
	out := make([]compiledRule, 0, len(p.rules))
	for _, r := range p.rules {
		if !excluded[r.id] {
			out = append(out, r)
		}
	}
	return &PatternSet{rules: out}, nil
}

// hasLocked はロック取得済みの状態で id のルール存在を調べる。
func (p *PatternSet) hasLocked(id string) bool {
	for _, r := range p.rules {
		if r.id == id {
			return true
		}
	}
	return false
}

// compiledRule is a Rule ready for scanning: keywords lowercased once and
// the regex compiled once.
type compiledRule struct {
	id          string
	re          *regexp.Regexp
	keywords    []string // lowercased; nil means "always run"
	entropy     float64  // 0 means DefaultEntropyThreshold
	secretGroup int
}

// LoadPatterns は gitleaks 互換 TOML（rules.toml / 外部 gitleaks.toml）をパース・検証する。
// 検証: ルール数 >= 1・id 非空かつ一意・regex 非空かつ regexp.Compile 可能・entropy は 0 以上。
// 失敗時は error（呼び出し側は fail-closed: 起動失敗）。
func LoadPatterns(data []byte) (*PatternSet, error) {
	var doc struct {
		Rules []Rule `toml:"rules"`
	}
	if err := toml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}
	if len(doc.Rules) < 1 {
		return nil, fmt.Errorf("rules: at least one rule required, got %d", len(doc.Rules))
	}
	ps := &PatternSet{rules: make([]compiledRule, 0, len(doc.Rules))}
	seen := make(map[string]bool, len(doc.Rules))
	for _, r := range doc.Rules {
		if r.ID == "" {
			return nil, fmt.Errorf("rules: empty rule id")
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("rules: duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
		if r.Regex == "" {
			return nil, fmt.Errorf("rules: rule %q has empty regex", r.ID)
		}
		re, err := regexp.Compile(r.Regex)
		if err != nil {
			return nil, fmt.Errorf("rules: rule %q regex: %w", r.ID, err)
		}
		if r.Entropy < 0 {
			return nil, fmt.Errorf("rules: rule %q has negative entropy %v", r.ID, r.Entropy)
		}
		var kw []string
		for _, k := range r.Keywords {
			if k != "" {
				kw = append(kw, strings.ToLower(k))
			}
		}
		ps.rules = append(ps.rules, compiledRule{
			id:          r.ID,
			re:          re,
			keywords:    kw,
			entropy:     r.Entropy,
			secretGroup: r.SecretGroup,
		})
	}
	return ps, nil
}

// DefaultPatterns は同梱 rules.toml（go:embed）から構築した PatternSet を返す。
func DefaultPatterns() (*PatternSet, error) {
	b, err := rulesFS.ReadFile("rules.toml")
	if err != nil {
		return nil, fmt.Errorf("read embedded rules.toml: %w", err)
	}
	return LoadPatterns(b)
}

// Scan は text 内のパターン一致を redact.Marker に置換する。
// 3 段: ①keywords が無いルールは常に実行、あるルールは keywords のいずれかが text に
//
//	 含まれる場合のみ実行（大文字小文字は無視）
//	②regexp マッチ（RE2）。secret_group > 0 なら該当キャプチャグループの範囲のみを置換対象、
//	 0 ならマッチ全体。既に Marker で置換済みの部分に再度マッチした場合は置換しない
//	③マッチ文字列の Shannon entropy が閾値未満ならスキップ
//
// 戻り値: 置換済み text・置換が行われたか。パターン検出は「初回マッチ位置」で判定し、
// 同一ルールの複数マッチは全て置換する。
func (p *PatternSet) Scan(text string) (string, bool) {
	if p == nil || text == "" {
		return text, false
	}
	p.mu.RLock()
	rules := p.rules
	p.mu.RUnlock()
	if len(rules) == 0 {
		return text, false
	}
	lower := strings.ToLower(text)
	out := text
	changed := false
	for _, rule := range rules {
		if !rule.gate(lower) {
			continue
		}
		sub, ok := scanRule(&rule, out)
		if !ok {
			continue
		}
		out = sub
		changed = true
	}
	return out, changed
}

// gate reports whether rule should run against text (the lowercased input).
// Rules without keywords always run; keyword rules run only when at least
// one keyword appears as a substring.
func (r *compiledRule) gate(lowerText string) bool {
	if len(r.keywords) == 0 {
		return true
	}
	for _, k := range r.keywords {
		if strings.Contains(lowerText, k) {
			return true
		}
	}
	return false
}

// entropy returns the Shannon entropy of s in bits per rune. An empty
// string has entropy 0 (matching gitleaks, which short-circuits early).
func entropy(s string) float64 {
	counts := make(map[rune]int)
	for _, r := range s {
		counts[r]++
	}
	n := 0
	for _, c := range counts {
		n += c
	}
	if n == 0 {
		return 0
	}
	var h float64
	for _, c := range counts {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}

// threshold returns the entropy floor for r: the rule's own value when set,
// DefaultEntropyThreshold otherwise.
func (r *compiledRule) threshold() float64 {
	if r.entropy > 0 {
		return r.entropy
	}
	return DefaultEntropyThreshold
}

// scanRule replaces every occurrence of r in text whose secret value clears
// the entropy threshold. The secret value is the capture group the regex
// designates as the credential (group 1 when the rule does not set
// secret_group): measuring the assignment context ("key = ") instead would
// inflate entropy past the threshold on ordinary placeholder text
// (e.g. `const apiKey = "configured via env"`). The replaced span is the
// whole match for plain rules, and the secret_group capture only when the
// rule explicitly sets it (gitleaks semantics). Matches are processed from
// the end so earlier replacements never shift later indices.
func scanRule(r *compiledRule, text string) (string, bool) {
	idx := r.re.FindAllStringSubmatchIndex(text, -1)
	if len(idx) == 0 {
		return text, false
	}
	type span struct{ start, end int }
	var hits []span
	group := r.secretGroup
	if group == 0 && r.re.NumSubexp() >= 1 {
		group = 1 // the regex's designated secret capture
	}
	for _, m := range idx {
		if strings.Contains(text[m[0]:m[1]], Marker) {
			continue // already redacted by an earlier layer/rule
		}
		if group > 0 && 2*group+1 < len(m) && m[2*group] >= 0 && m[2*group+1] > m[2*group] {
			if entropy(text[m[2*group]:m[2*group+1]]) < r.threshold() {
				continue
			}
			hits = append(hits, span{m[2*group], m[2*group+1]})
		} else {
			if entropy(text[m[0]:m[1]]) < r.threshold() {
				continue
			}
			hits = append(hits, span{m[0], m[1]})
		}
	}
	if len(hits) == 0 {
		return text, false
	}
	var b strings.Builder
	b.Grow(len(text))
	last := 0
	for _, h := range hits {
		b.WriteString(text[last:h.start])
		b.WriteString(Marker)
		last = h.end
	}
	b.WriteString(text[last:])
	return b.String(), true
}

// ScanAll は第1層（既知値 ScanAndRedact）→ 第2層（patterns.Scan）の順に適用する。
// patterns が nil なら第1層のみ（従来挙動と完全互換）。
func ScanAll(text string, secrets []string, minLen int, patterns *PatternSet) (string, bool) {
	out, changed := ScanAndRedact(text, secrets, minLen)
	if patterns == nil {
		return out, changed
	}
	pat, patChanged := patterns.Scan(out)
	return pat, changed || patChanged
}
