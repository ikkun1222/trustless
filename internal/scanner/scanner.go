package scanner

import (
	"regexp"
	"strings"
)

type Scanner struct {
	patterns []*regexp.Regexp
}

func New() *Scanner {
	s := &Scanner{}
	defaultPatterns := []string{
		`\bgh[pousr]_[A-Za-z0-9_]{8,}\b`,
		`\bsk-[A-Za-z0-9_-]{20,}\b`,
		`\bsk-ant-[A-Za-z0-9_-]{20,}\b`,
		`\bBearer\s+[A-Za-z0-9._\-]{8,}\b`,
		`\bAKIA[0-9A-Z]{16}\b`,
		`\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*['"]?\S{8,}\b`,
		`\bxai-[A-Za-z0-9._-]{8,}\b`,
	}
	for _, p := range defaultPatterns {
		s.patterns = append(s.patterns, regexp.MustCompile(p))
	}
	return s
}

func (s *Scanner) AddPattern(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	s.patterns = append(s.patterns, re)
	return nil
}

func (s *Scanner) Scan(input []byte) []byte {
	if len(input) == 0 {
		return input
	}
	output := string(input)
	for _, re := range s.patterns {
		output = re.ReplaceAllString(output, "[REDACTED]")
	}
	return []byte(output)
}

func (s *Scanner) ScanWithValues(input []byte, extraValues []string) []byte {
	output := s.Scan(input)
	if len(extraValues) == 0 {
		return output
	}
	sout := string(output)
	for _, v := range extraValues {
		if v == "" {
			continue
		}
		sout = strings.ReplaceAll(sout, v, "[REDACTED]")
	}
	return []byte(sout)
}
