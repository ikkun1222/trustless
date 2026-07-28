# Step B: Implement credential output scanner (`internal/scanner/`)

## Context

Go CLI project at `/home/ubuntu/projects/trustless`.

We need a pattern-based output scanner that detects and redacts common credential formats from byte streams. This will later be used by `trustless run --sanitize` to prevent credentials from leaking into the LLM context window.

## Task

Create `internal/scanner/scanner.go` with the following API:

```go
package scanner

// Scanner holds credential patterns and redacts matches.
type Scanner struct {
    patterns []*regexp.Regexp
}

// New creates a Scanner with built-in default patterns.
func New() *Scanner

// AddPattern compiles and adds a regex pattern to the scanner.
func (s *Scanner) AddPattern(pattern string) error

// Scan replaces all known credential patterns in input with [REDACTED].
func (s *Scanner) Scan(input []byte) []byte

// ScanWithValues scans input and also redacts any of the provided values
// if they appear in the output (case-insensitive substring match for safety).
func (s *Scanner) ScanWithValues(input []byte, extraValues []string) []byte
```

### Default patterns (must be compiled in `New()`)

```
GitHub tokens:      \bgh[pousr]_[A-Za-z0-9_]{8,}\b
OpenAI keys:        \bsk-[A-Za-z0-9]{20,}\b
Anthropic keys:     \bsk-ant-[A-Za-z0-9]{20,}\b
Bearer tokens:      \bBearer\s+[A-Za-z0-9._\-]{8,}\b
AWS access keys:    \bAKIA[0-9A-Z]{16}\b
Generic key=value:  \b(?:api[_-]?key|secret|token|password)\s*[:=]\s*['"]?\S{8,}\b
XAI keys:           \bxai-[A-Za-z0-9]{20,}\b
```

### Behavior

- `Scan()` replaces **all** matches with `[REDACTED]`
- `ScanWithValues()` additionally performs a case-insensitive search for each extra value string in the input and replaces any occurrence with `[REDACTED]`
- The scanner is safe for concurrent use once constructed (patterns are read-only)
- Input that contains no matches is returned unchanged
- The scanner should not panic on invalid regex (AddPattern returns error)

### Important implementation details

- Use `regexp` package (stdlib)
- For `ScanWithValues`, use `strings.Replace(string(input), value, "[REDACTED]", -1)` with `strings.EqualFold` for case-insensitive matching, or simpler: `strings.Replace(strings.ToLower(input), strings.ToLower(value), "[REDACTED]", -1)` — but that can't be case-insensitive byte replacement. Better: iterate and use `strings.Replace(inputStr, val, "[REDACTED]", -1)` — this is case-sensitive but catches exact matches which is the most important case.
- The scanner doesn't need to be optimized for throughput — it's running on subprocess output which is typically small (< 1MB)

## Acceptance tests

```go
// In tests/scanner_test.go or inline test in the task:
// 1. Scanner should redact GitHub token
input1 := []byte("token=ghp_abc123def456xyz789")
output1 := scanner.Scan(input1)
// output1 should contain "[REDACTED]" not "ghp_abc"

// 2. Scanner should redact OpenAI key  
input2 := []byte("OPENAI_API_KEY=sk-proj-abc123def456xyz789abc123def456")
output2 := scanner.Scan(input2)
// output2 should contain "[REDACTED]" for the key

// 3. Scanner should redact XAI key
input3 := []byte("xai-8R...4Hvc")
output3 := scanner.Scan(input3)
// output3 should contain "[REDACTED]" not "xai-8R"

// 4. ScanWithValues should redact extra values
output4 := scanner.ScanWithValues([]byte("my-secret-value"), []string{"my-secret-value"})
// output4 should be "[REDACTED]"

// 5. Clean input passes through unchanged
output5 := scanner.Scan([]byte("hello world this is safe"))
// output5 should be "hello world this is safe"

// 6. No false positives on normal text
output6 := scanner.Scan([]byte("The quick brown fox"))
// output6 should be unchanged
```

## File structure

- Create: `internal/scanner/scanner.go`
- Optionally create: `internal/scanner/scanner_test.go` (not required but nice)

## Build verification

```bash
cd /home/ubuntu/projects/trustless
go build ./...
# Create and run a quick Go test
cat > /tmp/test_scanner.go << 'GOEOF'
package main
import (
    "fmt"
    "github.com/ikkun1222/trustless/internal/scanner"
)
func main() {
    s := scanner.New()
    // Test 1: GitHub token
    out := s.Scan([]byte("ghp_abc123def456xyz789"))
    fmt.Printf("Test 1: %q\n", string(out))
    // Test 2: Clean text
    out2 := s.Scan([]byte("hello world"))
    fmt.Printf("Test 2: %q\n", string(out2))
    // Test 3: ScanWithValues
    out3 := s.ScanWithValues([]byte("secret=mykey123"), []string{"mykey123"})
    fmt.Printf("Test 3: %q\n", string(out3))
}
GOEOF
go run /tmp/test_scanner.go
```
