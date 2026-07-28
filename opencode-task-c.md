# Step C: Integrate scanner into `trustless run` for output sanitization

## Context

Go project at `/home/ubuntu/projects/trustless`.

Existing:
- `internal/run/command.go` — `trustless run` with subprocess execution (raw passthrough + JSON)
- `internal/scanner/scanner.go` — credential pattern scanner with `Scan()` and `ScanWithValues()`
- `internal/config/config.go` — TOML config with `sanitize.patterns` and `run_defaults.sanitize = true`

## Task

Modify `internal/run/command.go` to integrate the scanner into the subprocess output pipeline.

### New flags to add

- `--sanitize` (bool, default: true from `cfg.RunDefaults.Sanitize`) — enable/disable output scanning
- `--sanitize-policy` (string, default: empty) — path to a file with custom redaction patterns (one per line)

### Scanner initialization

In `Run()`, after flag parsing and before subprocess execution:

1. Create a scanner with `scanner.New()` (has all default patterns)
2. If `cfg.Sanitize.Patterns` has custom patterns, add them via `scanner.AddPattern()`
3. If `--sanitize-policy` is specified, read the file and add each line as a pattern
4. Store the injected credential values for ScanWithValues

### Output pipeline modification

**When sanitize is enabled:**

- For passthrough mode (default, no `--json`):
  - Capture stdout and stderr into buffers (instead of writing directly to os.Stdout/os.Stderr)
  - After subprocess completes, run `scanner.ScanWithValues()` on both stdout and stderr, passing the injected credential values as `extraValues`
  - Write the sanitized output to os.Stdout / os.Stderr

- For JSON mode (`--json`):
  - After capturing stdout/stderr, run the scanner on both before encoding the JSON result

**When sanitize is disabled** (explicitly via `--sanitize=false` or config `run_defaults.sanitize = false`):
  - Existing behavior unchanged (passthrough or raw JSON)

### Injected value protection

When `ScanWithValues` is called, pass all resolved credential values as `extraValues`. This ensures that if the subprocess echoes back the credential (e.g. `echo $API_KEY`), it gets redacted.

### Import changes

Add to `internal/run/command.go`:
```go
import (
    "bytes"
    "github.com/ikkun1222/trustless/internal/scanner"
)
```

### Config value access

The config has:
```go
cfg.RunDefaults.Sanitize  // bool
cfg.Sanitize.Patterns     // []string
```

### Sanitize policy file format

One regex pattern per line. Blank lines and lines starting with `#` are ignored.

### Important

- `--sanitize` flag default should be `true` if config says so. Since flag defaults are compile-time constants, you can't use a dynamic default with `flag.Bool()`. Instead, set the default to `true` in the flag, and if `--sanitize` is explicitly set to `false`, it overrides the config value. OR: parse flags manually and apply config default. Easiest approach: add a `--no-sanitize` flag that disables sanitization, and use config default otherwise. But the design calls for `--sanitize`. Alternative: parse flags into a separate struct, then apply config defaults for unset flags. For simplicity, use `--sanitize` bool with default `true`, and the config value can override via `flag.Lookup` before parsing. But `flag` doesn't support dynamic defaults easily.

**Simplest approach**: Default sanitize to `true`. If the user explicitly passes `--sanitize=false` or `--sanitize=true`, respect that. If the user doesn't pass it, check the config value. Implementation: after flag parsing, if the flag wasn't explicitly set, use the config value.

```go
sanitizeFlag := fs.Bool("sanitize", true, "enable output sanitization")
// ... parse flags ...
*sanitizeFlag = *sanitizeFlag && cfg.RunDefaults.Sanitize
```

Or more precisely:
```go
// After fs.Parse():
sanitize := *sanitizeFlag  // user's explicit value or true
if !fsChanged("sanitize") { // check if the flag was explicitly provided
    sanitize = cfg.RunDefaults.Sanitize
}
```

Implementing `fsChanged` requires inspecting `fs.Visit()` or using a custom approach. For simplicity, just use:
```go
sanitize := cfg.RunDefaults.Sanitize
// If explicitly set via flag, it overrides
```

Actually, the cleanest approach: when sanitize flag is `--sanitize` (no default in flag), store the value from config, then if `--sanitize` is seen, override.

Simplest: just use `cfg.RunDefaults.Sanitize` directly and don't add a flag. But the design spec says `--sanitize` flag.

OK, practical approach: Add `--sanitize` as a bool flag with no default (use a custom flag type or just read the config value and let the flag override it). 

Actually simplest that works: 

```go
noSanitize := fs.Bool("no-sanitize", false, "disable output sanitization")
```

Then:
```go
sanitize := cfg.RunDefaults.Sanitize && !*noSanitize
```

This avoids the dynamic default problem entirely. If config says true and user doesn't pass --no-sanitize → sanitize enabled. If user passes --no-sanitize → disabled.

BUT: the design says `--sanitize`. Let's keep it simple and do it the pragmatic way:

```go
sanitizeFlag := fs.Bool("sanitize", true, "enable output sanitization")
```

After parsing, combine with config:
```go
sanitize := *sanitizeFlag && cfg.RunDefaults.Sanitize
```

This means: if user says `--sanitize=false`, it's false regardless of config. If user says `--sanitize=true`, it's still subject to config (config can force-disable). This is a reasonable behavior.

## Acceptance tests

```bash
cd /home/ubuntu/projects/trustless

# 1. Sanitize default: credential value should be redacted from output
go build && ./trustless run -s iria/api/xai -- sh -c 'echo $XAI'
# Expected: [REDACTED] (not the actual key)

# 2. JSON mode with sanitize
./trustless run --json -s iria/api/xai -- sh -c 'echo $XAI'
# Expected: {"exit_code":0,"stdout":"[REDACTED]\n","stderr":""}

# 3. Multiple credentials
./trustless run --json -s iria/api/xai -s iria/api/openrouter -- sh -c 'echo "X=$XAI O=$OPENROUTER"'
# Expected: both values redacted

# 4. --sanitize=false should show raw values
./trustless run --sanitize=false -s iria/api/xai -- sh -c 'echo $XAI'
# Expected: the actual credential value visible

# 5. Clean command output should pass through unchanged
./trustless run -- sh -c 'echo "hello world"'
# Expected: hello world
```

## Files to modify

- `internal/run/command.go` — add scanner integration
- (no new files needed)

## Notes

- `bytes` package from stdlib for buffer
- Scanner is already tested in Step B — don't re-test it
- Focus on the integration points: creating scanner, processing output through it
- The passthrough mode with sanitize enabled should buffer output, scan it, then write to terminal
