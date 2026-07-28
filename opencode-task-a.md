# Step A: Implement `trustless run` — subprocess credential injection

## Context

This is a Go CLI project at `/home/ubuntu/projects/trustless` for AI-agent credential brokering.

Existing structure:
- `main.go` — subcommand dispatch (secret, config working, run/proxy stubbed)
- `internal/backend/backend.go` — `Backend` interface with `Resolve(ctx, key) (string, error)` and `List(ctx) ([]Entry, error)`
- `internal/backend/pass.go` — `PassBackend` implementing it via `pass show` CLI
- `internal/config/config.go` — TOML config loading

## What to implement

### 1. Create `internal/run/command.go`

A `Run(args []string, be backend.Backend, cfg *config.Config)` function that:

**Flag parsing:**
- `-s, --secret` — repeatable, specifies credential keys to inject (e.g. `-s iria/api/xai -s iria/oci/api-key`)
- `--json` — output results as JSON instead of raw passthrough
- `--timeout` — subprocess timeout as duration string (e.g. `"30s"`, `"5m"`)

Since Go's `flag` package doesn't natively support repeatable string flags, define a custom type:
```go
type stringSlice []string
func (s *stringSlice) String() string { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }
```

**Command extraction:**
- After the flag.FlagSet has parsed, the remaining non-flag args are the command to run
- If `--` separator is encountered, everything after it is the command (even if it starts with `-`)

**Credential resolution:**
- For each `-s` key, call `be.Resolve(ctx, key)`
- Determine env var name from the last path segment of the key:
  - `iria/api/xai` → env var `XAI`
  - `iria/cloudflare/api-token` → env var `API_TOKEN` (note: hyphens become underscores)
  - `iria/oci/api-key` → env var `API_KEY`
- Store resolved values in a map `map[string]string{envVarName: value}`

**Subprocess execution (default mode):**
- Use `exec.CommandContext` with the command and its args
- If `--timeout` is set, create the context with `context.WithTimeout`
- Set `cmd.Env` to inherit current env + injected env vars
- For default mode: set `cmd.Stdout = os.Stdout` and `cmd.Stderr = os.Stderr` (passthrough)
- For JSON mode: capture stdout/stderr via `cmd.StdoutPipe()` / `cmd.StderrPipe()`
- Run the subprocess, wait for completion
- Collect exit code (0 if `cmd.Run()` returns nil, otherwise exit code from `ExitError`)

**JSON output mode (`--json`):**
```json
{"exit_code": 0, "stdout": "...", "stderr": "..."}
```

### 2. Modify `main.go`

Update the `run` case (currently a stub printing "Not yet implemented"):

```go
case "run":
    run.Run(args, be, cfg)
```

### 3. Build and test

```bash
cd /home/ubuntu/projects/trustless
go build ./...
```

## Acceptance tests

```bash
cd /home/ubuntu/projects/trustless

# 1. Basic run with credential injection (raw passthrough mode)
./trustless run -s iria/api/xai -- sh -c 'echo "XAI_KEY=$XAI"'
# Expected: XAI_KEY=<the actual key value>

# 2. JSON output mode
./trustless run --json -s iria/api/xai -- sh -c 'echo hello'
# Expected: {"exit_code": 0, "stdout": "hello\n", "stderr": ""}

# 3. Timeout
./trustless run --timeout 1s -- sh -c 'sleep 10'
# Expected: exits with error about timeout or killed process

# 4. Multiple secrets
./trustless run --json -s iria/api/xai -s iria/api/openrouter -- sh -c 'echo "X=$XAI O=$OPENROUTER"'
# Expected: JSON with both values visible in stdout

# 5. Error on nonexistent key
./trustless run -s nonexistent/key -- sh -c 'echo should not run'
# Expected: error message, exit code 2
```

## Notes

- Keep it simple — no sanitization yet, that's Step C
- Use `context.Background()` when no timeout is set
- The config `cfg` param is passed but not used in this step (placeholder for later)
- After `flag.FlagSet.Parse()`, `flagSet.Args()` gives remaining non-flag args
