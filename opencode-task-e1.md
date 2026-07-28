# Step E1: Shell completion, config set, help improvements

## Context

Go project at `/home/ubuntu/projects/trustless`.

The CLI works but is missing finishing touches: shell completion, `config set` subcommand, and descriptive help messages.

## Task

### 1. Shell completion (`trustless completion bash|zsh|fish`)

Add a `completion` command to `main.go` that outputs shell completion scripts:

```go
case "completion":
    if len(args) < 1 {
        fmt.Fprintln(os.Stderr, "Usage: trustless completion bash|zsh|fish")
        os.Exit(1)
    }
    switch args[0] {
    case "bash":
        // Output bash completion script
    case "zsh":
        // Output zsh completion script
    case "fish":
        // Output fish completion script
    default:
        fmt.Fprintf(os.Stderr, "Unknown shell: %s\n", args[0])
        os.Exit(1)
    }
```

For the completion scripts, use simple static completions since we're not using cobra. The bash completion should provide command and subcommand completion:

```bash
# bash completion
_trustless_completion() {
    local cur=${COMP_WORDS[COMP_CWORD]}
    local prev=${COMP_WORDS[COMP_CWORD-1]}

    if [ $COMP_CWORD -eq 1 ]; then
        COMPREPLY=($(compgen -W "secret run proxy config completion" -- "$cur"))
        return
    fi

    case "${COMP_WORDS[1]}" in
        secret)
            if [ $COMP_CWORD -eq 2 ]; then
                COMPREPLY=($(compgen -W "list get set" -- "$cur"))
            fi
            ;;
        config)
            if [ $COMP_CWORD -eq 2 ]; then
                COMPREPLY=($(compgen -W "init show set" -- "$cur"))
            fi
            ;;
        proxy)
            if [ $COMP_CWORD -eq 2 ]; then
                COMPREPLY=($(compgen -W "start" -- "$cur"))
            fi
            ;;
    esac
}
complete -F _trustless_completion trustless
```

Similarly provide zsh and fish completions. The zsh completion can be a simple compdef wrapper around the bash completion.

### 2. `trustless config set <key> <value>`

Add a `set` subcommand to `config` in `main.go`. It should:

```go
case "set":
    if len(args) < 2 {
        fmt.Fprintln(os.Stderr, "Usage: trustless config set <key> <value>")
        os.Exit(1)
    }
    key := args[1]
    value := strings.Join(args[2:], " ")
    
    // Reload existing config
    currentCfg, err := config.Load(cfgPath)
    if err != nil {
        currentCfg = config.Default()
    }
    
    // Update the config value
    switch key {
    case "backend":
        currentCfg.Backend = value
    case "output":
        currentCfg.Output = value
    case "run_defaults.sanitize":
        currentCfg.RunDefaults.Sanitize = value == "true"
    case "run_defaults.timeout":
        currentCfg.RunDefaults.Timeout = value
    case "proxy.port":
        port, err := strconv.Atoi(value)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Error: invalid port: %s\n", value)
            os.Exit(1)
        }
        currentCfg.Proxy.Port = port
    default:
        fmt.Fprintf(os.Stderr, "Error: unknown config key: %s\n", key)
        os.Exit(1)
    }
    
    // Save
    if err := config.Save(cfgPath, currentCfg); err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        os.Exit(1)
    }
    fmt.Fprintf(os.Stderr, "Config updated: %s = %s\n", key, value)
```

### 3. Help improvements

Enhance usage messages across all subcommands to be more descriptive:

**main help** (when `trustless` is run without args):
```
trustless — credential broker for AI agents

Usage:
  trustless secret     Manage credentials (list, get, set)
  trustless run        Run command with injected credentials
  trustless proxy      Start credential injection proxy
  trustless config     Manage configuration
  trustless completion Generate shell completion script
```

**secret help** (`trustless secret` without subcommand):
```
Usage: trustless secret <command> [<args>]

Commands:
  list              List all available credential keys
  get    <key>      Retrieve a credential value
  set    <key>      Store a new credential (prompts for value)

Use 'pass' directly for advanced credential management.
```

**run help** (`trustless run --help`):
```
Usage: trustless run [flags] [--] <command> [args...]

Run a command with credentials injected as environment variables.
Credentials are resolved from the pass store and set on the subprocess.
Output is scanned for credential patterns and redacted.

Flags:
  -s, --secret <key>     Credential key to inject (repeatable)
  --json                 Output results as JSON
  --timeout <duration>   Subprocess timeout (e.g. "30s", "5m")
  --sanitize             Enable output sanitization (default: true)
  --sanitize-policy <file>  Path to custom redaction patterns file

Examples:
  trustless run -s iria/api/xai -- curl -s https://api.x.ai/v1/models
  trustless run --json -s iria/api/xai -s iria/api/openrouter -- sh -c 'echo done'
```

**proxy help** (`trustless proxy start --help`):
```
Usage: trustless proxy start [flags]

Start a local HTTP forward proxy that substitutes credential placeholders.
Placeholders are resolved from the pass store in real-time.

Placeholder format: __KEY_NAME__ (e.g. __GITHUB_TOKEN__, __XAI__)
Resolution: lowercase(KEY_NAME) → pass key, fallback: iria/api/lowercase(KEY_NAME)

Flags:
  --port <n>           Listen port (default: 8080)
  --unix-socket <path>  Listen on Unix socket instead of TCP

Examples:
  trustless proxy start --port 8080
  HTTPS_PROXY=http://127.0.0.1:8080 curl -H "Authorization: Bearer __XAI__" https://api.x.ai/v1/models
```

**config help** (`trustless config` without subcommand):
```
Usage: trustless config <command> [<args>]

Commands:
  init              Create default config file
  show              Show current configuration
  set    <key> <value>  Update a configuration value

Config keys:
  backend                  Credential backend (default: pass)
  output                   Default output mode (default: json)
  run_defaults.sanitize    Enable sanitization by default (true/false)
  run_defaults.timeout     Default subprocess timeout
  proxy.port               Default proxy port
```

**completion help** (`trustless completion` without subcommand):
```
Usage: trustless completion bash|zsh|fish

Generate shell completion script.

Examples:
  trustless completion bash > /etc/bash_completion.d/trustless
  trustless completion zsh > /usr/local/share/zsh/site-functions/_trustless
  trustless completion fish > ~/.config/fish/completions/trustless.fish
```

### 4. Update `printUsage()` and `printConfigUsage()` in main.go

Replace the short usage with the detailed versions above.

## Files to modify

- `main.go` — add completion command, config set, help improvements

## Build and test

```bash
cd /home/ubuntu/projects/trustless
go build -o trustless .

# Test help
./trustless
./trustless secret
./trustless run --help
./trustless proxy start --help
./trustless config
./trustless completion

# Test config set
./trustless config set proxy.port 9090
./trustless config show | grep proxy.port

# Test shell completion
./trustless completion bash | head -5
./trustless completion zsh | head -5
./trustless completion fish | head -5
```
