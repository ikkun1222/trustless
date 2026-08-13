package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ikkun1222/trustless/internal/backend"
	"github.com/ikkun1222/trustless/internal/config"
	"github.com/ikkun1222/trustless/internal/dlp"
	"github.com/ikkun1222/trustless/internal/doctor"
	"github.com/ikkun1222/trustless/internal/oauth"
	"github.com/ikkun1222/trustless/internal/proxy"
	"github.com/ikkun1222/trustless/internal/run"
	"github.com/ikkun1222/trustless/internal/secret"
	"github.com/ikkun1222/trustless/internal/serve"
	"github.com/ikkun1222/trustless/internal/setup"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Load config
	cfgPath := config.DefaultConfigPath()
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: config error: %v\n", err)
		// Continue with defaults
		cfg = config.Default()
	}

	// Initialize backend
	cmd := os.Args[1]
	args := os.Args[2:]

	// bw-unlock must run even when the session is invalid (that is its purpose),
	// so it bypasses backend initialization entirely.
	if cmd == "bw-unlock" {
		runBWUnlock(args)
		return
	}

	// dlp is standalone: it selects its own backend from the dlp config
	// (secrets_source), so it skips the global backend initialization.
	if cmd == "dlp" {
		dlp.Run(args)
		return
	}

	// serve runs both listeners (forward injection + DLP reverse) in one
	// process. It builds its own shared backend from the trustless config,
	// so it must run before the global backend initialization below (which
	// would otherwise load a second, unused backend).
	if cmd == "serve" {
		serve.Run(args, cfg)
		return
	}

	be := newBackend(cfg)

	dispatch(cmd, args, be, cfg, cfgPath)
}

// dispatch は backend 初期化後に実行するサブコマンドを振り分ける。
// main の cyclomatic complexity を CCN 15 以下に保つため分離している。
func dispatch(cmd string, args []string, be backend.Backend, cfg *config.Config, cfgPath string) {
	switch cmd {
	case "secret":
		secret.Run(args, be, cfg)
	case "run":
		run.Run(args, be, cfg)
	case "proxy":
		proxy.Run(args, be, cfg)
	case "oauth":
		// oauth.Run は return int 方式（他のコマンドは os.Exit 内部呼び出し）。
		// exit code を伝播させるため os.Exit で受ける。
		os.Exit(oauth.Run(args, oauth.NewBackend(be, oauth.ProvidersFromConfig(cfg)), cfg))
	case "config":
		runConfig(args, cfg, cfgPath)
	case "version":
		fmt.Println("trustless v0.1.0")
	case "completion":
		runCompletion(args)
	case "doctor":
		doctor.Run(args)
	case "setup":
		setup.Run(args)
	case "bw-unlock":
		runBWUnlock(args)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

// newBackend selects the credential backend from the config. Kept separate from
// main to keep its cyclomatic complexity under the CCN 15 gate.
func newBackend(cfg *config.Config) backend.Backend {
	switch cfg.Backend {
	case "env":
		return backend.NewEnvBackend()
	case "bitwarden":
		bwb := backend.NewBitwardenBackend(backend.Options{})
		if err := bwb.Load(context.Background()); err != nil {
			fmt.Fprintf(os.Stderr, "Error: bitwarden backend: %v\n", err)
			os.Exit(1)
		}
		return bwb
	default:
		return backend.NewPassBackend()
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "trustless — credential broker for AI agents")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  trustless secret     Manage credentials (list, get, set)")
	fmt.Fprintln(os.Stderr, "  trustless run        Run command with injected credentials")
	fmt.Fprintln(os.Stderr, "  trustless proxy      Start credential injection proxy")
	fmt.Fprintln(os.Stderr, "  trustless oauth      Manage OAuth credentials (login, refresh, status, providers)")
	fmt.Fprintln(os.Stderr, "  trustless serve      Run injection + DLP proxies in one process")
	fmt.Fprintln(os.Stderr, "  trustless config     Manage configuration")
	fmt.Fprintln(os.Stderr, "  trustless version    Show version information")
	fmt.Fprintln(os.Stderr, "  trustless completion   Generate shell completion script")
	fmt.Fprintln(os.Stderr, "  trustless doctor       System health check (--fix, --json)")
	fmt.Fprintln(os.Stderr, "  trustless setup        First-time setup wizard (GPG, pass, .env migration)")
	fmt.Fprintln(os.Stderr, "  trustless bw-unlock    Unlock the Bitwarden vault (session key via stdin)")
}

// runBWUnlock implements `trustless bw-unlock`: it prompts for the master
// password on the terminal, runs `bw unlock --raw`, and stores the session key
// in ~/.config/trustless/bw-session (chmod 600). The master password never
// touches argv, environment, or disk (design §3.1 M-3).
func runBWUnlock(args []string) {
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "Usage: trustless bw-unlock")
		fmt.Fprintln(os.Stderr, "Prompts for the Bitwarden master password via stdin; no arguments are accepted.")
		os.Exit(1)
	}

	fmt.Fprint(os.Stderr, "Bitwarden master password: ")
	pass, err := readPassword()
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr)

	sessionPath := configPath()
	if err := backend.Unlock("bw", sessionPath, pass); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Unlocked. Session key saved to %s\n", sessionPath)
}

// readPassword reads a line from stdin without echoing. Requires /dev/tty.
func readPassword() (string, error) {
	f, err := os.Open("/dev/tty")
	if err != nil {
		// Fallback for non-interactive stdin (CI, pipes): read a raw line.
		return readLine(os.Stdin)
	}
	defer f.Close()

	fd := int(f.Fd())
	oldState, err := makeRaw(fd)
	if err != nil {
		return "", err
	}
	defer restoreTerm(fd, oldState)

	line, err := readLine(f)
	if err != nil {
		return "", err
	}
	return line, nil
}

func readLine(r io.Reader) (string, error) {
	var sb strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if buf[0] == '\n' {
				return strings.TrimSuffix(sb.String(), "\r"), nil
			}
			sb.WriteByte(buf[0])
		}
		if err != nil {
			if err == io.EOF && sb.Len() > 0 {
				return sb.String(), nil
			}
			return "", err
		}
	}
}

// configPath returns ~/.config/trustless (the directory holding bw-session).
func configPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "trustless", "bw-session")
	}
	return filepath.Join(home, ".config", "trustless", "bw-session")
}

func runConfig(args []string, cfg *config.Config, cfgPath string) {
	if len(args) < 1 {
		printConfigUsage()
		os.Exit(1)
	}

	switch args[0] {
	case "init":
		if err := config.Save(cfgPath, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Config written to %s\n", cfgPath)
	case "show":
		cfg, err := config.Load(cfgPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("backend = %s\n", cfg.Backend)
		fmt.Printf("output = %s\n", cfg.Output)
		fmt.Printf("run_defaults.sanitize = %v\n", cfg.RunDefaults.Sanitize)
		fmt.Printf("run_defaults.timeout = %s\n", cfg.RunDefaults.Timeout)
		fmt.Printf("proxy.port = %d\n", cfg.Proxy.Port)
		if len(cfg.Policy.Default.DeniedCommands) > 0 {
			fmt.Printf("policy.default.denied_commands = %v\n", cfg.Policy.Default.DeniedCommands)
		}
		for _, o := range cfg.Policy.Overrides {
			fmt.Printf("policy.override[%s].denied_commands = %v\n", o.SecretKey, o.DeniedCommands)
		}
	case "set":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: trustless config set <key> <value>")
			os.Exit(1)
		}
		key := args[1]
		value := strings.Join(args[2:], " ")

		currentCfg, err := config.Load(cfgPath)
		if err != nil {
			currentCfg = config.Default()
		}

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
		case "policy.default.denied_commands":
			currentCfg.Policy.Default.DeniedCommands = strings.Split(value, ",")
			for i, cmd := range currentCfg.Policy.Default.DeniedCommands {
				currentCfg.Policy.Default.DeniedCommands[i] = strings.TrimSpace(cmd)
			}
		default:
			fmt.Fprintf(os.Stderr, "Error: unknown config key: %s\n", key)
			os.Exit(1)
		}

		if err := config.Save(cfgPath, currentCfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Config updated: %s = %s\n", key, value)
	default:
		fmt.Fprintf(os.Stderr, "Unknown config subcommand: %s\n", args[0])
		printConfigUsage()
		os.Exit(1)
	}
}

func runCompletion(args []string) {
	if len(args) < 1 {
		printCompletionUsage()
		os.Exit(1)
	}
	switch args[0] {
	case "bash":
		fmt.Print(`# bash completion
_trustless_completion() {
    local cur=${COMP_WORDS[COMP_CWORD]}
    local prev=${COMP_WORDS[COMP_CWORD-1]}

    if [ $COMP_CWORD -eq 1 ]; then
        COMPREPLY=($(compgen -W "secret run proxy config completion doctor setup" -- "$cur"))
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
`)
	case "zsh":
		fmt.Print(`#compdef trustless

_trustless_completion() {
    local -a commands
    commands=(
        'secret:Manage credentials (list, get, set)'
        'run:Run command with injected credentials'
        'proxy:Start credential injection proxy'
        'config:Manage configuration'
        'doctor:System health check (--fix, --json)'
        'setup:First-time setup wizard'
        'completion:Generate shell completion script'
    )

    local -a secret_subcommands
    secret_subcommands=(
        'list:List all available credential keys'
        'get:Retrieve a credential value'
        'set:Store a new credential'
    )

    local -a config_subcommands
    config_subcommands=(
        'init:Create default config file'
        'show:Show current configuration'
        'set:Update a configuration value'
    )

    local -a proxy_subcommands
    proxy_subcommands=(
        'start:Start credential injection proxy'
    )

    if [ $CURRENT -eq 2 ]; then
        _describe 'command' commands
    else
        case "$words[2]" in
            secret) _describe 'secret subcommand' secret_subcommands ;;
            config) _describe 'config subcommand' config_subcommands ;;
            proxy)  _describe 'proxy subcommand' proxy_subcommands ;;
        esac
    fi
}

_trustless_completion
`)
	case "fish":
		fmt.Print(`# fish completion

complete -c trustless -f -n '__fish_use_subcommand' -a 'secret' -d 'Manage credentials (list, get, set)'
complete -c trustless -f -n '__fish_use_subcommand' -a 'run' -d 'Run command with injected credentials'
complete -c trustless -f -n '__fish_use_subcommand' -a 'proxy' -d 'Start credential injection proxy'
complete -c trustless -f -n '__fish_use_subcommand' -a 'config' -d 'Manage configuration'
complete -c trustless -f -n '__fish_use_subcommand' -a 'doctor' -d 'System health check (--fix, --json)'
complete -c trustless -f -n '__fish_use_subcommand' -a 'setup' -d 'First-time setup wizard'
complete -c trustless -f -n '__fish_use_subcommand' -a 'completion' -d 'Generate shell completion script'

# secret subcommands
complete -c trustless -f -n '__fish_seen_subcommand_from secret' -a 'list' -d 'List all available credential keys'
complete -c trustless -f -n '__fish_seen_subcommand_from secret' -a 'get' -d 'Retrieve a credential value'
complete -c trustless -f -n '__fish_seen_subcommand_from secret' -a 'set' -d 'Store a new credential'

# config subcommands
complete -c trustless -f -n '__fish_seen_subcommand_from config' -a 'init' -d 'Create default config file'
complete -c trustless -f -n '__fish_seen_subcommand_from config' -a 'show' -d 'Show current configuration'
complete -c trustless -f -n '__fish_seen_subcommand_from config' -a 'set' -d 'Update a configuration value'

# proxy subcommands
complete -c trustless -f -n '__fish_seen_subcommand_from proxy' -a 'start' -d 'Start credential injection proxy'
`)
	default:
		fmt.Fprintf(os.Stderr, "Unknown shell: %s\n", args[0])
		os.Exit(1)
	}
}

func printCompletionUsage() {
	fmt.Fprintln(os.Stderr, "Usage: trustless completion bash|zsh|fish")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Generate shell completion script.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Examples:")
	fmt.Fprintln(os.Stderr, "  trustless completion bash > /etc/bash_completion.d/trustless")
	fmt.Fprintln(os.Stderr, "  trustless completion zsh > /usr/local/share/zsh/site-functions/_trustless")
	fmt.Fprintln(os.Stderr, "  trustless completion fish > ~/.config/fish/completions/trustless.fish")
}

func printConfigUsage() {
	fmt.Fprintln(os.Stderr, "Usage: trustless config <command> [<args>]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  init              Create default config file")
	fmt.Fprintln(os.Stderr, "  show              Show current configuration")
	fmt.Fprintln(os.Stderr, "  set    <key> <value>  Update a configuration value")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Config keys:")
	fmt.Fprintln(os.Stderr, "  backend                  Credential backend (default: pass)")
	fmt.Fprintln(os.Stderr, "  output                   Default output mode (default: json)")
	fmt.Fprintln(os.Stderr, "  run_defaults.sanitize    Enable sanitization by default (true/false)")
	fmt.Fprintln(os.Stderr, "  run_defaults.timeout     Default subprocess timeout")
	fmt.Fprintln(os.Stderr, "  proxy.port               Default proxy port")
}
