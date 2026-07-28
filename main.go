package main

import (
	"fmt"
	"os"

	"github.com/ikkun1222/trustless/internal/backend"
	"github.com/ikkun1222/trustless/internal/config"
	"github.com/ikkun1222/trustless/internal/secret"
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
	be := backend.NewPassBackend()

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "secret":
		secret.Run(args, be, cfg)
	case "run":
		fmt.Fprintln(os.Stderr, "Not yet implemented: trustless run")
		os.Exit(1)
	case "proxy":
		fmt.Fprintln(os.Stderr, "Not yet implemented: trustless proxy")
		os.Exit(1)
	case "config":
		runConfig(args, cfg, cfgPath)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  trustless secret     Manage credentials")
	fmt.Fprintln(os.Stderr, "  trustless run        Run command with injected credentials")
	fmt.Fprintln(os.Stderr, "  trustless proxy      Start credential proxy")
	fmt.Fprintln(os.Stderr, "  trustless config     Manage configuration")
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
	default:
		fmt.Fprintf(os.Stderr, "Unknown config subcommand: %s\n", args[0])
		printConfigUsage()
		os.Exit(1)
	}
}

func printConfigUsage() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  trustless config init     Create default config file")
	fmt.Fprintln(os.Stderr, "  trustless config show     Show current config")
}
