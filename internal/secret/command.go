package secret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ikkun1222/trustless/internal/backend"
	"github.com/ikkun1222/trustless/internal/config"
)

func Run(args []string, be backend.Backend, cfg *config.Config) {
	if len(args) < 1 {
		printUsage()
		os.Exit(1)
	}

	switch args[0] {
	case "list":
		list(be)
	case "get":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: trustless secret get <key>")
			os.Exit(1)
		}
		get(be, args[1])
	case "set":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: trustless secret set <key> [value]")
			os.Exit(1)
		}
		key := args[1]
		val := ""
		if len(args) >= 3 {
			val = args[2]
		}
		if val == "" {
			// Read the value from stdin (pipe or tty) so it never appears on
			// argv (ps / shell history leak).
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: read value from stdin: %v\n", err)
				os.Exit(1)
			}
			val = strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
		}
		if err := be.Set(context.Background(), key, val); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Stored %s\n", key)
	default:
		fmt.Fprintf(os.Stderr, "Unknown secret subcommand: %s\n", args[0])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: trustless secret <command> [<args>]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  list              List all available credential keys")
	fmt.Fprintln(os.Stderr, "  get    <key>      Retrieve a credential value")
	fmt.Fprintln(os.Stderr, "  set    <key>      Store a new credential (prompts for value)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Use 'pass' directly for advanced credential management.")
}

func list(be backend.Backend) {
	entries, err := be.List(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}

	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Key)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func get(be backend.Backend, key string) {
	val, err := be.Resolve(context.Background(), key)
	if err != nil {
		var nf *backend.ErrNotFound
		if errors.As(err, &nf) {
			fmt.Fprintf(os.Stderr, "Error: credential %q not found\n", key)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	out := map[string]string{"key": key, "value": val}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
