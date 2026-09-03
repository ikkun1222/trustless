package setup

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	green = ""
	cyan  = ""
	red   = ""
	reset = ""
)

func init() {
	fi, err := os.Stdout.Stat()
	if err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		green = "\033[32m"
		cyan = "\033[36m"
		red = "\033[31m"
		reset = "\033[0m"
	}
}

type SetupOptions struct {
	NonInteractive bool
	GPGKeyID       string
}

func promptConfirm(msg string, defaultYes bool) bool {
	suffix := "[y/N] "
	if defaultYes {
		suffix = "[Y/n] "
	}
	fmt.Printf("%s %s", msg, suffix)
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return defaultYes
	}
	input = strings.TrimSpace(strings.ToLower(input))
	if input == "" {
		return defaultYes
	}
	return input == "y" || input == "yes"
}

func Run(args []string) {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	opts := SetupOptions{}
	fs.BoolVar(&opts.NonInteractive, "non-interactive", false, "Run in non-interactive mode")
	var importDirs []string
	fs.Func("import-dir", "Directory to scan for .env files (can be specified multiple times)", func(s string) error {
		importDirs = append(importDirs, s)
		return nil
	})

	fs.Parse(args)

	if len(importDirs) == 0 {
		importDirs = []string{"."}
	}

	fmt.Printf("\n%s%s%s\n", cyan, "trustless setup \u2014 first-time credential broker setup", reset)
	fmt.Println(strings.Repeat("=", 50))
	fmt.Println()

	ctx := context.Background()

	if err := stepGPG(ctx, &opts); err != nil {
		os.Exit(1)
	}
	fmt.Println()

	if err := stepPass(ctx, &opts); err != nil {
		os.Exit(1)
	}
	fmt.Println()

	if err := stepEnvImport(ctx, &opts, importDirs); err != nil {
		os.Exit(1)
	}
	fmt.Println()

	if err := stepAgentIntegration(&opts); err != nil {
		os.Exit(1)
	}
	fmt.Println()

	fmt.Printf("%s\u2500\u2500 Setup Complete \u2500\u2500%s\n", green, reset)
	fmt.Printf("Next: %strustless doctor%s     \u2192 verify everything is healthy\n", cyan, reset)
	fmt.Printf("      %strustless run -s KEY%s  \u2192 inject a credential into a subprocess\n", cyan, reset)
}

func stepGPG(ctx context.Context, opts *SetupOptions) error {
	fmt.Printf("[1/4] %sGPG Key%s\n", cyan, reset)

	keyID, err := FindGPGKey(ctx)
	if err == nil && keyID != "" {
		fmt.Printf("  %s\u2713%s Found GPG key: %s%s%s\n", green, reset, cyan, keyID, reset)
		opts.GPGKeyID = keyID
		return nil
	}

	fmt.Printf("  %s\u2192%s Creating new GPG key (RSA 3072, no passphrase, 5y expiry)\n", cyan, reset)
	keyID, err = CreateGPGKey(ctx)
	if err != nil {
		fmt.Printf("  %s\u2717%s %v\n", red, reset, err)
		if !opts.NonInteractive && promptConfirm("Continue anyway?", false) {
			return nil
		}
		return err
	}

	fmt.Printf("  %s\u2713%s GPG key created: %s%s%s\n", green, reset, cyan, keyID, reset)
	opts.GPGKeyID = keyID
	return nil
}

func stepPass(ctx context.Context, opts *SetupOptions) error {
	fmt.Printf("[2/4] %spass Store%s\n", cyan, reset)

	if opts.GPGKeyID == "" {
		fmt.Printf("  %s\u2717%s No GPG key available for pass initialization\n", red, reset)
		if !opts.NonInteractive && promptConfirm("Continue anyway?", false) {
			return nil
		}
		return fmt.Errorf("no GPG key available")
	}

	fmt.Printf("  %s\u2192%s Initializing pass store with key %s%s%s\n", cyan, reset, cyan, opts.GPGKeyID, reset)
	if err := InitPassStore(opts.GPGKeyID); err != nil {
		fmt.Printf("  %s\u2717%s %v\n", red, reset, err)
		if !opts.NonInteractive && promptConfirm("Continue anyway?", false) {
			return nil
		}
		return err
	}

	home, _ := os.UserHomeDir()
	if home == "" {
		home = "~"
	}
	fmt.Printf("  %s\u2713%s pass store ready at %s%s%s%s\n", green, reset, cyan, home, "/.password-store/", reset)
	fmt.Printf("  %s\u2713%s pass git init complete\n", green, reset)
	return nil
}

func stepEnvImport(ctx context.Context, opts *SetupOptions, importDirs []string) error {
	fmt.Printf("[3/4] %s.env Credential Import%s\n", cyan, reset)
	fmt.Printf("  %s\u2192%s Scanning for .env files...\n", cyan, reset)

	envFiles, err := ScanEnvFiles(importDirs)
	if err != nil {
		fmt.Printf("  %s\u2717%s %v\n", red, reset, err)
		if !opts.NonInteractive && promptConfirm("Continue anyway?", false) {
			return nil
		}
		return err
	}

	if len(envFiles) == 0 {
		fmt.Printf("  %s\u2713%s No .env files found to import\n", green, reset)
		return nil
	}

	for _, ef := range envFiles {
		fmt.Printf("  %s\u2713%s Found %s (%d entries)\n", green, reset, ef.Path, len(ef.Entries))
	}

	total := 0
	for _, ef := range envFiles {
		total += len(ef.Entries)
	}

	importCreds := true
	if !opts.NonInteractive {
		importCreds = promptConfirm(fmt.Sprintf("Import %d credentials to pass?", total), true)
	}

	if !importCreds {
		return nil
	}

	home, _ := os.UserHomeDir()
	if home == "" {
		home = os.TempDir()
	}
	backupDir := filepath.Join(home, fmt.Sprintf(".env-backup-%s", time.Now().Format("20060102")))

	if err := ImportToPass(envFiles); err != nil {
		fmt.Printf("  %s\u2717%s Failed to import: %v\n", red, reset, err)
		if !opts.NonInteractive && promptConfirm("Continue anyway?", false) {
			return nil
		}
		return err
	}
	fmt.Printf("  %s\u2713%s Imported %d credentials\n", green, reset, total)

	if !opts.NonInteractive && promptConfirm("Backup and remove plaintext .env files?", true) {
		if err := BackupEnvFiles(envFiles, backupDir); err != nil {
			fmt.Printf("  %s\u2717%s Backup failed: %v\n", red, reset, err)
			if !opts.NonInteractive && promptConfirm("Continue anyway?", false) {
				return nil
			}
			return err
		}
		fmt.Printf("  %s\u2713%s Backed up to %s%s%s\n", green, reset, cyan, backupDir, reset)

		if err := RemoveEnvFiles(envFiles, backupDir); err != nil {
			fmt.Printf("  %s\u2717%s Removal failed: %v\n", red, reset, err)
			if !opts.NonInteractive && promptConfirm("Continue anyway?", false) {
				return nil
			}
			return err
		}
	}

	return nil
}

func stepAgentIntegration(opts *SetupOptions) error {
	fmt.Printf("[4/4] %sAgent Integration%s\n", cyan, reset)

	type agentCheck struct {
		name   string
		detect func() (*AgentDetectResult, error)
	}

	agents := []agentCheck{
		{"OpenCode", DetectOpenCode},
		{"Claude Code", DetectClaudeCode},
		{"Codex", DetectCodex},
		{"Hermes", DetectHermes},
	}

	var needChange []AgentDetectResult

	for _, a := range agents {
		result, err := a.detect()
		if err != nil {
			fmt.Printf("  %s\u2717%s %s: detection error \u2014 %v\n", red, reset, a.name, err)
			continue
		}
		if result == nil {
			fmt.Printf("  %s\u2713%s %s: not detected\n", green, reset, a.name)
			continue
		}
		fmt.Printf("  %s\u2713%s %s: %s\n", green, reset, a.name, result.Description)
		if result.NeedsChange {
			needChange = append(needChange, *result)
		}
	}

	if len(needChange) == 0 || opts.NonInteractive {
		return nil
	}

	if !promptConfirm("Apply agent integrations?", true) {
		return nil
	}

	for _, r := range needChange {
		if r.ChangeFunc == nil {
			continue
		}
		if err := r.ChangeFunc(); err != nil {
			fmt.Printf("  %s\u2717%s Failed to configure %s: %v\n", red, reset, r.Name, err)
			continue
		}
		fmt.Printf("  %s\u2713%s %s configured\n", green, reset, r.Name)
	}

	return nil
}
