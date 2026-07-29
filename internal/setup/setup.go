package setup

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

type SetupOptions struct {
	NonInteractive bool
	GPGKeyID       string
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

	fmt.Println("trustless setup — first-time setup wizard")

	keyID, err := SetupGPG(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	opts.GPGKeyID = keyID
	fmt.Printf("GPG key ID: %s\n", keyID)

	if err := InitPassStore(keyID); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[1/2] Initialized pass store with GPG key %s\n", keyID)

	if len(importDirs) == 0 {
		importDirs = []string{"."}
	}

	envFiles, err := ScanEnvFiles(importDirs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if len(envFiles) > 0 {
		fmt.Println("Found .env files:")
		for _, ef := range envFiles {
			fmt.Printf("  %s (%d entries)\n", ef.Path, len(ef.Entries))
		}

		backupDir := filepath.Join(os.TempDir(), "trustless-env-backup")
		if err := ImportToPass(envFiles, backupDir); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if err := BackupEnvFiles(envFiles, backupDir); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if err := RemoveEnvFiles(envFiles); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		total := 0
		for _, ef := range envFiles {
			total += len(ef.Entries)
		}
		fmt.Printf("[2/2] Imported %d credentials from .env files\n", total)
	} else {
		fmt.Println("[2/2] No .env files found to import")
	}
}
