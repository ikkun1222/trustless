package setup

import (
	"context"
	"flag"
	"fmt"
	"os"
)

type SetupOptions struct {
	NonInteractive bool
	GPGKeyID       string
}

func Run(args []string) {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	opts := SetupOptions{}
	fs.BoolVar(&opts.NonInteractive, "non-interactive", false, "Run in non-interactive mode")
	fs.Parse(args)

	fmt.Println("trustless setup — first-time setup wizard")

	keyID, err := SetupGPG(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	opts.GPGKeyID = keyID
	fmt.Printf("GPG key ID: %s\n", keyID)
}
