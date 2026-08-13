package dlp

import (
	"flag"
	"fmt"
	"log"

	dlpconfig "github.com/ikkun1222/trustless/internal/dlp/config"
	"github.com/ikkun1222/trustless/internal/dlp/scrub"
)

// runScrubE implements `trustless dlp scrub-db <db> [--apply] [--backup]`
// and is the testable core of the command; it returns errors instead of
// exiting. Default is dry-run: scans the DB and prints hit counts without
// writing. Secrets are loaded from the config's secrets_source (pass or
// bitwarden — バックエンド選択可能）with the given minimum length.
func runScrubE(args []string, logger *log.Logger) error {
	fs := flag.NewFlagSet("scrub-db", flag.ContinueOnError)
	apply := fs.Bool("apply", false, "write changes (default: dry-run scan only)")
	backup := fs.Bool("backup", false, "copy DB to <db>.bak before writing")
	minLen := fs.Int("min-len", 8, "minimum secret length to consider")
	configPath := fs.String("config", defaultConfigPath(), "path to config.json (defines secrets_source)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: trustless dlp scrub-db <db-path> [--apply] [--backup]")
	}
	dbPath := fs.Arg(0)

	secrets, err := secretsFromConfig(*configPath, *minLen)
	if err != nil {
		return err
	}
	return runScrubWithSecrets(dbPath, secrets, *minLen, *apply, *backup, logger)
}

// runScrubTextE implements `trustless dlp scrub-text <file-or-dir>
// [--apply]`. Default is dry-run; --apply replaces secrets in text files
// under the given path. Used for sessions/, logs/, and other non-DB text
// stores.
func runScrubTextE(args []string, logger *log.Logger) error {
	fs := flag.NewFlagSet("scrub-text", flag.ContinueOnError)
	apply := fs.Bool("apply", false, "write changes (default: dry-run scan only)")
	minLen := fs.Int("min-len", 8, "minimum secret length to consider")
	configPath := fs.String("config", defaultConfigPath(), "path to config.json (defines secrets_source)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: trustless dlp scrub-text <file-or-dir> [--apply]")
	}
	root := fs.Arg(0)

	secrets, err := secretsFromConfig(*configPath, *minLen)
	if err != nil {
		return err
	}
	return runScrubTextWithSecrets(root, secrets, *minLen, *apply, logger)
}

// runScrubTextWithSecrets is the pure core of scrub-text: scans or scrubs
// root with the given secrets. Used by runScrubTextE (real backend) and
// tests (injected values).
func runScrubTextWithSecrets(root string, secrets []string, minLen int, apply bool, logger *log.Logger) error {
	if apply {
		rep, err := scrub.ScrubTextFiles(root, secrets, minLen)
		if err != nil {
			return fmt.Errorf("scrub: %w", err)
		}
		logger.Printf("SCRUBBED-TEXT %s: %d hits in %d files",
			root, rep.TotalHits(), len(rep.Hits))
		for k, v := range rep.Hits {
			logger.Printf("  %s: %d", k, v)
		}
		return nil
	}

	rep, err := scrub.ScanTextFiles(root, secrets, minLen)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	logger.Printf("DRY-RUN-TEXT %s: %d hits in %d files (use --apply to scrub)",
		root, rep.TotalHits(), len(rep.Hits))
	for k, v := range rep.Hits {
		logger.Printf("  %s: %d", k, v)
	}
	return nil
}

// runScrubWithSecrets is the pure core: scrubs or scans dbPath with the
// given secrets. Used by runScrubE (real backend) and tests (injected
// values).
func runScrubWithSecrets(dbPath string, secrets []string, minLen int, apply, backup bool, logger *log.Logger) error {
	logger.Printf("loaded %d secrets (min length %d)", len(secrets), minLen)

	if apply {
		rep, err := scrub.ScrubDB(dbPath, secrets, minLen, backup)
		if err != nil {
			return fmt.Errorf("scrub: %w", err)
		}
		logger.Printf("SCRUBBED %s: %d hits in %d columns; FTS rebuilt: %v",
			dbPath, rep.TotalHits(), len(rep.Tables), rep.FTSRebuilt)
		for k, v := range rep.Tables {
			logger.Printf("  %s: %d", k, v)
		}
		return nil
	}

	rep, err := scrub.ScanDB(dbPath, secrets, minLen)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	logger.Printf("DRY-RUN %s: %d hits in %d columns (use --apply to scrub)",
		dbPath, rep.TotalHits(), len(rep.Tables))
	for k, v := range rep.Tables {
		logger.Printf("  %s: %d", k, v)
	}
	return nil
}

// secretsFromConfig loads the config file and resolves the secret list
// through the same backend selection as the proxy (loadSecrets), so scrub
// commands follow the configured secrets_source.
func secretsFromConfig(configPath string, minLen int) ([]string, error) {
	cfg, err := dlpconfig.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	secrets, err := loadSecrets(cfg)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", cfg.SecretsSource, err)
	}
	if minLen != cfg.MinSecretLen {
		secrets = filterMinLen(secrets, minLen)
	}
	return secrets, nil
}

// filterMinLen drops secrets shorter than minLen.
func filterMinLen(secrets []string, minLen int) []string {
	kept := make([]string, 0, len(secrets))
	for _, s := range secrets {
		if len(s) >= minLen {
			kept = append(kept, s)
		}
	}
	return kept
}
