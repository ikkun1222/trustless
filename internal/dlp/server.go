// Package dlp implements the `trustless dlp` subcommands. It is standalone:
// unlike the rest of trustless it selects its own credential backend from the
// dlp config's secrets_source, so it skips the global backend initialization.
package dlp

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ikkun1222/trustless/internal/backend"
	dlpconfig "github.com/ikkun1222/trustless/internal/dlp/config"
	dlpproxy "github.com/ikkun1222/trustless/internal/dlp/proxy"
	"github.com/ikkun1222/trustless/internal/dlp/redact"
)

// defaultConfigPath returns ~/.config/dlp-proxy/config.json.
func defaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "config.json"
	}
	return filepath.Join(home, ".config", "dlp-proxy", "config.json")
}

// Run dispatches the `trustless dlp` subcommands. Unknown subcommands print
// the usage to stderr and exit 1.
func Run(args []string) {
	logger := log.New(os.Stderr, "dlp-proxy: ", log.LstdFlags)
	if len(args) < 1 {
		printUsage()
		os.Exit(1)
	}
	switch args[0] {
	case "start":
		start(args[1:])
	case "scrub-db":
		if err := runScrubE(args[1:], logger); err != nil {
			logger.Fatalf("scrub-db: %v", err)
		}
	case "scrub-text":
		if err := runScrubTextE(args[1:], logger); err != nil {
			logger.Fatalf("scrub-text: %v", err)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown dlp subcommand: %s\n", args[0])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: trustless dlp <command> [<args>]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  start       Start the DLP reverse proxy")
	fmt.Fprintln(os.Stderr, "  scrub-db    Scan/scrub secrets from a local SQLite DB")
	fmt.Fprintln(os.Stderr, "  scrub-text  Scan/scrub secrets from text files")
}

// start loads the config, selects the backend from secrets_source, loads the
// secret list, and serves the DLP reverse proxy. All errors are fatal
// (fail-closed): the proxy never starts with a partial or empty secret set.
func start(args []string) {
	logger := log.New(os.Stderr, "dlp-proxy: ", log.LstdFlags)

	fs := flag.NewFlagSet("dlp start", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath(), "path to config.json")
	fs.Parse(args)

	cfg, err := dlpconfig.Load(*configPath)
	if err != nil {
		logger.Fatalf("config: %v", err)
	}

	secrets, err := loadSecrets(cfg)
	if err != nil {
		logger.Fatalf("%s: %v", cfg.SecretsSource, err)
	}
	logger.Printf("loaded %d secrets from %s (min length %d)", len(secrets), cfg.SecretsSource, cfg.MinSecretLen)

	secretSet := dlpproxy.NewSecrets(secrets)
	handler := buildHandler(cfg, secretSet, logger)
	load := func(cfg *dlpconfig.Config) ([]string, error) {
		return loadSecrets(cfg)
	}
	// SIGHUP で即時リロード（新規秘密を格納した直後に手動適用するため）:
	//   systemctl --user kill -s HUP dlp-proxy
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	manual := make(chan struct{}, 1)
	go func() {
		for range hup {
			select {
			case manual <- struct{}{}:
			default: // 既に要求が溜まっている場合は1つに集約（連打しても1回のリロード）
			}
		}
	}()
	go refreshLoop(cfg, secretSet, load, logger, nil, manual)
	logger.Printf("listening on %s", cfg.Listen)
	if err := http.ListenAndServe(cfg.Listen, handler); err != nil {
		logger.Fatalf("server: %v", err)
	}
}

// loadSecrets loads known secrets for the configured source: pass (default)
// or Bitwarden — バックエンド選択可能（trustless と同仕様）。Any load error
// aborts startup (fail-closed). The Backend.Values interface replaces
// dlp-proxy's bitwardenloader/passstore; email addresses are excluded from
// the secret list (redact.IsEmail — keep() 相当) because they are
// identifiers, not credentials.
func loadSecrets(cfg *dlpconfig.Config) ([]string, error) {
	var be backend.Backend
	switch cfg.SecretsSource {
	case dlpconfig.SecretsBitwarden:
		bwb := backend.NewBitwardenBackend(backend.Options{})
		if err := bwb.Load(context.Background()); err != nil {
			return nil, err
		}
		be = bwb
	case dlpconfig.SecretsPass:
		be = backend.NewPassBackend()
	default:
		return nil, fmt.Errorf("unsupported secrets source %q", cfg.SecretsSource)
	}

	vals, err := be.Values(context.Background(), cfg.MinSecretLen)
	if err != nil {
		return nil, err
	}
	kept := vals[:0]
	for _, v := range vals {
		if !redact.IsEmail(v) {
			kept = append(kept, v)
		}
	}
	return kept, nil
}

// buildHandler assembles the route-multiplexing handler. Each route strips
// its local prefix, forwards the remainder to the upstream (joining the
// upstream's base path), and masks secrets in the request body. The secrets
// set is shared across routes and may be hot-swapped at runtime.
func buildHandler(cfg *dlpconfig.Config, secrets *dlpproxy.Secrets, logger *log.Logger) http.Handler {
	mux := http.NewServeMux()
	for _, r := range cfg.Routes {
		p := dlpproxy.New(dlpproxy.Options{
			Secrets:      secrets,
			MinSecretLen: cfg.MinSecretLen,
			UpstreamURL:  r.URL,
			Logger:       logger,
		})
		stripped := http.StripPrefix(r.Prefix, p)
		mux.Handle(r.Prefix, stripped)
		mux.Handle(r.Prefix+"/", stripped)
	}
	return mux
}

// refreshLoop periodically reloads secrets from the configured source and
// atomically swaps them into the shared set. A failed reload keeps the
// previous set (the proxy stays armed with the last good list) and is
// logged as a warning — never fatal. Hot reload exists so vault changes
// (e.g. repaired fields, rotated tokens) take effect without a restart
// that would cut in-flight LLM routes. manual (SIGHUP) triggers an
// immediate reload for newly stored secrets.
func refreshLoop(cfg *dlpconfig.Config, set *dlpproxy.Secrets, load func(*dlpconfig.Config) ([]string, error), logger *log.Logger, stop, manual <-chan struct{}) {
	ticker := time.NewTicker(cfg.SecretsRefresh)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			reload(cfg, set, load, logger)
		case <-manual:
			logger.Printf("manual reload requested (SIGHUP)")
			reload(cfg, set, load, logger)
		}
	}
}

// reload reads the secret source once and atomically swaps the shared set.
// On failure it keeps the current set and logs a warning (fail-safe).
func reload(cfg *dlpconfig.Config, set *dlpproxy.Secrets, load func(*dlpconfig.Config) ([]string, error), logger *log.Logger) {
	fresh, err := load(cfg)
	if err != nil {
		logger.Printf("WARN: secret reload failed, keeping %d secrets: %v", set.Len(), err)
		return
	}
	set.Replace(fresh)
	logger.Printf("reloaded %d secrets from %s", len(fresh), cfg.SecretsSource)
}
