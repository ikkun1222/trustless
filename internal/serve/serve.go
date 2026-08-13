// Package serve implements `trustless serve`: a single process that runs
// both the forward credential-injection proxy and the outbound DLP reverse
// proxy, sharing one credential backend. This is the final Phase 4 form —
// it replaces running `trustless proxy start` and `trustless dlp start`
// as separate processes.
package serve

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ikkun1222/trustless/internal/backend"
	"github.com/ikkun1222/trustless/internal/config"
	"github.com/ikkun1222/trustless/internal/dlp"
	dlpconfig "github.com/ikkun1222/trustless/internal/dlp/config"
	dlpproxy "github.com/ikkun1222/trustless/internal/dlp/proxy"
	"github.com/ikkun1222/trustless/internal/proxy"
)

// defaultDlpConfigPath returns ~/.config/dlp-proxy/config.json, matching
// the standalone `trustless dlp start` default.
func defaultDlpConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "config.json"
	}
	return home + "/.config/dlp-proxy/config.json"
}

// Run parses the serve flags and starts both listeners with a single shared
// backend. All fatal errors exit 1 (fail-closed): serve never starts with a
// broken dlp config or an unusable backend.
func Run(args []string, trustlessCfg *config.Config) {
	logger := log.New(os.Stderr, "trustless serve: ", log.LstdFlags)

	fs := flag.NewFlagSet("trustless serve", flag.ContinueOnError)
	injectPort := fs.Int("inject-port", 8080, "forward injection proxy listen port")
	scrubListen := fs.String("scrub-listen", "127.0.0.1:8787", "DLP reverse proxy listen address")
	dlpConfigPath := fs.String("dlp-config", defaultDlpConfigPath(), "path to dlp-proxy config.json")
	mitm := fs.Bool("mitm", false, "Enable MITM mode on the injection proxy (intercept HTTPS)")
	fs.Usage = printUsage

	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	// Fail-closed: the dlp config must be loadable before any listener
	// starts (serveCore re-reads it for the actual values).
	if _, err := dlpconfig.Load(*dlpConfigPath); err != nil {
		logger.Fatalf("dlp config: %v", err)
	}

	be := newBackend(trustlessCfg)
	if be == nil {
		logger.Fatalf("unsupported backend %q", trustlessCfg.Backend)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := serveCore(ctx, *injectPort, *scrubListen, *dlpConfigPath, *mitm, trustlessCfg, be, logger); err != nil {
		logger.Fatalf("serve: %v", err)
	}
}

// newBackend builds the single shared backend from the trustless config,
// running Load for backends that require it (bitwarden). Any load error is
// fatal (fail-closed). Returns nil for an unsupported backend name.
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

// serveCore starts the injection proxy and the DLP reverse proxy as
// goroutines on the same context, then runs the periodic reload loop until
// the context is cancelled. Both listeners must bind successfully or the
// whole serve fails (fail-closed).
func serveCore(ctx context.Context, injectPort int, scrubListen, dlpConfigPath string, mitm bool, trustlessCfg *config.Config, be backend.Backend, logger *log.Logger) error {
	dlpCfg, err := dlpconfig.Load(dlpConfigPath)
	if err != nil {
		return fmt.Errorf("dlp config: %w", err)
	}

	secrets, err := dlp.LoadSecretsFromBackend(be, dlpCfg.MinSecretLen)
	if err != nil {
		return fmt.Errorf("load secrets: %w", err)
	}
	logger.Printf("loaded %d secrets (min length %d)", len(secrets), dlpCfg.MinSecretLen)
	set := dlpproxy.NewSecrets(secrets)

	dlpHandler := recoverMiddleware(dlp.BuildHandler(dlpCfg, set, logger), logger)
	dlpServer := &http.Server{Handler: dlpHandler}
	dlpListener, err := net.Listen("tcp", scrubListen)
	if err != nil {
		return fmt.Errorf("dlp listen %s: %w", scrubListen, err)
	}
	go func() {
		if err := dlpServer.Serve(dlpListener); err != nil && err != http.ErrServerClosed {
			logger.Printf("dlp server: %v", err)
		}
	}()

	fwd, err := proxy.StartForward(ctx, be, trustlessCfg, injectPort, mitm)
	if err != nil {
		dlpServer.Close()
		return fmt.Errorf("injection proxy: %w", err)
	}

	logger.Printf("forward injection proxy listening on %s", fwd.Addr())
	logger.Printf("dlp reverse proxy listening on %s", dlpListener.Addr())

	go func() {
		<-ctx.Done()
		dlpServer.Close()
	}()

	// Periodic hot reload: re-read both configs and refresh the shared
	// backend + secrets set. A failed reload keeps the previous state
	// (fail-safe), exactly like the standalone dlp process.
	ticker := time.NewTicker(dlpCfg.SecretsRefresh)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			reloadAll(dlpConfigPath, dlpCfg, set, be, fwd, logger)
		}
	}
}

// reloadAll re-reads the trustless config (rules/allowlist) and the dlp
// config, then reloads the shared backend and atomically replaces the
// secrets set. On failure the previous state is kept and the problem is
// logged as a warning (fail-safe).
func reloadAll(dlpConfigPath string, dlpCfg *dlpconfig.Config, set *dlpproxy.Secrets, be backend.Backend, fwd *proxy.Proxy, logger *log.Logger) {
	newTrustless, err := config.Load(config.DefaultConfigPath())
	if err != nil {
		logger.Printf("WARN: trustless config reload failed, keeping current rules: %v", err)
	} else {
		fwd.UpdateRules(newTrustless.Proxy.Rules, newTrustless.Proxy.Allowlist)
	}

	if r, ok := be.(interface{ Reload(context.Context) error }); ok {
		if err := r.Reload(context.Background()); err != nil {
			logger.Printf("WARN: backend reload failed, keeping current secrets: %v", err)
			return
		}
	}

	newDlpCfg, err := dlpconfig.Load(dlpConfigPath)
	if err != nil {
		logger.Printf("WARN: dlp config reload failed, keeping current secrets: %v", err)
		return
	}
	fresh, err := dlp.LoadSecretsFromBackend(be, newDlpCfg.MinSecretLen)
	if err != nil {
		logger.Printf("WARN: secret reload failed, keeping %d secrets: %v", set.Len(), err)
		return
	}
	set.Replace(fresh)
	logger.Printf("reloaded %d secrets (min length %d)", len(fresh), newDlpCfg.MinSecretLen)
}

// recoverMiddleware converts a panicking handler into a 500 response so a
// single bad request cannot kill the whole process.
func recoverMiddleware(next http.Handler, logger *log.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				logger.Printf("panic in handler: %v", rec)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: trustless serve [flags]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Run the forward credential-injection proxy and the DLP reverse proxy in a single process.")
	fmt.Fprintln(os.Stderr, "One shared credential backend serves both listeners.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Flags:")
	fmt.Fprintln(os.Stderr, "  --inject-port <n>    Forward injection proxy listen port (default: 8080)")
	fmt.Fprintln(os.Stderr, "  --scrub-listen <addr> DLP reverse proxy listen address (default: 127.0.0.1:8787)")
	fmt.Fprintln(os.Stderr, "  --dlp-config <path>  Path to dlp-proxy config.json (default: ~/.config/dlp-proxy/config.json)")
	fmt.Fprintln(os.Stderr, "  --mitm               Enable MITM mode on the injection proxy (intercept HTTPS)")
}
