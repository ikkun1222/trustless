package proxy

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/ikkun1222/trustless/internal/backend"
	"github.com/ikkun1222/trustless/internal/config"
)

func Run(args []string, be backend.Backend, cfg *config.Config) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: trustless proxy start")
		os.Exit(1)
	}
	switch args[0] {
	case "start":
		start(args[1:], be, cfg)
	default:
		fmt.Fprintf(os.Stderr, "Unknown proxy subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func start(args []string, be backend.Backend, cfg *config.Config) {
	fs := flag.NewFlagSet("proxy-start", flag.ContinueOnError)
	port := fs.Int("port", cfg.Proxy.Port, "listen port")
	unixSocket := fs.String("unix-socket", "", "unix socket path")

	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	_ = unixSocket

	fmt.Fprintf(os.Stderr, "trustless proxy listening on 127.0.0.1:%d\n", *port)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "trustless proxy placeholder - real proxy coming in Step D2")
	})

	server := &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", *port),
		Handler: mux,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		server.Shutdown(context.Background())
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "proxy error: %v\n", err)
		os.Exit(1)
	}
}
