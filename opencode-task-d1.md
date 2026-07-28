# Step D1: `trustless proxy start` — skeleton + subcommand dispatch

## Context

Go project at `/home/ubuntu/projects/trustless`.

We need the proxy subcommand skeleton that dispatches `trustless proxy start` and creates the directory structure.

## Task

### 1. Create `internal/proxy/command.go`

A minimal subcommand dispatcher:

```go
package proxy

import (
    "context"
    "flag"
    "fmt"
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

    // Create proxy instance (minimal — just placeholder that starts a server)
    fmt.Fprintf(os.Stderr, "trustless proxy listening on 127.0.0.1:%d\n", *port)
    
    // For now, just start a basic HTTP server that returns 200 OK
    // This will be replaced with the real proxy in Step D2
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
```

Make sure to add these imports: `context`, `flag`, `fmt`, "net/http", `os`, `os/signal`, `syscall`, and the project's internal packages.

### 2. Modify `main.go`

Add proxy import and case:
```go
import "github.com/ikkun1222/trustless/internal/proxy"
// ...
case "proxy":
    proxy.Run(args, be, cfg)
```

## Build and minimal test

```bash
cd /home/ubuntu/projects/trustless
go build -o trustless .

# Start proxy and quickly test it
timeout 3 ./trustless proxy start --port 9997 2>&1 || true
# Should print: trustless proxy listening on 127.0.0.1:9997
```
