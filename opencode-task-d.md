# Step D: Implement `trustless proxy` — HTTP Credential Proxy

## Context

Go project at `/home/ubuntu/projects/trustless`.

We need an HTTP forward proxy that intercepts outbound requests and substitutes `__KEY_NAME__` placeholders with real credentials resolved from the pass backend.

## Task

### 1. Create `internal/proxy/proxy.go`

A forward proxy server with the following features:

**Core logic:**
- Listen on a TCP port (default 8080) or Unix socket
- For HTTP requests: forward using `httputil.ReverseProxy`, but first scan headers, URL, and body for placeholders
- For HTTPS CONNECT requests: tunnel transparently (no placeholder substitution — we can't see inside TLS)
- Placeholder format: `__KEY_NAME__` (double underscore + uppercase key name with underscores + double underscore)
  - Example: `__GITHUB_TOKEN__`, `__OPENAI_KEY__`, `__XAI__`
- Resolve the key name via `be.Resolve(ctx, key)` and substitute the value
- Domain allowlisting: only proxy requests to allowed domains
- Graceful shutdown on SIGINT/SIGTERM

**Data flow:**
```
Client → trustless proxy (port 8080)
  ↓
Read request, scan for __KEY_NAME__ placeholders
  ↓
Resolve each key from backend
  ↓
Substitute placeholders with real values in headers and body
  ↓
Forward to target server
  ↓
Return response to client (unchanged)
```

**Key API:**
```go
package proxy

type Proxy struct {
    backend  backend.Backend
    port     int
    unixPath string
    allowlist []string
}

func New(be backend.Backend, cfg *config.Config) *Proxy

// Start begins listening and serving. Blocks until shutdown.
func (p *Proxy) Start(ctx context.Context) error
```

**Implementation details:**
- Use `http.Server` with a custom handler
- For HTTP forwarding, use `httputil.ReverseProxy` with a custom `Director` function that:
  - Scans the request URL, headers, and body for `__KEY_NAME__` patterns
  - Uses regexp `__(\\w+)__` to find placeholders
  - Resolves each placeholder to a credential value
  - Applies domain allowlist check
- For placeholder substitution in body:
  - Read body into bytes
  - Replace placeholders
  - Set `newBody` on the request
- For CONNECT: use `Hijacker` to tunnel raw TCP
- Domain allowlist: check `r.Host` against configured domains (support glob patterns like `*.github.com`)
- Graceful shutdown: listen for `os.Signal`, call `server.Shutdown(ctx)`

**Starting the proxy:**
```go
func (p *Proxy) Start(ctx context.Context) error {
    handler := http.HandlerFunc(p.handleRequest)
    server := &http.Server{
        Addr:    fmt.Sprintf("127.0.0.1:%d", p.port),
        Handler: handler,
    }
    // ... signal handling, graceful shutdown ...
    return server.ListenAndServe()
}
```

### 2. Create `internal/proxy/command.go`

Subcommand dispatcher for the proxy subcommand:

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

    p := &Proxy{
        backend:   be,
        port:      *port,
        unixPath:  *unixSocket,
        allowlist: nil, // from config later
    }

    ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer stop()

    fmt.Fprintf(os.Stderr, "trustless proxy listening on 127.0.0.1:%d\n", *port)
    if err := p.Start(ctx); err != nil {
        fmt.Fprintf(os.Stderr, "proxy error: %v\n", err)
        os.Exit(1)
    }
}
```

### 3. Modify `main.go`

Add proxy subcommand dispatch:

```go
case "proxy":
    proxy.Run(args, be, cfg)
```

Add import for `internal/proxy`.

## Acceptance tests

```bash
cd /home/ubuntu/projects/trustless
go build

# Start proxy in background
./trustless proxy start --port 9999 &
PROXY_PID=$!
sleep 1

# Test 1: HTTP request with placeholder substitution
# First, add a test secret to pass
echo "test-token-12345" | pass insert --force test/placeholder-key

# Test 2: curl with placeholder
HTTPS_PROXY=http://127.0.0.1:9999 curl -s -H "Authorization: Bearer __TEST_PLACEHOLDER_KEY__" http://httpbin.org/headers 2>&1

# Test 3: Verify placeholder was substituted
# (the response from httpbin should show the actual token in the Authorization header)

# Cleanup
kill $PROXY_PID 2>/dev/null
wait $PROXY_PID 2>/dev/null
```

Note: Since the test requires an external HTTP endpoint (httpbin.org), you can also test locally with a simple Go HTTP server or just verify the build compiles and proxy starts.

**Minimal acceptance:**
```bash
cd /home/ubuntu/projects/trustless
go build -o trustless .

# Proxy should start and accept connections
timeout 3 ./trustless proxy start --port 9998 2>&1 || true
# Should print: "trustless proxy listening on 127.0.0.1:9998"
```

## Files to create

- `internal/proxy/proxy.go` — main proxy logic
- `internal/proxy/command.go` — subcommand dispatcher

## Files to modify

- `main.go` — add proxy import and case

## Important notes

- Only HTTP proxying supports placeholder substitution. HTTPS (CONNECT) tunnels transparently with no substitution.
- The proxy should bind to `127.0.0.1` only (not `0.0.0.0`) for security
- For CONNECT tunneling, implement a simple `Hijack` + `io.Copy` bidirectional tunnel
- The domain allowlist in config (`proxy.allowlist`) should be supported but can be empty (allow all) for now
- Handle `http.Hijacker` properly for CONNECT — get the underlying `net.Conn` from `http.ResponseWriter`
- Use `bufio.ReadWriter` for the CONNECT tunnel to ensure proper flushing
