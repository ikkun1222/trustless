# Step D2: HTTP Forward Proxy with placeholder substitution

## Context

Go project at `/home/ubuntu/projects/trustless`.

We already have `internal/proxy/command.go` with `trustless proxy start` skeleton (placeholder HTTP server). Replace it with a real HTTP forward proxy that substitutes `__KEY_NAME__` placeholders with credential values.

## Task

### Replace `internal/proxy/command.go` with real proxy implementation

Rewrite the file to contain a real forward proxy. Keep the `Run()` and `start()` functions, but replace the placeholder server with a `httputil.ReverseProxy`-based implementation.

### Proxy design

```go
package proxy

type Proxy struct {
    backend   backend.Backend
    port      int
    unixPath  string
    allowlist []string
    resolver  *strings.Replacer // built from resolved credentials
    mu        sync.Mutex        // protects resolver
}
```

**Request flow:**

1. Client sends HTTP request to proxy
2. Proxy reads the request, scans for `__([A-Z0-9_]+)__` placeholders in:
   - `r.Header` values (e.g. `Authorization: Bearer __GITHUB_TOKEN__`)
   - `r.URL` (for query params like `?api_key=__SERVICE_KEY__`)
   - `r.Body` (for POST bodies with placeholders)
3. For each unique placeholder key found:
   - Call `be.Resolve(ctx, key)` to get the credential value
   - Replace ALL occurrences of `__KEY__` with the value
4. Forward the modified request to the target using `httputil.ReverseProxy`
5. Return the response to the client unchanged

**HTTP forwarding:**
```go
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
    // Scan and substitute placeholders
    substitutedReq := p.substitute(r)
    
    // Create reverse proxy
    proxy := &httputil.ReverseProxy{
        Director: func(targetReq *http.Request) {
            // Copy method, URL, headers, body from substitutedReq
            *targetReq = *substitutedReq
            targetReq.URL.Scheme = "http" // or https depending on target
            targetReq.URL.Host = substitutedReq.Host
        },
    }
    proxy.ServeHTTP(w, substitutedReq)
}
```

Wait — `httputil.ReverseProxy` for a forward proxy is slightly different from a reverse proxy. For forward proxying, the client sends the full URL (`GET http://api.example.com/foo HTTP/1.1`). The proxy needs to:

1. Parse the target URL from `r.URL` (which has the full URL for forward proxy requests)
2. Strip the proxy prefix and forward to the actual target
3. For HTTPS, handle CONNECT tunneling

Better approach: implement the proxy using `http.Transport` directly instead of `httputil.ReverseProxy`:

```go
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
    // Create outgoing request
    outReq, _ := http.NewRequest(r.Method, r.URL.String(), r.Body)
    outReq.Header = r.Header.Clone()
    
    // Substitute placeholders in URL, headers, body
    p.substituteRequest(outReq)
    
    // Send and return response
    resp, err := http.DefaultTransport.RoundTrip(outReq)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadGateway)
        return
    }
    defer resp.Body.Close()
    
    // Copy response headers and body
    for k, vv := range resp.Header {
        for _, v := range vv {
            w.Header().Add(k, v)
        }
    }
    w.WriteHeader(resp.StatusCode)
    io.Copy(w, resp.Body)
}
```

**Placeholder substitution in body:**

```go
func (p *Proxy) substituteRequest(r *http.Request) {
    // Substitute in URL query
    r.URL.RawQuery = p.replacePlaceholders(r.URL.RawQuery)
    
    // Substitute in headers
    for key, values := range r.Header {
        for i, v := range values {
            r.Header[key][i] = p.replacePlaceholders(v)
        }
    }
    
    // Substitute in body (only if content is text-like)
    if r.Body != nil && r.Body != http.NoBody {
        body, _ := io.ReadAll(r.Body)
        r.Body.Close()
        newBody := p.replacePlaceholders(string(body))
        r.Body = io.NopCloser(strings.NewReader(newBody))
        r.ContentLength = int64(len(newBody))
    }
}
```

**Placeholder resolution:**

```go
var placeholderRE = regexp.MustCompile(`__([A-Z][A-Z0-9_]*)__`)

func (p *Proxy) replacePlaceholders(s string) string {
    return placeholderRE.ReplaceAllStringFunc(s, func(match string) string {
        key := match[2 : len(match)-2] // strip __
        // Convert key to pass path format (lowercase, underscores to hyphens or dots?)
        // For now, try the key as-is
        val, err := p.backend.Resolve(context.Background(), key)
        if err != nil {
            return match // keep original if not found
        }
        return val
    })
}
```

**Key name mapping:** The placeholder `__XAI__` should resolve the key `xai` from pass. Simple lowercase should work. For deeper keys, the user can use underscores as path separators: `__IRIA_API_XAI__` → try to find `iria/api/xai`. This can be simple: just lowercase and replace `_` with `/` in the key.

Or simpler: the key in pass is the lowercase version of the placeholder. `__GITHUB_TOKEN__` → looks for `github_token` in pass (which could be `iria/api/github_token` or just `github_token`). Since the pass backend does exact matching via `pass show`, the key must exist exactly.

For now, just use lowercase: `__XAI__` → resolve `xai`. If the user wants to use a nested key, they put the full path: the system can try multiple variants.

**Simplest approach:** `__KEY__` → lowercase(`KEY`) → try to resolve. If not found, try `iria/api/` + lowercase(`KEY`). If not found, keep the placeholder unchanged.

### Modify `internal/proxy/command.go` to use the real proxy

Replace the placeholder HTTP server with:

```go
func start(args []string, be backend.Backend, cfg *config.Config) {
    fs := flag.NewFlagSet("proxy-start", flag.ContinueOnError)
    port := fs.Int("port", cfg.Proxy.Port, "listen port")
    unixSocket := fs.String("unix-socket", "", "unix socket path")

    if err := fs.Parse(args); err != nil {
        os.Exit(2)
    }

    p := &Proxy{
        backend: be,
        port:    *port,
        unixPath: *unixSocket,
    }

    ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer stop()

    fmt.Fprintf(os.Stderr, "trustless proxy listening on 127.0.0.1:%d\n", *port)
    if err := p.Start(ctx); err != nil {
        fmt.Fprintf(os.Stderr, "trustless proxy error: %v\n", err)
        os.Exit(1)
    }
}
```

The `Proxy.Start()` method is in the same file (or in proxy.go if you split).

### Important implementation details

1. Use `net/http` stdlib for the server and transport
2. Use `regexp` for placeholder pattern matching
3. Thread-safety: Backend interface is called per-request, so use `context.Background()` or propagate context
4. Error handling: if a placeholder can't be resolved, leave it as-is (don't crash)
5. Proxy must handle both absolute URLs (`GET http://example.com/foo HTTP/1.1`) and relative URLs (though forward proxies always get absolute URLs from clients)
6. Support `io.Copy` for efficient body transfer

## Build and test

```bash
cd /home/ubuntu/projects/trustless
go build -o trustless .

# Start proxy in background (will test manually later)
./trustless proxy start --port 9996 &
sleep 1

# Quick test with curl (replace __XAI__ with actual XAI key)
# First check proxy is running
curl -s --proxy http://127.0.0.1:9996 http://httpbin.org/ip

# Kill proxy
kill %1 2>/dev/null; wait 2>/dev/null
```

Note: placeholder substitution can only be verified manually since it needs actual pass entries. The build and basic proxy functionality should be verifiable.

## Files to modify

- `internal/proxy/command.go` — rewrite with real proxy logic
