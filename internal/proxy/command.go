package proxy

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/ikkun1222/trustless/internal/backend"
	"github.com/ikkun1222/trustless/internal/config"
)

type Proxy struct {
	backend   backend.Backend
	port      int
	unixPath  string
	rules     map[string]config.ProxyRule
	allowlist []string
	ca        *CA
}

// resolveKey resolves a credential key using the standard resolution rule:
// lowercase(key) -> pass key, fallback: iria/api/lowercase(key).
func (p *Proxy) resolveKey(key string) (string, bool) {
	val, err := p.backend.Resolve(context.Background(), strings.ToLower(key))
	if err == nil {
		return val, true
	}
	val2, err2 := p.backend.Resolve(context.Background(), "iria/api/"+strings.ToLower(key))
	if err2 != nil {
		return "", false
	}
	return val2, true
}

// hostOnly strips the port from a host:port string.
func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// allowedHost checks the host against the allowlist. An empty allowlist
// permits all hosts (no egress restriction).
func (p *Proxy) allowedHost(host string) bool {
	if len(p.allowlist) == 0 {
		return true
	}
	h := hostOnly(host)
	for _, a := range p.allowlist {
		if a == h {
			return true
		}
	}
	return false
}

// injectByHost applies host-based credential injection rules. If the request
// host matches a rule, the resolved credential is injected into the target
// header or query parameter. Existing header values are never overwritten;
// unresolved keys fail open (no injection).
func (p *Proxy) injectByHost(r *http.Request) {
	host := hostOnly(r.Host)
	if host == "" {
		host = hostOnly(r.URL.Host)
	}
	rule, ok := p.rules[host]
	if !ok {
		return
	}
	val, ok := p.resolveKey(rule.Key)
	if !ok {
		return // fail-open: unresolved key is not injected
	}

	if rule.Header != "" {
		if r.Header.Get(rule.Header) == "" {
			r.Header.Set(rule.Header, rule.Prefix+val+rule.Suffix)
		}
		return
	}
	if rule.Query != "" {
		q := r.URL.Query()
		if q.Get(rule.Query) == "" {
			q.Set(rule.Query, val)
			r.URL.RawQuery = q.Encode()
		}
	}
}

func (p *Proxy) substituteRequest(r *http.Request) {
	p.injectByHost(r)
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if !p.allowedHost(r.Host) {
		http.Error(w, "host not allowed by proxy allowlist", http.StatusForbidden)
		return
	}
	outReq, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	outReq.Header = r.Header.Clone()

	p.substituteRequest(outReq)

	resp, err := http.DefaultTransport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (p *Proxy) handleCONNECT(w http.ResponseWriter, r *http.Request) {
	if !p.allowedHost(r.Host) {
		http.Error(w, "host not allowed by proxy allowlist", http.StatusForbidden)
		return
	}
	targetConn, err := net.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	go func() {
		io.Copy(targetConn, clientConn)
		targetConn.Close()
	}()
	go func() {
		io.Copy(clientConn, targetConn)
		clientConn.Close()
	}()
}

func (p *Proxy) Start(ctx context.Context) error {
	handler := p.handler()

	listener, err := p.listen()
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	server := &http.Server{Handler: handler}

	go func() {
		<-ctx.Done()
		server.Close()
	}()

	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// handler returns the top-level http.Handler. Go's ServeMux routes CONNECT
// requests by host, not path, so a "/" pattern never matches them (404).
// CONNECT is therefore handled explicitly before delegating to the mux.
func (p *Proxy) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p.handleHTTP(w, r)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			if p.ca != nil {
				p.mitmHandleCONNECT(w, r, p.ca)
			} else {
				p.handleCONNECT(w, r)
			}
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (p *Proxy) listen() (net.Listener, error) {
	if p.unixPath != "" {
		os.Remove(p.unixPath)
		return net.Listen("unix", p.unixPath)
	}
	return net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p.port))
}

func Run(args []string, be backend.Backend, cfg *config.Config) {
	if len(args) < 1 {
		printUsage()
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
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: trustless proxy start [flags]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Start a local HTTP forward proxy that injects credentials into requests by host.")
		fmt.Fprintln(os.Stderr, "Injection rules are defined in config [proxy.rules] (host -> {header|query, key}).")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Flags:")
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  trustless proxy start --port 8080")
		fmt.Fprintln(os.Stderr, "  HTTPS_PROXY=http://127.0.0.1:8080 curl https://api.x.ai/v1/models")
	}
	port := fs.Int("port", cfg.Proxy.Port, "listen port")
	unixSocket := fs.String("unix-socket", "", "unix socket path")
	mitm := fs.Bool("mitm", false, "Enable MITM mode (intercept HTTPS for credential injection)")

	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	p := &Proxy{
		backend:   be,
		port:      *port,
		unixPath:  *unixSocket,
		rules:     cfg.Proxy.Rules,
		allowlist: cfg.Proxy.Allowlist,
	}

	if *mitm {
		caCfg := DefaultCAPaths()
		var caErr error
		p.ca, caErr = LoadOrGenerateCA(caCfg)
		if caErr != nil {
			fmt.Fprintf(os.Stderr, "Error: MITM CA setup failed: %v\n", caErr)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "MITM CA certificate: %s\n", caCfg.CertPath)
		fmt.Fprintf(os.Stderr, "Install: sudo cp %s /usr/local/share/ca-certificates/ && sudo update-ca-certificates\n", caCfg.CertPath)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stderr, "trustless proxy listening on 127.0.0.1:%d\n", *port)
	if err := p.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "trustless proxy error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: trustless proxy start [flags]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Start a local HTTP forward proxy that injects credentials into requests by host.")
	fmt.Fprintln(os.Stderr, "Injection rules are defined in config [proxy.rules] (host -> {header|query, key}).")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Flags:")
	fmt.Fprintln(os.Stderr, "  --port <n>           Listen port (default: 8080)")
	fmt.Fprintln(os.Stderr, "  --unix-socket <path>  Listen on Unix socket instead of TCP")
	fmt.Fprintln(os.Stderr, "  --mitm                Enable MITM mode (intercept HTTPS for header injection)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Examples:")
	fmt.Fprintln(os.Stderr, "  trustless proxy start --port 8080")
	fmt.Fprintln(os.Stderr, "  HTTPS_PROXY=http://127.0.0.1:8080 curl https://api.x.ai/v1/models")
}
