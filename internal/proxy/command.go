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
	"sync"
	"syscall"
	"time"

	"github.com/ikkun1222/trustless/internal/audit"
	"github.com/ikkun1222/trustless/internal/backend"
	"github.com/ikkun1222/trustless/internal/config"
)

type Proxy struct {
	mu        sync.RWMutex // guards rules/allowlist (hot reload on SIGHUP)
	backend   backend.Backend
	audit     audit.Sink
	port      int
	unixPath  string
	rules     map[string]config.ProxyRule
	allowlist []string
	ca        *CA

	muAddr   sync.RWMutex // guards listener (set by Start; read by Addr)
	listener net.Listener
}

// SetAudit wires the structured audit sink (nil-safe: no audit when unset).
func (p *Proxy) SetAudit(s audit.Sink) {
	p.audit = s
}

func (p *Proxy) emit(ev audit.Event) {
	if p.audit != nil {
		p.audit.Emit(ev)
	}
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
	p.mu.RLock()
	defer p.mu.RUnlock()
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
	p.mu.RLock()
	rule, ok := p.rules[host]
	p.mu.RUnlock()
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
			p.emit(audit.Event{TS: time.Now(), Event: audit.ProxyInject, Key: rule.Key, Host: host, Verdict: audit.VerdictInject, Detail: "header=" + rule.Header})
		}
		return
	}
	if rule.Query != "" {
		q := r.URL.Query()
		if q.Get(rule.Query) == "" {
			q.Set(rule.Query, val)
			r.URL.RawQuery = q.Encode()
			p.emit(audit.Event{TS: time.Now(), Event: audit.ProxyInject, Key: rule.Key, Host: host, Verdict: audit.VerdictInject, Detail: "query=" + rule.Query})
		}
	}
}

func (p *Proxy) substituteRequest(r *http.Request) {
	p.injectByHost(r)
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if !p.allowedHost(r.Host) {
		p.emit(audit.Event{TS: time.Now(), Event: audit.ProxyDeny, Host: hostOnly(r.Host), Verdict: audit.VerdictDeny, Detail: "allowlist"})
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
		p.emit(audit.Event{TS: time.Now(), Event: audit.ProxyDeny, Host: hostOnly(r.Host), Verdict: audit.VerdictDeny, Detail: "allowlist"})
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
	if err := p.bindListener(); err != nil {
		return err
	}
	return p.serve(ctx)
}

// bindListener binds the listen address and records the listener for Addr.
func (p *Proxy) bindListener() error {
	listener, err := p.listen()
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	p.muAddr.Lock()
	p.listener = listener
	p.muAddr.Unlock()
	return nil
}

// serve runs the HTTP server on the bound listener until ctx is cancelled.
func (p *Proxy) serve(ctx context.Context) error {
	server := &http.Server{Handler: p.handler()}

	go func() {
		<-ctx.Done()
		server.Close()
	}()

	if err := server.Serve(p.listener); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Addr returns the bound listener address (useful when listening on port 0).
// It blocks until Start has bound the listener.
func (p *Proxy) Addr() net.Addr {
	for {
		p.muAddr.RLock()
		l := p.listener
		p.muAddr.RUnlock()
		if l != nil {
			return l.Addr()
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// UpdateRules atomically swaps the injection rules and allowlist (SIGHUP
// hot reload). The existing rules stay in effect until the swap completes.
func (p *Proxy) UpdateRules(rules map[string]config.ProxyRule, allowlist []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rules = rules
	p.allowlist = allowlist
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

	// 単体 proxy コマンドの監査は file sink がデフォルト（serve は journald）。
	kind := cfg.Audit.Sink
	if kind == "" {
		kind = "file"
	}
	p.SetAudit(audit.New(kind, cfg.Audit.File, cfg.Audit.Buffer))

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

	// SIGHUP: hot reload — re-read config (rules/allowlist) and refresh the
	// backend cache so credential rotations take effect without restart.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			cfgPath := config.DefaultConfigPath()
			newCfg, err := config.Load(cfgPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "trustless proxy: SIGHUP reload failed: %v\n", err)
				continue
			}
			p.mu.Lock()
			p.rules = newCfg.Proxy.Rules
			p.allowlist = newCfg.Proxy.Allowlist
			p.mu.Unlock()
			if r, ok := be.(interface{ Reload(context.Context) error }); ok {
				if err := r.Reload(ctx); err != nil {
					fmt.Fprintf(os.Stderr, "trustless proxy: SIGHUP backend reload failed: %v\n", err)
					continue
				}
			}
			fmt.Fprintf(os.Stderr, "trustless proxy: SIGHUP reloaded (rules=%d allowlist=%d)\n",
				len(newCfg.Proxy.Rules), len(newCfg.Proxy.Allowlist))
		}
	}()

	fmt.Fprintf(os.Stderr, "trustless proxy listening on 127.0.0.1:%d\n", *port)
	if err := p.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "trustless proxy error: %v\n", err)
		os.Exit(1)
	}
}

// StartForward builds a Proxy from the given backend and config and serves
// it on the injection port. Unlike start() it performs no flag parsing and
// no SIGHUP loop — `trustless serve` owns signal handling and hot reload
// centrally. When mitm is set, the shared MITM CA is loaded/generated (the
// same path start() takes).
func StartForward(ctx context.Context, be backend.Backend, cfg *config.Config, port int, mitm bool, sink audit.Sink) (*Proxy, error) {
	p := &Proxy{
		backend:   be,
		port:      port,
		rules:     cfg.Proxy.Rules,
		allowlist: cfg.Proxy.Allowlist,
	}
	p.SetAudit(sink)

	if mitm {
		caCfg := DefaultCAPaths()
		ca, err := LoadOrGenerateCA(caCfg)
		if err != nil {
			return nil, fmt.Errorf("MITM CA setup failed: %w", err)
		}
		p.ca = ca
	}

	// Bind synchronously so callers fail fast (fail-closed): a port that
	// cannot be bound aborts serve before any listener starts serving.
	if err := p.bindListener(); err != nil {
		return nil, err
	}
	// Serve in the background — StartForward must return so the caller's
	// reload loop can run. Serve errors (beyond ctx cancellation) are logged.
	go func() {
		if err := p.serve(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "trustless proxy error: %v\n", err)
		}
	}()
	return p, nil
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
