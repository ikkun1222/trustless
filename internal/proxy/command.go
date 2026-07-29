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
	"regexp"
	"strings"
	"syscall"

	"github.com/ikkun1222/trustless/internal/backend"
	"github.com/ikkun1222/trustless/internal/config"
)

var placeholderRE = regexp.MustCompile(`__([A-Z][A-Z0-9_]*)__`)

type Proxy struct {
	backend   backend.Backend
	port      int
	unixPath  string
	allowlist []string
	ca        *CA
}

func (p *Proxy) replacePlaceholders(s string) string {
	return placeholderRE.ReplaceAllStringFunc(s, func(match string) string {
		key := match[2 : len(match)-2]
		val, err := p.backend.Resolve(context.Background(), strings.ToLower(key))
		if err != nil {
			val2, err2 := p.backend.Resolve(context.Background(), "iria/api/"+strings.ToLower(key))
			if err2 != nil {
				return match
			}
			return val2
		}
		return val
	})
}

func (p *Proxy) substituteRequest(r *http.Request) {
	r.URL.RawQuery = p.replacePlaceholders(r.URL.RawQuery)

	for key, values := range r.Header {
		for i, v := range values {
			r.Header[key][i] = p.replacePlaceholders(v)
		}
	}

	if r.Body != nil && r.Body != http.NoBody {
		body, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err == nil {
			newBody := p.replacePlaceholders(string(body))
			r.Body = io.NopCloser(strings.NewReader(newBody))
			r.ContentLength = int64(len(newBody))
		}
	}
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
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
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			if p.ca != nil {
				p.mitmHandleCONNECT(w, r, p.ca)
			} else {
				p.handleCONNECT(w, r)
			}
			return
		}
		p.handleHTTP(w, r)
	})

	listener, err := p.listen()
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	server := &http.Server{Handler: mux}

	go func() {
		<-ctx.Done()
		server.Close()
	}()

	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
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
		fmt.Fprintln(os.Stderr, "Start a local HTTP forward proxy that substitutes credential placeholders.")
		fmt.Fprintln(os.Stderr, "Placeholders are resolved from the pass store in real-time.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Placeholder format: __KEY_NAME__ (e.g. __GITHUB_TOKEN__, __XAI__)")
		fmt.Fprintln(os.Stderr, "Resolution: lowercase(KEY_NAME) -> pass key, fallback: iria/api/lowercase(KEY_NAME)")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Flags:")
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  trustless proxy start --port 8080")
		fmt.Fprintln(os.Stderr, "  HTTPS_PROXY=http://127.0.0.1:8080 curl -H \"Authorization: Bearer __XAI__\" https://api.x.ai/v1/models")
	}
	port := fs.Int("port", cfg.Proxy.Port, "listen port")
	unixSocket := fs.String("unix-socket", "", "unix socket path")
	mitm := fs.Bool("mitm", false, "Enable MITM mode (intercept HTTPS for placeholder substitution)")

	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	p := &Proxy{
		backend:  be,
		port:     *port,
		unixPath: *unixSocket,
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
	fmt.Fprintln(os.Stderr, "Start a local HTTP forward proxy that substitutes credential placeholders.")
	fmt.Fprintln(os.Stderr, "Placeholders are resolved from the pass store in real-time.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Placeholder format: __KEY_NAME__ (e.g. __GITHUB_TOKEN__, __XAI__)")
	fmt.Fprintln(os.Stderr, "Resolution: lowercase(KEY_NAME) -> pass key, fallback: iria/api/lowercase(KEY_NAME)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Flags:")
	fmt.Fprintln(os.Stderr, "  --port <n>           Listen port (default: 8080)")
	fmt.Fprintln(os.Stderr, "  --unix-socket <path>  Listen on Unix socket instead of TCP")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Examples:")
	fmt.Fprintln(os.Stderr, "  trustless proxy start --port 8080")
	fmt.Fprintln(os.Stderr, "  HTTPS_PROXY=http://127.0.0.1:8080 curl -H \"Authorization: Bearer __XAI__\" https://api.x.ai/v1/models")
}
