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
			p.handleCONNECT(w, r)
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
		backend:  be,
		port:     *port,
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
