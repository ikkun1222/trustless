// Package proxy implements the outbound DLP reverse proxy. It forwards
// requests to a single upstream, scanning and masking request bodies for
// known secret values before they leave the host. Responses (including SSE
// streams) pass through untouched.
package proxy

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/ikkun1222/trustless/internal/dlp/redact"
)

// Options configures a Proxy.
type Options struct {
	// Secrets are the known secret values scanned for in request bodies.
	// A nil value is treated as an empty set. Use NewSecrets to build one;
	// the set may be hot-swapped at runtime via Replace.
	Secrets *Secrets
	// MinSecretLen is the minimum secret length considered (shorter values
	// are ignored to avoid false positives in ordinary prose).
	MinSecretLen int
	// UpstreamURL is the base URL requests are forwarded to.
	UpstreamURL string
	// Logger receives scan diagnostics. Nil disables logging.
	Logger *log.Logger
}

// Proxy is a reverse proxy that masks secrets in outbound request bodies.
type Proxy struct {
	rp      *httputil.ReverseProxy
	secrets *Secrets
	minLen  int
	logger  *log.Logger
}

// New builds a Proxy forwarding to upstreamURL, masking any secret value
// found in request bodies. The upstream URL may carry a base path (e.g.
// https://host/v1/openai); httputil's director joins it with the incoming
// request path automatically.
func New(opts Options) http.Handler {
	target, err := url.Parse(opts.UpstreamURL)
	if err != nil {
		panic("proxy: invalid upstream URL: " + err.Error())
	}
	p := &Proxy{
		secrets: opts.Secrets,
		minLen:  opts.MinSecretLen,
		logger:  opts.Logger,
	}
	if p.secrets == nil {
		p.secrets = NewSecrets(nil)
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	originalDirector := rp.Director
	rp.Director = func(req *http.Request) {
		originalDirector(req)
		// NewSingleHostReverseProxy rewrites req.URL.Host but leaves
		// req.Host (the HTTP/1.1 Host header) untouched. Without this,
		// upstream edge proxies (Cloudflare etc.) reject the request with
		// 403 because the Host header still says 127.0.0.1:8787.
		req.Host = target.Host
		p.scanBody(req)
	}
	p.rp = rp
	return p
}

// scanBody reads the request body, masks known secrets, and replaces the
// body for forwarding. Non-re-readable bodies are left untouched.
func (p *Proxy) scanBody(req *http.Request) {
	if req.Body == nil || req.Body == http.NoBody {
		return
	}
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		p.logf("scan: read body: %v", err)
		return
	}
	_ = req.Body.Close()

	masked, changed := redact.ScanAndRedact(string(raw), p.secrets.Snapshot(), p.minLen)
	if changed {
		p.logf("scan: redacted secrets in %s %s", req.Method, req.URL.Path)
	}
	req.Body = io.NopCloser(bytes.NewReader([]byte(masked)))
	req.ContentLength = int64(len(masked))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader([]byte(masked))), nil
	}
}

func (p *Proxy) logf(format string, args ...any) {
	if p.logger != nil {
		p.logger.Printf(format, args...)
	}
}

// ServeHTTP delegates to the underlying reverse proxy.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.rp.ServeHTTP(w, r)
}
