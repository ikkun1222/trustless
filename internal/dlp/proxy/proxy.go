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
	"time"

	"github.com/ikkun1222/trustless/internal/audit"
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
	// Patterns is the compiled gitleaks-compatible rule set for the
	// pattern-based layer (keyword → RE2 → entropy). A nil value keeps the
	// legacy behavior: known-value substring scanning only.
	Patterns *redact.PatternSet
	// PatternMode is the action applied to pattern matches: "mask" (the
	// default; any other value also masks) or "log" (detection only — the
	// body is left unchanged and a dlp.redact audit event is emitted).
	PatternMode string
	// UpstreamURL is the base URL requests are forwarded to.
	UpstreamURL string
	// Logger receives scan diagnostics. Nil disables logging.
	Logger *log.Logger
	Audit  audit.Sink
}

// Proxy is a reverse proxy that masks secrets in outbound request bodies.
type Proxy struct {
	rp          *httputil.ReverseProxy
	secrets     *Secrets
	minLen      int
	patterns    *redact.PatternSet
	patternMode string
	logger      *log.Logger
	audit       audit.Sink
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
		secrets:     opts.Secrets,
		minLen:      opts.MinSecretLen,
		patterns:    opts.Patterns,
		patternMode: opts.PatternMode,
		logger:      opts.Logger,
		audit:       opts.Audit,
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

	// Layer 1 (known values) is always masked. Layer 2 (patterns) then
	// either masks the result or only reports detections (log mode).
	masked, changed := redact.ScanAndRedact(string(raw), p.secrets.Snapshot(), p.minLen)
	if p.patterns != nil {
		if p.patternMode == "log" {
			// 第1層のマスクは常に適用（changed は既に反映済み）。
			// 第2層は検出のみ: 本文を変えず audit を発行する（段階ロールアウト用）。
			if _, patHit := p.patterns.Scan(string(raw)); patHit {
				p.logf("scan: pattern detected (mode=log) %s %s", req.Method, req.URL.Path)
				if p.audit != nil {
					p.audit.Emit(audit.Event{
						TS:      time.Now(),
						Event:   audit.DlpRedact,
						Host:    req.URL.Host,
						Verdict: audit.VerdictRedact,
						Detail:  "patterns=hit&mode=log",
					})
				}
			}
		} else { // "mask"
			patMasked, patChanged := p.patterns.Scan(masked) // 第1層マスク済みテキストに適用
			if patChanged {
				masked, changed = patMasked, true
			}
		}
	}
	if changed {
		p.logf("scan: redacted secrets in %s %s", req.Method, req.URL.Path)
		if p.audit != nil {
			p.audit.Emit(audit.Event{
				TS:      time.Now(),
				Event:   audit.DlpRedact,
				Host:    req.URL.Host,
				Verdict: audit.VerdictRedact,
				Detail:  "redacted=true",
			})
		}
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
