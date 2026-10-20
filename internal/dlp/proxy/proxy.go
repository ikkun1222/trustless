// Package proxy implements the outbound DLP reverse proxy. It forwards
// requests to a single upstream, scanning and masking request bodies for
// known secret values before they leave the host. Responses (including SSE
// streams) pass through untouched.
package proxy

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ikkun1222/trustless/internal/audit"
	"github.com/ikkun1222/trustless/internal/dlp/redact"
)

// maxDecodedBody caps the size of a request body after Content-Encoding is
// applied. Compressed input can expand thousands of times (a "zip bomb"), so
// the scanner must bound how much work it does before forwarding. 32 MiB
// comfortably covers normal LLM request bodies while keeping the decompressed
// copy bounded; anything larger is rejected (413) rather than partially
// scanned and forwarded.
const maxDecodedBody = 32 << 20

// errBodyTooLarge and errUnsupportedEncoding let scanBody map decode failures
// to a status code without inspecting error strings.
var (
	errBodyTooLarge        = errors.New("decoded body exceeds limit")
	errUnsupportedEncoding = errors.New("unsupported content-encoding")
)

// PatternMode はルート間で共有されるパターン第2層の動作モード。
// ホットリロード（reloadAll からの Set）に対応するため atomic で読取る。
type PatternMode struct {
	v atomic.Value // string: "mask" | "log"
}

// NewPatternMode は初期値 m の PatternMode を返す。
func NewPatternMode(m string) *PatternMode {
	pm := &PatternMode{}
	pm.v.Store(m)
	return pm
}

// Get は現在のモード文字列（"mask" | "log"）を返す。
func (m *PatternMode) Get() string {
	s, _ := m.v.Load().(string)
	return s
}

// Set はモードを原子的に更新する（ホットリロード）。
func (m *PatternMode) Set(s string) {
	m.v.Store(s)
}

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
	// The holder is shared across routes and may be hot-swapped at runtime
	// via Set; nil defaults to NewPatternMode("mask").
	PatternMode *PatternMode
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
	patternMode *PatternMode
	logger      *log.Logger
	audit       audit.Sink
	// boundHost is the configured upstream authority (host:port). Audit
	// events use it instead of the request's absolute-form target, which is
	// caller-controlled.
	boundHost string
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
		boundHost:   target.Host,
	}
	if p.secrets == nil {
		p.secrets = NewSecrets(nil)
	}
	if p.patternMode == nil {
		p.patternMode = NewPatternMode("mask")
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
	}
	p.rp = rp
	return p
}

// scanBody reads the request body, decodes a supported Content-Encoding,
// masks known secrets, and replaces the body for forwarding. It returns false
// when the request was rejected and must not be forwarded.
//
// Unknown codings are rejected (415) rather than forwarded unscanned: the
// whole point of the proxy is that bodies are inspected, and a coding the
// scanner cannot decode would silently bypass it. A body that inflates past
// maxDecodedBody is rejected (413) for the same reason.
func (p *Proxy) scanBody(w http.ResponseWriter, req *http.Request) bool {
	if req.Body == nil || req.Body == http.NoBody {
		return true
	}
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		p.logf("scan: read body: %v", err)
		return true
	}
	_ = req.Body.Close()

	coding := strings.ToLower(strings.TrimSpace(strings.Join(req.Header.Values("Content-Encoding"), ",")))
	decoded, err := decodeBody(raw, coding)
	if err != nil {
		switch {
		case errors.Is(err, errBodyTooLarge):
			p.logf("scan: decoded body exceeds %d bytes (%s) %s %q", maxDecodedBody, coding, req.Method, req.URL.Path)
			http.Error(w, "request body too large after decoding", http.StatusRequestEntityTooLarge)
		case errors.Is(err, errUnsupportedEncoding):
			p.logf("scan: unsupported content-encoding %q %s %q", coding, req.Method, req.URL.Path)
			http.Error(w, "unsupported content-encoding", http.StatusUnsupportedMediaType)
		default:
			p.logf("scan: decode %s body: %v", coding, err)
			http.Error(w, "invalid request body encoding", http.StatusBadRequest)
		}
		return false
	}

	masked := p.redactText(req, string(decoded))
	out, err := encodeBody([]byte(masked), coding)
	if err != nil {
		p.logf("scan: re-encode %s body: %v", coding, err)
		http.Error(w, "cannot re-encode request body", http.StatusInternalServerError)
		return false
	}

	req.Body = io.NopCloser(bytes.NewReader(out))
	req.ContentLength = int64(len(out))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(out)), nil
	}
	return true
}

// decodeBody returns the decoded request body for a single Content-Encoding
// coding. Empty and "identity" pass the bytes through unchanged.
func decodeBody(raw []byte, coding string) ([]byte, error) {
	var open func(io.Reader) (io.ReadCloser, error)
	switch coding {
	case "", "identity":
		return raw, nil
	case "gzip", "x-gzip":
		open = func(r io.Reader) (io.ReadCloser, error) { return gzip.NewReader(r) }
	case "deflate":
		open = func(r io.Reader) (io.ReadCloser, error) { return zlib.NewReader(r) }
	default:
		return nil, errUnsupportedEncoding
	}

	zr, err := open(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, maxDecodedBody+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxDecodedBody {
		return nil, errBodyTooLarge
	}
	return out, nil
}

// encodeBody re-applies the original coding so the upstream sees the same
// Content-Encoding it would have without the proxy.
func encodeBody(body []byte, coding string) ([]byte, error) {
	var buf bytes.Buffer
	switch coding {
	case "gzip", "x-gzip":
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(body); err != nil {
			return nil, err
		}
		if err := zw.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	case "deflate":
		zw := zlib.NewWriter(&buf)
		if _, err := zw.Write(body); err != nil {
			return nil, err
		}
		if err := zw.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}
	return body, nil
}

// redactText applies the existing two-layer redaction (known values always,
// patterns per pattern_mode) to text and emits the matching audit events.
func (p *Proxy) redactText(req *http.Request, text string) string {
	masked, changed := redact.ScanAndRedact(text, p.secrets.Snapshot(), p.minLen)
	if p.patterns != nil {
		if p.patternMode.Get() == "log" {
			// 第1層のマスクは常に適用（changed は既に反映済み）。
			// 第2層は検出のみ: 本文を変えず audit を発行する（段階ロールアウト用）。
			if _, patHit := p.patterns.Scan(text); patHit {
				p.logf("scan: pattern detected (mode=log) %s %q", req.Method, req.URL.Path)
				if p.audit != nil {
					p.audit.Emit(audit.Event{
						TS:      time.Now(),
						Event:   audit.DlpRedact,
						Host:    p.boundHost,
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
		p.logf("scan: redacted secrets in %s %q", req.Method, req.URL.Path)
		if p.audit != nil {
			p.audit.Emit(audit.Event{
				TS:      time.Now(),
				Event:   audit.DlpRedact,
				Host:    p.boundHost,
				Verdict: audit.VerdictRedact,
				Detail:  "redacted=true",
			})
		}
	}
	return masked
}

func (p *Proxy) logf(format string, args ...any) {
	if p.logger != nil {
		p.logger.Printf(format, args...)
	}
}

// ServeHTTP scans the body before delegating to the reverse proxy. Scanning
// happens here (not in Director) so a rejected encoding can be answered with
// a status code instead of being forwarded.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !p.scanBody(w, r) {
		return
	}
	p.rp.ServeHTTP(w, r)
}
