package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ikkun1222/trustless/internal/audit"
	"github.com/ikkun1222/trustless/internal/dlp/redact"
)

// testSink is a thread-safe in-memory audit sink.
type testSink struct {
	mu  sync.Mutex
	evs []audit.Event
}

func (s *testSink) Emit(ev audit.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evs = append(s.evs, ev)
}

func (s *testSink) Close() {}

func (s *testSink) events() []audit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]audit.Event, len(s.evs))
	copy(out, s.evs)
	return out
}

// buildPatterns returns a minimal gitleaks-compatible set that matches
// sk-proj- + 40 alphanumeric chars (high entropy).
func buildPatterns(t *testing.T) *redact.PatternSet {
	t.Helper()
	ps, err := redact.LoadPatterns([]byte(`
[[rules]]
id = "test-openai"
description = "test rule"
regex = '''sk-proj-[A-Za-z0-9]{40}'''
keywords = ["sk-proj-"]
entropy = 3.0
`))
	if err != nil {
		t.Fatalf("LoadPatterns: %v", err)
	}
	return ps
}

// highEntropyPat returns a pattern-matchable fixture: sk-proj- + 40 chars
// drawn from a 62-char alphabet so the match clears the entropy threshold.
func highEntropyPat() string {
	seg := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	return "sk-proj-" + seg[:40]
}

// newTestSetup starts an upstream httptest server that records the bodies it
// receives, plus a dlp-proxy in front of it. Returns the proxy base URL and
// a way to inspect what the upstream actually received.
func newTestSetup(t *testing.T, secrets []string, minLen int) (string, func() [][]byte) {
	t.Helper()

	var mu sync.Mutex
	var received [][]byte

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("upstream read: %v", err)
		}
		mu.Lock()
		received = append(received, body)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(upstream.Close)

	proxy := New(Options{
		Secrets:      NewSecrets(secrets),
		MinSecretLen: minLen,
		UpstreamURL:  upstream.URL,
	})
	proxyServer := httptest.NewServer(proxy)
	t.Cleanup(proxyServer.Close)

	getReceived := func() [][]byte {
		mu.Lock()
		defer mu.Unlock()
		out := make([][]byte, len(received))
		copy(out, received)
		return out
	}
	return proxyServer.URL, getReceived
}

// TestProxy_LogPathCannotForgeLines is the regression for log-line forgery:
// a percent-encoded newline in the request path must be escaped (%q) so a
// single request produces a single log line.
func TestProxy_LogPathCannotForgeLines(t *testing.T) {
	const secret = "sk-log-injection-secret-1234567890"

	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(upstream.Close)

	proxyServer := httptest.NewServer(New(Options{
		Secrets:      NewSecrets([]string{secret}),
		MinSecretLen: 8,
		UpstreamURL:  upstream.URL,
		Logger:       logger,
	}))
	t.Cleanup(proxyServer.Close)

	path := "/v1/chat%0A2026/10/20%2006:00:31%20dlp-proxy:%20reloaded%200%20secrets"
	req, err := http.NewRequest(http.MethodPost, proxyServer.URL+path,
		strings.NewReader(`{"content":"`+secret+`"}`))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	logs := buf.String()
	if n := strings.Count(logs, "\n"); n != 1 {
		t.Fatalf("expected exactly 1 log line, got %d:\n%s", n, logs)
	}
	if !strings.Contains(logs, `\n`) {
		t.Fatalf("expected the newline to be escaped as \\n, got: %s", logs)
	}
}

// TestProxy_AuditHostUsesConfiguredUpstream is the regression for audit host
// forgery: an absolute-form request target must not dictate the recorded
// dlp.redact Host, which is the configured upstream host.
func TestProxy_AuditHostUsesConfiguredUpstream(t *testing.T) {
	const secret = "sk-audit-host-secret-1234567890"
	const forgedHost = "audit-forged.example"

	sink := &testSink{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(upstream.Close)

	proxyServer := New(Options{
		Secrets:      NewSecrets([]string{secret}),
		MinSecretLen: 8,
		UpstreamURL:  upstream.URL,
		Audit:        sink,
	})
	handlerServer := httptest.NewServer(proxyServer)
	t.Cleanup(handlerServer.Close)

	conn, err := net.Dial("tcp", strings.TrimPrefix(handlerServer.URL, "http://"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	body := `{"content":"` + secret + `"}`
	fmt.Fprintf(conn, "POST http://%s/v1/chat HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		forgedHost, forgedHost, len(body), body)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp.Body.Close()

	evs := sink.events()
	if len(evs) != 1 {
		t.Fatalf("expected 1 audit event, got %d: %+v", len(evs), evs)
	}
	wantHost := strings.TrimPrefix(upstream.URL, "http://")
	if evs[0].Host != wantHost {
		t.Fatalf("audit Host = %q, want configured upstream %q", evs[0].Host, wantHost)
	}
	if evs[0].Host == forgedHost {
		t.Fatalf("audit Host was controlled by the caller: %q", evs[0].Host)
	}
}

func TestProxy_MasksSecretInBody(t *testing.T) {
	secret := "sk-superdupersecret1234567890"
	base, received := newTestSetup(t, []string{secret}, 8)

	resp, err := http.Post(base+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"my key is `+secret+` ok"}]}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	bodies := received()
	if len(bodies) != 1 {
		t.Fatalf("upstream received %d requests, want 1", len(bodies))
	}
	got := string(bodies[0])
	if strings.Contains(got, secret) {
		t.Fatalf("secret reached upstream: %s", got)
	}
	if !strings.Contains(got, "<redacted>") {
		t.Fatalf("expected <redacted> in upstream body: %s", got)
	}
	// JSON must remain valid after masking.
	var parsed map[string]any
	if err := json.Unmarshal(bodies[0], &parsed); err != nil {
		t.Fatalf("upstream body is not valid JSON after masking: %v\n%s", err, got)
	}
}

func TestProxy_NoMatchPassesThrough(t *testing.T) {
	secret := "nothing-here-to-match-12345"
	base, received := newTestSetup(t, []string{secret}, 8)
	body := `{"model":"m","messages":[{"role":"user","content":"hello world"}]}`

	resp, err := http.Post(base+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	bodies := received()
	if len(bodies) != 1 || string(bodies[0]) != body {
		t.Fatalf("body should pass through unchanged, got %s", bodies[0])
	}
}

func TestProxy_PreservesHeaders(t *testing.T) {
	secret := "sk-header-test-secret-987654321"
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		io.Copy(io.Discard, r.Body)
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(upstream.Close)

	proxy := New(Options{Secrets: NewSecrets([]string{secret}), MinSecretLen: 8, UpstreamURL: upstream.URL})
	proxyServer := httptest.NewServer(proxy)
	t.Cleanup(proxyServer.Close)

	req, _ := http.NewRequest(http.MethodPost, proxyServer.URL+"/v1/chat/completions",
		strings.NewReader(`{"messages":[{"content":"x"}]}`))
	req.Header.Set("Authorization", "Bearer test-token-123")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if gotAuth != "Bearer test-token-123" {
		t.Fatalf("Authorization header lost: %q", gotAuth)
	}
}

func TestProxy_NonJSONBodyStillScanned(t *testing.T) {
	secret := "plaintext-secret-value-abc123"
	base, received := newTestSetup(t, []string{secret}, 8)

	resp, err := http.Post(base+"/v1/responses", "text/plain",
		strings.NewReader("raw body with "+secret+" inside"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	got := string(received()[0])
	if strings.Contains(got, secret) {
		t.Fatalf("secret leaked in non-JSON body: %s", got)
	}
}

func TestProxy_StreamingResponsePassesThrough(t *testing.T) {
	// SSE responses must flow through untouched (masking is request-only).
	secret := "sk-stream-secret-123456789"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		w.Write([]byte("data: {\"content\":\"hello\"}\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
		w.Write([]byte("data: [DONE]\n\n"))
	}))
	t.Cleanup(upstream.Close)

	proxy := New(Options{Secrets: NewSecrets([]string{secret}), MinSecretLen: 8, UpstreamURL: upstream.URL})
	proxyServer := httptest.NewServer(proxy)
	t.Cleanup(proxyServer.Close)

	resp, err := http.Post(proxyServer.URL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"stream":true,"messages":[{"content":"hi"}]}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("data: [DONE]")) {
		t.Fatalf("streaming chunks lost: %q", body)
	}
	if strings.Contains(string(body), secret) {
		t.Fatalf("secret leaked into response: %q", body)
	}
}

func TestProxy_ErrorFromUpstreamPropagates(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"bad key"}`))
	}))
	t.Cleanup(upstream.Close)

	proxy := New(Options{Secrets: NewSecrets([]string{"x"}), MinSecretLen: 8, UpstreamURL: upstream.URL})
	proxyServer := httptest.NewServer(proxy)
	t.Cleanup(proxyServer.Close)

	resp, err := http.Post(proxyServer.URL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"messages":[{"content":"x"}]}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "bad key") {
		t.Fatalf("upstream error body not propagated: %q", body)
	}
}

func TestProxy_JoinsUpstreamBasePath(t *testing.T) {
	// Upstream URL carries a base path (/v1/openai). The incoming request
	// path (already prefix-stripped) must be appended after it.
	secret := "sk-basepath-secret-987654321"
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		io.Copy(io.Discard, r.Body)
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(upstream.Close)

	proxy := New(Options{
		Secrets:      NewSecrets([]string{secret}),
		MinSecretLen: 8,
		UpstreamURL:  upstream.URL + "/v1/openai",
	})
	proxyServer := httptest.NewServer(proxy)
	t.Cleanup(proxyServer.Close)

	resp, err := http.Post(proxyServer.URL+"/chat/completions", "application/json",
		strings.NewReader(`{"messages":[{"content":"hi"}]}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if gotPath != "/v1/openai/chat/completions" {
		t.Fatalf("upstream path = %q, want /v1/openai/chat/completions", gotPath)
	}
}

func TestProxy_RewritesHostHeader(t *testing.T) {
	// The upstream must see its own host in the Host header, not the
	// proxy's address — edge proxies (Cloudflare) reject mismatched hosts.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Saw-Host", r.Host)
		io.Copy(io.Discard, r.Body)
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(upstream.Close)

	proxy := New(Options{Secrets: NewSecrets([]string{"x"}), MinSecretLen: 8, UpstreamURL: upstream.URL})
	proxyServer := httptest.NewServer(proxy)
	t.Cleanup(proxyServer.Close)

	resp, err := http.Post(proxyServer.URL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"messages":[{"content":"hi"}]}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	upstreamHost := upstream.URL[len("http://"):]
	if got := resp.Header.Get("X-Saw-Host"); got != upstreamHost {
		t.Fatalf("upstream saw Host %q, want %q", got, upstreamHost)
	}
}

// TestSecrets_HotSwap verifies that Replace atomically swaps the scanned
// secret set: a secret added after construction is masked on the next
// request, and a removed secret is no longer masked. This is the behavior
// the background hot-reload relies on.
func TestSecrets_HotSwap(t *testing.T) {
	oldSecret := "«redacted:sk-old…»"
	newSecret := "«redacted:sk-new…»"
	set := NewSecrets([]string{oldSecret})

	var mu sync.Mutex
	var gotBodies [][]byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotBodies = append(gotBodies, b)
		mu.Unlock()
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(upstream.Close)

	proxy := New(Options{Secrets: set, MinSecretLen: 8, UpstreamURL: upstream.URL})
	proxyServer := httptest.NewServer(proxy)
	t.Cleanup(proxyServer.Close)

	post := func(body string) string {
		resp, err := http.Post(proxyServer.URL+"/v1/openai/chat/completions", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		mu.Lock()
		defer mu.Unlock()
		return string(gotBodies[len(gotBodies)-1])
	}

	// Before Replace: old secret masked, new secret passes through.
	if got := post(`{"content":"old is ` + oldSecret + `"}`); strings.Contains(got, oldSecret) {
		t.Fatalf("old secret reached upstream before swap: %s", got)
	}
	if got := post(`{"content":"new is ` + newSecret + `"}`); !strings.Contains(got, newSecret) {
		t.Fatalf("new secret masked before swap: %s", got)
	}

	// Hot swap: new secret in, old secret out.
	set.Replace([]string{newSecret})

	if got := post(`{"content":"new is ` + newSecret + `"}`); strings.Contains(got, newSecret) {
		t.Fatalf("new secret reached upstream after swap: %s", got)
	}
	if got := post(`{"content":"old is ` + oldSecret + `"}`); !strings.Contains(got, oldSecret) {
		t.Fatalf("old secret still masked after swap: %s", got)
	}
}

// TestPatternMode_GetSet verifies the atomic holder: Set switches the mode
// that subsequent Get calls report, including an empty initial value.
func TestPatternMode_GetSet(t *testing.T) {
	m := NewPatternMode("")
	if got := m.Get(); got != "" {
		t.Fatalf("initial Get = %q, want \"\"", got)
	}
	m.Set("log")
	if got := m.Get(); got != "log" {
		t.Fatalf("Get after Set(log) = %q, want log", got)
	}
	m.Set("mask")
	if got := m.Get(); got != "mask" {
		t.Fatalf("Get after Set(mask) = %q, want mask", got)
	}
}

// TestProxy_PatternModeHotSwap verifies that switching the shared PatternMode
// holder at runtime changes scanBody behavior: the same proxy starts in
// mask mode (pattern redacted), flips to log mode (body unchanged + audit),
// and flips back to mask mode.
func TestProxy_PatternModeHotSwap(t *testing.T) {
	pat := highEntropyPat()
	sink := &testSink{}

	var received []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(upstream.Close)

	mode := NewPatternMode("mask")
	proxy := New(Options{
		Secrets:      NewSecrets(nil),
		MinSecretLen: 8,
		Patterns:     buildPatterns(t),
		PatternMode:  mode,
		UpstreamURL:  upstream.URL,
		Audit:        sink,
	})
	proxyServer := httptest.NewServer(proxy)
	t.Cleanup(proxyServer.Close)

	body := `{"content":"key is ` + pat + ` now"}`
	post := func() string {
		resp, err := http.Post(proxyServer.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		return string(received)
	}

	// mask モード: パターンが置換される
	if got := post(); !strings.Contains(got, redact.Marker) || strings.Contains(got, pat) {
		t.Fatalf("mask mode must redact the pattern, got %q", got)
	}

	// log モードへ切替: 本文は不変・audit 発行
	mode.Set("log")
	if got := post(); got != body {
		t.Fatalf("log mode must not change the body, got %q want %q", got, body)
	}
	evs := sink.events()
	var logEvents int
	for _, ev := range evs {
		if ev.Detail == "patterns=hit&mode=log" {
			logEvents++
		}
	}
	if logEvents != 1 {
		t.Fatalf("expected 1 log audit event, got %d: %+v", logEvents, evs)
	}

	// mask モードへ戻す: 再び置換される
	mode.Set("mask")
	if got := post(); !strings.Contains(got, redact.Marker) || strings.Contains(got, pat) {
		t.Fatalf("mask mode after flip must redact the pattern, got %q", got)
	}
}

// TestProxy_NilPatternModeDefaultsToMask verifies that a nil PatternMode in
// Options defaults to mask: pattern matches are redacted.
func TestProxy_NilPatternModeDefaultsToMask(t *testing.T) {
	pat := highEntropyPat()

	var received []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(upstream.Close)

	proxy := New(Options{
		Secrets:      NewSecrets(nil),
		MinSecretLen: 8,
		Patterns:     buildPatterns(t),
		UpstreamURL:  upstream.URL,
	})
	proxyServer := httptest.NewServer(proxy)
	t.Cleanup(proxyServer.Close)

	body := `{"content":"key is ` + pat + ` now"}`
	resp, err := http.Post(proxyServer.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if got := string(received); !strings.Contains(got, redact.Marker) || strings.Contains(got, pat) {
		t.Fatalf("nil PatternMode must default to mask, got %q", got)
	}
}

// TestProxy_LogModeEmitsAuditBodyUnchanged verifies the log mode: pattern
// detection leaves the body untouched but emits a dlp.redact audit event.
func TestProxy_LogModeEmitsAuditBodyUnchanged(t *testing.T) {
	pat := highEntropyPat()
	sink := &testSink{}

	var received []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(upstream.Close)

	proxy := New(Options{
		Secrets:      NewSecrets(nil),
		MinSecretLen: 8,
		Patterns:     buildPatterns(t),
		PatternMode:  NewPatternMode("log"),
		UpstreamURL:  upstream.URL,
		Audit:        sink,
	})
	proxyServer := httptest.NewServer(proxy)
	t.Cleanup(proxyServer.Close)

	body := `{"content":"key is ` + pat + ` now"}`
	resp, err := http.Post(proxyServer.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if string(received) != body {
		t.Fatalf("log mode must not change the body, got %q want %q", received, body)
	}
	evs := sink.events()
	if len(evs) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(evs))
	}
	if evs[0].Event != audit.DlpRedact || evs[0].Verdict != audit.VerdictRedact || evs[0].Detail != "patterns=hit&mode=log" {
		t.Fatalf("unexpected audit event: %+v", evs[0])
	}
}

// TestProxy_LogModeNoPatternHit verifies that log mode emits nothing when no
// pattern matches.
func TestProxy_LogModeNoPatternHit(t *testing.T) {
	sink := &testSink{}

	var received []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(upstream.Close)

	proxy := New(Options{
		Secrets:      NewSecrets(nil),
		MinSecretLen: 8,
		Patterns:     buildPatterns(t),
		PatternMode:  NewPatternMode("log"),
		UpstreamURL:  upstream.URL,
		Audit:        sink,
	})
	proxyServer := httptest.NewServer(proxy)
	t.Cleanup(proxyServer.Close)

	body := `{"content":"hello world"}`
	resp, err := http.Post(proxyServer.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if string(received) != body {
		t.Fatalf("body changed unexpectedly: %q", received)
	}
	if evs := sink.events(); len(evs) != 0 {
		t.Fatalf("expected no audit events, got %d: %+v", len(evs), evs)
	}
}

// TestProxy_MaskModeRedactsPattern verifies the mask mode: layer 2 replaces
// pattern matches in the body (already layer-1-masked text).
func TestProxy_MaskModeRedactsPattern(t *testing.T) {
	pat := highEntropyPat()
	known := "sk-known-secret-value-abc123"
	sink := &testSink{}

	var received []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(upstream.Close)

	proxy := New(Options{
		Secrets:      NewSecrets([]string{known}),
		MinSecretLen: 8,
		Patterns:     buildPatterns(t),
		PatternMode:  NewPatternMode("mask"),
		UpstreamURL:  upstream.URL,
		Audit:        sink,
	})
	proxyServer := httptest.NewServer(proxy)
	t.Cleanup(proxyServer.Close)

	body := `{"content":"known ` + known + ` and pat ` + pat + `"}`
	resp, err := http.Post(proxyServer.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	got := string(received)
	if strings.Contains(got, known) || strings.Contains(got, pat) {
		t.Fatalf("mask mode must redact both layers, got %q", got)
	}
	if n := strings.Count(got, redact.Marker); n != 2 {
		t.Fatalf("expected exactly 2 markers, got %d in %q", n, got)
	}
	evs := sink.events()
	if len(evs) != 1 || evs[0].Detail != "redacted=true" {
		t.Fatalf("expected 1 redacted audit event, got %d: %+v", len(evs), evs)
	}
}

// TestProxy_NilPatternsLegacy verifies that a nil pattern set keeps the
// legacy behavior: only known-value masking, no pattern masking or log audit.
func TestProxy_NilPatternsLegacy(t *testing.T) {
	pat := highEntropyPat()
	sink := &testSink{}

	var received []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(upstream.Close)

	proxy := New(Options{
		Secrets:      NewSecrets(nil),
		MinSecretLen: 8,
		UpstreamURL:  upstream.URL,
		Audit:        sink,
	})
	proxyServer := httptest.NewServer(proxy)
	t.Cleanup(proxyServer.Close)

	body := `{"content":"key is ` + pat + ` now"}`
	resp, err := http.Post(proxyServer.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if string(received) != body {
		t.Fatalf("nil patterns must pass the body through unchanged, got %q", received)
	}
	if evs := sink.events(); len(evs) != 0 {
		t.Fatalf("expected no audit events, got %d: %+v", len(evs), evs)
	}
}

// newEncodedSetup starts an upstream that decodes request bodies according to
// coding before recording them, plus a DLP proxy in front of it. coding == ""
// means the upstream expects a plain (identity) body.
func newEncodedSetup(t *testing.T, secrets []string, coding string) (string, func() [][]byte) {
	t.Helper()

	var mu sync.Mutex
	var received [][]byte

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		var err error
		switch coding {
		case "gzip", "x-gzip":
			var zr *gzip.Reader
			zr, err = gzip.NewReader(r.Body)
			if err == nil {
				body, err = io.ReadAll(zr)
				_ = zr.Close()
			}
		case "deflate":
			var zr io.ReadCloser
			zr, err = zlib.NewReader(r.Body)
			if err == nil {
				body, err = io.ReadAll(zr)
				_ = zr.Close()
			}
		default:
			body, err = io.ReadAll(r.Body)
		}
		if err != nil {
			t.Errorf("upstream decode (%s): %v", coding, err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		received = append(received, body)
		mu.Unlock()
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(upstream.Close)

	proxy := New(Options{
		Secrets:      NewSecrets(secrets),
		MinSecretLen: 8,
		UpstreamURL:  upstream.URL,
	})
	proxyServer := httptest.NewServer(proxy)
	t.Cleanup(proxyServer.Close)

	return proxyServer.URL, func() [][]byte {
		mu.Lock()
		defer mu.Unlock()
		out := make([][]byte, len(received))
		copy(out, received)
		return out
	}
}

// encodeForTest compresses raw with the given Content-Encoding coding.
func encodeForTest(t *testing.T, coding string, raw []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	switch coding {
	case "gzip", "x-gzip":
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(raw); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	case "deflate":
		zw := zlib.NewWriter(&buf)
		if _, err := zw.Write(raw); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	return raw
}

// TestProxy_DecodesCompressedBodyBeforeScanning is the regression for the
// Content-Encoding bypass: a gzip/deflate body must be inflated, scanned, and
// recompressed so the secret never reaches the upstream.
func TestProxy_DecodesCompressedBodyBeforeScanning(t *testing.T) {
	secret := "sk-compressed-secret-1234567890"
	for _, coding := range []string{"gzip", "deflate"} {
		t.Run(coding, func(t *testing.T) {
			base, received := newEncodedSetup(t, []string{secret}, coding)
			payload := []byte(`{"content":"my key is ` + secret + ` ok"}`)

			req, err := http.NewRequest(http.MethodPost, base+"/v1/chat/completions",
				bytes.NewReader(encodeForTest(t, coding, payload)))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Content-Encoding", coding)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("POST: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
			}

			bodies := received()
			if len(bodies) != 1 {
				t.Fatalf("upstream received %d requests, want 1", len(bodies))
			}
			got := string(bodies[0])
			if strings.Contains(got, secret) {
				t.Fatalf("secret reached upstream through %s: %s", coding, got)
			}
			if !strings.Contains(got, redact.Marker) {
				t.Fatalf("expected <redacted> in %s body: %s", coding, got)
			}
		})
	}
}

// TestProxy_IdentityEncodingStillScanned is the control: an explicit
// Content-Encoding: identity body is scanned exactly like no header at all.
func TestProxy_IdentityEncodingStillScanned(t *testing.T) {
	secret := "sk-identity-secret-1234567890"
	base, received := newEncodedSetup(t, []string{secret}, "")

	req, err := http.NewRequest(http.MethodPost, base+"/v1/chat/completions",
		strings.NewReader(`{"content":"key `+secret+` here"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "identity")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	bodies := received()
	if len(bodies) != 1 {
		t.Fatalf("upstream received %d requests, want 1", len(bodies))
	}
	got := string(bodies[0])
	if strings.Contains(got, secret) || !strings.Contains(got, redact.Marker) {
		t.Fatalf("identity body not masked: %s", got)
	}
}

// TestProxy_RejectsUnsupportedContentEncoding pins fail-closed behavior for
// codings the scanner cannot decode (br, zstd, comma-separated stacks): 415
// and zero requests to the upstream.
func TestProxy_RejectsUnsupportedContentEncoding(t *testing.T) {
	for _, coding := range []string{"br", "zstd", "gzip, br"} {
		t.Run(coding, func(t *testing.T) {
			base, received := newEncodedSetup(t, []string{"sk-unsupported-secret-1234"}, "")

			req, err := http.NewRequest(http.MethodPost, base+"/v1/chat/completions",
				strings.NewReader(`{"content":"whatever"}`))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Encoding", coding)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("POST: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnsupportedMediaType {
				t.Fatalf("status = %d, want 415", resp.StatusCode)
			}
			if n := len(received()); n != 0 {
				t.Fatalf("upstream received %d requests, want 0", n)
			}
		})
	}
}

// TestProxy_RejectsOversizedDecodedBody is the compression-bomb guard: a
// small gzip input that inflates past the 32 MiB cap is rejected with 413 and
// never forwarded.
func TestProxy_RejectsOversizedDecodedBody(t *testing.T) {
	base, received := newEncodedSetup(t, nil, "gzip")

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	chunk := bytes.Repeat([]byte("A"), 1<<20)
	for i := 0; i < (32<<20)/(1<<20)+1; i++ {
		if _, err := zw.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	compressed := buf.Bytes()
	if len(compressed) >= 1<<20 {
		t.Fatalf("test payload should compress small, got %d bytes", len(compressed))
	}

	req, err := http.NewRequest(http.MethodPost, base+"/v1/chat/completions", bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Encoding", "gzip")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
	if n := len(received()); n != 0 {
		t.Fatalf("upstream received %d requests, want 0", n)
	}
}
