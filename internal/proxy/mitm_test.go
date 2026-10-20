package proxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ikkun1222/trustless/internal/audit"
	"github.com/ikkun1222/trustless/internal/config"
)

// TestMITMConnectHostMismatchDoesNotLeakCredential pins the fail-closed
// boundary: the credential rule is selected for the CONNECT authority, not
// for the Host header read inside the tunnel. A client that CONNECTs to an
// attacker host must never receive credentials configured for another host.
func TestMITMConnectHostMismatchDoesNotLeakCredential(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	var mu sync.Mutex
	var gotHost, gotAuth string
	sink := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotHost = r.Host
		gotAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer sink.Close()

	sinkAddr := strings.TrimPrefix(sink.URL, "https://")

	be := &mockBackend{values: map[string]string{"k": "DUMMY-SECRET"}}
	cfg := &config.Config{}
	cfg.Proxy.Rules = map[string]config.ProxyRule{
		"api.example.com": {Header: "Authorization", Prefix: "Bearer ", Key: "k"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := StartForward(ctx, be, cfg, 0, true, audit.Off())
	if err != nil {
		t.Fatalf("StartForward: %v", err)
	}
	p.upstreamRoots = testRootPool(sink.Certificate())

	conn, err := net.Dial("tcp", p.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	connect := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", sinkAddr, sinkAddr)
	if _, err := io.WriteString(conn, connect); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	defer tlsConn.Close()
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}

	// The tunnel destination is the sink, but the inner request claims to be
	// api.example.com. Old code selected the rule from this header and leaked.
	if _, err := io.WriteString(tlsConn, "GET /steal HTTP/1.1\r\nHost: api.example.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write inner request: %v", err)
	}

	// The proxy may answer 400 or simply close; either is acceptable. Reading
	// the response also ensures a buggy proxy finished forwarding to the sink
	// before we inspect what it received.
	if inner, err := http.ReadResponse(bufio.NewReader(tlsConn), &http.Request{Method: http.MethodGet}); err == nil {
		io.Copy(io.Discard, inner.Body)
		inner.Body.Close()
	}

	mu.Lock()
	auth, host := gotAuth, gotHost
	mu.Unlock()

	if auth != "" {
		t.Fatalf("credential leaked to CONNECT target: sink received Authorization %q (Host %q)", auth, host)
	}
}

// TestInjectForHostUsesBoundHost pins that rule selection follows the host
// argument (the CONNECT authority in MITM), not the request's Host header.
func TestInjectForHostUsesBoundHost(t *testing.T) {
	p := newTestProxy(map[string]config.ProxyRule{
		"api.example.com": {Header: "Authorization", Prefix: "Bearer ", Key: "xai"},
	}, nil)

	bound := httptestNewRequest(http.MethodGet, "https://attacker.example.com/steal")
	p.injectForHost(bound, "api.example.com")
	if got := bound.Header.Get("Authorization"); got != "Bearer sk-test-xai-12345" {
		t.Fatalf("bound host injection: Authorization = %q, want %q", got, "Bearer sk-test-xai-12345")
	}

	other := httptestNewRequest(http.MethodGet, "https://api.example.com/")
	p.injectForHost(other, "other.example.com")
	if got := other.Header.Get("Authorization"); got != "" {
		t.Fatalf("non-matching bound host injected Authorization %q, want empty", got)
	}
}

// TestHostsMatchNormalizesCaseAndPort ensures the fail-closed comparison does
// not reject legitimate tunnels whose Host header differs only in case or by
// carrying an explicit port.
func TestHostsMatchNormalizesCaseAndPort(t *testing.T) {
	cases := []struct {
		connect, inner string
	}{
		{"api.example.com:443", "api.example.com"},
		{"API.example.com:443", "api.example.com"},
		{"api.example.com", "API.example.com:443"},
	}
	for _, c := range cases {
		if !hostsMatch(c.connect, c.inner) {
			t.Fatalf("hostsMatch(%q, %q) = false, want true", c.connect, c.inner)
		}
	}
	if hostsMatch("api.example.com:443", "attacker.example.com:443") {
		t.Fatal("hostsMatch must reject different hosts")
	}
}

// TestMITMRejectsUntrustedUpstreamCertificate pins that the MITM upstream
// dial verifies the server certificate against the system trust store. A
// self-signed sink whose SAN does not match the dial target must be rejected
// with a 502, and the injected credential must never be written to it.
func TestMITMRejectsUntrustedUpstreamCertificate(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	var hits atomic.Int32
	var mu sync.Mutex
	var gotAuth string
	sink := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	sink.TLS = &tls.Config{Certificates: []tls.Certificate{selfSignedTLSCertificate(t, "ledger.example")}}
	sink.StartTLS()
	defer sink.Close()

	sinkAddr := strings.TrimPrefix(sink.URL, "https://")

	be := &mockBackend{values: map[string]string{"k": "DUMMY-SECRET"}}
	cfg := &config.Config{}
	cfg.Proxy.Rules = map[string]config.ProxyRule{
		"127.0.0.1": {Header: "Authorization", Prefix: "Bearer ", Key: "k"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := StartForward(ctx, be, cfg, 0, true, audit.Off())
	if err != nil {
		t.Fatalf("StartForward: %v", err)
	}
	// Deliberately leave p.upstreamRoots nil: the system roots must reject
	// the self-signed upstream.

	tlsConn := openMITMTunnel(t, p, sinkAddr)
	defer tlsConn.Close()

	fmt.Fprintf(tlsConn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", sinkAddr)
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read inner response: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("inner status = %d, want 502", resp.StatusCode)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("untrusted sink received %d request(s), want 0", n)
	}
	mu.Lock()
	auth := gotAuth
	mu.Unlock()
	if auth != "" {
		t.Fatalf("credential reached untrusted sink: Authorization %q", auth)
	}
}

// TestMITMAcceptsUpstreamTrustedByConfiguredRoots pins the positive path: when
// the sink certificate is trusted (the same-package test hook), the upstream
// handshake succeeds and the injected header is delivered.
func TestMITMAcceptsUpstreamTrustedByConfiguredRoots(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	var mu sync.Mutex
	var hits int
	var gotAuth string
	sink := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		gotAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer sink.Close()

	sinkAddr := strings.TrimPrefix(sink.URL, "https://")

	be := &mockBackend{values: map[string]string{"k": "DUMMY-SECRET"}}
	cfg := &config.Config{}
	cfg.Proxy.Rules = map[string]config.ProxyRule{
		"127.0.0.1": {Header: "Authorization", Prefix: "Bearer ", Key: "k"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := StartForward(ctx, be, cfg, 0, true, audit.Off())
	if err != nil {
		t.Fatalf("StartForward: %v", err)
	}
	p.upstreamRoots = testRootPool(sink.Certificate())

	tlsConn := openMITMTunnel(t, p, sinkAddr)
	defer tlsConn.Close()

	fmt.Fprintf(tlsConn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", sinkAddr)
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read inner response: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("inner status = %d, want 200", resp.StatusCode)
	}
	mu.Lock()
	auth, n := gotAuth, hits
	mu.Unlock()
	if n != 1 {
		t.Fatalf("sink received %d request(s), want 1", n)
	}
	if auth != "Bearer DUMMY-SECRET" {
		t.Fatalf("Authorization = %q, want %q", auth, "Bearer DUMMY-SECRET")
	}
}

// openMITMTunnel CONNECTs to target through the proxy, completes the client
// side of the MITM TLS handshake, and returns the tunnel connection.
func openMITMTunnel(t *testing.T, p *Proxy, target string) *tls.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", p.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		t.Fatalf("read CONNECT response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		t.Fatalf("client TLS handshake: %v", err)
	}
	return tlsConn
}

func testRootPool(cert *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}

// selfSignedTLSCertificate builds a self-signed server certificate for the
// given DNS SAN, used to model an attacker-controlled upstream.
func selfSignedTLSCertificate(t *testing.T, san string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: san},
		DNSNames:     []string{san},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
