package proxy

import (
	"bufio"
	"crypto/tls"
	"net/http"
	"strings"
)

// canonicalHost lowercases a host and strips any port so that CONNECT
// authority and inner Host header comparisons are insensitive to case and
// an explicit :443.
func canonicalHost(host string) string {
	return strings.ToLower(hostOnly(host))
}

// hostsMatch reports whether two authority strings refer to the same host.
func hostsMatch(a, b string) bool {
	return canonicalHost(a) == canonicalHost(b)
}

func (p *Proxy) mitmHandleCONNECT(w http.ResponseWriter, r *http.Request, ca *CA) {
	if !p.allowedHost(r.Host) {
		http.Error(w, "host not allowed by proxy allowlist", http.StatusForbidden)
		return
	}
	boundHost := canonicalHost(r.Host)
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
	defer clientConn.Close()

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	leafCert, err := ca.LeafCert(boundHost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{leafCert},
	}
	tlsConn := tls.Server(clientConn, tlsConfig)
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		return
	}

	reader := bufio.NewReader(tlsConn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	innerHost := req.Host
	if innerHost == "" {
		innerHost = req.URL.Host
	}
	if !hostsMatch(r.Host, innerHost) {
		tlsConn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		return
	}

	p.injectForHost(req, boundHost)

	upstreamTLS := &tls.Config{
		ServerName: boundHost,
		RootCAs:    p.upstreamRoots,
	}
	upstream, err := tls.Dial("tcp", r.Host, upstreamTLS)
	if err != nil {
		// Verification failed (or the upstream is unreachable): report the
		// failure without ever writing the request (and its injected
		// credentials) to the peer.
		tlsConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		return
	}
	defer upstream.Close()

	if err := req.Write(upstream); err != nil {
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(upstream), req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	resp.Write(tlsConn)
}
