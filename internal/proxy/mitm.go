package proxy

import (
	"bufio"
	"crypto/tls"
	"net/http"
)

func (p *Proxy) mitmHandleCONNECT(w http.ResponseWriter, r *http.Request, ca *CA) {
	if !p.allowedHost(r.Host) {
		http.Error(w, "host not allowed by proxy allowlist", http.StatusForbidden)
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
	defer clientConn.Close()

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	host := hostOnly(r.Host)
	leafCert, err := ca.LeafCert(host)
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

	p.substituteRequest(req)

	upstreamTLS := &tls.Config{InsecureSkipVerify: true}
	upstream, err := tls.Dial("tcp", r.Host, upstreamTLS)
	if err != nil {
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
