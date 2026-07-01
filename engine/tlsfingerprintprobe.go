// tlsfingerprintprobe.go: phase 2.9 driver that captures TLS handshake
// telemetry per port flagged as TLS.
//
// Implementation choice: we use stdlib crypto/tls instead of pulling in
// projectdiscovery/tlsx (which would add ~50 MB and another nest of
// transitive deps). The stdlib path records cipher suite, negotiated
// protocol version, ALPN, server name, and peer cert subject/issuer.
// We then compute a JA4-style identifier from the parameters we sent
// (it is a "JA4-like" tag, not the official ja4 hash, because that
// requires capturing low-level ClientHello extensions). Sufficient for
// "same server fingerprint across ports / hosts" correlation.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

// TLSFingerprintReport is one TLS handshake summary per host:port.
type TLSFingerprintReport struct {
	Host              string   `json:"host"`
	Port              int      `json:"port"`
	TLSVersion        string   `json:"tls_version,omitempty"`
	CipherSuite       string   `json:"cipher_suite,omitempty"`
	ALPN              string   `json:"alpn,omitempty"`
	SNI               string   `json:"sni,omitempty"`
	JA3               string   `json:"ja3,omitempty"`
	JA3S              string   `json:"ja3s,omitempty"`
	JA4               string   `json:"ja4,omitempty"`
	JA4S              string   `json:"ja4s,omitempty"`
	PeerSubject       string   `json:"peer_subject,omitempty"`
	PeerIssuer        string   `json:"peer_issuer,omitempty"`
	PeerCN            string   `json:"peer_cn,omitempty"`
	CertNotBefore     string   `json:"cert_not_before,omitempty"`
	CertNotAfter      string   `json:"cert_not_after,omitempty"`
	CertDaysRemaining int      `json:"cert_days_remaining"`
	CertSANs          []string `json:"cert_sans,omitempty"`
	CertSerial        string   `json:"cert_serial,omitempty"`
	ProbeErrors       []string `json:"probe_errors,omitempty"`
}

// ProbeTLSFingerprint performs a TLS handshake against host:port using
// stdlib crypto/tls. Returns a report even on partial failures (errors
// accumulated in ProbeErrors).
func ProbeTLSFingerprint(host string, port int, timeout time.Duration) (*TLSFingerprintReport, error) {
	rep := &TLSFingerprintReport{Host: host, Port: port, SNI: host}

	addr := fmt.Sprintf("%s:%d", host, port)
	d := net.Dialer{Timeout: timeout}
	rawConn, err := d.Dial("tcp", addr)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer rawConn.Close()
	rawConn.SetDeadline(time.Now().Add(timeout))

	cfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
	}
	conn := tls.Client(rawConn, cfg)
	if err := conn.Handshake(); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("handshake: %v", err))
		return rep, nil
	}
	state := conn.ConnectionState()
	rep.TLSVersion = tlsVersionString(state.Version)
	rep.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	rep.ALPN = state.NegotiatedProtocol
	if len(state.PeerCertificates) > 0 {
		c := state.PeerCertificates[0]
		rep.PeerSubject = c.Subject.String()
		rep.PeerIssuer = c.Issuer.String()
		rep.PeerCN = c.Subject.CommonName
		rep.CertNotBefore = c.NotBefore.UTC().Format("2006-01-02")
		rep.CertNotAfter = c.NotAfter.UTC().Format("2006-01-02")
		rep.CertDaysRemaining = int(time.Until(c.NotAfter).Hours() / 24)
		rep.CertSerial = c.SerialNumber.Text(16)
		for _, san := range c.DNSNames {
			rep.CertSANs = append(rep.CertSANs, san)
		}
		for _, ip := range c.IPAddresses {
			rep.CertSANs = append(rep.CertSANs, ip.String())
		}
	}
	// JA4 / JA4S abbreviated tags. Real JA4 needs the actual TLS
	// extension list which crypto/tls hides. We use a "JA4-style"
	// fingerprint that captures the negotiated version + ALPN + cipher
	// so two ports on the same server stack produce the same value.
	rep.JA4 = ja4Like(state)
	rep.JA4S = ja4sLike(state)
	conn.Close()
	return rep, nil
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	case 0x0300:
		return "SSL 3.0"
	}
	return fmt.Sprintf("0x%04x", v)
}

// ja4Like produces a JA4-style label: "tls_version,ALPN,cipher_hex".
// Not the official JA4 hash, but unique-per-server-config.
func ja4Like(s tls.ConnectionState) string {
	alpn := s.NegotiatedProtocol
	if alpn == "" {
		alpn = "-"
	}
	return fmt.Sprintf("t%02x_%s_%04x", s.Version&0xFF, alpn, s.CipherSuite)
}

// ja4sLike: server-side compact tag (TLS ver + cipher, no alpn).
func ja4sLike(s tls.ConnectionState) string {
	return fmt.Sprintf("s%02x_%04x", s.Version&0xFF, s.CipherSuite)
}

// formatPeerName returns a short label for the peer cert (CN if set,
// else subject).
func formatPeerName(c *x509.Certificate) string {
	if c == nil {
		return ""
	}
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	return strings.TrimSpace(c.Subject.String())
}

// Ensure formatPeerName stays linked for future use; suppress
// "declared but not used" if not called elsewhere.
var _ = formatPeerName
