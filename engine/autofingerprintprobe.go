// autofingerprintprobe.go: Phase 2.4 cascade for ports that nmap
// labelled "", "tcpwrapped", or "unknown". Inferred service feeds the
// same Phase 2.5 driver dispatch + plugin engine. Each cascade step is
// budget-capped (2s/step, 8s total).
//
// Order:
//   1. Passive read of first 512 bytes for well-known banner prefixes.
//   2. Active TLS ClientHello via crypto/tls.Dial.
//   3. Active HTTP/1.0 GET.
//   4. Active X.224 ConnectionRequest (RDP).
//   5. Active SMB1 NEGOTIATE.
//
// Returns service-name, raw banner bytes, method name. Method goes into
// Port.Extra so NDJSON records HOW we inferred the service.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// autoFPBudget is the cumulative cascade ceiling. Per-step timeout is 2s.
const autoFPBudget = 8 * time.Second
const autoFPStep = 2 * time.Second

// AutoFingerprint runs the passive-then-active cascade. Returns
// ("", nil, "") if nothing matched.
func AutoFingerprint(host string, port int, timeout time.Duration) (service string, banner []byte, method string) {
	if timeout <= 0 {
		timeout = autoFPBudget
	}
	deadline := time.Now().Add(timeout)
	addr := fmt.Sprintf("%s:%d", host, port)

	// Step 1: passive read.
	if svc, b := passiveRead(addr); svc != "" {
		return svc, b, "passive"
	} else if b != nil {
		banner = b
	}
	if time.Now().After(deadline) {
		return "", banner, ""
	}

	// Step 2: TLS handshake.
	if tlsActive(addr) {
		return "ssl/http", banner, "tls"
	}
	if time.Now().After(deadline) {
		return "", banner, ""
	}

	// Step 3: HTTP GET.
	if b := httpActive(addr); b != nil {
		return "http", b, "http"
	}
	if time.Now().After(deadline) {
		return "", banner, ""
	}

	// Step 4: X.224.
	if b := x224Active(addr); b != nil {
		return "ms-wbt-server", b, "x224"
	}
	if time.Now().After(deadline) {
		return "", banner, ""
	}

	// Step 5: SMB1.
	if b := smbActive(addr); b != nil {
		return "microsoft-ds", b, "smb"
	}
	return "", banner, ""
}

// passiveRead dials and reads up to 512 bytes within 2s, classifying by
// well-known banner prefix. Returns (service, banner) or ("", banner) if
// nothing matched.
func passiveRead(addr string) (string, []byte) {
	conn, err := net.DialTimeout("tcp", addr, autoFPStep)
	if err != nil {
		return "", nil
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(autoFPStep))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n <= 0 {
		return "", nil
	}
	b := buf[:n]
	return classifyBanner(b), b
}

// classifyBanner returns a service name for a banner prefix, or "".
func classifyBanner(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	// SSH-1.x / SSH-2.0
	if bytes.HasPrefix(b, []byte("SSH-")) {
		return "ssh"
	}
	// HTTP/1.x server-pushed (rare but possible)
	if bytes.HasPrefix(b, []byte("HTTP/")) {
		return "http"
	}
	// POP3
	if bytes.HasPrefix(b, []byte("+OK ")) {
		return "pop3"
	}
	// IMAP
	if bytes.HasPrefix(b, []byte("* OK ")) {
		return "imap"
	}
	// VNC RFB
	if bytes.HasPrefix(b, []byte("RFB ")) {
		return "vnc"
	}
	// Telnet IAC negotiation: 0xFF 0xFB / 0xFD
	if len(b) >= 2 && b[0] == 0xff && (b[1] == 0xfb || b[1] == 0xfd || b[1] == 0xfc || b[1] == 0xfe) {
		return "telnet"
	}
	// MySQL: 4-byte packet header then protocol byte 0x0a at offset 4.
	// Offset 3 is sequence id (often 0). Length is offset 0..2 little
	// endian, but cheapest heuristic is offset 4 == 0x0a and offset 3 == 0x00.
	if len(b) >= 5 && b[3] == 0x00 && b[4] == 0x0a {
		return "mysql"
	}
	// SMTP / FTP both start with "220 ".
	if bytes.HasPrefix(b, []byte("220 ")) || bytes.HasPrefix(b, []byte("220-")) {
		upper := strings.ToUpper(string(b))
		if strings.Contains(upper, "ESMTP") || strings.Contains(upper, "SMTP") {
			return "smtp"
		}
		if strings.Contains(upper, "FTP") ||
			strings.Contains(upper, "VSFTPD") ||
			strings.Contains(upper, "PROFTPD") ||
			strings.Contains(upper, "PURE-FTPD") ||
			strings.Contains(upper, "FILEZILLA") {
			return "ftp"
		}
		// Default 220 to FTP (more common in pentest scope).
		return "ftp"
	}
	// MongoDB OP_QUERY-style BSON: marker check.
	if bytes.Contains(b, []byte("ismaster")) || bytes.Contains(b, []byte("isMaster")) {
		return "mongodb"
	}
	return ""
}

// tlsActive attempts a TLS handshake. Returns true if it completes.
func tlsActive(addr string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), autoFPStep)
	defer cancel()
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: autoFPStep},
		Config:    &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10},
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// httpActive sends a minimal GET / HTTP/1.0 and returns the body bytes
// if the response begins with "HTTP/". Nil otherwise.
func httpActive(addr string) []byte {
	conn, err := net.DialTimeout("tcp", addr, autoFPStep)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(autoFPStep))
	if _, err := conn.Write([]byte("GET / HTTP/1.0\r\nHost: x\r\nUser-Agent: fastscan\r\n\r\n")); err != nil {
		return nil
	}
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n <= 0 {
		return nil
	}
	if bytes.HasPrefix(buf[:n], []byte("HTTP/")) {
		return buf[:n]
	}
	return nil
}

// x224Active sends an X.224 CR and returns response bytes if it looks
// like an X.224 CC. We re-build the same packet rdpprobe.go uses
// (requested = 0 = standard security).
func x224Active(addr string) []byte {
	conn, err := net.DialTimeout("tcp", addr, autoFPStep)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(autoFPStep))
	pkt := buildX224CR(0)
	if _, err := conn.Write(pkt); err != nil {
		return nil
	}
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n < 11 {
		return nil
	}
	// X.224 CC: TPKT 0x03 0x00 .. .. then X.224 LI byte then 0xd0 (CC).
	if buf[0] == 0x03 && buf[1] == 0x00 && buf[6] == 0xd0 {
		return buf[:n]
	}
	return nil
}

// smbActive sends an SMB1 NEGOTIATE and returns response bytes if the
// reply begins with the SMB signature.
func smbActive(addr string) []byte {
	// Build SMB1 NEGOTIATE packet (same dialect list as smbprobe.go).
	dialects := []string{
		"PC NETWORK PROGRAM 1.0",
		"LANMAN1.0",
		"LM1.2X002",
		"NT LANMAN 1.0",
		"NT LM 0.12",
	}
	var byteCount int
	var dialectBytes []byte
	for _, d := range dialects {
		dialectBytes = append(dialectBytes, 0x02)
		dialectBytes = append(dialectBytes, []byte(d)...)
		dialectBytes = append(dialectBytes, 0x00)
		byteCount += 2 + len(d)
	}
	smbHeader := []byte{
		0xff, 'S', 'M', 'B',
		0x72,
		0x00, 0x00, 0x00, 0x00,
		0x18,
		0x53, 0xc8,
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x2f, 0x4b,
		0x00, 0x00,
		0xc5, 0x5e,
	}
	body := []byte{0x00, byte(byteCount), byte(byteCount >> 8)}
	body = append(body, dialectBytes...)
	smbBody := append(smbHeader, body...)
	totalLen := len(smbBody)
	nbt := []byte{0x00, 0x00, byte(totalLen >> 8), byte(totalLen)}
	pkt := append(nbt, smbBody...)

	conn, err := net.DialTimeout("tcp", addr, autoFPStep)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(autoFPStep))
	if _, err := conn.Write(pkt); err != nil {
		return nil
	}
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if n < 8 {
		return nil
	}
	if buf[4] == 0xff && buf[5] == 'S' && buf[6] == 'M' && buf[7] == 'B' {
		return buf[:n]
	}
	return nil
}

// runAutoFingerprint walks every port and, for any unknown one, runs the
// cascade. On a hit it mutates Port.Service and appends a marker to
// Port.Extra so the NDJSON shows how we inferred it. Concurrency capped
// at 16 in flight.
func runAutoFingerprint(ports []*Port) (probed int, classified int) {
	if len(ports) == 0 {
		return 0, 0
	}
	type job struct{ p *Port }
	var (
		wg     sync.WaitGroup
		sem    = make(chan struct{}, 16)
		mu     sync.Mutex
	)
	for _, p := range ports {
		if !isUnknownService(p) {
			continue
		}
		probed++
		wg.Add(1)
		sem <- struct{}{}
		go func(p *Port) {
			defer wg.Done()
			defer func() { <-sem }()
			svc, _, method := AutoFingerprint(p.Host, p.Port, autoFPBudget)
			if svc == "" {
				return
			}
			mu.Lock()
			p.Service = svc
			tag := "auto-fingerprint:" + method
			if p.Extra == "" {
				p.Extra = tag
			} else {
				p.Extra = p.Extra + " | " + tag
			}
			classified++
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	return probed, classified
}

// isUnknownService returns true if the port still needs classification
// after nmap. tcpwrapped is treated as unknown because nmap couldn't
// finish the version probe.
func isUnknownService(p *Port) bool {
	switch p.Service {
	case "", "tcpwrapped", "unknown":
		return true
	}
	return false
}
