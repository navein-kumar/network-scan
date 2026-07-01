// informixprobe.go: phase 3 driver for IBM Informix (sqli, 1526 default,
// 9088 onstat).
//
// v0: TCP connect, send a 4-byte SQLI version hello (the Informix
// SQLI/Q4 protocol kicks off with the client offering version bytes; a
// real server replies with version metadata or an error response that
// nonetheless contains "informix" in printable form). We capture the
// first response bytes as hex and search for an "informix" substring as
// the product fingerprint.
package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

type InformixReport struct {
	Host          string   `json:"host"`
	Port          int      `json:"port"`
	Reachable     bool     `json:"reachable"`
	ProductMatch  bool     `json:"product_match"`
	BannerBytes   string   `json:"banner_bytes,omitempty"`
	BannerText    string   `json:"banner_text,omitempty"`
	ProbeErrors   []string `json:"probe_errors,omitempty"`
}

func ProbeInformix(host string, port int, timeout time.Duration) (*InformixReport, error) {
	rep := &InformixReport{Host: host, Port: port}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Send a small SQLI handshake hint: 's' + a NUL + version magic. The
	// real protocol is connection-string based, but a number of Informix
	// versions reply with a printable error block that names the product,
	// which is enough for v0 fingerprinting.
	hello := []byte("sq" + "\x00\x00\x00\x09\x00")
	if _, err := conn.Write(hello); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("write: %v", err))
		return rep, nil
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("read: %v", err))
		return rep, nil
	}
	rep.Reachable = true
	if n > 128 {
		rep.BannerBytes = hex.EncodeToString(buf[:128])
	} else {
		rep.BannerBytes = hex.EncodeToString(buf[:n])
	}
	rep.BannerText = printableInformixRun(buf[:n])
	if strings.Contains(strings.ToLower(rep.BannerText), "informix") {
		rep.ProductMatch = true
	}
	return rep, nil
}

func printableInformixRun(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x20 && c < 0x7F {
			sb.WriteByte(c)
		} else if sb.Len() > 0 && c == 0 {
			sb.WriteByte(' ')
		}
	}
	return strings.TrimSpace(sb.String())
}
