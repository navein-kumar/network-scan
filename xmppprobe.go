// xmppprobe.go: phase 3 driver for XMPP (5222 c2s, 5269 s2s).
//
// Open a TCP connection, send a stream:stream opening, and read whatever
// the server sends back (typically the matching stream open + a
// stream:features block). We surface stream id, server name, whether
// STARTTLS is offered, and the SASL mechanism list. v0 doesn't continue
// the handshake.
package main

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

type XMPPReport struct {
	Host             string   `json:"host"`
	Port             int      `json:"port"`
	Reachable        bool     `json:"reachable"`
	StreamID         string   `json:"stream_id,omitempty"`
	ServerName       string   `json:"server_name,omitempty"`
	StartTLSOffered  bool     `json:"starttls_offered"`
	AuthMechanisms   []string `json:"auth_mechanisms,omitempty"`
	ProbeErrors      []string `json:"probe_errors,omitempty"`
}

var (
	xmppStreamIDRE   = regexp.MustCompile(`id\s*=\s*['"]([^'"]+)['"]`)
	xmppStreamFromRE = regexp.MustCompile(`from\s*=\s*['"]([^'"]+)['"]`)
	xmppMechRE       = regexp.MustCompile(`<mechanism[^>]*>([^<]+)</mechanism>`)
)

func ProbeXMPP(host string, port int, timeout time.Duration) (*XMPPReport, error) {
	rep := &XMPPReport{Host: host, Port: port}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	streamNS := "jabber:client"
	if port == 5269 {
		streamNS = "jabber:server"
	}
	open := fmt.Sprintf(
		`<?xml version='1.0'?><stream:stream xmlns='%s' xmlns:stream='http://etherx.jabber.org/streams' to='%s' version='1.0'>`,
		streamNS, host)
	if _, err := conn.Write([]byte(open)); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("write: %v", err))
		return rep, nil
	}
	// Read up to ~8 KiB or until features block ends; XMPP servers
	// usually flush <stream:features> within one or two writes.
	buf := make([]byte, 8192)
	total := 0
	conn.SetReadDeadline(time.Now().Add(timeout))
	for total < len(buf) {
		n, rerr := conn.Read(buf[total:])
		if n > 0 {
			total += n
			if strings.Contains(string(buf[:total]), "</stream:features>") ||
				strings.Contains(string(buf[:total]), "<stream:features/>") {
				break
			}
		}
		if rerr != nil {
			break
		}
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	}
	if total == 0 {
		rep.ProbeErrors = append(rep.ProbeErrors, "no response")
		return rep, nil
	}
	s := string(buf[:total])
	if !strings.Contains(s, "<stream:stream") && !strings.Contains(s, "<stream:error") &&
		!strings.Contains(s, "<?xml") {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("non-xmpp banner: %q", firstNBytes(s, 64)))
		return rep, nil
	}
	rep.Reachable = true
	if m := xmppStreamIDRE.FindStringSubmatch(s); len(m) > 1 {
		rep.StreamID = m[1]
	}
	if m := xmppStreamFromRE.FindStringSubmatch(s); len(m) > 1 {
		rep.ServerName = m[1]
	}
	if strings.Contains(s, "<starttls") {
		rep.StartTLSOffered = true
	}
	for _, m := range xmppMechRE.FindAllStringSubmatch(s, -1) {
		rep.AuthMechanisms = append(rep.AuthMechanisms, m[1])
	}
	return rep, nil
}

func firstNBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
