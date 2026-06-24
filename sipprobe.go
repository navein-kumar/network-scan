// sipprobe.go: phase 3 driver for SIP (5060/udp + 5060/tcp).
//
// Hand-rolled SIP OPTIONS request. Most SIP endpoints answer OPTIONS
// without authentication, even ones that 401 on INVITE. We prefer UDP
// since it's the more common deployment, with TCP as fallback when UDP
// times out.
package main

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type SIPReport struct {
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	Reachable    bool     `json:"reachable"`
	StatusCode   int      `json:"status_code,omitempty"`
	StatusReason string   `json:"status_reason,omitempty"`
	ServerHeader string   `json:"server_header,omitempty"`
	AllowMethods []string `json:"allow_methods,omitempty"`
	Extensions   []string `json:"extensions,omitempty"`
	ProbeErrors  []string `json:"probe_errors,omitempty"`
}

func ProbeSIP(host string, port int, timeout time.Duration) (*SIPReport, error) {
	rep := &SIPReport{Host: host, Port: port}

	req := buildSIPOptions(host, port, "UDP")

	// Try UDP first.
	if resp, err := sipSendUDP(host, port, []byte(req), timeout); err == nil && len(resp) > 0 {
		parseSIPResponse(rep, string(resp))
		enumSIPExtensions(rep, host, port, timeout)
		return rep, nil
	} else if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("udp: %v", err))
	}

	// Fall back to TCP (some SIP trunks force TCP transport).
	req = buildSIPOptions(host, port, "TCP")
	if resp, err := sipSendTCP(host, port, []byte(req), timeout); err == nil && len(resp) > 0 {
		parseSIPResponse(rep, string(resp))
		return rep, nil
	} else if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("tcp: %v", err))
	}
	return rep, nil
}

func buildSIPOptions(host string, port int, transport string) string {
	return strings.Join([]string{
		fmt.Sprintf("OPTIONS sip:%s SIP/2.0", host),
		fmt.Sprintf("Via: SIP/2.0/%s fastscan.local:5060;branch=z9hG4bK-fastscan", transport),
		"From: <sip:fastscan@fastscan.local>;tag=1",
		fmt.Sprintf("To: <sip:probe@%s>", host),
		"Call-ID: fastscan-probe@fastscan.local",
		"CSeq: 1 OPTIONS",
		"Max-Forwards: 70",
		"Content-Length: 0",
		"", "",
	}, "\r\n")
}

// sipExtCandidates is the built-in shortlist tried during enumeration.
var sipExtCandidates = []string{
	"100", "101", "102", "200", "1000", "1001",
	"2000", "admin", "sip", "test", "operator", "phone",
}

// enumSIPExtensions enumerates valid extensions by response-code differencing.
// An auth challenge (401/407) for a given To/From extension implies a real
// account, while 404/403 implies it does not exist. We first baseline with a
// clearly-bogus extension: if the server challenges that too, it is a catch-all
// (alwaysauthreject) and per-extension results are meaningless, so we record
// nothing. Bounded and best-effort; never panics.
func enumSIPExtensions(rep *SIPReport, host string, port int, timeout time.Duration) {
	const bogus = "zzqx9183777"

	exists, err := sipExtChallenged(host, port, bogus, timeout)
	if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("sip-enum baseline: %v", err))
		return
	}
	if exists {
		// Catch-all server: challenges every extension, so we cannot tell
		// real accounts apart. Skip enumeration to avoid false positives.
		rep.ProbeErrors = append(rep.ProbeErrors,
			"sip-enum: server challenges unknown extensions (catch-all), enumeration unreliable")
		return
	}

	for _, ext := range sipExtCandidates {
		challenged, err := sipExtChallenged(host, port, ext, timeout)
		if err != nil {
			continue
		}
		if challenged {
			rep.Extensions = append(rep.Extensions, ext)
		}
	}
}

// sipExtChallenged sends a REGISTER for ext and reports whether the server
// answered with an auth challenge (401/407), which marks the extension as real.
func sipExtChallenged(host string, port int, ext string, timeout time.Duration) (bool, error) {
	req := buildSIPRegister(host, port, ext)
	resp, err := sipSendUDP(host, port, []byte(req), timeout)
	if err != nil {
		return false, err
	}
	if len(resp) == 0 {
		return false, nil
	}
	code := sipStatusCode(string(resp))
	return code == 401 || code == 407, nil
}

// sipStatusCode pulls the numeric status from a SIP response's first line.
func sipStatusCode(raw string) int {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	if len(lines) == 0 {
		return 0
	}
	if m := sipStatusLineRe.FindStringSubmatch(strings.TrimSpace(lines[0])); m != nil {
		code, _ := strconv.Atoi(m[1])
		return code
	}
	return 0
}

// buildSIPRegister builds a REGISTER addressed at a specific extension. We use
// REGISTER (never INVITE, which would ring phones) so the server reveals
// whether the account exists via its auth-challenge behaviour.
func buildSIPRegister(host string, port int, ext string) string {
	branch := "z9hG4bK-fastscan-" + ext
	callID := "fastscan-enum-" + ext + "@fastscan.local"
	return strings.Join([]string{
		fmt.Sprintf("REGISTER sip:%s SIP/2.0", host),
		fmt.Sprintf("Via: SIP/2.0/UDP fastscan.local:5060;branch=%s", branch),
		fmt.Sprintf("From: <sip:%s@%s>;tag=1", ext, host),
		fmt.Sprintf("To: <sip:%s@%s>", ext, host),
		fmt.Sprintf("Contact: <sip:%s@fastscan.local:5060>", ext),
		fmt.Sprintf("Call-ID: %s", callID),
		"CSeq: 1 REGISTER",
		"Max-Forwards: 70",
		"Expires: 0",
		"Content-Length: 0",
		"", "",
	}, "\r\n")
}

func sipSendUDP(host string, port int, req []byte, timeout time.Duration) ([]byte, error) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	buf := make([]byte, 8192)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func sipSendTCP(host string, port int, req []byte, timeout time.Duration) ([]byte, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	// Read at most 8 KiB or until we see two CRLFs.
	var got []byte
	for len(got) < 8192 {
		chunk := make([]byte, 1024)
		n, err := br.Read(chunk)
		if n > 0 {
			got = append(got, chunk[:n]...)
			if strings.Contains(string(got), "\r\n\r\n") {
				break
			}
		}
		if err != nil {
			break
		}
	}
	return got, nil
}

var sipStatusLineRe = regexp.MustCompile(`^SIP/2\.0\s+(\d{3})\s+(.+)$`)

func parseSIPResponse(rep *SIPReport, raw string) {
	rep.Reachable = true
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	if len(lines) == 0 {
		return
	}
	if m := sipStatusLineRe.FindStringSubmatch(strings.TrimSpace(lines[0])); m != nil {
		code, _ := strconv.Atoi(m[1])
		rep.StatusCode = code
		rep.StatusReason = strings.TrimSpace(m[2])
	}
	for _, l := range lines[1:] {
		l = strings.TrimRight(l, "\r")
		if l == "" {
			break
		}
		colon := strings.IndexByte(l, ':')
		if colon < 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(l[:colon]))
		val := strings.TrimSpace(l[colon+1:])
		switch name {
		case "server", "user-agent":
			if rep.ServerHeader == "" {
				rep.ServerHeader = val
			}
		case "allow":
			for _, m := range strings.Split(val, ",") {
				m = strings.TrimSpace(m)
				if m != "" {
					rep.AllowMethods = append(rep.AllowMethods, m)
				}
			}
		}
	}
}
