// smtpprobe.go: phase 3 driver for SMTP (25, 587, 2525).
//
// Plain SMTP probe via stdlib net/textproto:
//   1. read 220 greeting
//   2. EHLO probe.fastscan.local; parse multi-line 250 capabilities
//   3. open-relay quick check via MAIL FROM / RCPT TO to two invalid
//      external addresses; a 250 to the RCPT TO confirms relaying.
package main

import (
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"time"
)

// SMTPReport is what Phase 3 emits per SMTP port.
type SMTPReport struct {
	Host            string   `json:"host"`
	Port            int      `json:"port"`
	Banner          string   `json:"banner,omitempty"`
	Product         string   `json:"product,omitempty"`
	ProductVersion  string   `json:"product_version,omitempty"`
	EHLOHostname    string   `json:"ehlo_hostname,omitempty"`
	Capabilities    []string `json:"capabilities,omitempty"`
	STARTTLSOffered bool     `json:"starttls_offered"`
	AuthMethods     []string `json:"auth_methods,omitempty"`
	OpenRelay       bool     `json:"open_relay"`
	VRFYUsers       []string `json:"vrfy_users,omitempty"`
	ProbeErrors     []string `json:"probe_errors,omitempty"`
}

// ProbeSMTP opens an SMTP session, captures banner + EHLO caps, then
// tests for open relay.
func ProbeSMTP(host string, port int, timeout time.Duration) (*SMTPReport, error) {
	rep := &SMTPReport{Host: host, Port: port}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	tc := textproto.NewConn(conn)
	defer tc.Close()

	// Read greeting (220 line, possibly multi-line)
	code, banner, err := tc.ReadResponse(220)
	if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("read greeting: %v", err))
		return rep, nil
	}
	rep.Banner = fmt.Sprintf("%d %s", code, banner)
	rep.Product, rep.ProductVersion = parseProductVersion(rep.Banner)

	// EHLO
	if err := tc.PrintfLine("EHLO probe.fastscan.local"); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("write EHLO: %v", err))
		return rep, nil
	}
	code, ehloResp, err := tc.ReadResponse(250)
	if err != nil {
		// If EHLO fails, server might be ESMTP-incapable: try HELO
		_ = tc.PrintfLine("HELO probe.fastscan.local")
		code, ehloResp, _ = tc.ReadResponse(250)
		if code == 0 {
			rep.ProbeErrors = append(rep.ProbeErrors,
				fmt.Sprintf("read EHLO: %v", err))
			return rep, nil
		}
	}
	// Parse capabilities. First line is the greeting (e.g.
	// "metasploitable.localdomain Hello ...."). Subsequent lines are
	// caps, one per line.
	lines := strings.Split(ehloResp, "\n")
	if len(lines) > 0 {
		rep.EHLOHostname = strings.TrimSpace(strings.SplitN(lines[0], " ", 2)[0])
	}
	for _, l := range lines[1:] {
		cap := strings.TrimSpace(l)
		if cap == "" {
			continue
		}
		rep.Capabilities = append(rep.Capabilities, cap)
		upper := strings.ToUpper(cap)
		if upper == "STARTTLS" {
			rep.STARTTLSOffered = true
		}
		if strings.HasPrefix(upper, "AUTH") {
			// "AUTH PLAIN LOGIN CRAM-MD5"
			parts := strings.Fields(cap)
			if len(parts) > 1 {
				rep.AuthMethods = append(rep.AuthMethods, parts[1:]...)
			}
		}
	}

	// User enumeration via VRFY: probe a short built-in list of common
	// accounts. Only a definitive 250 ("address is valid") is recorded, so
	// servers that answer 252 ("cannot verify, will accept") for everything
	// do not produce false positives. This is the deep-content evidence for
	// SMTP, matching nmap smtp-enum-users.
	rep.VRFYUsers = smtpEnumUsers(tc)

	// Open-relay quick check.
	// We try sender from one invalid external domain, recipient on
	// another invalid external domain. A 250 to the RCPT TO indicates
	// the server is willing to relay for us; any 5xx means it isn't.
	if err := tc.PrintfLine("MAIL FROM:<probe@external.invalid>"); err == nil {
		mailCode, _, _ := tc.ReadResponse(0)
		if mailCode == 250 {
			if err := tc.PrintfLine("RCPT TO:<recipient@another.invalid>"); err == nil {
				rcptCode, _, _ := tc.ReadResponse(0)
				if rcptCode == 250 {
					rep.OpenRelay = true
				}
			}
			_ = tc.PrintfLine("RSET")
			_, _, _ = tc.ReadResponse(0)
		}
	}
	_ = tc.PrintfLine("QUIT")
	_, _, _ = tc.ReadResponse(0)
	return rep, nil
}

// smtpEnumUsers issues VRFY for a short list of common accounts and returns
// those the server confirms with a 250 reply. Bounded and best-effort: many
// servers disable VRFY or answer 252 for all, in which case this is empty.
func smtpEnumUsers(tc *textproto.Conn) []string {
	candidates := []string{
		"root", "admin", "administrator", "postmaster", "webmaster",
		"user", "test", "mail", "www-data", "ftp",
	}
	var found []string
	for _, u := range candidates {
		if err := tc.PrintfLine("VRFY %s", u); err != nil {
			break
		}
		code, msg, _ := tc.ReadResponse(0)
		if code == 250 {
			entry := u
			if m := strings.TrimSpace(msg); m != "" {
				entry = u + " (" + m + ")"
			}
			found = append(found, entry)
		}
	}
	return found
}
