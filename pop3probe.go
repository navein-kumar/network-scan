// pop3probe.go: phase 3 driver for POP3 (110).
//
// Stdlib net. Read +OK greeting, CAPA, parse STLS / SASL.
package main

import (
	"bufio"
	"fmt"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// POP3Report is what Phase 3 emits per POP3 port.
type POP3Report struct {
	Host           string   `json:"host"`
	Port           int      `json:"port"`
	Banner         string   `json:"banner,omitempty"`
	Product        string   `json:"product,omitempty"`
	ProductVersion string   `json:"product_version,omitempty"`
	Capabilities   []string `json:"capabilities,omitempty"`
	STLSOffered    bool     `json:"stls_offered"`
	SASLMechanisms []string `json:"sasl_mechanisms,omitempty"`
	MessageCount   int      `json:"message_count,omitempty"`
	Messages       []string `json:"messages,omitempty"`
	ProbeErrors    []string `json:"probe_errors,omitempty"`
}

// ProbePOP3 connects, reads greeting, runs CAPA.
func ProbePOP3(host string, port int, timeout time.Duration) (*POP3Report, error) {
	rep := &POP3Report{Host: host, Port: port}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	br := bufio.NewReader(conn)

	greeting, err := br.ReadString('\n')
	if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("read greeting: %v", err))
		return rep, nil
	}
	rep.Banner = strings.TrimRight(greeting, "\r\n")
	rep.Product, rep.ProductVersion = parseProductVersion(rep.Banner)
	if !strings.HasPrefix(rep.Banner, "+OK") {
		// Not a POP3 server (or it returned -ERR right off).
		return rep, nil
	}

	if _, err := conn.Write([]byte("CAPA\r\n")); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("write CAPA: %v", err))
		_ = quitPOP3(conn)
		return rep, nil
	}
	// First line: +OK ... or -ERR
	first, err := br.ReadString('\n')
	if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("read CAPA: %v", err))
		return rep, nil
	}
	first = strings.TrimRight(first, "\r\n")
	if !strings.HasPrefix(first, "+OK") {
		_ = quitPOP3(conn)
		return rep, nil
	}
	// Multi-line until "." on its own line.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "." {
			break
		}
		if line == "" {
			continue
		}
		rep.Capabilities = append(rep.Capabilities, line)
		upper := strings.ToUpper(line)
		if upper == "STLS" {
			rep.STLSOffered = true
		}
		if strings.HasPrefix(upper, "SASL ") {
			rep.SASLMechanisms = append(rep.SASLMechanisms,
				strings.Fields(line)[1:]...)
		}
	}
	// Best-effort default credential probe. Default creds are uncommon for
	// real mail servers, but lab and misconfigured hosts sometimes accept
	// anonymous/test/admin pairs; capture mailbox stats if one works.
	capturePOP3Messages(conn, br, rep, timeout)

	_ = quitPOP3(conn)
	return rep, nil
}

// capturePOP3Messages tries a tiny default credential set via USER/PASS and,
// on the first +OK, records STAT count and up to 20 LIST entries. It shares
// the existing bufio.Reader via a textproto.Reader.
func capturePOP3Messages(conn net.Conn, br *bufio.Reader, rep *POP3Report, timeout time.Duration) {
	defer func() { _ = recover() }()

	creds := [][2]string{
		{"anonymous", "anonymous"},
		{"test", "test"},
		{"admin", "admin"},
	}

	tr := textproto.NewReader(br)

	for _, c := range creds {
		conn.SetDeadline(time.Now().Add(timeout))
		if _, err := conn.Write([]byte("USER " + c[0] + "\r\n")); err != nil {
			return
		}
		if ok, err := readPOP3Status(tr); err != nil {
			return
		} else if !ok {
			continue
		}
		if _, err := conn.Write([]byte("PASS " + c[1] + "\r\n")); err != nil {
			return
		}
		ok, err := readPOP3Status(tr)
		if err != nil {
			return
		}
		if !ok {
			continue // bad password; try next pair
		}

		// Authenticated: STAT then LIST.
		if _, err := conn.Write([]byte("STAT\r\n")); err != nil {
			return
		}
		statLine, err := tr.ReadLine()
		if err != nil {
			return
		}
		if strings.HasPrefix(statLine, "+OK") {
			if f := strings.Fields(statLine); len(f) >= 2 {
				if n, e := strconv.Atoi(f[1]); e == nil {
					rep.MessageCount = n
				}
			}
		}

		if _, err := conn.Write([]byte("LIST\r\n")); err != nil {
			return
		}
		first, err := tr.ReadLine()
		if err != nil {
			return
		}
		if !strings.HasPrefix(first, "+OK") {
			return
		}
		for {
			line, err := tr.ReadLine()
			if err != nil {
				return
			}
			if line == "." {
				break
			}
			if line == "" {
				continue
			}
			if len(rep.Messages) < 20 {
				rep.Messages = append(rep.Messages, line)
			}
		}
		return
	}
}

// readPOP3Status reads one response line and reports whether it begins +OK.
func readPOP3Status(tr *textproto.Reader) (bool, error) {
	line, err := tr.ReadLine()
	if err != nil {
		return false, err
	}
	return strings.HasPrefix(line, "+OK"), nil
}

func quitPOP3(conn net.Conn) error {
	_, err := conn.Write([]byte("QUIT\r\n"))
	return err
}
