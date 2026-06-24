// imapprobe.go: phase 3 driver for IMAP (143).
//
// Stdlib net. Read * OK greeting, then ". CAPABILITY".
package main

import (
	"bufio"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"time"
)

// IMAPReport is what Phase 3 emits per IMAP port.
type IMAPReport struct {
	Host            string   `json:"host"`
	Port            int      `json:"port"`
	Banner          string   `json:"banner,omitempty"`
	Product         string   `json:"product,omitempty"`
	ProductVersion  string   `json:"product_version,omitempty"`
	Capabilities    []string `json:"capabilities,omitempty"`
	STARTTLSOffered bool     `json:"starttls_offered"`
	LoginDisabled   bool     `json:"login_disabled"`
	AuthMechanisms  []string `json:"auth_mechanisms,omitempty"`
	Mailboxes       []string `json:"mailboxes,omitempty"`
	ProbeErrors     []string `json:"probe_errors,omitempty"`
}

// ProbeIMAP connects, reads the greeting, then issues CAPABILITY.
func ProbeIMAP(host string, port int, timeout time.Duration) (*IMAPReport, error) {
	rep := &IMAPReport{Host: host, Port: port}

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
	if !strings.HasPrefix(rep.Banner, "* OK") {
		return rep, nil
	}

	if _, err := conn.Write([]byte(". CAPABILITY\r\n")); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("write CAPABILITY: %v", err))
		_ = quitIMAP(conn)
		return rep, nil
	}
	// Expect: "* CAPABILITY <tokens>" then ". OK ..."
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, ". ") || strings.HasPrefix(line, ".OK") {
			// tagged completion line ends our read
			break
		}
		if strings.HasPrefix(strings.ToUpper(line), "* CAPABILITY") {
			tokens := strings.Fields(line)
			// drop "*" and "CAPABILITY"
			if len(tokens) > 2 {
				caps := tokens[2:]
				rep.Capabilities = append(rep.Capabilities, caps...)
				for _, c := range caps {
					upper := strings.ToUpper(c)
					switch {
					case upper == "STARTTLS":
						rep.STARTTLSOffered = true
					case upper == "LOGINDISABLED":
						rep.LoginDisabled = true
					case strings.HasPrefix(upper, "AUTH="):
						rep.AuthMechanisms = append(rep.AuthMechanisms,
							c[len("AUTH="):])
					}
				}
			}
		}
	}
	// Best-effort default/anonymous credential probe. Default creds are
	// uncommon for real mail servers, but anonymous/test/admin pairs do
	// turn up on lab and misconfigured hosts. Skip entirely if the server
	// advertised LOGINDISABLED (plaintext login refused until STARTTLS).
	if !rep.LoginDisabled {
		captureIMAPMailboxes(conn, br, rep, timeout)
	}

	_ = quitIMAP(conn)
	return rep, nil
}

// captureIMAPMailboxes tries a tiny default credential set and, on the first
// successful LOGIN, lists mailboxes via LIST "" "*". It shares the existing
// bufio.Reader through a textproto.Reader so no buffered bytes are lost.
func captureIMAPMailboxes(conn net.Conn, br *bufio.Reader, rep *IMAPReport, timeout time.Duration) {
	defer func() { _ = recover() }()

	creds := [][2]string{
		{"anonymous", "anonymous"},
		{"test", "test"},
		{"admin", "admin"},
	}

	tr := textproto.NewReader(br)

	for _, c := range creds {
		conn.SetDeadline(time.Now().Add(timeout))
		cmd := fmt.Sprintf("a LOGIN %s %s\r\n", c[0], c[1])
		if _, err := conn.Write([]byte(cmd)); err != nil {
			return
		}
		ok, err := readIMAPTagged(tr, "a")
		if err != nil {
			return
		}
		if !ok {
			continue
		}

		// Logged in: list mailboxes.
		if _, err := conn.Write([]byte("b LIST \"\" \"*\"\r\n")); err != nil {
			return
		}
		for {
			line, err := tr.ReadLine()
			if err != nil {
				return
			}
			if strings.HasPrefix(line, "b ") {
				break // tagged completion
			}
			if mb := parseIMAPListLine(line); mb != "" && len(rep.Mailboxes) < 50 {
				rep.Mailboxes = append(rep.Mailboxes, mb)
			}
		}
		return
	}
}

// readIMAPTagged reads untagged lines until the tagged completion for tag,
// returning true when the completion is "<tag> OK".
func readIMAPTagged(tr *textproto.Reader, tag string) (bool, error) {
	prefix := tag + " "
	for {
		line, err := tr.ReadLine()
		if err != nil {
			return false, err
		}
		if strings.HasPrefix(line, prefix) {
			return strings.HasPrefix(strings.ToUpper(line), strings.ToUpper(prefix)+"OK"), nil
		}
	}
}

// parseIMAPListLine extracts the mailbox name from an untagged LIST reply of
// the form: * LIST (\flags) "/" "INBOX"  or  * LIST (\flags) "/" INBOX
// (the trailing mailbox name may be quoted or a bare atom).
func parseIMAPListLine(line string) string {
	if !strings.HasPrefix(strings.ToUpper(line), "* LIST") {
		return ""
	}
	line = strings.TrimRight(line, " \t")
	// Quoted name: the mailbox is the final "..." segment of the line.
	if strings.HasSuffix(line, "\"") {
		if j := strings.LastIndex(line[:len(line)-1], "\""); j >= 0 {
			return line[j+1 : len(line)-1]
		}
	}
	// Bare atom: the mailbox is the last whitespace-delimited token.
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

func quitIMAP(conn net.Conn) error {
	_, err := conn.Write([]byte(". LOGOUT\r\n"))
	return err
}
