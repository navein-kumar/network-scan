// fingerprobe.go: phase 3 driver for the finger protocol (79, RFC 1288).
//
// The finger protocol is a single request/response: the client sends a
// query line terminated by CRLF, the server returns free-form text and
// closes. An empty query ("\r\n") asks for the list of logged-in users;
// a "{user}\r\n" query asks for one account. Best-effort, never panics.
package main

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// FingerReport is what Phase 3 emits per finger port.
type FingerReport struct {
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	Reachable   bool     `json:"reachable"`
	Users       []string `json:"users,omitempty"`
	ProbeErrors []string `json:"probe_errors,omitempty"`
}

// ProbeFinger connects, queries the user list, and records the
// informative response lines (likely user / account rows).
func ProbeFinger(host string, port int, timeout time.Duration) (*FingerReport, error) {
	rep := &FingerReport{Host: host, Port: port}

	// First try an empty query (list all users). If that yields nothing,
	// retry with "root" which many fingerd implementations will answer.
	for _, query := range []string{"\r\n", "root\r\n"} {
		body, ok := fingerQuery(host, port, query, timeout, rep)
		if ok {
			rep.Reachable = true
		}
		fingerCollectUsers(body, rep)
		if len(rep.Users) > 0 {
			break
		}
	}
	return rep, nil
}

// fingerQuery opens a fresh connection, sends one query, and reads the
// response (capped at 4 KB). Returns the body and whether the connection
// succeeded.
func fingerQuery(host string, port int, query string, timeout time.Duration, rep *FingerReport) (string, bool) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("dial: %v", err))
		return "", false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	if _, werr := conn.Write([]byte(query)); werr != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("write: %v", werr))
		return "", true
	}

	var sb strings.Builder
	buf := make([]byte, 1024)
	for sb.Len() < 4096 {
		conn.SetDeadline(time.Now().Add(timeout))
		n, rerr := conn.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if rerr != nil {
			break
		}
	}
	return sb.String(), true
}

// fingerCollectUsers splits the response into lines and records the
// informative ones, skipping obvious headers and blanks (cap 30).
func fingerCollectUsers(body string, rep *FingerReport) {
	for _, raw := range strings.Split(body, "\n") {
		if len(rep.Users) >= 30 {
			break
		}
		line := strings.TrimRight(raw, "\r")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if fingerIsHeader(line) {
			continue
		}
		if !contains(rep.Users, line) {
			rep.Users = append(rep.Users, line)
		}
	}
}

// fingerIsHeader filters the common column-header rows so they do not
// show up as users.
func fingerIsHeader(line string) bool {
	l := strings.ToLower(line)
	switch {
	case strings.HasPrefix(l, "login") && strings.Contains(l, "name"):
		return true
	case strings.HasPrefix(l, "no one logged on"):
		return true
	case strings.HasPrefix(l, "finger:"):
		return true
	}
	return false
}
