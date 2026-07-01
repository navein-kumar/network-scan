// redisprobe.go: phase 3 driver for Redis (6379).
//
// Hand-rolled RESP. Steps:
//   1. PING. +PONG = no-auth open. -NOAUTH / -ERR AUTH = auth required.
//   2. If no-auth: INFO server → version, role. CONFIG GET dir → data dir.
package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// RedisReport is what Phase 3 emits per Redis target.
type RedisReport struct {
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	Reachable    bool     `json:"reachable"`
	AuthRequired bool     `json:"auth_required"`
	Version      string   `json:"version,omitempty"`
	Role         string   `json:"role,omitempty"`
	DataDir      string        `json:"data_dir,omitempty"`
	KeyCount     int           `json:"key_count,omitempty"`
	Keys         []string      `json:"keys,omitempty"`
	CredAttempts []CredAttempt `json:"cred_attempts,omitempty"`
	ProbeErrors  []string      `json:"probe_errors,omitempty"`
}

// ProbeRedis dials and runs PING / INFO / CONFIG GET.
func ProbeRedis(host string, port int, timeout time.Duration) (*RedisReport, error) {
	rep := &RedisReport{Host: host, Port: port}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	br := bufio.NewReader(conn)

	// PING
	if _, err := conn.Write([]byte("*1\r\n$4\r\nPING\r\n")); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("write PING: %v", err))
		return rep, nil
	}
	pingResp, err := readRESP(br)
	if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("read PING: %v", err))
		return rep, nil
	}
	rep.Reachable = true
	upper := strings.ToUpper(pingResp)
	if strings.HasPrefix(upper, "-NOAUTH") ||
		strings.Contains(upper, "AUTHENTICATION REQUIRED") ||
		strings.Contains(upper, "CLIENT SENT AUTH") {
		rep.AuthRequired = true
		return rep, nil
	}
	if !strings.HasPrefix(pingResp, "+PONG") {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("unexpected PING reply: %q", pingResp))
		return rep, nil
	}

	// INFO server
	if _, err := conn.Write([]byte("*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n")); err == nil {
		if info, ierr := readRESP(br); ierr == nil {
			rep.Version = parseInfoField(info, "redis_version")
			rep.Role = parseInfoField(info, "role")
		}
	}
	// If role still empty, try plain INFO (covers older servers that
	// don't accept the section arg).
	if rep.Role == "" {
		if _, err := conn.Write([]byte("*2\r\n$4\r\nINFO\r\n$11\r\nreplication\r\n")); err == nil {
			if info, ierr := readRESP(br); ierr == nil {
				rep.Role = parseInfoField(info, "role")
			}
		}
	}

	// CONFIG GET dir
	if _, err := conn.Write([]byte("*3\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$3\r\ndir\r\n")); err == nil {
		if cfg, cerr := readRESP(br); cerr == nil {
			// Array reply: ["dir", "<value>"]. parseInfoField won't work
			// here; pull the second bulk-string entry.
			rep.DataDir = parseConfigGetSecond(cfg)
		}
	}

	// DBSIZE: how many keys are exposed (proves accessible data, not just
	// an open port). Integer reply ":N".
	if _, err := conn.Write([]byte("*1\r\n$6\r\nDBSIZE\r\n")); err == nil {
		if sz, serr := readRESP(br); serr == nil {
			n := 0
			fmt.Sscanf(strings.TrimPrefix(strings.TrimSpace(sz), ":"), "%d", &n)
			rep.KeyCount = n
		}
	}

	// SCAN a sample of keys (bounded; safer than KEYS * on large DBs). The
	// reply is [cursor, [k1,k2,...]] which readRESP flattens; line 0 is the
	// cursor, the rest are keys.
	if _, err := conn.Write([]byte("*4\r\n$4\r\nSCAN\r\n$1\r\n0\r\n$5\r\nCOUNT\r\n$2\r\n30\r\n")); err == nil {
		if scan, serr := readRESP(br); serr == nil {
			parts := strings.Split(strings.TrimSpace(scan), "\n")
			for i, k := range parts {
				if i == 0 { // cursor
					continue
				}
				k = strings.TrimSpace(k)
				if k == "" {
					continue
				}
				rep.Keys = append(rep.Keys, k)
				if len(rep.Keys) >= 30 {
					break
				}
			}
		}
	}
	return rep, nil
}

// redisDumpWithAuth authenticates with the given password then samples the
// keyspace (DBSIZE + a bounded SCAN). Used when a default Redis password
// succeeds, so the evidence shows the exposed data, not just "auth weak".
func redisDumpWithAuth(host string, port int, pass string, timeout time.Duration) ([]string, int) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return nil, 0
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	br := bufio.NewReader(conn)

	authCmd := fmt.Sprintf("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(pass), pass)
	if _, err := conn.Write([]byte(authCmd)); err != nil {
		return nil, 0
	}
	if resp, rerr := readRESP(br); rerr != nil || !strings.HasPrefix(resp, "+OK") {
		return nil, 0
	}

	count := 0
	if _, err := conn.Write([]byte("*1\r\n$6\r\nDBSIZE\r\n")); err == nil {
		if sz, serr := readRESP(br); serr == nil {
			fmt.Sscanf(strings.TrimPrefix(strings.TrimSpace(sz), ":"), "%d", &count)
		}
	}

	var keys []string
	if _, err := conn.Write([]byte("*4\r\n$4\r\nSCAN\r\n$1\r\n0\r\n$5\r\nCOUNT\r\n$2\r\n30\r\n")); err == nil {
		if scan, serr := readRESP(br); serr == nil {
			parts := strings.Split(strings.TrimSpace(scan), "\n")
			for i, k := range parts {
				if i == 0 {
					continue
				}
				k = strings.TrimSpace(k)
				if k == "" {
					continue
				}
				keys = append(keys, k)
				if len(keys) >= 30 {
					break
				}
			}
		}
	}
	return keys, count
}

// readRESP reads exactly one RESP reply (simple string, error, integer,
// bulk string, or array) and returns it as the raw bytes (decoded into
// a UTF-8 string with framing preserved enough for line scanners).
func readRESP(br *bufio.Reader) (string, error) {
	prefix, err := br.ReadByte()
	if err != nil {
		return "", err
	}
	line, err := readRESPLine(br)
	if err != nil {
		return "", err
	}
	switch prefix {
	case '+':
		return "+" + line, nil
	case '-':
		return "-" + line, nil
	case ':':
		return ":" + line, nil
	case '$':
		var n int
		fmt.Sscanf(line, "%d", &n)
		if n < 0 {
			return "$-1", nil
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", err
		}
		// trailing CRLF
		_, _ = br.ReadByte()
		_, _ = br.ReadByte()
		return string(buf), nil
	case '*':
		var n int
		fmt.Sscanf(line, "%d", &n)
		if n < 0 {
			return "*-1", nil
		}
		var sb strings.Builder
		for i := 0; i < n; i++ {
			elem, err := readRESP(br)
			if err != nil {
				return sb.String(), err
			}
			sb.WriteString(elem)
			sb.WriteString("\n")
		}
		return sb.String(), nil
	}
	return string(prefix) + line, nil
}

func readRESPLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// parseInfoField finds "field:value" inside an INFO bulk-string reply.
func parseInfoField(blob, field string) string {
	for _, l := range strings.Split(blob, "\n") {
		l = strings.TrimRight(l, "\r")
		if strings.HasPrefix(l, field+":") {
			return strings.TrimSpace(l[len(field)+1:])
		}
	}
	return ""
}

// parseConfigGetSecond extracts the second element of a CONFIG GET reply.
// readRESP currently flattens arrays into newline-separated entries.
func parseConfigGetSecond(blob string) string {
	parts := strings.Split(strings.TrimRight(blob, "\n"), "\n")
	if len(parts) < 2 {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
