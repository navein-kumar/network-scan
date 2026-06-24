// weblogicprobe.go: phase 3 driver for WebLogic T3 (7001 cleartext, 7002 TLS).
//
// Hand-rolled T3 handshake: send a "t3 <ver>\nAS:255\nHL:19\nMS:10000000\n\n"
// blob and parse the "HELO:<version>" reply line. WebLogic identifies its
// build number in the HELO response.
package main

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

type WebLogicReport struct {
	Host                 string   `json:"host"`
	Port                 int      `json:"port"`
	Reachable            bool     `json:"reachable"`
	T3VersionAdvertised  string   `json:"t3_version_advertised,omitempty"`
	WebLogicVersion      string   `json:"weblogic_version,omitempty"`
	RawHELO              string   `json:"raw_helo,omitempty"`
	ProbeErrors          []string `json:"probe_errors,omitempty"`
}

var weblogicHeloRE = regexp.MustCompile(`HELO:([\d.]+)`)

func ProbeWebLogic(host string, port int, timeout time.Duration) (*WebLogicReport, error) {
	rep := &WebLogicReport{Host: host, Port: port}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	handshake := "t3 12.2.1\nAS:255\nHL:19\nMS:10000000\n\n"
	if _, err := conn.Write([]byte(handshake)); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("write: %v", err))
		return rep, nil
	}
	rdr := bufio.NewReader(conn)
	// Read up to 8 lines or any blank.
	for i := 0; i < 8; i++ {
		line, err := rdr.ReadString('\n')
		if err != nil && line == "" {
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if strings.HasPrefix(line, "HELO:") {
			rep.Reachable = true
			rep.RawHELO = line
			if m := weblogicHeloRE.FindStringSubmatch(line); len(m) > 1 {
				rep.WebLogicVersion = m[1]
			}
			rest := strings.TrimPrefix(line, "HELO:")
			rep.T3VersionAdvertised = strings.TrimSpace(rest)
		}
	}
	if !rep.Reachable && len(rep.ProbeErrors) == 0 {
		rep.ProbeErrors = append(rep.ProbeErrors, "no HELO reply")
	}
	return rep, nil
}
