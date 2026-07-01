// rsyncprobe.go: phase 3 driver for the rsync daemon protocol (873).
//
// The rsync daemon speaks a tiny line protocol before any module is
// selected: on connect it prints "@RSYNCD: <version>\n"; the client echoes
// "@RSYNCD: <version>\n" then sends a bare newline to request the module
// list. The server replies with one "name<tab>comment" line per module,
// then "@RSYNCD: EXIT". Best-effort, never panics.
package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

// RsyncReport is what Phase 3 emits per rsync daemon port.
type RsyncReport struct {
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	Reachable   bool     `json:"reachable"`
	Version     string   `json:"version,omitempty"`
	Modules     []string `json:"modules,omitempty"`
	ProbeErrors []string `json:"probe_errors,omitempty"`
}

// ProbeRsync connects, completes the @RSYNCD handshake, and lists the
// daemon module (share) names.
func ProbeRsync(host string, port int, timeout time.Duration) (*RsyncReport, error) {
	rep := &RsyncReport{Host: host, Port: port}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	r := bufio.NewReader(conn)

	// Greeting: "@RSYNCD: <version>".
	greeting, err := r.ReadString('\n')
	if err != nil && greeting == "" {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("read greeting: %v", err))
		return rep, nil
	}
	greeting = strings.TrimRight(greeting, "\r\n")
	if !strings.HasPrefix(greeting, "@RSYNCD:") {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("unexpected greeting: %q", greeting))
		return rep, nil
	}
	rep.Reachable = true
	rep.Version = strings.TrimSpace(strings.TrimPrefix(greeting, "@RSYNCD:"))

	// Echo the protocol version back, then ask for the module list with a
	// bare newline. Echo exactly what the server announced so version
	// negotiation lines up.
	if _, werr := conn.Write([]byte(greeting + "\n")); werr != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("write version: %v", werr))
		return rep, nil
	}
	if _, werr := conn.Write([]byte("\n")); werr != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("write list request: %v", werr))
		return rep, nil
	}

	// Read module lines until EXIT or close. Each module is
	// "name<tab>comment"; lines starting with "@" are protocol control.
	for len(rep.Modules) < 50 {
		conn.SetDeadline(time.Now().Add(timeout))
		line, rerr := r.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if line != "" {
			if strings.HasPrefix(line, "@") {
				if strings.HasPrefix(line, "@RSYNCD: EXIT") {
					break
				}
				// @ERROR or other control: record once, keep going.
				rep.ProbeErrors = append(rep.ProbeErrors, line)
			} else {
				name := line
				if tab := strings.IndexAny(line, "\t"); tab >= 0 {
					name = strings.TrimSpace(line[:tab])
				}
				name = strings.TrimSpace(name)
				if name != "" {
					rep.Modules = append(rep.Modules, name)
				}
			}
		}
		if rerr != nil {
			break
		}
	}
	return rep, nil
}
