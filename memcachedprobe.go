// memcachedprobe.go: phase 3 driver for memcached (11211).
//
// Stdlib net. Send "stats\r\n" and parse the "STAT key value\r\n" lines
// until END. The memcached TCP protocol has no auth, so version is the
// headline finding.
package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

// MemcachedReport is what Phase 3 emits per memcached target.
type MemcachedReport struct {
	Host        string            `json:"host"`
	Port        int               `json:"port"`
	Reachable   bool              `json:"reachable"`
	Version     string            `json:"version,omitempty"`
	Stats       map[string]string `json:"stats,omitempty"`
	ProbeErrors []string          `json:"probe_errors,omitempty"`
}

// statsKeysOfInterest is the subset of "stats" output we keep. Memcached
// emits 40+ lines; we don't want them all in the report.
var statsKeysOfInterest = map[string]bool{
	"version":            true,
	"pid":                true,
	"time":               true,
	"uptime":             true,
	"curr_connections":   true,
	"total_connections":  true,
	"bytes":              true,
	"evictions":          true,
	"curr_items":         true,
}

// ProbeMemcached connects, sends "stats", and parses STAT lines.
func ProbeMemcached(host string, port int, timeout time.Duration) (*MemcachedReport, error) {
	rep := &MemcachedReport{Host: host, Port: port, Stats: map[string]string{}}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write([]byte("stats\r\n")); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("write stats: %v", err))
		return rep, nil
	}
	br := bufio.NewReader(conn)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "END" || line == "ERROR" {
			break
		}
		if !strings.HasPrefix(line, "STAT ") {
			continue
		}
		parts := strings.SplitN(line[5:], " ", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := parts[0], parts[1]
		if statsKeysOfInterest[key] {
			rep.Stats[key] = val
		}
		if key == "version" {
			rep.Version = val
		}
	}
	if rep.Version != "" || len(rep.Stats) > 0 {
		rep.Reachable = true
	}
	return rep, nil
}
