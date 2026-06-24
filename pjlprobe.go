// pjlprobe.go: phase 3 driver for HP PJL (Printer Job Language) on 9100.
//
// Send PJL INFO ID and INFO STATUS framed by UEL (Universal Exit Language).
// Reply is line-oriented text with model + firmware revision.
package main

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"
)

type PJLReport struct {
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	Reachable   bool     `json:"reachable"`
	ModelID     string   `json:"model_id,omitempty"`
	Status      string   `json:"status,omitempty"`
	Firmware    string   `json:"firmware,omitempty"`
	RawReply    string   `json:"raw_reply,omitempty"`
	ProbeErrors []string `json:"probe_errors,omitempty"`
}

func ProbePJL(host string, port int, timeout time.Duration) (*PJLReport, error) {
	rep := &PJLReport{Host: host, Port: port}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	probe := "\x1B%-12345X@PJL INFO ID\r\n@PJL INFO STATUS\r\n@PJL INFO CONFIG\r\n@PJL EOJ\r\n\x1B%-12345X"
	if _, err := conn.Write([]byte(probe)); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("write: %v", err))
		return rep, nil
	}
	var buf bytes.Buffer
	tmp := make([]byte, 4096)
	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
			if buf.Len() > 1<<16 {
				break
			}
		}
		if err != nil {
			break
		}
	}
	if buf.Len() == 0 {
		rep.ProbeErrors = append(rep.ProbeErrors, "no reply")
		return rep, nil
	}
	rep.Reachable = true
	raw := buf.String()
	if len(raw) > 4096 {
		rep.RawReply = raw[:4096]
	} else {
		rep.RawReply = raw
	}
	rep.ModelID = pjlExtract(raw, "@PJL INFO ID")
	rep.Status = pjlExtract(raw, "@PJL INFO STATUS")
	rep.Firmware = pjlExtractField(raw, "FIRMWARE")
	if rep.Firmware == "" {
		rep.Firmware = pjlExtractField(raw, "VERSION")
	}
	return rep, nil
}

// pjlExtract returns the first non-empty line that follows the marker.
func pjlExtract(raw, marker string) string {
	idx := strings.Index(raw, marker)
	if idx < 0 {
		return ""
	}
	tail := raw[idx+len(marker):]
	lines := strings.Split(tail, "\n")
	for _, l := range lines[1:] {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "@PJL") || strings.HasPrefix(l, "\x1B") {
			if l != "" {
				return ""
			}
			continue
		}
		return strings.Trim(l, `"`)
	}
	return ""
}

// pjlExtractField looks for "FIELD = VALUE" anywhere in the reply.
func pjlExtractField(raw, field string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(line), field+"=") || strings.HasPrefix(strings.ToUpper(line), field+" =") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(strings.Trim(parts[1], `"`))
			}
		}
	}
	return ""
}
