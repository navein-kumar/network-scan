// ajpprobe.go: phase 3 driver for AJP13 (Tomcat 8009).
//
// Hand-rolled per the AJP13 protocol spec. Two probes:
//   1. CPing (0x0A) → CPong (0x09): confirms the server is speaking AJP13.
//   2. A minimal Forward-Request for GET / : exercises the request path; a
//      response of any kind (Send-Body-Chunk / End-Response / Send-Headers)
//      is the Ghostcat probe surface marker. We do NOT attempt the actual
//      CVE-2020-1938 attribute-slot exploitation; that's left for manual
//      verification.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// AJPReport is what Phase 3 emits per AJP target.
type AJPReport struct {
	Host                string   `json:"host"`
	Port                int      `json:"port"`
	AJP13Responding     bool     `json:"ajp13_responding"`
	GhostcatProbeStatus string   `json:"ghostcat_probe_status,omitempty"`
	ProbeErrors         []string `json:"probe_errors,omitempty"`
}

const (
	ajpMagicFromContainer = 0x4142 // "AB" container → web server
	ajpMagicFromWebServer = 0x1234 // web server → container
	ajpCPing              = 0x0A
	ajpCPong              = 0x09
	ajpForwardRequest     = 0x02
)

// ProbeAJP runs the two probes and decodes the results.
func ProbeAJP(host string, port int, timeout time.Duration) (*AJPReport, error) {
	rep := &AJPReport{Host: host, Port: port}

	// ── Probe 1: CPing ────────────────────────────────────────────────
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// CPing packet: magic(2) + length(2) + 0x0A
	ping := []byte{0x12, 0x34, 0x00, 0x01, ajpCPing}
	if _, err := conn.Write(ping); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("cping write: %v", err))
		return rep, nil
	}
	resp := make([]byte, 16)
	n, err := conn.Read(resp)
	if err != nil || n < 5 {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("cping read: %v", err))
		return rep, nil
	}
	// AB magic + length + 0x09 CPong
	if resp[0] == 0x41 && resp[1] == 0x42 && resp[4] == ajpCPong {
		rep.AJP13Responding = true
	}

	// ── Probe 2: Forward-Request (Ghostcat surface) ───────────────────
	// Reconnect for a fresh state (AJP13 connections are usually closed
	// by the container after CPong on some implementations).
	conn2, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("dial2: %v", err))
		return rep, nil
	}
	defer conn2.Close()
	conn2.SetDeadline(time.Now().Add(timeout))

	fr := buildAJPForwardRequest()
	if _, err := conn2.Write(fr); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("forward-request write: %v", err))
		rep.GhostcatProbeStatus = "error"
		return rep, nil
	}
	resp2 := make([]byte, 1024)
	n2, err := conn2.Read(resp2)
	switch {
	case err != nil || n2 < 4:
		rep.GhostcatProbeStatus = "no_response"
	case resp2[0] == 0x41 && resp2[1] == 0x42:
		rep.GhostcatProbeStatus = "got_response"
		// If CPing was filtered but the FR worked we still know AJP13 is up.
		rep.AJP13Responding = true
	default:
		rep.GhostcatProbeStatus = "no_response"
	}
	return rep, nil
}

// buildAJPForwardRequest builds a minimal AJP13 Forward-Request for
// GET http://localhost/ . Enough to elicit a response from a Tomcat
// AJP13 listener.
func buildAJPForwardRequest() []byte {
	var p bytes.Buffer
	// Inside payload first; we'll wrap with magic+length after.
	var body bytes.Buffer
	body.WriteByte(ajpForwardRequest) // prefix code
	body.WriteByte(2)                 // method: GET
	writeAJPString(&body, "HTTP/1.1") // protocol
	writeAJPString(&body, "/")        // req_uri
	writeAJPString(&body, "127.0.0.1") // remote_addr
	writeAJPString(&body, "")          // remote_host
	writeAJPString(&body, "localhost") // server_name
	binary.Write(&body, binary.BigEndian, uint16(80)) // server_port
	body.WriteByte(0) // is_ssl
	// num_headers (2 bytes)
	binary.Write(&body, binary.BigEndian, uint16(1))
	// header: Host: localhost
	// "Host" can be encoded as the well-known code 0xA00B (SC_REQ_HOST).
	binary.Write(&body, binary.BigEndian, uint16(0xA00B))
	writeAJPString(&body, "localhost")
	// no request attributes, just terminator
	body.WriteByte(0xFF)

	// Wrap: magic 0x1234 + length(2) + body
	binary.Write(&p, binary.BigEndian, uint16(ajpMagicFromWebServer))
	binary.Write(&p, binary.BigEndian, uint16(body.Len()))
	p.Write(body.Bytes())
	return p.Bytes()
}

// writeAJPString writes an AJP-encoded string: length(2 BE) + bytes + 0x00.
// Empty string is length 0xFFFF.
func writeAJPString(b *bytes.Buffer, s string) {
	if s == "" {
		binary.Write(b, binary.BigEndian, uint16(0xFFFF))
		return
	}
	binary.Write(b, binary.BigEndian, uint16(len(s)))
	b.WriteString(s)
	b.WriteByte(0x00)
}
