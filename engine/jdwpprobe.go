// jdwpprobe.go: phase 3 driver for JDWP (Java Debug Wire Protocol).
//
// Hand-rolled per the JDWP spec.
//   1. Send handshake "JDWP-Handshake" (14 bytes).
//   2. Read 14-byte echo confirming JDWP.
//   3. Send VirtualMachine.Version (cmdSet=1, cmd=1), parse 11-byte header
//      reply + variable-length UTF-8 strings (description, jdwpMajor,
//      jdwpMinor, vmVersion, vmName).
//
// JDWP exposure on any port is critical (remote code execution).
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

type JDWPReport struct {
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	Reachable    bool     `json:"reachable"`
	JDWPVersion  string   `json:"jdwp_version,omitempty"`
	VMVersion    string   `json:"vm_version,omitempty"`
	VMName       string   `json:"vm_name,omitempty"`
	Description  string   `json:"description,omitempty"`
	ProbeErrors  []string `json:"probe_errors,omitempty"`
}

const jdwpHandshake = "JDWP-Handshake"

func ProbeJDWP(host string, port int, timeout time.Duration) (*JDWPReport, error) {
	rep := &JDWPReport{Host: host, Port: port}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write([]byte(jdwpHandshake)); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("handshake write: %v", err))
		return rep, nil
	}
	buf := make([]byte, len(jdwpHandshake))
	if _, err := io.ReadFull(conn, buf); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("handshake read: %v", err))
		return rep, nil
	}
	if string(buf) != jdwpHandshake {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("handshake mismatch: %q", string(buf)))
		return rep, nil
	}
	rep.Reachable = true

	// VirtualMachine.Version: 11-byte JDWP header + no data.
	// length=11, id=1, flags=0, cmdSet=1, cmd=1
	pkt := make([]byte, 11)
	binary.BigEndian.PutUint32(pkt[0:4], 11)
	binary.BigEndian.PutUint32(pkt[4:8], 1)
	pkt[8] = 0
	pkt[9] = 1
	pkt[10] = 1
	if _, err := conn.Write(pkt); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("version write: %v", err))
		return rep, nil
	}
	// Read header (11 bytes).
	hdr := make([]byte, 11)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("version hdr: %v", err))
		return rep, nil
	}
	total := binary.BigEndian.Uint32(hdr[0:4])
	if total < 11 || total > 65536 {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("bad reply length %d", total))
		return rep, nil
	}
	body := make([]byte, total-11)
	if _, err := io.ReadFull(conn, body); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("version body: %v", err))
		return rep, nil
	}
	// Reply: description (string), jdwpMajor (int), jdwpMinor (int),
	// vmVersion (string), vmName (string). JDWP strings are length(4) + UTF-8.
	off := 0
	desc, n, ok := readJDWPString(body, off)
	if ok {
		rep.Description = desc
		off += n
	}
	if off+8 <= len(body) {
		major := binary.BigEndian.Uint32(body[off : off+4])
		minor := binary.BigEndian.Uint32(body[off+4 : off+8])
		rep.JDWPVersion = fmt.Sprintf("%d.%d", major, minor)
		off += 8
	}
	if vmv, n, ok := readJDWPString(body, off); ok {
		rep.VMVersion = vmv
		off += n
	}
	if vmn, _, ok := readJDWPString(body, off); ok {
		rep.VMName = vmn
	}
	return rep, nil
}

func readJDWPString(b []byte, off int) (string, int, bool) {
	if off+4 > len(b) {
		return "", 0, false
	}
	n := int(binary.BigEndian.Uint32(b[off : off+4]))
	if n < 0 || off+4+n > len(b) {
		return "", 0, false
	}
	return string(b[off+4 : off+4+n]), 4 + n, true
}
