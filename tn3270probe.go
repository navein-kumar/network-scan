// tn3270probe.go: phase 3 driver for TN3270 / TN3270E (telnet for IBM
// mainframes, default port 23 or 2323).
//
// We open the connection, read the telnet option-negotiation burst (IAC
// commands), and look for TN3270E (option 40), TERMINAL-TYPE (24), and
// NEW-ENVIRON (39). If TN3270E is offered we mark the listener as a
// likely mainframe / TN3270 endpoint. We do NOT continue to the
// SSCP-LU bind phase; that's manual.
package main

import (
	"bytes"
	"fmt"
	"net"
	"time"
)

type TN3270Report struct {
	Host                string   `json:"host"`
	Port                int      `json:"port"`
	Reachable           bool     `json:"reachable"`
	TN3270EOffered      bool     `json:"tn3270e_offered"`
	TerminalTypeOffered bool     `json:"terminal_type_offered"`
	LUName              string   `json:"lu_name,omitempty"`
	ProbeErrors         []string `json:"probe_errors,omitempty"`
}

const (
	telIAC       = 0xff
	telDO        = 0xfd
	telDONT      = 0xfe
	telWILL      = 0xfb
	telWONT      = 0xfc
	telSB        = 0xfa
	telSE        = 0xf0
	telOptTType  = 0x18
	telOptNewEnv = 0x27
	telOptTN3270 = 0x28
)

func ProbeTN3270(host string, port int, timeout time.Duration) (*TN3270Report, error) {
	rep := &TN3270Report{Host: host, Port: port}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Many TN3270E servers wait for the client to start. Send the
	// minimal "I'll do TN3270E" handshake to coax options out.
	conn.Write([]byte{telIAC, telWILL, telOptTN3270, telIAC, telWILL, telOptTType})

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("read: %v", err))
		return rep, nil
	}
	rep.Reachable = true
	scan := buf[:n]
	for i := 0; i+2 < len(scan); i++ {
		if scan[i] != telIAC {
			continue
		}
		cmd := scan[i+1]
		opt := scan[i+2]
		// DO / WILL / WONT / DONT all sit on the option byte
		if cmd == telDO || cmd == telWILL || cmd == telWONT || cmd == telDONT {
			switch opt {
			case telOptTN3270:
				rep.TN3270EOffered = true
			case telOptTType:
				rep.TerminalTypeOffered = true
			}
		}
	}
	// Look for a TN3270E SB block with a CONNECT or DEVICE-TYPE-IS
	// device name embedded after IAC SB 0x28 ... IAC SE
	if rep.TN3270EOffered {
		if lu := extractLU(scan); lu != "" {
			rep.LUName = lu
		}
	}
	return rep, nil
}

func extractLU(b []byte) string {
	sbMarker := []byte{telIAC, telSB, telOptTN3270}
	start := bytes.Index(b, sbMarker)
	if start < 0 {
		return ""
	}
	end := bytes.Index(b[start:], []byte{telIAC, telSE})
	if end < 0 {
		return ""
	}
	body := b[start+len(sbMarker) : start+end]
	// Strip the TN3270E sub-command bytes (op, subop) and any binary
	// fillers; keep printable ASCII >= 2 chars.
	var out bytes.Buffer
	for _, c := range body {
		if c >= 0x20 && c < 0x7f {
			out.WriteByte(c)
		} else if out.Len() >= 2 {
			break
		} else {
			out.Reset()
		}
	}
	return out.String()
}
