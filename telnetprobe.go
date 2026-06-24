// telnetprobe.go: phase 3 driver for Telnet (23).
//
// Read first chunk after connect. Parse IAC sequences per RFC 854:
//   0xFF (IAC) + (WILL/WONT/DO/DONT) + option-byte
//   0xFF + SB + option + ... + IAC + SE  (subnegotiation, skipped)
// Anything after / between IAC sequences is the login banner.
package main

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// TelnetReport is what Phase 3 emits per Telnet port.
type TelnetReport struct {
	Host                  string   `json:"host"`
	Port                  int      `json:"port"`
	OptionsNegotiated     []string `json:"options_negotiated,omitempty"`
	Banner                string   `json:"banner,omitempty"`
	AuthenticationOffered bool     `json:"authentication_offered"`
	EncryptOffered        bool     `json:"encrypt_offered"`
	ProbeErrors           []string `json:"probe_errors,omitempty"`
}

// telnetOptionName maps RFC 854/855/2941/2946 option numbers to names.
var telnetOptionName = map[byte]string{
	0:  "BINARY",
	1:  "ECHO",
	3:  "SGA",
	5:  "STATUS",
	6:  "TIMING_MARK",
	24: "TERMINAL_TYPE",
	31: "NAWS",
	32: "TERMINAL_SPEED",
	33: "REMOTE_FLOW_CONTROL",
	34: "LINEMODE",
	35: "X_DISPLAY_LOCATION",
	36: "ENVIRON",
	37: "AUTHENTICATION",
	38: "ENCRYPT",
	39: "NEW_ENVIRON",
}

const (
	telnetIAC  = 0xFF
	telnetWILL = 0xFB
	telnetWONT = 0xFC
	telnetDO   = 0xFD
	telnetDONT = 0xFE
	telnetSB   = 0xFA
	telnetSE   = 0xF0
)

// ProbeTelnet connects, reads up to 1024 bytes, and parses out the
// negotiated options and login banner.
func ProbeTelnet(host string, port int, timeout time.Duration) (*TelnetReport, error) {
	rep := &TelnetReport{Host: host, Port: port}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("read: %v", err))
		return rep, nil
	}
	chunk := buf[:n]
	parseTelnetChunk(chunk, rep)

	// Reply WONT/DONT to every WILL/DO and keep reading. Some servers
	// (e.g. Metasploitable2) only print their login banner after several
	// negotiation rounds settle, so loop a few times until the prompt text
	// arrives or the server goes quiet. Bounded so a chatty server can't
	// stall the probe.
	for round := 0; round < 5; round++ {
		resp := buildTelnetNoNegotiate(chunk)
		if len(resp) > 0 {
			conn.SetDeadline(time.Now().Add(timeout))
			if _, werr := conn.Write(resp); werr != nil {
				break
			}
		}
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		nr, rerr := conn.Read(buf)
		if nr > 0 {
			chunk = buf[:nr]
			parseTelnetChunk(chunk, rep)
		} else {
			chunk = nil
		}
		// Stop once we have a usable banner with a login prompt, or the
		// server has nothing left to send.
		if telnetHasPrompt(rep.Banner) || (nr == 0 && len(resp) == 0) || rerr != nil {
			break
		}
	}
	rep.Banner = strings.TrimSpace(rep.Banner)
	return rep, nil
}

// telnetHasPrompt reports whether the accumulated banner already contains a
// login/password prompt, signalling the negotiation has settled and there is
// no need to keep reading.
func telnetHasPrompt(banner string) bool {
	l := strings.ToLower(banner)
	return strings.Contains(l, "login:") || strings.Contains(l, "username:") ||
		strings.Contains(l, "password:")
}

// parseTelnetChunk walks one byte sequence, separating IAC negotiation
// from printable banner text. Existing rep.Banner is appended to.
func parseTelnetChunk(chunk []byte, rep *TelnetReport) {
	var text strings.Builder
	for i := 0; i < len(chunk); {
		if chunk[i] != telnetIAC {
			b := chunk[i]
			if b >= 0x20 && b < 0x7F || b == '\r' || b == '\n' || b == '\t' {
				text.WriteByte(b)
			}
			i++
			continue
		}
		// IAC ...
		if i+1 >= len(chunk) {
			break
		}
		cmd := chunk[i+1]
		switch cmd {
		case telnetWILL, telnetWONT, telnetDO, telnetDONT:
			if i+2 >= len(chunk) {
				return
			}
			opt := chunk[i+2]
			name := telnetOptionName[opt]
			if name == "" {
				name = fmt.Sprintf("OPT_0x%02X", opt)
			}
			if !contains(rep.OptionsNegotiated, name) {
				rep.OptionsNegotiated = append(rep.OptionsNegotiated, name)
			}
			if opt == 37 {
				rep.AuthenticationOffered = true
			}
			if opt == 38 {
				rep.EncryptOffered = true
			}
			i += 3
		case telnetSB:
			// skip until IAC SE
			j := i + 2
			for j+1 < len(chunk) && !(chunk[j] == telnetIAC && chunk[j+1] == telnetSE) {
				j++
			}
			i = j + 2
		default:
			// 2-byte IAC command (NOP, BRK, etc.) or IAC IAC.
			i += 2
		}
	}
	if rep.Banner != "" && text.Len() > 0 {
		rep.Banner += "\n"
	}
	rep.Banner += text.String()
}

// buildTelnetNoNegotiate builds a polite "no" reply to every WILL/DO
// in the chunk so the server stops waiting on negotiation.
func buildTelnetNoNegotiate(chunk []byte) []byte {
	var out []byte
	for i := 0; i+2 < len(chunk); i++ {
		if chunk[i] != telnetIAC {
			continue
		}
		cmd := chunk[i+1]
		opt := chunk[i+2]
		switch cmd {
		case telnetWILL:
			out = append(out, telnetIAC, telnetDONT, opt)
		case telnetDO:
			out = append(out, telnetIAC, telnetWONT, opt)
		}
		i += 2
	}
	return out
}
