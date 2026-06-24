// ntpprobe.go: phase 3 driver for NTP (UDP 123).
//
// Two probes:
//  1. SNTPv4 client packet → server reply: version, stratum, reference ID.
//  2. NTPv2 mode 7 REQ_MON_GETLIST_1 ("monlist") → if the server replies
//     with a populated mode-7 response, monlist is enabled (CVE-2013-5211
//     amplification surface).
//
// Pure stdlib; no third-party NTP library.
package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// NTPReport is what Phase 3 emits per NTP target.
type NTPReport struct {
	Host              string   `json:"host"`
	Port              int      `json:"port"`
	Reachable         bool     `json:"reachable"`
	Version           int      `json:"version,omitempty"`
	Stratum           int      `json:"stratum,omitempty"`
	ReferenceID       string   `json:"reference_id,omitempty"`
	MonlistResponding bool     `json:"monlist_responding"`
	MonlistEntries    int      `json:"monlist_entries,omitempty"`
	SystemInfo        []string `json:"system_info,omitempty"`
	Peers             []string `json:"peers,omitempty"`
	ProbeErrors       []string `json:"probe_errors,omitempty"`
}

// ProbeNTP runs SNTP query and a monlist probe.
func ProbeNTP(host string, port int, timeout time.Duration) (*NTPReport, error) {
	rep := &NTPReport{Host: host, Port: port}

	addr := &net.UDPAddr{IP: net.ParseIP(host), Port: port}
	if addr.IP == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return rep, fmt.Errorf("resolve: %v", err)
		}
		addr.IP = ips[0]
	}

	// ── Probe 1: SNTPv4 client query ──────────────────────────────────
	conn1, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return rep, fmt.Errorf("dial udp: %w", err)
	}
	defer conn1.Close()
	conn1.SetDeadline(time.Now().Add(timeout))

	// First byte: LI(2)=0, VN(3)=4, Mode(3)=3 (client) → 0b00_100_011 = 0x23
	sntpReq := make([]byte, 48)
	sntpReq[0] = 0x23
	if _, err := conn1.Write(sntpReq); err == nil {
		resp := make([]byte, 48)
		n, rerr := conn1.Read(resp)
		if rerr == nil && n >= 48 {
			rep.Reachable = true
			liVnMode := resp[0]
			rep.Version = int((liVnMode >> 3) & 0x07)
			rep.Stratum = int(resp[1])
			// Reference ID at offset 12. For stratum 1, ASCII tag.
			// For stratum >= 2, IPv4 of the upstream peer.
			refID := resp[12:16]
			if rep.Stratum == 1 {
				rep.ReferenceID = printableASCII(refID)
			} else {
				rep.ReferenceID = fmt.Sprintf("%d.%d.%d.%d",
					refID[0], refID[1], refID[2], refID[3])
			}
		} else if rerr != nil {
			rep.ProbeErrors = append(rep.ProbeErrors,
				fmt.Sprintf("sntp read: %v", rerr))
		}
	} else {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("sntp write: %v", err))
	}

	// ── Probe 2: monlist (NTPv2 mode 7, REQ_MON_GETLIST_1) ────────────
	conn2, err := net.DialUDP("udp", nil, addr)
	if err == nil {
		defer conn2.Close()
		conn2.SetDeadline(time.Now().Add(timeout))
		req := buildMonlistRequest()
		if _, err := conn2.Write(req); err == nil {
			// Read up to 8 packets; mode-7 replies can be fragmented across
			// multiple datagrams. We use a short deadline per read after
			// the first to avoid hanging on silent servers.
			conn2.SetReadDeadline(time.Now().Add(timeout))
			buf := make([]byte, 4096)
			var firstReply []byte
			for i := 0; i < 8; i++ {
				n, rerr := conn2.Read(buf)
				if rerr != nil {
					break
				}
				if i == 0 {
					firstReply = append([]byte{}, buf[:n]...)
				}
				if n >= 8 {
					// Mode 7 reply header: bit 7 = response, bit 6 = more.
					// Each mode-7 packet carries a count in offset 6:7
					// (item_count, big-endian u16).
					more := buf[0]&0x40 != 0
					items := int(binary.BigEndian.Uint16(buf[6:8]))
					rep.MonlistEntries += items
					if !more {
						break
					}
				}
				conn2.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			}
			if firstReply != nil && len(firstReply) >= 8 &&
				(firstReply[0]&0x80) != 0 && firstReply[1] == 42 {
				// Response (R) bit set and req_code=42 echo → monlist is on.
				rep.MonlistResponding = true
			}
		}
	}

	// ── Probe 3: mode-6 READVAR (system variables) ────────────────────
	// Leaks version / processor / system / clock etc. as ASCII key=value
	// pairs. Read-only and safe; may be restricted by ntpd's "restrict"
	// directive, in which case we get nothing.
	probeReadvar(addr, timeout, rep)

	// ── Probe 4: mode-6 READSTAT (peer associations) ──────────────────
	probeReadstat(addr, timeout, rep)

	return rep, nil
}

// probeReadvar sends a mode-6 control READVAR for the system association
// (assoc id 0) and parses the returned key=value pairs into rep.SystemInfo.
// Control responses may span multiple fragments (the More bit in byte 1);
// we read whatever arrives within the timeout, best-effort.
func probeReadvar(addr *net.UDPAddr, timeout time.Duration, rep *NTPReport) {
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Control packet: LI=0 VN=2 Mode=6 → 0x16; opcode 2 = READVAR;
	// sequence 1; assoc id 0 (system vars).
	req := []byte{0x16, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(req); err != nil {
		return
	}

	data := readControlData(conn, timeout)
	if len(data) == 0 {
		return
	}

	// Keys we care about, in a stable preference order.
	want := []string{"version", "processor", "system", "leap", "stratum",
		"refid", "clock", "peer"}
	for _, k := range want {
		if v, ok := lookupVar(data, k); ok {
			rep.SystemInfo = append(rep.SystemInfo, k+"="+v)
			if len(rep.SystemInfo) >= 30 {
				break
			}
		}
	}
}

// probeReadstat sends a mode-6 control READSTAT (opcode 1, assoc id 0). The
// response data is a list of 4-byte entries: 2-byte association id followed by
// 2-byte peer status. We record each into rep.Peers (cap 30).
func probeReadstat(addr *net.UDPAddr, timeout time.Duration, rep *NTPReport) {
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Control packet: 0x16; opcode 1 = READSTAT; sequence 2; assoc id 0.
	req := []byte{0x16, 0x01, 0x00, 0x02, 0, 0, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(req); err != nil {
		return
	}

	data := readControlData(conn, timeout)
	for i := 0; i+4 <= len(data); i += 4 {
		assoc := binary.BigEndian.Uint16(data[i : i+2])
		status := binary.BigEndian.Uint16(data[i+2 : i+4])
		if assoc == 0 {
			continue
		}
		rep.Peers = append(rep.Peers,
			fmt.Sprintf("assoc=%d status=0x%04x", assoc, status))
		if len(rep.Peers) >= 30 {
			break
		}
	}
}

// readControlData reads one or more mode-6 control response fragments and
// returns the concatenated data payload. NTP control header is 12 bytes;
// byte 1 bit 5 (0x20) is the More flag, bytes 10:11 hold the data count and
// bytes 8:9 the data offset. Best-effort, bounded by the timeout.
func readControlData(conn *net.UDPConn, timeout time.Duration) []byte {
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 4096)
	var out []byte
	for i := 0; i < 16; i++ {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		if n < 12 {
			continue
		}
		// Confirm this is a control response (mode 6, R bit set).
		if buf[0]&0x07 != 6 || buf[1]&0x80 == 0 {
			break
		}
		count := int(binary.BigEndian.Uint16(buf[10:12]))
		if count > n-12 {
			count = n - 12
		}
		if count > 0 {
			out = append(out, buf[12:12+count]...)
		}
		more := buf[1]&0x20 != 0
		if !more {
			break
		}
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	}
	return out
}

// lookupVar finds key=value in a comma/newline-separated ASCII control payload
// and returns the value with surrounding double quotes and whitespace stripped.
func lookupVar(data []byte, key string) (string, bool) {
	for _, field := range splitVars(string(data)) {
		eq := strings.IndexByte(field, '=')
		if eq < 0 {
			continue
		}
		k := strings.TrimSpace(field[:eq])
		if k != key {
			continue
		}
		v := strings.TrimSpace(field[eq+1:])
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			v = v[1 : len(v)-1]
		}
		return v, true
	}
	return "", false
}

// splitVars splits a control payload on commas and newlines, respecting
// double-quoted values (which may legitimately contain commas).
func splitVars(s string) []string {
	var fields []string
	var cur []byte
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQuote = !inQuote
			cur = append(cur, c)
		case (c == ',' || c == '\n' || c == '\r') && !inQuote:
			if len(cur) > 0 {
				fields = append(fields, string(cur))
				cur = cur[:0]
			}
		default:
			cur = append(cur, c)
		}
	}
	if len(cur) > 0 {
		fields = append(fields, string(cur))
	}
	return fields
}

// buildMonlistRequest crafts a 48-byte NTPv2 mode 7 request for
// REQ_MON_GETLIST_1 (request code 42).
//
// Layout per ntpdc/wire spec:
//
//	byte 0: response(1) more(1) version(3) mode(3), for v2 mode 7: 0x17
//	byte 1: auth(1) seq(7):                                  0x00
//	byte 2: implementation:                                  0x03 (XNTPD)
//	byte 3: request code:                                    0x2A (42 = MON_GETLIST_1)
//	bytes 4..47: err/n_items/mbz/data_size + payload zeros
func buildMonlistRequest() []byte {
	req := make([]byte, 48)
	req[0] = 0x17 // version=2, mode=7
	req[1] = 0x00
	req[2] = 0x03 // IMPL_XNTPD
	req[3] = 0x2A // REQ_MON_GETLIST_1
	return req
}

func printableASCII(b []byte) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c >= 0x20 && c < 0x7F {
			out = append(out, c)
		}
	}
	return string(out)
}
