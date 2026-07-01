// netbiosprobe.go: phase 3 driver for NetBIOS Name Service (UDP 137).
//
// Hand-rolled NBSTAT query (RFC 1002 §4.2.17):
//   header: txnid(2) + flags(2 = 0x0010 query) + counts(QD=1, AN=0, NS=0, AR=0)
//   question: encoded NetBIOS name = 0x20 + 32-char encoded "*" + 0x00,
//             type=0x21 (NBSTAT), class=0x0001 (IN).
// Response: standard DNS-style header + one answer RR carrying a "name
// table" of NumNames entries, each 18 bytes (15-byte name + 1-byte
// suffix + 2-byte flags). After the name table, 6 bytes of MAC.
package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// NetBIOSReport is what Phase 3 emits per NBNS target.
type NetBIOSReport struct {
	Host        string         `json:"host"`
	Port        int            `json:"port"`
	Names       []NetBIOSName  `json:"names,omitempty"`
	MAC         string         `json:"mac,omitempty"`
	ProbeErrors []string       `json:"probe_errors,omitempty"`
}

// NetBIOSName is one entry in the NBSTAT name table.
type NetBIOSName struct {
	Name   string `json:"name"`
	Suffix string `json:"suffix"` // "0x00", "0x20", "0x1B", ...
	Role   string `json:"role"`
	Flags  string `json:"flags"` // "unique" / "group" + status hints
}

// suffix → role lookup, common NetBIOS service codes.
var netbiosSuffixRole = map[byte]string{
	0x00: "workstation",
	0x03: "messenger",
	0x06: "ras-server",
	0x1B: "domain-master-browser",
	0x1C: "domain-controllers",
	0x1D: "master-browser",
	0x1E: "browser-election",
	0x1F: "net-ddesvc",
	0x20: "server-service",
	0x21: "ras-client",
	0x22: "exchange-interchange",
}

// ProbeNetBIOS sends one NBSTAT query and parses the response.
func ProbeNetBIOS(host string, port int, timeout time.Duration) (*NetBIOSReport, error) {
	rep := &NetBIOSReport{Host: host, Port: port}

	addr := &net.UDPAddr{IP: net.ParseIP(host), Port: port}
	if addr.IP == nil {
		// Try DNS resolution.
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return rep, fmt.Errorf("resolve: %v", err)
		}
		addr.IP = ips[0]
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return rep, fmt.Errorf("dial udp: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	q := buildNBSTATQuery()
	if _, err := conn.Write(q); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("write nbstat: %v", err))
		return rep, nil
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("read nbstat: %v", err))
		return rep, nil
	}
	parseNBSTATResponse(buf[:n], rep)
	return rep, nil
}

// buildNBSTATQuery builds the 50-byte NBSTAT wildcard query.
func buildNBSTATQuery() []byte {
	var b []byte
	// Header: txnid + flags + counts
	b = append(b, 0x12, 0x34) // txnid (arbitrary)
	b = append(b, 0x00, 0x10) // flags: NBNS broadcast query (RD=0, recursion-not-desired, no broadcast bit needed for unicast)
	b = append(b, 0x00, 0x01) // QDCOUNT = 1
	b = append(b, 0x00, 0x00) // ANCOUNT
	b = append(b, 0x00, 0x00) // NSCOUNT
	b = append(b, 0x00, 0x00) // ARCOUNT

	// Question: NetBIOS-encoded name. The wildcard "*" encodes as:
	//   0x20 (length byte) + "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + 0x00
	// "*" = 0x2A 0x00 ... -> nibble-encoded so each nibble + 'A' (0x41).
	// For wildcard: 0x2A first byte = "CK", then padding 0x00 nibbles = "AA"*15.
	b = append(b, 0x20)
	b = append(b, 'C', 'K')
	for i := 0; i < 30; i++ {
		b = append(b, 'A')
	}
	b = append(b, 0x00)         // root-domain terminator
	b = append(b, 0x00, 0x21)   // QTYPE = NBSTAT
	b = append(b, 0x00, 0x01)   // QCLASS = IN
	return b
}

// parseNBSTATResponse extracts the name table and MAC address.
func parseNBSTATResponse(buf []byte, rep *NetBIOSReport) {
	if len(buf) < 12 {
		rep.ProbeErrors = append(rep.ProbeErrors, "response too short for header")
		return
	}
	ancount := binary.BigEndian.Uint16(buf[6:8])
	if ancount == 0 {
		rep.ProbeErrors = append(rep.ProbeErrors, "no answer in NBSTAT response")
		return
	}
	// Skip header (12 bytes), then skip question section. The question
	// repeats the encoded name (1 length byte + 32 + null = 34 bytes)
	// + QTYPE(2) + QCLASS(2). But not every server echoes the question.
	// We'll search forward from the header for the answer-RR pattern.
	// The answer name is the same encoded "*" + suffix. Then:
	//   TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) NumNames(1) [Name(15)+Suffix(1)+Flags(2)]*N MAC(6)
	off := 12
	// skip question name if present: 1 byte len(0x20), 32 chars, null
	if off+34 <= len(buf) && buf[off] == 0x20 {
		off += 34
		// skip QTYPE + QCLASS
		if off+4 <= len(buf) {
			off += 4
		}
	}
	// skip answer name (same encoded form)
	if off+34 <= len(buf) && buf[off] == 0x20 {
		off += 34
	} else if off+2 <= len(buf) && buf[off] == 0xC0 {
		// compressed pointer
		off += 2
	}
	// TYPE(2) CLASS(2) TTL(4) RDLENGTH(2)
	if off+10 > len(buf) {
		rep.ProbeErrors = append(rep.ProbeErrors, "truncated answer header")
		return
	}
	off += 10
	// NumNames
	if off >= len(buf) {
		return
	}
	numNames := int(buf[off])
	off++
	for i := 0; i < numNames; i++ {
		if off+18 > len(buf) {
			break
		}
		nameRaw := buf[off : off+15]
		suffix := buf[off+15]
		flags := binary.BigEndian.Uint16(buf[off+16 : off+18])
		off += 18
		name := strings.TrimRight(string(nameRaw), " \x00")
		role := netbiosSuffixRole[suffix]
		if role == "" {
			role = "unknown"
		}
		flagsStr := "unique"
		if flags&0x8000 != 0 {
			flagsStr = "group"
		}
		if flags&0x0200 != 0 {
			flagsStr += ",conflict"
		}
		if flags&0x0400 != 0 {
			flagsStr += ",deregister"
		}
		if flags&0x0800 != 0 {
			flagsStr += ",permanent"
		}
		rep.Names = append(rep.Names, NetBIOSName{
			Name:   name,
			Suffix: fmt.Sprintf("0x%02X", suffix),
			Role:   role,
			Flags:  flagsStr,
		})
	}
	if off+6 <= len(buf) {
		mac := buf[off : off+6]
		rep.MAC = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
	}
}
