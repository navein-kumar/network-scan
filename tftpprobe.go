// tftpprobe.go: phase 3 driver for TFTP (69/udp).
//
// Hand-rolled per RFC 1350:
//   - Build RRQ packet: opcode 1 + filename + 0 + mode + 0.
//   - opcode 3 (DATA) reply: server is serving files anonymously.
//   - opcode 5 (ERROR) reply: at least confirms TFTP speaks here.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

type TFTPReport struct {
	Host            string   `json:"host"`
	Port            int      `json:"port"`
	Reachable       bool     `json:"reachable"`
	AcceptsRequests bool     `json:"accepts_requests"`
	ErrorCode       int      `json:"error_code,omitempty"`
	ErrorMessage    string   `json:"error_message,omitempty"`
	RetrievedFiles  []string `json:"retrieved_files,omitempty"`
	ProbeErrors     []string `json:"probe_errors,omitempty"`
}

// tftpWellKnown is a small list of filenames routinely left readable on
// device TFTP servers (router/switch configs, boot files, secrets).
var tftpWellKnown = []string{
	"running-config",
	"startup-config",
	"config.txt",
	"backup.cfg",
	"passwd",
	"sysconfig",
	"test.txt",
	"tftpboot/pxelinux.0",
}

// tftpMaxFiles caps how many retrieved files we record.
const tftpMaxFiles = 16

func ProbeTFTP(host string, port int, timeout time.Duration) (*TFTPReport, error) {
	rep := &TFTPReport{Host: host, Port: port}
	addr := &net.UDPAddr{IP: net.ParseIP(host), Port: port}
	if addr.IP == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return rep, fmt.Errorf("resolve: %v", err)
		}
		addr.IP = ips[0]
	}
	// Use an unconnected socket: RFC 1350 servers answer from a fresh
	// transfer ID (a new port), which a connected (Dial) socket would drop.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// RRQ: opcode(2)=1, filename, 0, mode, 0.
	var pkt bytes.Buffer
	binary.Write(&pkt, binary.BigEndian, uint16(1))
	pkt.WriteString("version.txt")
	pkt.WriteByte(0)
	pkt.WriteString("netascii")
	pkt.WriteByte(0)
	if _, err := conn.WriteToUDP(pkt.Bytes(), addr); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("write: %v", err))
		return rep, nil
	}
	buf := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("read: %v", err))
		return rep, nil
	}
	if n < 4 {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("short reply %d", n))
		return rep, nil
	}
	op := binary.BigEndian.Uint16(buf[0:2])
	switch op {
	case 3: // DATA
		rep.Reachable = true
		rep.AcceptsRequests = true
	case 5: // ERROR
		rep.Reachable = true
		rep.ErrorCode = int(binary.BigEndian.Uint16(buf[2:4]))
		end := bytes.IndexByte(buf[4:n], 0)
		if end < 0 {
			end = n - 4
		}
		rep.ErrorMessage = strings.TrimRight(string(buf[4:4+end]), "\x00")
	default:
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("opcode %d", op))
	}

	// TFTP has no directory listing, so attempt a RRQ for each well-known
	// filename. A DATA reply (opcode 3) means the file is readable; an
	// ERROR reply (opcode 5) means it is not. Bounded by the deadline.
	if rep.Reachable {
		for _, name := range tftpWellKnown {
			if len(rep.RetrievedFiles) >= tftpMaxFiles {
				break
			}
			sz, ok := tftpRetrieve(addr, name, timeout)
			if ok {
				rep.RetrievedFiles = append(rep.RetrievedFiles,
					fmt.Sprintf("%s (%d bytes)", name, sz))
			}
		}
	}
	return rep, nil
}

// tftpRetrieve sends an octet-mode RRQ for name and, if the server answers
// with DATA, reads the file to count its size then lets the transfer end.
// Returns (size, true) on a DATA reply, else 0,false.
//
// Per RFC 1350 the server answers from a fresh transfer ID (a new UDP port),
// so we use an unconnected socket and ReadFromUDP: a connected (Dial) socket
// would drop the reply for coming from a different source port. ACKs are sent
// back to whatever port the DATA arrived from.
func tftpRetrieve(addr *net.UDPAddr, name string, timeout time.Duration) (int, bool) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return 0, false
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	conn.SetDeadline(deadline)

	// RRQ: opcode(2)=1, filename, 0, mode "octet", 0.
	var pkt bytes.Buffer
	binary.Write(&pkt, binary.BigEndian, uint16(1))
	pkt.WriteString(name)
	pkt.WriteByte(0)
	pkt.WriteString("octet")
	pkt.WriteByte(0)
	if _, err := conn.WriteToUDP(pkt.Bytes(), addr); err != nil {
		return 0, false
	}

	const maxBytes = 1 << 20 // 1 MiB cap to bound a hostile/huge file.
	buf := make([]byte, 1024)
	total := 0
	gotData := false
	for time.Now().Before(deadline) && total < maxBytes {
		n, srv, err := conn.ReadFromUDP(buf)
		if err != nil || n < 4 {
			break
		}
		op := binary.BigEndian.Uint16(buf[0:2])
		if op == 5 { // ERROR: file not available.
			return 0, false
		}
		if op != 3 { // not DATA: give up on this name.
			break
		}
		gotData = true
		block := binary.BigEndian.Uint16(buf[2:4])
		dataLen := n - 4
		total += dataLen
		// ACK this block (to the server's TID) so it keeps streaming.
		ack := []byte{0, 4, byte(block >> 8), byte(block)}
		conn.WriteToUDP(ack, srv)
		if dataLen < 512 { // last block (default 512-byte blocks).
			break
		}
	}
	if !gotData {
		return 0, false
	}
	return total, true
}
