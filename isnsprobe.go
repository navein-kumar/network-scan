// isnsprobe.go: phase 3 driver for iSNS (Internet Storage Name Service, 3205).
//
// Hand-rolled per RFC 4171. v0 sends a DevAttrQry (function 0x0014)
// with no source attribute filter; we only care whether the server
// responds with an iSNS message header carrying the correct version
// and function-id of the reply. A reply means an iSNS server is alive
// and reachable to anyone on the network, which leaks the storage
// fabric topology.
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

type ISNSReport struct {
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	Reachable    bool     `json:"reachable"`
	DeviceCount  int      `json:"device_count,omitempty"`
	FunctionID   string   `json:"function_id,omitempty"`
	ProbeErrors  []string `json:"probe_errors,omitempty"`
}

func ProbeISNS(host string, port int, timeout time.Duration) (*ISNSReport, error) {
	rep := &ISNSReport{Host: host, Port: port}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// iSNS message header: version(2) functionID(2) pduLength(2)
	// flags(2) transactionID(2) sequenceID(2) = 12 bytes, then payload.
	// We send DevAttrQry (0x0014) with FIRST_PDU(0x0400) + LAST_PDU(0x0800)
	// + SENDER_CLIENT(0x0040) flags and an empty payload (some servers
	// reply 'Message Format Error' but still confirm reachability).
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], 0x0001)  // iSNSP version
	binary.BigEndian.PutUint16(hdr[2:4], 0x0014)  // DevAttrQry
	binary.BigEndian.PutUint16(hdr[4:6], 0)       // payload length
	binary.BigEndian.PutUint16(hdr[6:8], 0x0c40)  // FIRST+LAST+SENDER_CLIENT
	binary.BigEndian.PutUint16(hdr[8:10], 0x0001) // transaction id
	binary.BigEndian.PutUint16(hdr[10:12], 0x0001) // sequence id
	if _, err := conn.Write(hdr); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("write: %v", err))
		return rep, nil
	}

	respHdr := make([]byte, 12)
	if _, err := io.ReadFull(conn, respHdr); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("read: %v", err))
		return rep, nil
	}
	if binary.BigEndian.Uint16(respHdr[0:2]) != 0x0001 {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("bad version 0x%04x", binary.BigEndian.Uint16(respHdr[0:2])))
		return rep, nil
	}
	rep.Reachable = true
	rep.FunctionID = fmt.Sprintf("0x%04x", binary.BigEndian.Uint16(respHdr[2:4]))
	pduLen := int(binary.BigEndian.Uint16(respHdr[4:6]))
	if pduLen > 0 && pduLen < 1<<16 {
		payload := make([]byte, pduLen)
		if _, err := io.ReadFull(conn, payload); err == nil {
			// Each registered device emits an iSCSI Name attribute (tag
			// 0x00000020 per RFC 4171 Table 5). Count occurrences as a
			// rough device count. v0: simple substring scan.
			for off := 0; off+8 <= len(payload); off += 4 {
				tag := binary.BigEndian.Uint32(payload[off : off+4])
				if tag == 0x00000020 {
					rep.DeviceCount++
				}
			}
		}
	}
	return rep, nil
}
