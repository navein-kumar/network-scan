// afpprobe.go: phase 3 driver for AFP (Apple Filing Protocol) over TCP (548).
//
// Hand-rolled DSI (Data Stream Interface). Send a DSIGetStatus request:
//   flags=0x00, command=3 (GetStatus), requestID=1, errorCode=0,
//   totalDataLength=0, reserved=0. Reply contains an offset to the AFP
//   server info block which carries:
//     MachineType offset (2)
//     AFPVersionCount offset (2)
//     UAMCount offset (2)
//     VolumeIconAndMask offset (2)
//     Flags (2)
//     ServerName (pascal-style)
//   Followed by the offsets' targets.
//
// Reference: Apple Filing Protocol Reference (legacy) §6 DSIGetStatus.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

type AFPReport struct {
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	Reachable    bool     `json:"reachable"`
	ServerName   string   `json:"server_name,omitempty"`
	MachineType  string   `json:"machine_type,omitempty"`
	AFPVersions  []string `json:"afp_versions,omitempty"`
	UAMs         []string `json:"uams,omitempty"`
	ServerSig    string   `json:"server_signature,omitempty"`
	Volumes      []string `json:"volumes,omitempty"`
	ProbeErrors  []string `json:"probe_errors,omitempty"`
}

func ProbeAFP(host string, port int, timeout time.Duration) (*AFPReport, error) {
	rep := &AFPReport{Host: host, Port: port}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// DSI header: flags(1)=0, command(1)=3 GetStatus, requestID(2)=1,
	// errorCode/dataOffset(4)=0, totalDataLength(4)=0, reserved(4)=0.
	var pkt bytes.Buffer
	pkt.WriteByte(0x00)
	pkt.WriteByte(0x03)
	binary.Write(&pkt, binary.BigEndian, uint16(1))
	binary.Write(&pkt, binary.BigEndian, uint32(0))
	binary.Write(&pkt, binary.BigEndian, uint32(0))
	binary.Write(&pkt, binary.BigEndian, uint32(0))
	if _, err := conn.Write(pkt.Bytes()); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("write: %v", err))
		return rep, nil
	}

	// Read 16-byte DSI reply header.
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("hdr: %v", err))
		return rep, nil
	}
	dataLen := binary.BigEndian.Uint32(hdr[8:12])
	if dataLen == 0 || dataLen > 1<<16 {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("bad data len %d", dataLen))
		return rep, nil
	}
	data := make([]byte, dataLen)
	if _, err := io.ReadFull(conn, data); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("data: %v", err))
		return rep, nil
	}
	rep.Reachable = true

	// AFP GetStatus reply layout (first part). Offsets are relative to start of data.
	if len(data) < 10 {
		return rep, nil
	}
	off := func(at int) int {
		if at+2 > len(data) {
			return -1
		}
		return int(binary.BigEndian.Uint16(data[at : at+2]))
	}
	machineOff := off(0)
	versOff := off(2)
	uamOff := off(4)

	if machineOff > 0 && machineOff < len(data) {
		rep.MachineType = readAFPPascal(data, machineOff)
	}
	if versOff > 0 && versOff < len(data) {
		rep.AFPVersions = readAFPList(data, versOff)
	}
	if uamOff > 0 && uamOff < len(data) {
		rep.UAMs = readAFPList(data, uamOff)
	}
	// ServerName lives right after the fixed offset block (off 10), but on
	// some implementations a more reliable extraction is to use the
	// machineOff position minus a pascal string scan; just take the bytes at
	// the conventional ServerName position when present.
	rep.ServerName = readAFPPascal(data, 10)

	// Deep content: if the server offers anonymous access ("No User Authent"),
	// log in anonymously and enumerate shared volumes (Nessus-style). Best
	// effort over DSI: any error leaves Volumes empty and never panics.
	if afpHasNoUserAuth(rep.UAMs) {
		afpListVolumes(host, port, rep, timeout)
	}

	return rep, nil
}

// afpHasNoUserAuth reports whether the server advertises the anonymous UAM.
func afpHasNoUserAuth(uams []string) bool {
	for _, u := range uams {
		if u == "No User Authent" {
			return true
		}
	}
	return false
}

// afpPickVersion returns the AFP version string to present at login. Prefer the
// newest 3.x dialect the server reported, else fall back to the first entry.
func afpPickVersion(versions []string) string {
	best := ""
	for _, v := range versions {
		if best == "" {
			best = v
		}
		// AFPX03 / AFP3.x are preferable for FPGetSrvrParms over DSICommand.
		if v == "AFPX03" || v == "AFP3.1" || v == "AFP3.2" || v == "AFP3.3" || v == "AFP3.4" {
			best = v
		}
	}
	return best
}

// dsiOpenSession sends a DSIOpenSession request (command byte 4) and consumes
// the reply, establishing a session in which DSICommand requests are accepted.
func dsiOpenSession(conn net.Conn, timeout time.Duration) error {
	conn.SetDeadline(time.Now().Add(timeout))
	var pkt bytes.Buffer
	pkt.WriteByte(0x00) // flags: request
	pkt.WriteByte(0x04) // command: DSIOpenSession
	binary.Write(&pkt, binary.BigEndian, uint16(1))
	binary.Write(&pkt, binary.BigEndian, uint32(0)) // dataOffset
	binary.Write(&pkt, binary.BigEndian, uint32(0)) // totalDataLength
	binary.Write(&pkt, binary.BigEndian, uint32(0)) // reserved
	if _, err := conn.Write(pkt.Bytes()); err != nil {
		return err
	}
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return err
	}
	dataLen := binary.BigEndian.Uint32(hdr[8:12])
	if dataLen > 0 && dataLen <= 1<<16 {
		// Drain the option block (server quantum etc.); contents unused.
		if _, err := io.ReadFull(conn, make([]byte, dataLen)); err != nil {
			return err
		}
	}
	return nil
}

// dsiCommand sends one DSICommand request (command byte 2) carrying payload as
// the AFP request body, then reads the DSI reply and returns its data block.
// requestID is supplied by the caller to keep the DSI session in step.
func dsiCommand(conn net.Conn, requestID uint16, payload []byte, timeout time.Duration) ([]byte, error) {
	conn.SetDeadline(time.Now().Add(timeout))
	var pkt bytes.Buffer
	pkt.WriteByte(0x00) // flags: request
	pkt.WriteByte(0x02) // command: DSICommand
	binary.Write(&pkt, binary.BigEndian, requestID)
	binary.Write(&pkt, binary.BigEndian, uint32(0))             // dataOffset
	binary.Write(&pkt, binary.BigEndian, uint32(len(payload)))  // totalDataLength
	binary.Write(&pkt, binary.BigEndian, uint32(0))             // reserved
	pkt.Write(payload)
	if _, err := conn.Write(pkt.Bytes()); err != nil {
		return nil, err
	}
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}
	dataLen := binary.BigEndian.Uint32(hdr[8:12])
	if dataLen == 0 {
		return nil, nil
	}
	if dataLen > 1<<16 {
		return nil, fmt.Errorf("dsi reply too large: %d", dataLen)
	}
	data := make([]byte, dataLen)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}
	return data, nil
}

// afpListVolumes performs an anonymous FPLogin then FPGetSrvrParms and fills
// rep.Volumes with the advertised volume names (cap 50). It uses a fresh TCP
// connection because servers (e.g. netatalk) close the socket after a
// GetStatus query.
func afpListVolumes(host string, port int, rep *AFPReport, timeout time.Duration) {
	defer func() { _ = recover() }()

	version := afpPickVersion(rep.AFPVersions)
	if version == "" {
		return
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	// A DSIOpenSession (command 4) must establish a real session before any
	// DSICommand is accepted; the prior GetStatus was only a status query.
	if err := dsiOpenSession(conn, timeout); err != nil {
		return
	}

	// FPLogin request body: command(1)=18, AFPVersion (pascal), UAM (pascal).
	// "No User Authent" carries no extra auth data.
	var login bytes.Buffer
	login.WriteByte(18) // FPLogin
	writeAFPPascal(&login, version)
	writeAFPPascal(&login, "No User Authent")
	if _, err := dsiCommand(conn, 2, login.Bytes(), timeout); err != nil {
		return
	}

	// FPGetSrvrParms request body: command(1)=16, pad(1)=0.
	var parms bytes.Buffer
	parms.WriteByte(16) // FPGetSrvrParms
	parms.WriteByte(0)  // pad
	data, err := dsiCommand(conn, 3, parms.Bytes(), timeout)
	if err != nil || len(data) < 5 {
		return
	}

	// Reply: server time (4) + volume count (1) + per volume flags(1) + pascal name.
	off := 4
	count := int(data[off])
	off++
	for i := 0; i < count && off < len(data); i++ {
		off++ // skip per-volume flags byte
		if off >= len(data) {
			break
		}
		n := int(data[off])
		if off+1+n > len(data) {
			break
		}
		name := string(data[off+1 : off+1+n])
		off += 1 + n
		rep.Volumes = append(rep.Volumes, name)
		if len(rep.Volumes) >= 50 {
			break
		}
	}
}

// writeAFPPascal writes a 1-byte length prefix followed by the string bytes.
func writeAFPPascal(buf *bytes.Buffer, s string) {
	if len(s) > 255 {
		s = s[:255]
	}
	buf.WriteByte(byte(len(s)))
	buf.WriteString(s)
}

// readAFPPascal reads a length-prefixed (1-byte) string starting at off.
func readAFPPascal(data []byte, off int) string {
	if off < 0 || off >= len(data) {
		return ""
	}
	n := int(data[off])
	if off+1+n > len(data) {
		return ""
	}
	return string(data[off+1 : off+1+n])
}

// readAFPList reads a count(1) followed by count pascal strings.
func readAFPList(data []byte, off int) []string {
	if off < 0 || off >= len(data) {
		return nil
	}
	n := int(data[off])
	off++
	var out []string
	for i := 0; i < n && off < len(data); i++ {
		l := int(data[off])
		if off+1+l > len(data) {
			break
		}
		out = append(out, string(data[off+1:off+1+l]))
		off += 1 + l
	}
	return out
}
