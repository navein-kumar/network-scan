// rpcprobe.go: phase 3 driver for SunRPC portmap (111) + NFS mountd.
//
// Hand-rolled per RFC 1057 (RPC) and RFC 1813 (NFSv3 / MOUNT). Steps:
//   1. Connect TCP/111 (fall back to UDP/111).
//   2. RPC CALL: program=100000 (portmap), version=2, proc=4 (DUMP).
//   3. Parse list of {program, version, protocol, port} entries.
//   4. If NFS (100003) present, contact mountd port and DUMP its exports
//      (program=100005, version=3, proc=5 EXPORT).
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
	"time"
)

// RPCProgram is one entry in the portmap dump.
type RPCProgram struct {
	Program  int    `json:"program"`
	Version  int    `json:"version"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Name     string `json:"name,omitempty"`
}

// RPCReport is what Phase 3 emits per RPC target.
type RPCReport struct {
	Host          string       `json:"host"`
	Port          int          `json:"port"`
	Programs      []RPCProgram `json:"programs,omitempty"`
	NFSEnabled    bool         `json:"nfs_enabled"`
	MountdPort    int          `json:"mountd_port,omitempty"`
	ExportedPaths []string     `json:"exported_paths,omitempty"`
	ProbeErrors   []string     `json:"probe_errors,omitempty"`
}

// rpcProgramName maps well-known RPC program numbers to names.
var rpcProgramName = map[int]string{
	100000: "portmapper",
	100003: "nfs",
	100005: "mountd",
	100021: "nlockmgr",
	100024: "status",
	100227: "nfs_acl",
}

const (
	rpcPortmap = 100000
	rpcMountd  = 100005
	rpcNFS     = 100003
	rpcVer2    = 2
	rpcVer3    = 3
	procDump   = 4 // portmap DUMP
	procExport = 5 // mountd EXPORT (v3)
)

// ProbeRPC connects to portmap, dumps the program list, and (if NFS is
// present) dumps mountd exports.
func ProbeRPC(host string, port int, timeout time.Duration) (*RPCReport, error) {
	rep := &RPCReport{Host: host, Port: port}

	// Try TCP first
	dumpReply, err := rpcDumpTCP(host, port, timeout)
	if err != nil {
		// Fall back to UDP/111
		dumpReply, err = rpcDumpUDP(host, port, timeout)
		if err != nil {
			rep.ProbeErrors = append(rep.ProbeErrors,
				fmt.Sprintf("portmap dump (tcp+udp): %v", err))
			return rep, nil
		}
	}
	progs, err := parsePortmapDump(dumpReply)
	if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("parse dump: %v", err))
		return rep, nil
	}
	for _, p := range progs {
		p.Name = rpcProgramName[p.Program]
		rep.Programs = append(rep.Programs, p)
		if p.Program == rpcNFS {
			rep.NFSEnabled = true
		}
		if p.Program == rpcMountd && p.Protocol == "tcp" && rep.MountdPort == 0 {
			rep.MountdPort = p.Port
		}
	}
	// If we only saw mountd on UDP, take that.
	if rep.MountdPort == 0 {
		for _, p := range rep.Programs {
			if p.Program == rpcMountd {
				rep.MountdPort = p.Port
				break
			}
		}
	}

	// Mount EXPORT if mountd port known.
	if rep.MountdPort > 0 {
		paths, merr := mountdExport(host, rep.MountdPort, timeout)
		if merr != nil {
			rep.ProbeErrors = append(rep.ProbeErrors,
				fmt.Sprintf("mountd export: %v", merr))
		} else {
			rep.ExportedPaths = paths
		}
	}
	return rep, nil
}

// buildRPCCall builds an RPC CALL message for the given program/version/proc.
// Auth = AUTH_NULL, verifier = AUTH_NULL. xid randomized.
func buildRPCCall(program, version, proc uint32) ([]byte, uint32) {
	var b bytes.Buffer
	xid := rand.Uint32()
	binary.Write(&b, binary.BigEndian, xid)
	binary.Write(&b, binary.BigEndian, uint32(0)) // msg_type = CALL
	binary.Write(&b, binary.BigEndian, uint32(2)) // rpcvers = 2
	binary.Write(&b, binary.BigEndian, program)
	binary.Write(&b, binary.BigEndian, version)
	binary.Write(&b, binary.BigEndian, proc)
	// auth: flavor=0 (AUTH_NULL), length=0
	binary.Write(&b, binary.BigEndian, uint32(0))
	binary.Write(&b, binary.BigEndian, uint32(0))
	// verf: flavor=0, length=0
	binary.Write(&b, binary.BigEndian, uint32(0))
	binary.Write(&b, binary.BigEndian, uint32(0))
	return b.Bytes(), xid
}

// rpcDumpTCP sends an RPC CALL over TCP and returns the reply payload
// (after the record marker and RPC reply header up to the procedure result).
func rpcDumpTCP(host string, port int, timeout time.Duration) ([]byte, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	body, _ := buildRPCCall(rpcPortmap, rpcVer2, procDump)
	// TCP record marker: high bit set + length
	hdr := uint32(0x80000000) | uint32(len(body))
	var pkt bytes.Buffer
	binary.Write(&pkt, binary.BigEndian, hdr)
	pkt.Write(body)
	if _, err := conn.Write(pkt.Bytes()); err != nil {
		return nil, err
	}
	// Read record marker(s) until last fragment.
	return readTCPRecord(conn)
}

// readTCPRecord assembles RPC TCP record fragments into one payload.
func readTCPRecord(r io.Reader) ([]byte, error) {
	var out bytes.Buffer
	for {
		var marker uint32
		if err := binary.Read(r, binary.BigEndian, &marker); err != nil {
			return nil, err
		}
		last := (marker & 0x80000000) != 0
		size := int(marker & 0x7FFFFFFF)
		if size <= 0 || size > 1<<20 {
			return nil, fmt.Errorf("bad fragment size %d", size)
		}
		frag := make([]byte, size)
		if _, err := io.ReadFull(r, frag); err != nil {
			return nil, err
		}
		out.Write(frag)
		if last {
			break
		}
	}
	return out.Bytes(), nil
}

// rpcDumpUDP sends an RPC CALL over UDP and returns the reply.
func rpcDumpUDP(host string, port int, timeout time.Duration) ([]byte, error) {
	addr := &net.UDPAddr{IP: net.ParseIP(host), Port: port}
	if addr.IP == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("resolve: %v", err)
		}
		addr.IP = ips[0]
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	body, _ := buildRPCCall(rpcPortmap, rpcVer2, procDump)
	if _, err := conn.Write(body); err != nil {
		return nil, err
	}
	buf := make([]byte, 65536)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// parsePortmapDump consumes an RPC reply for portmap DUMP and returns the
// list of program entries. Skips xid, msg_type, reply_state, verf, accept_state.
func parsePortmapDump(reply []byte) ([]RPCProgram, error) {
	r := bytes.NewReader(reply)
	// xid(4), msg_type(4)=1 (REPLY), reply_state(4)=0 MSG_ACCEPTED
	var xid, mtype, rstate uint32
	if err := binary.Read(r, binary.BigEndian, &xid); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.BigEndian, &mtype); err != nil {
		return nil, err
	}
	if mtype != 1 {
		return nil, fmt.Errorf("not a reply (msg_type=%d)", mtype)
	}
	if err := binary.Read(r, binary.BigEndian, &rstate); err != nil {
		return nil, err
	}
	if rstate != 0 {
		return nil, fmt.Errorf("reply rejected (state=%d)", rstate)
	}
	// verifier: flavor(4) + opaque-len(4) + opaque
	var vflavor, vlen uint32
	binary.Read(r, binary.BigEndian, &vflavor)
	binary.Read(r, binary.BigEndian, &vlen)
	if vlen > 0 {
		io.CopyN(io.Discard, r, int64(roundUp4(int(vlen))))
	}
	// accept_state(4) = 0 SUCCESS
	var astate uint32
	if err := binary.Read(r, binary.BigEndian, &astate); err != nil {
		return nil, err
	}
	if astate != 0 {
		return nil, fmt.Errorf("rpc accept_state=%d", astate)
	}
	// Now the DUMP result: linked list of {present(1), prog(4), vers(4),
	// proto(4), port(4)} entries, terminated by present=0.
	var out []RPCProgram
	for {
		var present uint32
		if err := binary.Read(r, binary.BigEndian, &present); err != nil {
			return out, nil
		}
		if present == 0 {
			break
		}
		var prog, vers, proto, prt uint32
		if err := binary.Read(r, binary.BigEndian, &prog); err != nil {
			return out, err
		}
		if err := binary.Read(r, binary.BigEndian, &vers); err != nil {
			return out, err
		}
		if err := binary.Read(r, binary.BigEndian, &proto); err != nil {
			return out, err
		}
		if err := binary.Read(r, binary.BigEndian, &prt); err != nil {
			return out, err
		}
		protoName := "tcp"
		if proto == 17 {
			protoName = "udp"
		}
		out = append(out, RPCProgram{
			Program: int(prog), Version: int(vers),
			Protocol: protoName, Port: int(prt),
		})
	}
	return out, nil
}

// mountdExport dials mountd (TCP) and runs MOUNT v3 procedure 5 EXPORT.
// Returns the list of exported paths.
func mountdExport(host string, port int, timeout time.Duration) ([]string, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	body, _ := buildRPCCall(rpcMountd, rpcVer3, procExport)
	hdr := uint32(0x80000000) | uint32(len(body))
	var pkt bytes.Buffer
	binary.Write(&pkt, binary.BigEndian, hdr)
	pkt.Write(body)
	if _, err := conn.Write(pkt.Bytes()); err != nil {
		return nil, err
	}
	reply, err := readTCPRecord(conn)
	if err != nil {
		return nil, err
	}
	return parseExportList(reply)
}

// parseExportList parses the mountd EXPORT reply: list of {path, groups}.
// We only care about the paths.
func parseExportList(reply []byte) ([]string, error) {
	r := bytes.NewReader(reply)
	// Skip RPC reply header (same as portmap).
	var xid, mtype, rstate uint32
	binary.Read(r, binary.BigEndian, &xid)
	binary.Read(r, binary.BigEndian, &mtype)
	binary.Read(r, binary.BigEndian, &rstate)
	if mtype != 1 || rstate != 0 {
		return nil, fmt.Errorf("bad reply header")
	}
	var vflavor, vlen uint32
	binary.Read(r, binary.BigEndian, &vflavor)
	binary.Read(r, binary.BigEndian, &vlen)
	if vlen > 0 {
		io.CopyN(io.Discard, r, int64(roundUp4(int(vlen))))
	}
	var astate uint32
	binary.Read(r, binary.BigEndian, &astate)
	if astate != 0 {
		return nil, fmt.Errorf("accept_state=%d", astate)
	}
	// EXPORT result: linked list of exportnode { dirpath (string), groups, next }.
	var out []string
	for {
		var present uint32
		if err := binary.Read(r, binary.BigEndian, &present); err != nil {
			return out, nil
		}
		if present == 0 {
			break
		}
		// dirpath: opaque variable-length string.
		path, err := readXDRString(r)
		if err != nil {
			return out, err
		}
		out = append(out, path)
		// groups: linked list of {name, next}. Walk and discard.
		for {
			var gpresent uint32
			if err := binary.Read(r, binary.BigEndian, &gpresent); err != nil {
				return out, nil
			}
			if gpresent == 0 {
				break
			}
			if _, err := readXDRString(r); err != nil {
				return out, err
			}
		}
	}
	return out, nil
}

// readXDRString reads an XDR variable-length opaque string (length(4) +
// bytes + padding to 4-byte boundary).
func readXDRString(r io.Reader) (string, error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return "", err
	}
	if n == 0 {
		return "", nil
	}
	if n > 1<<16 {
		return "", fmt.Errorf("xdr string too long: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	pad := roundUp4(int(n)) - int(n)
	if pad > 0 {
		io.CopyN(io.Discard, r, int64(pad))
	}
	return strings.TrimRight(string(buf), "\x00"), nil
}

func roundUp4(n int) int {
	return (n + 3) &^ 3
}
