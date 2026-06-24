// nfsprobe.go: phase 3 driver for NFS (TCP 2049 direct + portmapper 111).
//
// What it does:
//   1. TCP/2049 reachability check  -> NFSReachable.
//   2. Portmap (TCP/111) RPC NULL   -> RPCBindOpen.
//   3. Walk portmap DUMP, find mountd port, then run MOUNT v3 EXPORT
//      keeping the per-export host ACL ("groups" list). An export with
//      zero groups OR a "*" group is treated as world-readable.
//   4. Anonymous-mount probe: send an RPC NULL (proc 0) to NFS 2049 over
//      TCP. A clean MSG_ACCEPTED reply means the daemon talks to us
//      with AUTH_NULL, which is the precondition for an unauthenticated
//      mount attempt. We deliberately do NOT issue MOUNT/READ ops.
//
// Reuses helpers from rpcprobe.go (same package):
//   buildRPCCall, readTCPRecord, readXDRString, roundUp4,
//   rpcPortmap/rpcMountd/rpcNFS/rpcVer2/rpcVer3/procDump/procExport.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// NFSExport is one entry returned by mountd EXPORT.
type NFSExport struct {
	Path          string   `json:"path"`
	AllowedHosts  []string `json:"allowed_hosts,omitempty"`
	WorldReadable bool     `json:"world_readable"`
}

// NFSReport is what Phase 3 emits per NFS target.
type NFSReport struct {
	Host           string      `json:"host"`
	Port           int         `json:"port"`
	NFSReachable   bool        `json:"nfs_reachable"`
	RPCBindOpen    bool        `json:"rpcbind_open"`
	MountdPort     int         `json:"mountd_port,omitempty"`
	Exports        []NFSExport `json:"exports,omitempty"`
	AnonMountTried bool        `json:"anon_mount_tried"`
	AnonMountOK    bool        `json:"anon_mount_ok"`
	ProbeErrors    []string    `json:"probe_errors,omitempty"`
}

const (
	nfsDefaultPort      = 2049
	portmapDefaultPort  = 111
	procNFSNull         = 0
	rpcMsgTypeReply     = 1
	rpcReplyAccepted    = 0
	rpcAcceptStateOK    = 0
)

// ProbeNFS runs the four checks above. `port` is the port that triggered
// dispatch; usually 2049 (NFS direct) but the driver also independently
// queries 111 for portmap data.
func ProbeNFS(host string, port int, timeout time.Duration) (*NFSReport, error) {
	rep := &NFSReport{Host: host, Port: port}

	// 1. NFS reachability on 2049/tcp.
	nfsPort := nfsDefaultPort
	if port == nfsDefaultPort || port == 0 {
		nfsPort = nfsDefaultPort
	} else {
		// dispatch can call us on a custom NFS port; honor it.
		nfsPort = port
	}
	if c, err := net.DialTimeout("tcp",
		fmt.Sprintf("%s:%d", host, nfsPort), timeout); err == nil {
		rep.NFSReachable = true
		c.Close()
	}

	// 2. portmap RPC NULL on 111/tcp.
	if reachable, err := nfsPortmapNull(host, portmapDefaultPort, timeout); err == nil && reachable {
		rep.RPCBindOpen = true
	}

	// 3. Find mountd via portmap DUMP, then EXPORT with groups.
	if rep.RPCBindOpen {
		mp, exports, err := nfsListExports(host, portmapDefaultPort, timeout)
		if err != nil {
			rep.ProbeErrors = append(rep.ProbeErrors,
				fmt.Sprintf("mountd export: %v", err))
		} else {
			rep.MountdPort = mp
			rep.Exports = exports
		}
	}

	// 4. Anonymous-mount precondition test: NFS RPC NULL on 2049/tcp.
	if rep.NFSReachable {
		rep.AnonMountTried = true
		if ok, err := nfsAnonNull(host, nfsPort, timeout); err == nil && ok {
			rep.AnonMountOK = true
		} else if err != nil {
			rep.ProbeErrors = append(rep.ProbeErrors,
				fmt.Sprintf("nfs null: %v", err))
		}
	}

	return rep, nil
}

// nfsPortmapNull sends an RPC NULL to portmap to confirm a live RPC
// listener (cheap and side-effect-free).
func nfsPortmapNull(host string, port int, timeout time.Duration) (bool, error) {
	body, _ := buildRPCCall(rpcPortmap, rpcVer2, 0) // proc 0 = NULL
	reply, err := nfsRPCTCP(host, port, body, timeout)
	if err != nil {
		return false, err
	}
	return nfsReplyAccepted(reply), nil
}

// nfsAnonNull sends an RPC NULL to NFS v3 on the given port. A clean
// MSG_ACCEPTED reply means the daemon answers unauthenticated callers.
func nfsAnonNull(host string, port int, timeout time.Duration) (bool, error) {
	body, _ := buildRPCCall(rpcNFS, rpcVer3, procNFSNull)
	reply, err := nfsRPCTCP(host, port, body, timeout)
	if err != nil {
		return false, err
	}
	return nfsReplyAccepted(reply), nil
}

// nfsListExports does portmap DUMP -> mountd EXPORT, parsing per-export
// host ACL groups. Returns mountd port, exports, error.
func nfsListExports(host string, pmPort int, timeout time.Duration) (int, []NFSExport, error) {
	// Portmap DUMP.
	body, _ := buildRPCCall(rpcPortmap, rpcVer2, procDump)
	dumpReply, err := nfsRPCTCP(host, pmPort, body, timeout)
	if err != nil {
		return 0, nil, fmt.Errorf("portmap dump: %w", err)
	}
	progs, err := parsePortmapDump(dumpReply)
	if err != nil {
		return 0, nil, fmt.Errorf("parse dump: %w", err)
	}
	mountdPort := 0
	for _, p := range progs {
		if p.Program == rpcMountd && p.Protocol == "tcp" {
			mountdPort = p.Port
			break
		}
	}
	if mountdPort == 0 {
		// Fall back to UDP-registered mountd if no TCP entry.
		for _, p := range progs {
			if p.Program == rpcMountd {
				mountdPort = p.Port
				break
			}
		}
	}
	if mountdPort == 0 {
		return 0, nil, fmt.Errorf("mountd not registered")
	}

	// Mountd EXPORT, keeping groups.
	body, _ = buildRPCCall(rpcMountd, rpcVer3, procExport)
	mountReply, err := nfsRPCTCP(host, mountdPort, body, timeout)
	if err != nil {
		return mountdPort, nil, fmt.Errorf("mountd EXPORT: %w", err)
	}
	exports, err := nfsParseExportsWithGroups(mountReply)
	if err != nil {
		return mountdPort, nil, fmt.Errorf("parse exports: %w", err)
	}
	return mountdPort, exports, nil
}

// nfsRPCTCP sends one RPC call body over a fresh TCP connection and
// returns the response payload.
func nfsRPCTCP(host string, port int, body []byte, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	hdr := uint32(0x80000000) | uint32(len(body))
	var pkt bytes.Buffer
	binary.Write(&pkt, binary.BigEndian, hdr)
	pkt.Write(body)
	if _, err := conn.Write(pkt.Bytes()); err != nil {
		return nil, err
	}
	return readTCPRecord(conn)
}

// nfsReplyAccepted returns true iff the RPC reply is MSG_ACCEPTED /
// SUCCESS (i.e. the daemon accepted our AUTH_NULL call).
func nfsReplyAccepted(reply []byte) bool {
	r := bytes.NewReader(reply)
	var xid, mtype, rstate uint32
	if binary.Read(r, binary.BigEndian, &xid) != nil {
		return false
	}
	if binary.Read(r, binary.BigEndian, &mtype) != nil || mtype != rpcMsgTypeReply {
		return false
	}
	if binary.Read(r, binary.BigEndian, &rstate) != nil || rstate != rpcReplyAccepted {
		return false
	}
	var vflavor, vlen uint32
	binary.Read(r, binary.BigEndian, &vflavor)
	binary.Read(r, binary.BigEndian, &vlen)
	if vlen > 0 {
		io.CopyN(io.Discard, r, int64(roundUp4(int(vlen))))
	}
	var astate uint32
	if binary.Read(r, binary.BigEndian, &astate) != nil {
		return false
	}
	return astate == rpcAcceptStateOK
}

// nfsParseExportsWithGroups parses the mountd v3 EXPORT reply. Unlike
// rpcprobe.go's parseExportList (which discards groups), we keep them so
// we can flag world-readable shares.
//
// EXPORT result XDR (RFC 1813 sec 5.2.3):
//   exportnode { dirpath name; groups groups; exportnode *ex; }
//   groups    { name; groups *gr; }
// Each "*present" uint32 is the XDR list marker (1=node follows, 0=end).
func nfsParseExportsWithGroups(reply []byte) ([]NFSExport, error) {
	r := bytes.NewReader(reply)
	// Skip RPC reply header.
	var xid, mtype, rstate uint32
	binary.Read(r, binary.BigEndian, &xid)
	binary.Read(r, binary.BigEndian, &mtype)
	binary.Read(r, binary.BigEndian, &rstate)
	if mtype != rpcMsgTypeReply || rstate != rpcReplyAccepted {
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
	if astate != rpcAcceptStateOK {
		return nil, fmt.Errorf("accept_state=%d", astate)
	}

	var out []NFSExport
	for {
		var present uint32
		if err := binary.Read(r, binary.BigEndian, &present); err != nil {
			return out, nil
		}
		if present == 0 {
			break
		}
		path, err := readXDRString(r)
		if err != nil {
			return out, err
		}
		var hosts []string
		for {
			var gpresent uint32
			if err := binary.Read(r, binary.BigEndian, &gpresent); err != nil {
				return out, nil
			}
			if gpresent == 0 {
				break
			}
			name, err := readXDRString(r)
			if err != nil {
				return out, err
			}
			hosts = append(hosts, name)
		}
		out = append(out, NFSExport{
			Path:          path,
			AllowedHosts:  hosts,
			WorldReadable: nfsExportIsWorldReadable(hosts),
		})
	}
	return out, nil
}

// nfsExportIsWorldReadable returns true when the host ACL has no entries
// at all OR contains a wildcard ("*", "*.*", or a 0.0.0.0/0 style).
func nfsExportIsWorldReadable(hosts []string) bool {
	if len(hosts) == 0 {
		return true
	}
	for _, h := range hosts {
		if h == "*" || h == "*.*" || h == "0.0.0.0/0" || h == "::/0" {
			return true
		}
	}
	return false
}
