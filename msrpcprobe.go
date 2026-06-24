// msrpcprobe.go: phase 3 driver for MS-RPC Endpoint Mapper (135/tcp).
//
// Hand-rolled DCERPC BIND to EPMv4
// (UUID e1af8308-5d1f-11c9-91a4-08002b14a0fa version 3.0). The simpler
// "karpathy" path: confirm BIND_ACK is received and that confirms the
// server speaks DCERPC. Full EPM Lookup parsing is deferred; the
// machinery to send Lookup is too much (multi-policy-handle state).
//
// References:
//   [MS-RPCE] 2.2.2 DCERPC packet header
//   [MS-RPCE] 2.2.2.7 BIND PDU
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

type MSRPCEndpoint struct {
	UUID            string `json:"uuid"`
	Version         string `json:"version,omitempty"`
	VersMajor       int    `json:"vers_major,omitempty"`
	VersMinor       int    `json:"vers_minor,omitempty"`
	Annotation      string `json:"annotation,omitempty"`
	NamedPipe       string `json:"named_pipe,omitempty"`
	Port            int    `json:"port,omitempty"`
	ProtocolBinding string `json:"protocol_binding,omitempty"`
}

type MSRPCReport struct {
	Host            string          `json:"host"`
	Port            int             `json:"port"`
	Reachable       bool            `json:"reachable"`
	BindAckReceived bool            `json:"bind_ack_received"`
	Endpoints       []MSRPCEndpoint `json:"endpoints,omitempty"`
	ProbeErrors     []string        `json:"probe_errors,omitempty"`
}

// EPMv4 abstract syntax UUID e1af8308-5d1f-11c9-91a4-08002b14a0fa v3.0
// NDR transfer syntax 8a885d04-1ceb-11c9-9fe8-08002b104860 v2.0
var (
	epmUUID = [16]byte{
		0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11,
		0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa,
	}
	ndrUUID = [16]byte{
		0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
		0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
	}
)

func ProbeMSRPC(host string, port int, timeout time.Duration) (*MSRPCReport, error) {
	rep := &MSRPCReport{Host: host, Port: port}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	rep.Reachable = true

	bind := buildDCERPCBind()
	if _, err := conn.Write(bind); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("write bind: %v", err))
		return rep, nil
	}

	// Read 16-byte common DCERPC header then the rest.
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("read header: %v", err))
		return rep, nil
	}
	if hdr[0] != 0x05 {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("not DCERPC v5: rpc_vers=0x%02x", hdr[0]))
		return rep, nil
	}
	pktType := hdr[2]
	// frag length is at offset 8-10 little-endian.
	fragLen := int(binary.LittleEndian.Uint16(hdr[8:10]))
	if fragLen < 16 {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("bad frag len %d", fragLen))
		return rep, nil
	}
	rest := make([]byte, fragLen-16)
	if _, err := io.ReadFull(conn, rest); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("read body: %v", err))
		return rep, nil
	}
	// 0x0c = BIND_ACK, 0x0d = BIND_NAK
	if pktType == 0x0c {
		rep.BindAckReceived = true
	} else {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("unexpected pkt type 0x%02x", pktType))
		return rep, nil
	}

	// EPT_Lookup loop with pagination. ept_lookup returns an entry
	// handle + up to max_ents towers + a trailing ept_status_t. If the
	// status indicates "more entries available" we re-call with the
	// returned handle until we get ept_s_no_more_entries (0x16c9a0d6)
	// OR we hit the safety cap of 10 calls in case the server keeps
	// returning the same handle.
	const maxLookupCalls = 10
	var entryHandle [20]byte // zero handle on first call
	callID := uint32(2)
	totalCalls := 0
	for {
		totalCalls++
		lookup := buildDCERPCLookup(entryHandle, callID)
		if _, err := conn.Write(lookup); err != nil {
			rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("write lookup #%d: %v", totalCalls, err))
			break
		}
		respHdr := make([]byte, 16)
		if _, err := io.ReadFull(conn, respHdr); err != nil {
			rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("lookup #%d hdr: %v", totalCalls, err))
			break
		}
		if respHdr[0] != 0x05 || respHdr[2] != 0x02 {
			// Not a RESPONSE PDU (0x02). Could be FAULT (0x03).
			rep.ProbeErrors = append(rep.ProbeErrors,
				fmt.Sprintf("lookup #%d unexpected ptype 0x%02x", totalCalls, respHdr[2]))
			break
		}
		respLen := int(binary.LittleEndian.Uint16(respHdr[8:10]))
		if respLen < 24 || respLen > 65535 {
			rep.ProbeErrors = append(rep.ProbeErrors,
				fmt.Sprintf("lookup #%d bad frag len %d", totalCalls, respLen))
			break
		}
		respBody := make([]byte, respLen-16)
		if _, err := io.ReadFull(conn, respBody); err != nil {
			rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("lookup #%d body: %v", totalCalls, err))
			break
		}
		eps, nextHandle, status, perr := parseEPTLookupResponse(respBody)
		if perr != "" {
			rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("lookup #%d parse: %s", totalCalls, perr))
		}
		rep.Endpoints = append(rep.Endpoints, eps...)
		// Termination conditions:
		//   * status == ept_s_no_more_entries (0x16c9a0d6) -- happy path
		//   * status == 0 with zero entries returned                     (server done)
		//   * any non-success non-"more-data" status                     (server error)
		//   * handle came back all-zero                                  (no continuation)
		//   * we hit the safety cap                                      (server misbehaves)
		const eptNoMoreEntries = 0x16c9a0d6
		if status == eptNoMoreEntries {
			break
		}
		if status != 0 {
			// Any other non-zero status: stop. Some servers return
			// ept_s_max_calls_too_small etc; treat them as terminal
			// rather than risk an infinite loop.
			rep.ProbeErrors = append(rep.ProbeErrors,
				fmt.Sprintf("lookup #%d status 0x%08x -- stopping", totalCalls, status))
			break
		}
		if len(eps) == 0 {
			break
		}
		if isZeroHandle(nextHandle) {
			break
		}
		if entryHandle == nextHandle {
			// Handle unchanged: server is stuck. Stop to avoid loop.
			break
		}
		if totalCalls >= maxLookupCalls {
			rep.ProbeErrors = append(rep.ProbeErrors,
				fmt.Sprintf("lookup safety cap %d hit", maxLookupCalls))
			break
		}
		entryHandle = nextHandle
		callID++
		// Bump the per-call read deadline so we don't time out on the
		// very last fragment after several rounds.
		conn.SetDeadline(time.Now().Add(timeout))
	}
	return rep, nil
}

// isZeroHandle returns true if every byte in h is 0.
func isZeroHandle(h [20]byte) bool {
	for _, b := range h {
		if b != 0 {
			return false
		}
	}
	return true
}

// parseEPTLookupResponse walks an ept_lookup response stub for the
// (handle, num_towers, towers[]) sequence and decodes each Tower into
// an MSRPCEndpoint. Only the floors we care about (1 = abstract syntax
// UUID + version, 4 = TCP port or NetBIOS name, 5 = hostname/IP, plus
// named pipe path floors for ncacn_np) are extracted. Best-effort: a
// short or malformed buffer just stops at that point.
//
// Returns (endpoints, nextEntryHandle, status, err). status is the
// trailing ept_status_t (0 = success, 0x16c9a0d6 = no more entries,
// other = error). nextEntryHandle is the 20-byte handle to pass to the
// next ept_lookup call to continue enumeration.
func parseEPTLookupResponse(body []byte) ([]MSRPCEndpoint, [20]byte, uint32, string) {
	var nextHandle [20]byte
	// Skip 4 bytes DCERPC stub overhead (alloc_hint etc) if present.
	if len(body) < 24 {
		return nil, nextHandle, 0, "short body"
	}
	off := 8
	// ept_lookup_handle_t = 4 bytes attribute + 16 bytes uuid
	if len(body)-off < 20 {
		return nil, nextHandle, 0, "short handle"
	}
	copy(nextHandle[:], body[off:off+20])
	off += 20
	if len(body)-off < 4 {
		return nil, nextHandle, 0, "short num_towers"
	}
	numTowers := int(binary.LittleEndian.Uint32(body[off : off+4]))
	off += 4
	if numTowers < 0 || numTowers > 1024 {
		return nil, nextHandle, 0, fmt.Sprintf("absurd num_towers %d", numTowers)
	}
	// max_count, offset, actual_count for the conformant array
	if len(body)-off < 12 {
		return nil, nextHandle, 0, "short array hdr"
	}
	off += 12
	// Per entry: 4 bytes referent id + 4 bytes max_count_of_tower +
	// 4 bytes offset + 4 bytes actual_count + tower bytes + padding to
	// 4-byte boundary.
	var eps []MSRPCEndpoint
	for i := 0; i < numTowers && off < len(body); i++ {
		// 4 byte referent id (skip)
		if len(body)-off < 4 {
			break
		}
		off += 4
		if len(body)-off < 12 {
			break
		}
		// max_count uint32, offset uint32, actual_count uint32
		off += 4 // max
		off += 4 // offset
		actualCount := int(binary.LittleEndian.Uint32(body[off : off+4]))
		off += 4
		if actualCount < 0 || actualCount > 4096 || len(body)-off < actualCount {
			break
		}
		towerBytes := body[off : off+actualCount]
		off += actualCount
		// Align up to 4 byte boundary
		if pad := (4 - actualCount%4) % 4; pad != 0 && len(body)-off >= pad {
			off += pad
		}
		ep := decodeTower(towerBytes)
		if ep.UUID != "" || ep.Port != 0 || ep.NamedPipe != "" {
			eps = append(eps, ep)
		}
	}
	// Trailing ept_status_t is the final 4 bytes of the stub. If the
	// buffer is short we report status = 0 and let the caller treat it
	// as a terminal call.
	var status uint32
	if len(body) >= 4 {
		status = binary.LittleEndian.Uint32(body[len(body)-4:])
	}
	return eps, nextHandle, status, ""
}

// decodeTower walks the floors of a Tower per [MS-RPCE] §2.2.1.2.5.
// Floor format: uint16 lhs_len, lhs bytes, uint16 rhs_len, rhs bytes.
// Floor 1 LHS = 0x0D protocol id + 16 byte UUID + uint16 if_vers_major.
//         RHS = uint16 if_vers_minor.
// Floor 4 (for ncacn_ip_tcp) LHS = 0x07, RHS = uint16 port (big endian).
// Floor 4 (for ncacn_np)     LHS = 0x0F, RHS = pipe path (null term).
// Floor 5 LHS = 0x09 or 0x11, RHS = IP (4 bytes) or hostname.
func decodeTower(t []byte) MSRPCEndpoint {
	var ep MSRPCEndpoint
	if len(t) < 4 {
		return ep
	}
	numFloors := int(binary.LittleEndian.Uint16(t[:2]))
	if numFloors < 1 || numFloors > 16 {
		return ep
	}
	off := 2
	for i := 0; i < numFloors && off < len(t); i++ {
		if len(t)-off < 2 {
			return ep
		}
		lhsLen := int(binary.LittleEndian.Uint16(t[off : off+2]))
		off += 2
		if lhsLen < 1 || len(t)-off < lhsLen {
			return ep
		}
		lhs := t[off : off+lhsLen]
		off += lhsLen
		if len(t)-off < 2 {
			return ep
		}
		rhsLen := int(binary.LittleEndian.Uint16(t[off : off+2]))
		off += 2
		if len(t)-off < rhsLen {
			return ep
		}
		rhs := t[off : off+rhsLen]
		off += rhsLen
		if lhsLen < 1 {
			continue
		}
		protoID := lhs[0]
		switch protoID {
		case 0x0D: // interface UUID
			if lhsLen >= 19 {
				uuid := lhs[1:17]
				major := binary.LittleEndian.Uint16(lhs[17:19])
				ep.UUID = formatUUID(uuid)
				ep.VersMajor = int(major)
				if rhsLen >= 2 {
					minor := binary.LittleEndian.Uint16(rhs[:2])
					ep.VersMinor = int(minor)
					ep.Version = fmt.Sprintf("%d.%d", major, minor)
				} else {
					ep.Version = fmt.Sprintf("%d", major)
				}
			}
		case 0x07: // ncacn_ip_tcp
			ep.ProtocolBinding = "ncacn_ip_tcp"
			if rhsLen >= 2 {
				ep.Port = int(binary.BigEndian.Uint16(rhs[:2]))
			}
		case 0x0F: // ncacn_np
			ep.ProtocolBinding = "ncacn_np"
			if rhsLen > 0 {
				// strip trailing null
				p := rhs
				for len(p) > 0 && p[len(p)-1] == 0 {
					p = p[:len(p)-1]
				}
				ep.NamedPipe = string(p)
			}
		case 0x10: // ncacn_np netbios name
			if rhsLen > 0 && ep.NamedPipe == "" {
				p := rhs
				for len(p) > 0 && p[len(p)-1] == 0 {
					p = p[:len(p)-1]
				}
				ep.Annotation = string(p)
			}
		}
	}
	return ep
}

// formatUUID renders a 16-byte little-endian UUID as canonical 8-4-4-4-12.
func formatUUID(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	return fmt.Sprintf(
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		b[3], b[2], b[1], b[0],
		b[5], b[4],
		b[7], b[6],
		b[8], b[9],
		b[10], b[11], b[12], b[13], b[14], b[15],
	)
}

// buildDCERPCLookup builds an ept_lookup REQUEST PDU (ctx_id 0, opnum
// 2 = ept_lookup) with empty filter (inquiry_type = RPC_C_EP_ALL_ELTS,
// all UUID/iface/vers/object filters NULL). entryHandle is the
// continuation handle (zero on first call, server-returned handle for
// subsequent calls). callID lets the caller distinguish responses on
// the wire.
func buildDCERPCLookup(entryHandle [20]byte, callID uint32) []byte {
	// stub layout: ulong inquiry_type=0, ptr object=NULL,
	// ptr interface=NULL, ulong vers_option=0,
	// ept_lookup_handle_t entry_handle (20 bytes),
	// ulong max_ents = 32.
	stub := make([]byte, 0, 44)
	stub = binary.LittleEndian.AppendUint32(stub, 0) // inquiry_type ALL
	stub = binary.LittleEndian.AppendUint32(stub, 0) // object NULL ptr
	stub = binary.LittleEndian.AppendUint32(stub, 0) // interface NULL ptr
	stub = binary.LittleEndian.AppendUint32(stub, 0) // vers_option
	// ept_lookup_handle_t passed verbatim (caller supplies 20 zero bytes
	// for the first call; the server-returned handle for continuations).
	stub = append(stub, entryHandle[:]...)
	stub = binary.LittleEndian.AppendUint32(stub, 32) // max ents

	const opnum = 2 // ept_lookup
	const hdrLen = 24
	fragLen := hdrLen + len(stub)
	pkt := make([]byte, 0, fragLen)
	pkt = append(pkt,
		0x05, 0x00,             // rpc_vers, minor
		0x00,                   // ptype = REQUEST
		0x03,                   // pfc_flags FIRST|LAST
		0x10, 0x00, 0x00, 0x00, // data rep
	)
	pkt = binary.LittleEndian.AppendUint16(pkt, uint16(fragLen)) // frag len
	pkt = binary.LittleEndian.AppendUint16(pkt, 0)               // auth len
	pkt = binary.LittleEndian.AppendUint32(pkt, callID)          // call id
	pkt = binary.LittleEndian.AppendUint32(pkt, uint32(len(stub))) // alloc hint
	pkt = binary.LittleEndian.AppendUint16(pkt, 0)               // p_cont_id
	pkt = binary.LittleEndian.AppendUint16(pkt, opnum)           // opnum
	pkt = append(pkt, stub...)
	return pkt
}

// buildDCERPCBind builds a minimum BIND packet binding ctx_id 0 to the
// EPMv4 abstract syntax over NDR transfer syntax.
func buildDCERPCBind() []byte {
	const fragLen = 0x48 // 72 bytes total
	pkt := make([]byte, 0, fragLen)

	// Common header (16 bytes)
	pkt = append(pkt,
		0x05, 0x00,             // rpc_vers, rpc_vers_minor
		0x0b,                   // ptype = BIND
		0x03,                   // pfc_flags = FIRST_FRAG|LAST_FRAG
		0x10, 0x00, 0x00, 0x00, // data rep: little-endian, ASCII, IEEE
	)
	pkt = binary.LittleEndian.AppendUint16(pkt, fragLen) // frag length
	pkt = binary.LittleEndian.AppendUint16(pkt, 0)       // auth length
	pkt = binary.LittleEndian.AppendUint32(pkt, 1)       // call id

	// BIND-specific (12 bytes before context list)
	pkt = binary.LittleEndian.AppendUint16(pkt, 5840) // max xmit frag
	pkt = binary.LittleEndian.AppendUint16(pkt, 5840) // max recv frag
	pkt = binary.LittleEndian.AppendUint32(pkt, 0)    // assoc group
	pkt = append(pkt, 0x01, 0x00, 0x00, 0x00)         // n_context_elem=1 + 3 pad

	// Context element 0
	pkt = binary.LittleEndian.AppendUint16(pkt, 0) // p_cont_id
	pkt = append(pkt, 0x01, 0x00)                  // n_transfer_syn=1, reserved
	pkt = append(pkt, epmUUID[:]...)               // abstract syntax UUID
	pkt = binary.LittleEndian.AppendUint16(pkt, 3) // version
	pkt = binary.LittleEndian.AppendUint16(pkt, 0) // version minor
	pkt = append(pkt, ndrUUID[:]...)               // transfer syntax UUID
	pkt = binary.LittleEndian.AppendUint16(pkt, 2) // ndr version
	pkt = binary.LittleEndian.AppendUint16(pkt, 0) // version minor

	return pkt
}
