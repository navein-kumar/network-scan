// ikeprobe.go: phase 3 driver for IKE / IPsec (UDP 500, optionally 4500).
//
// Hand-rolled per RFC 2408 / RFC 5996. We send an IKEv1 Main Mode SA
// proposal with a single transform (3DES + SHA1 + PSK + DH group 2) and
// see if the server replies. If it does, IKE is exposed. Some IKE
// servers will also accept Aggressive Mode (a higher-severity finding);
// we send an Aggressive Mode SA proposal as a second probe and report
// the result separately. Vendor IDs in the reply are captured as hex.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type IKEReport struct {
	Host              string   `json:"host"`
	Port              int      `json:"port"`
	Reachable         bool     `json:"reachable"`
	IKEVersion        int      `json:"ike_version,omitempty"`
	MainModeAccepted  bool     `json:"main_mode_accepted"`
	AggressiveAccepted bool    `json:"aggressive_mode_accepted"`
	VendorIDs         []string `json:"vendor_ids,omitempty"`
	PSKHash           string   `json:"psk_hash,omitempty"`
	PSKHashFormat     string   `json:"psk_hash_format,omitempty"`
	ProbeErrors       []string `json:"probe_errors,omitempty"`
}

func ProbeIKE(host string, port int, timeout time.Duration) (*IKEReport, error) {
	rep := &IKEReport{Host: host, Port: port}
	addr := &net.UDPAddr{IP: net.ParseIP(host), Port: port}
	if addr.IP == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return rep, fmt.Errorf("resolve: %v", err)
		}
		addr.IP = ips[0]
	}

	// ── Probe 1: Main Mode (exchange type 2) ─────────────────────────
	if mainResp, err := sendIKE(addr, timeout, buildIKEPacket(2)); err == nil && len(mainResp) >= 28 {
		rep.Reachable = true
		rep.MainModeAccepted = true
		rep.IKEVersion = int(mainResp[17] >> 4)
		rep.VendorIDs = parseIKEVendorIDs(mainResp)
	} else if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("main: %v", err))
	}

	// ── Probe 2: Aggressive Mode (exchange type 4) ────────────────────
	if aggResp, err := sendIKE(addr, timeout, buildIKEPacket(4)); err == nil && len(aggResp) >= 28 {
		// Aggressive Mode is only "accepted" if the reply itself is an
		// Aggressive Mode response (exchange type byte 4), not a NOTIFY
		// rejection. Some implementations reply with exchange type 5
		// (INFORMATIONAL) carrying a NOTIFY/INVALID-EXCHANGE-TYPE.
		if aggResp[18] == 4 {
			rep.Reachable = true
			rep.AggressiveAccepted = true
			if rep.IKEVersion == 0 {
				rep.IKEVersion = int(aggResp[17] >> 4)
			}
			if len(rep.VendorIDs) == 0 {
				rep.VendorIDs = parseIKEVendorIDs(aggResp)
			}
		}
	} else if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("aggressive: %v", err))
	}

	// ── Deep content: Aggressive Mode PSK hash dump ──────────────────
	// The IKEv1 Aggressive Mode PSK hash crypto is too involved to
	// hand-roll, so we shell out to ike-scan (the standard tool) only
	// when the gateway actually accepted Aggressive Mode. The captured
	// psk-crack line feeds hashcat -m 5300 (after conversion) or psk-crack.
	if rep.AggressiveAccepted {
		if hash, err := ikeScanPSKHash(addr.IP.String(), port, timeout); err != nil {
			rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("psk-hash: %v", err))
		} else if hash != "" {
			rep.PSKHash = hash
			rep.PSKHashFormat = "psk-crack"
		}
	}
	return rep, nil
}

// ikeScanPSKHash shells out to ike-scan to capture the offline-crackable
// IKEv1 Aggressive Mode PSK hash. It runs:
//
//	ike-scan --aggressive --pskcrack <host> [--dport <port>]
//
// and returns the colon-separated psk-crack line (<g_xr>:<g_xi>:...:<hash_r>).
// Best-effort: if ike-scan is not installed or emits no hash line, it returns
// an empty string with no error. The run is bounded by a context timeout so it
// never blocks the scan. It never panics.
func ikeScanPSKHash(host string, port int, timeout time.Duration) (string, error) {
	bin, err := exec.LookPath("ike-scan")
	if err != nil {
		return "", fmt.Errorf("ike-scan not installed")
	}

	// Give the shell-out a generous bound: ike-scan does its own retries,
	// so allow several multiples of the per-packet timeout, with a floor.
	deadline := timeout * 4
	if deadline < 10*time.Second {
		deadline = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()

	args := []string{"--aggressive", "--pskcrack"}
	if port != 0 && port != 500 {
		args = append(args, "--dport", strconv.Itoa(port))
	}
	args = append(args, host)

	out, _ := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("ike-scan timed out after %s", deadline)
	}
	return parsePSKCrackLine(string(out)), nil
}

// parsePSKCrackLine extracts the psk-crack hash line from ike-scan output.
// ike-scan prints the hash as a single line of colon-separated hex fields
// (at least the nine values g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r),
// optionally prefixed with "IKE PSK parameters ...:". We return the bare
// colon-separated value, or "" if no such line is present.
func parsePSKCrackLine(out string) string {
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if i := strings.Index(line, "parameters"); i >= 0 {
			if j := strings.Index(line[i:], ":"); j >= 0 {
				line = strings.TrimSpace(line[i+j+1:])
			}
		}
		fields := strings.Split(line, ":")
		if len(fields) >= 9 && allHex(fields) {
			return line
		}
	}
	return ""
}

// allHex reports whether every field is a non-empty hexadecimal string.
func allHex(fields []string) bool {
	for _, f := range fields {
		if f == "" {
			return false
		}
		if _, err := hex.DecodeString(f); err != nil {
			return false
		}
	}
	return true
}

func sendIKE(addr *net.UDPAddr, timeout time.Duration, pkt []byte) ([]byte, error) {
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(pkt); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// buildIKEPacket assembles an IKEv1 Phase-1 packet with a single SA
// payload carrying one proposal + one transform (3DES-CBC, SHA1, PSK,
// DH group 2, lifetime 28800s). exchType is 2 for Main Mode, 4 for
// Aggressive Mode.
func buildIKEPacket(exchType byte) []byte {
	var cookie [8]byte
	rand.Read(cookie[:])

	// Transform payload (ISAKMP transform #1, type=KEY_IKE)
	tr := &bytes.Buffer{}
	tr.WriteByte(0) // next payload = NONE
	tr.WriteByte(0) // reserved
	binary.Write(tr, binary.BigEndian, uint16(0)) // length placeholder
	tr.WriteByte(1)                                // transform # 1
	tr.WriteByte(1)                                // transform-id = KEY_IKE
	binary.Write(tr, binary.BigEndian, uint16(0)) // reserved
	// SA attributes (TLV): Encryption=3DES(5), Hash=SHA1(2), Auth=PSK(1),
	// Group=2 (MODP-1024), Life-type=seconds(1), Life-duration=28800.
	writeIKEAttr(tr, 1, 5)     // enc
	writeIKEAttr(tr, 2, 2)     // hash
	writeIKEAttr(tr, 3, 1)     // auth
	writeIKEAttr(tr, 4, 2)     // group
	writeIKEAttr(tr, 11, 1)    // life-type
	writeIKEAttrVar(tr, 12, []byte{0x00, 0x00, 0x70, 0x80}) // life-duration 28800
	trBytes := tr.Bytes()
	binary.BigEndian.PutUint16(trBytes[2:4], uint16(len(trBytes)))

	// Proposal payload wrapping the transform
	pr := &bytes.Buffer{}
	pr.WriteByte(0) // next payload = NONE
	pr.WriteByte(0) // reserved
	binary.Write(pr, binary.BigEndian, uint16(0)) // length placeholder
	pr.WriteByte(1)                                // proposal # 1
	pr.WriteByte(1)                                // protocol-id = ISAKMP
	pr.WriteByte(0)                                // SPI size = 0
	pr.WriteByte(1)                                // # transforms = 1
	pr.Write(trBytes)
	prBytes := pr.Bytes()
	binary.BigEndian.PutUint16(prBytes[2:4], uint16(len(prBytes)))

	// SA payload wrapping the proposal
	sa := &bytes.Buffer{}
	sa.WriteByte(0) // next payload = NONE
	sa.WriteByte(0)
	binary.Write(sa, binary.BigEndian, uint16(0)) // length placeholder
	binary.Write(sa, binary.BigEndian, uint32(1)) // DOI = IPSEC
	binary.Write(sa, binary.BigEndian, uint32(1)) // situation = SIT_IDENTITY_ONLY
	sa.Write(prBytes)
	saBytes := sa.Bytes()
	binary.BigEndian.PutUint16(saBytes[2:4], uint16(len(saBytes)))

	// ISAKMP header
	pkt := &bytes.Buffer{}
	pkt.Write(cookie[:])                             // initiator cookie
	pkt.Write(make([]byte, 8))                       // responder cookie = 0
	pkt.WriteByte(1)                                 // next payload = SA
	pkt.WriteByte(0x10)                              // version 1.0
	pkt.WriteByte(exchType)                          // exchange type
	pkt.WriteByte(0)                                 // flags
	binary.Write(pkt, binary.BigEndian, uint32(0))   // message ID
	binary.Write(pkt, binary.BigEndian, uint32(28+len(saBytes))) // length
	pkt.Write(saBytes)
	return pkt.Bytes()
}

func writeIKEAttr(b *bytes.Buffer, t uint16, v uint16) {
	binary.Write(b, binary.BigEndian, uint16(0x8000|t))
	binary.Write(b, binary.BigEndian, v)
}
func writeIKEAttrVar(b *bytes.Buffer, t uint16, v []byte) {
	binary.Write(b, binary.BigEndian, t) // top bit clear = TLV
	binary.Write(b, binary.BigEndian, uint16(len(v)))
	b.Write(v)
}

// parseIKEVendorIDs walks the payload chain of an ISAKMP response and
// returns each Vendor ID (payload type 13) as a hex string.
func parseIKEVendorIDs(pkt []byte) []string {
	const isakmpHdrLen = 28
	if len(pkt) < isakmpHdrLen {
		return nil
	}
	nextPayload := pkt[16]
	off := isakmpHdrLen
	var vids []string
	for nextPayload != 0 && off+4 <= len(pkt) {
		np := pkt[off]
		ln := int(binary.BigEndian.Uint16(pkt[off+2 : off+4]))
		if ln < 4 || off+ln > len(pkt) {
			break
		}
		if nextPayload == 13 { // Vendor ID
			vids = append(vids, hex.EncodeToString(pkt[off+4:off+ln]))
		}
		nextPayload = np
		off += ln
	}
	return vids
}
